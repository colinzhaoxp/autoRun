"""GPU 利用率采样：调用 nvidia-smi，解析成不可变快照。

设计原则与主体一致 —— **采样绝不能拖垮或搞挂调用它的线程**：

- nvidia-smi 偶尔会 hang（驱动异常、卡掉等），`subprocess.run(timeout=...)` 保证
  最坏情况下也只是本轮采样失败，不会永久阻塞监控线程。
- nvidia-smi 不存在、返回非零、输出无法解析：都返回 `ok=False` 的快照并带上
  error 描述，**从不抛异常**。规则求值时看到 ok=False 会跳过本轮，避免把
  "采样失败" 误判成 "利用率为 0" 而误报。
- argv 形式固定，参数全是常量，没有任何注入面。
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime

# 查询字段顺序固定，解析时按位置取值。noheader/nounits 让输出是纯数字 CSV，
# 省去解析表头与 "MiB"/"%" 之类单位后缀。
_QUERY_FIELDS = "index,utilization.gpu,memory.used,memory.total,temperature.gpu"
_FORMAT = "csv,noheader,nounits"


@dataclass(frozen=True)
class GpuInfo:
    """单张卡的一次采样。内存以 MiB 计（nvidia-smi 的默认单位）。"""

    index: int
    util: float          # 利用率百分比 0-100
    mem_used: float      # MiB
    mem_total: float     # MiB
    temp: float          # 摄氏度

    @property
    def mem_util(self) -> float:
        """显存占用百分比。total 为 0 时返回 0，避免除零。"""
        if self.mem_total <= 0:
            return 0.0
        return round(self.mem_used / self.mem_total * 100, 1)


@dataclass(frozen=True)
class GpuSnapshot:
    """一次采样的完整结果与派生指标。

    `ok=False` 时 gpus 为空、派生指标为 0，error 说明失败原因。消费方（monitor、
    /v1/gpu、healthz）都应先看 ok 再用数据。
    """

    ok: bool
    sampled_at: str                       # ISO 8601 带时区
    gpus: tuple[GpuInfo, ...] = ()
    idle_util_threshold: float = 20.0
    error: str | None = None
    _mono: float = field(default=0.0, repr=False)  # time.monotonic()，仅供 monitor 计时用

    # --- 派生指标 -------------------------------------------------------

    @property
    def count(self) -> int:
        return len(self.gpus)

    @property
    def avg_util(self) -> float:
        if not self.gpus:
            return 0.0
        return round(sum(g.util for g in self.gpus) / len(self.gpus), 1)

    @property
    def min_gpu_util(self) -> float:
        if not self.gpus:
            return 0.0
        return round(min(g.util for g in self.gpus), 1)

    @property
    def max_gpu_util(self) -> float:
        if not self.gpus:
            return 0.0
        return round(max(g.util for g in self.gpus), 1)

    @property
    def idle_count(self) -> int:
        """利用率低于 idle_util_threshold 的卡数。"""
        return sum(1 for g in self.gpus if g.util < self.idle_util_threshold)

    @property
    def max_temp(self) -> float:
        if not self.gpus:
            return 0.0
        return round(max(g.temp for g in self.gpus), 1)

    @property
    def max_mem_util(self) -> float:
        if not self.gpus:
            return 0.0
        return round(max(g.mem_util for g in self.gpus), 1)

    def metric(self, name: str) -> float:
        """按名取一个标量指标，供规则求值使用。"""
        return {
            "avg_util": self.avg_util,
            "idle_count": float(self.idle_count),
            "min_gpu_util": self.min_gpu_util,
            "max_gpu_util": self.max_gpu_util,
            "max_temp": self.max_temp,
            "max_mem_util": self.max_mem_util,
        }[name]

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "sampled_at": self.sampled_at,
            "error": self.error,
            "count": self.count,
            "avg_util": self.avg_util,
            "min_gpu_util": self.min_gpu_util,
            "max_gpu_util": self.max_gpu_util,
            "idle_count": self.idle_count,
            "idle_util_threshold": self.idle_util_threshold,
            "max_temp": self.max_temp,
            "max_mem_util": self.max_mem_util,
            "gpus": [
                {
                    "index": g.index,
                    "util": g.util,
                    "mem_used": g.mem_used,
                    "mem_total": g.mem_total,
                    "mem_util": g.mem_util,
                    "temp": g.temp,
                }
                for g in self.gpus
            ],
        }


# 允许的规则指标集合。config 校验与 GpuSnapshot.metric 共用，改动只需一处。
METRICS = ("avg_util", "idle_count", "min_gpu_util", "max_gpu_util", "max_temp", "max_mem_util")


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def resolve_nvidia_smi(configured: str | None) -> str | None:
    """确定 nvidia-smi 路径：配置显式指定优先，否则 PATH 上 which。

    找不到返回 None（调用方据此决定是记 warning 还是采样时降级），不抛异常。
    """
    if configured:
        return configured
    return shutil.which("nvidia-smi")


def _parse_line(line: str) -> GpuInfo | None:
    """解析一行 CSV。字段数不对或非数字返回 None（跳过该行）。"""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) != 5:
        return None
    try:
        # utilization / temperature 在部分设备上可能是 "[N/A]"，float() 会抛，
        # 由上层捕获整体降级。这里只做直接转换。
        return GpuInfo(
            index=int(parts[0]),
            util=float(parts[1]),
            mem_used=float(parts[2]),
            mem_total=float(parts[3]),
            temp=float(parts[4]),
        )
    except ValueError:
        return None


def sample(
    nvidia_smi_path: str | None,
    *,
    timeout: float = 10.0,
    idle_util_threshold: float = 20.0,
) -> GpuSnapshot:
    """采样一次。任何失败都返回 ok=False 的快照，绝不抛异常。"""
    sampled_at = _now_iso()
    mono = time.monotonic()

    def fail(error: str) -> GpuSnapshot:
        return GpuSnapshot(
            ok=False,
            sampled_at=sampled_at,
            idle_util_threshold=idle_util_threshold,
            error=error,
            _mono=mono,
        )

    if not nvidia_smi_path:
        return fail("未找到 nvidia-smi（未配置且 PATH 中不存在）")

    argv = [
        nvidia_smi_path,
        f"--query-gpu={_QUERY_FIELDS}",
        f"--format={_FORMAT}",
    ]
    try:
        proc = subprocess.run(  # noqa: S603 - argv 固定，无客户端输入，无注入面
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
    except subprocess.TimeoutExpired:
        # nvidia-smi hang 是真实故障模式：驱动挂了时它会卡死。超时视为采样失败，
        # 而不是让监控线程一起卡住。
        return fail(f"nvidia-smi 采样超时（> {timeout}s）")
    except (OSError, ValueError) as exc:
        return fail(f"无法执行 nvidia-smi: {exc}")

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        msg = detail[0] if detail else f"退出码 {proc.returncode}"
        return fail(f"nvidia-smi 返回非零（{proc.returncode}）: {msg}")

    gpus: list[GpuInfo] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        info = _parse_line(line)
        if info is None:
            return fail(f"无法解析 nvidia-smi 输出行: {line!r}")
        gpus.append(info)

    if not gpus:
        return fail("nvidia-smi 未返回任何 GPU 信息")

    return GpuSnapshot(
        ok=True,
        sampled_at=sampled_at,
        gpus=tuple(gpus),
        idle_util_threshold=idle_util_threshold,
        _mono=mono,
    )


def render_table(snap: GpuSnapshot) -> str:
    """人类可读的表格，供 `autorun gpu` CLI 使用。"""
    if not snap.ok:
        return f"采样失败 @ {snap.sampled_at}: {snap.error}"
    lines = [
        f"采样时刻: {snap.sampled_at}   共 {snap.count} 卡"
        f"   平均利用率 {snap.avg_util}%   空闲卡数 {snap.idle_count}"
        f"（阈值 <{snap.idle_util_threshold:g}%）",
        f"{'GPU':>3}  {'Util%':>6}  {'Mem':>17}  {'Mem%':>6}  {'Temp':>5}",
        "-" * 48,
    ]
    for g in snap.gpus:
        mem = f"{g.mem_used:.0f}/{g.mem_total:.0f}MiB"
        lines.append(
            f"{g.index:>3}  {g.util:>6.0f}  {mem:>17}  {g.mem_util:>6.1f}  {g.temp:>5.0f}"
        )
    return "\n".join(lines)
