"""任务登记表：进程跟踪文件的读写。

这是"我现在正在跑什么、PID 是多少、怎么关掉它"这个诉求的落地实现。

权威数据是 `processes.json`。写入用 "临时文件 + fsync + os.replace" 三步，全程持有
文件锁与进程内锁，所以外部读者（包括用户直接 cat）永远看到一个完整的 JSON，
不会读到半截文件。另外渲染一份 `processes.txt` 供人直接阅读。
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .config import RegistryConfig

STATE_VERSION = 1

# 任务状态。区分得细是有意的：出事时"不知道结果"和"结果是失败"必须能分辨。
RUNNING_STATES = frozenset({"starting", "running", "orphaned"})
TERMINAL_STATES = frozenset({"exited", "failed", "killed", "timeout", "unknown"})


@dataclass
class JobRecord:
    job_id: str
    pid: int
    pgid: int
    alias: str | None
    command_display: str
    argv: list[str]
    cwd: str
    start_time: str
    status: str = "starting"
    run_as: str | None = None
    requested_by: dict[str, Any] = field(default_factory=dict)
    proc_starttime_ticks: int | None = None
    timeout_sec: int | None = None
    deadline_monotonic: float | None = None
    exit_code: int | None = None
    signal: str | None = None
    end_time: str | None = None
    log_file: str = ""
    output_bytes: int = 0
    note: str | None = None

    @property
    def is_running(self) -> bool:
        return self.status in RUNNING_STATES

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JobRecord:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


class _FileLock:
    """基于 flock 的跨进程互斥。

    需要它是因为 CLI（`autorun ps`）与服务进程可能同时访问状态文件。进程内的
    threading 锁挡不住另一个进程。
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)

    def __enter__(self) -> None:
        fcntl.flock(self._fd, fcntl.LOCK_EX)

    def __exit__(self, *exc: object) -> None:
        fcntl.flock(self._fd, fcntl.LOCK_UN)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


class Registry:
    """任务登记表。所有变更都会立刻落盘。"""

    def __init__(self, state_dir: Path, cfg: RegistryConfig) -> None:
        self._dir = Path(state_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._json_path = self._dir / "processes.json"
        self._txt_path = self._dir / "processes.txt"
        self._cfg = cfg
        self._rlock = threading.RLock()
        self._flock = _FileLock(self._dir / ".registry.lock")
        self._jobs: dict[str, JobRecord] = {}
        self._load_unlocked()

    # --- 持久化 ---------------------------------------------------------

    def _load_unlocked(self) -> None:
        if not self._json_path.is_file():
            return
        try:
            data = json.loads(self._json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # 状态文件损坏时不要让服务起不来：备份一份供事后分析，然后从空表开始。
            # 丢掉的是历史记录，不是正在运行的进程 —— 后者靠 reconcile 重新发现。
            try:
                self._json_path.rename(
                    self._json_path.with_suffix(f".corrupt.{int(time.time())}")
                )
            except OSError:
                pass
            return
        for jid, raw in (data.get("jobs") or {}).items():
            try:
                self._jobs[jid] = JobRecord.from_dict(raw)
            except TypeError:
                continue

    def _atomic_write_unlocked(self) -> None:
        payload = {
            "version": STATE_VERSION,
            "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "jobs": {jid: rec.to_dict() for jid, rec in self._jobs.items()},
        }
        tmp = self._json_path.with_suffix(".json.tmp")
        # 临时文件必须与目标同目录，否则 os.replace 可能跨文件系统而失去原子性。
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._json_path)
        if self._cfg.render_text_view:
            self._render_text_unlocked()

    def _render_text_unlocked(self) -> None:
        header = (
            f"{'JOB_ID':<26} {'PID':<7} {'PGID':<7} {'STATUS':<9} {'ALIAS':<14} "
            f"{'START_TIME':<19} {'ELAPSED':<9} {'EXIT':<5} COMMAND"
        )
        lines = [header, "-" * len(header)]
        for rec in sorted(self._jobs.values(), key=lambda r: r.start_time, reverse=True):
            lines.append(_render_row(rec))
        tmp = self._txt_path.with_suffix(".txt.tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._txt_path)

    def _flush_unlocked(self) -> None:
        self._prune_unlocked()
        self._atomic_write_unlocked()

    def _prune_unlocked(self) -> None:
        """清理过期的已结束任务。运行中的任务永不清理。"""
        cutoff = datetime.now().astimezone() - timedelta(hours=self._cfg.retain_finished_hours)
        keep: dict[str, JobRecord] = {}
        finished: list[JobRecord] = []
        for jid, rec in self._jobs.items():
            if rec.is_running:
                keep[jid] = rec
                continue
            ts = _parse_iso(rec.end_time or rec.start_time)
            if ts is None or ts >= cutoff:
                finished.append(rec)
        finished.sort(key=lambda r: r.end_time or r.start_time, reverse=True)
        room = max(self._cfg.max_records - len(keep), 0)
        for rec in finished[:room]:
            keep[rec.job_id] = rec
        self._jobs = keep

    # --- 公开接口 -------------------------------------------------------

    def add(self, record: JobRecord) -> None:
        with self._rlock, self._flock:
            self._jobs[record.job_id] = record
            self._flush_unlocked()

    def stage(self, record: JobRecord) -> None:
        """在 transaction() 内登记任务，退出事务时统一落盘。

        单独提供这个方法是为了让"检查配额 → 启动进程 → 登记"三步处于同一把锁内：
        分开做的话，两个并发请求会同时通过配额检查。
        """
        self._jobs[record.job_id] = record

    def update(self, job_id: str, **changes: Any) -> JobRecord | None:
        with self._rlock, self._flock:
            rec = self._jobs.get(job_id)
            if rec is None:
                return None
            for k, v in changes.items():
                setattr(rec, k, v)
            self._flush_unlocked()
            return rec

    def get(self, job_id: str) -> JobRecord | None:
        with self._rlock:
            return self._jobs.get(job_id)

    def all(self) -> list[JobRecord]:
        with self._rlock:
            return list(self._jobs.values())

    def running(self) -> list[JobRecord]:
        with self._rlock:
            return [r for r in self._jobs.values() if r.is_running]

    def running_count(self) -> int:
        with self._rlock:
            return sum(1 for r in self._jobs.values() if r.is_running)

    def has_running_alias(self, alias: str) -> bool:
        """singleton 检查。必须在启动新任务的同一把锁内调用，否则两个并发请求
        会同时看到"没有实例在跑"而各起一个。"""
        with self._rlock:
            return any(r.alias == alias and r.is_running for r in self._jobs.values())

    def find_by_pid(self, pid: int) -> JobRecord | None:
        with self._rlock:
            for rec in self._jobs.values():
                if rec.pid == pid and rec.is_running:
                    return rec
            return None

    def transaction(self) -> "_Transaction":
        """把"检查配额 + 登记任务"合成一个原子步骤，防止并发超发。"""
        return _Transaction(self)

    def flush(self) -> None:
        with self._rlock, self._flock:
            self._flush_unlocked()

    def close(self) -> None:
        self._flock.close()


class _Transaction:
    def __init__(self, registry: Registry) -> None:
        self._r = registry

    def __enter__(self) -> Registry:
        self._r._rlock.acquire()
        self._r._flock.__enter__()
        return self._r

    def __exit__(self, *exc: object) -> None:
        try:
            self._r._flush_unlocked()
        finally:
            self._r._flock.__exit__()
            self._r._rlock.release()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.astimezone()


def _render_row(rec: JobRecord) -> str:
    start = _parse_iso(rec.start_time)
    start_s = start.strftime("%Y-%m-%d %H:%M:%S") if start else "?"
    end = _parse_iso(rec.end_time) or datetime.now().astimezone()
    elapsed = "?"
    if start:
        total = int(max((end - start).total_seconds(), 0))
        elapsed = f"{total // 3600:02d}:{total % 3600 // 60:02d}:{total % 60:02d}"
    exit_s = "-" if rec.exit_code is None else str(rec.exit_code)
    if rec.signal:
        exit_s = f"S:{rec.signal}"
    cmd = rec.command_display.replace("\n", " ")
    return (
        f"{rec.job_id:<26} {rec.pid:<7} {rec.pgid:<7} {rec.status:<9} "
        f"{(rec.alias or '-'):<14} {start_s:<19} {elapsed:<9} {exit_s:<5} {cmd}"
    )


def render_table(records: Iterable[JobRecord]) -> str:
    """CLI 直接从 JSON 渲染同样的视图，因此 txt 镜像过期时 CLI 仍然准确。"""
    header = (
        f"{'JOB_ID':<26} {'PID':<7} {'PGID':<7} {'STATUS':<9} {'ALIAS':<14} "
        f"{'START_TIME':<19} {'ELAPSED':<9} {'EXIT':<5} COMMAND"
    )
    rows = [header, "-" * len(header)]
    for rec in sorted(records, key=lambda r: r.start_time, reverse=True):
        rows.append(_render_row(rec))
    return "\n".join(rows)
