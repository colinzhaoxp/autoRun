"""端点实现。每个函数对应一条路由，返回 (状态码, 数据)。

到达这些函数时，IP 白名单、限流、认证均已通过，`ctx.key` 是已验证的调用方。
每个函数仍需自行做**授权**检查（该 key 能否执行这个别名 / 裸命令 / kill）——
认证回答"你是谁"，授权回答"你能做什么"，两者不能混为一谈。
"""

from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import commands as cmdmod
from . import security
from .audit import AuditLog
from .config import Config, KeyConfig
from .errors import BadRequest, Conflict, Forbidden, JobNotFound, ValidationError
from .executor import Executor
from .monitor import GpuMonitor
from .registry import JobRecord, Registry

_SIGNAL_ALLOWLIST = {
    "TERM": signal.SIGTERM,
    "SIGTERM": signal.SIGTERM,
    "KILL": signal.SIGKILL,
    "SIGKILL": signal.SIGKILL,
    "INT": signal.SIGINT,
    "SIGINT": signal.SIGINT,
    "HUP": signal.SIGHUP,
    "SIGHUP": signal.SIGHUP,
    "USR1": signal.SIGUSR1,
    "USR2": signal.SIGUSR2,
}


@dataclass
class AppContext:
    """进程级共享状态。配置对象可被 SIGHUP 原子替换。"""

    config: Config
    registry: Registry
    executor: Executor
    audit: AuditLog
    rate_limiter: security.RateLimiter
    idempotency: security.IdempotencyCache
    gpu_monitor: GpuMonitor | None = None
    started_at: float = field(default_factory=time.time)
    _cfg_lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def cfg(self) -> Config:
        with self._cfg_lock:
            return self.config

    def replace_config(self, new_cfg: Config) -> None:
        """热加载。新配置已在外部完整校验通过，这里只做原子替换。"""
        with self._cfg_lock:
            self.config = new_cfg
        self.executor.update_config(new_cfg)
        self.rate_limiter.update_config(new_cfg)
        if self.gpu_monitor is not None:
            self.gpu_monitor.update_config(new_cfg)


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, list[str]]
    body: dict[str, Any]
    raw_body_len: int
    client_ip: str
    request_id: str
    key: KeyConfig | None
    headers: dict[str, str]
    path_params: dict[str, str] = field(default_factory=dict)


Handler = Callable[[AppContext, Request], tuple[int, dict[str, Any]]]


def _q_int(req: Request, name: str, default: int, lo: int, hi: int) -> int:
    raw = req.query.get(name, [None])[0]
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise BadRequest(f"查询参数 {name} 必须是整数") from exc
    return max(lo, min(hi, value))


def _body_int(req: Request, name: str) -> int | None:
    raw = req.body.get(name)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValidationError(f"{name} 必须是整数")
    return raw


def _job_view(rec: JobRecord) -> dict[str, Any]:
    return {
        "job_id": rec.job_id,
        "pid": rec.pid,
        "pgid": rec.pgid,
        "alias": rec.alias,
        "command": rec.command_display,
        "cwd": rec.cwd,
        "status": rec.status,
        "start_time": rec.start_time,
        "end_time": rec.end_time,
        "exit_code": rec.exit_code,
        "signal": rec.signal,
        "timeout_sec": rec.timeout_sec,
        "log_file": rec.log_file,
        "output_bytes": rec.output_bytes,
        "run_as": rec.run_as,
        "requested_by": rec.requested_by,
        "note": rec.note,
    }


# --- 端点 -----------------------------------------------------------------


def healthz(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    from . import __version__

    payload = {
        "status": "ok",
        "version": __version__,
        "uptime_sec": round(time.time() - ctx.started_at, 1),
        "running_jobs": ctx.registry.running_count(),
        "pid": os.getpid(),
    }
    if ctx.gpu_monitor is not None:
        summary = ctx.gpu_monitor.health_summary()
        if summary is not None:
            payload["gpu"] = summary
    return 200, payload


def gpu_status(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    """最近一次 GPU 快照 + 各规则去抖状态。"""
    if ctx.gpu_monitor is None:
        return 200, {"enabled": False, "snapshot": None, "rules": {}}
    return 200, ctx.gpu_monitor.status()


def list_commands(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    assert req.key is not None
    return 200, {"commands": cmdmod.describe_for_key(ctx.cfg, req.key.allowed_aliases)}


def _launch(
    ctx: AppContext, req: Request, prepared: cmdmod.PreparedCommand
) -> tuple[int, dict[str, Any]]:
    assert req.key is not None
    idem = req.headers.get("x-idempotency-key")
    if idem:
        cached = ctx.idempotency.get(idem)
        if cached is not None:
            # 重放：返回首次的 job_id，不再起第二个任务。
            return 200, {**cached, "idempotent_replay": True}

    rec = ctx.executor.launch(
        prepared,
        request_id=req.request_id,
        key_id=req.key.id,
        client_ip=req.client_ip,
    )
    payload = {
        "job_id": rec.job_id,
        "pid": rec.pid,
        "pgid": rec.pgid,
        "start_time": rec.start_time,
        "log_file": rec.log_file,
        "command": rec.command_display,
        "timeout_sec": rec.timeout_sec,
    }

    if prepared.mode == "sync":
        # 同步等待的预算要给 socket 超时留余量，否则连接先断，客户端拿不到结果。
        socket_budget = max(ctx.cfg.server.socket_timeout_sec - 2.0, 1.0)
        # 不限时任务（timeout_sec == 0）只受 socket 预算约束
        budget = (
            socket_budget
            if prepared.timeout_sec == 0
            else min(float(prepared.timeout_sec), socket_budget)
        )
        rec, finished = ctx.executor.wait_sync(rec.job_id, budget)
        tail = _read_tail(rec.log_file, 8192)
        if finished:
            return 200, {
                **payload,
                "status": rec.status,
                "exit_code": rec.exit_code,
                "signal": rec.signal,
                "output_tail": tail,
            }
        # 超出同步预算：如实告知任务仍在后台运行，而不是谎报一个结果。
        return 202, {
            **payload,
            "status": rec.status,
            "note": f"同步等待超过 {budget:.0f}s，任务仍在后台运行，请用 job_id 查询",
            "output_tail": tail,
        }

    if idem:
        ctx.idempotency.put(idem, payload)
    return 202, payload


def exec_alias(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    assert req.key is not None
    alias = req.body.get("alias")
    if not isinstance(alias, str) or not alias:
        raise ValidationError("alias 必须是非空字符串")
    # 授权先于命令构造：无权执行时不应泄露"这个别名存在与否"。
    security.authorize_alias(req.key, alias)
    params = req.body.get("params") or {}
    prepared = cmdmod.prepare_alias(
        ctx.cfg,
        alias,
        params,
        requested_timeout=_body_int(req, "timeout_sec"),
        requested_mode=req.body.get("mode"),
    )
    return _launch(ctx, req, prepared)


def exec_raw(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    assert req.key is not None
    security.authorize_raw(ctx.cfg, req.key)
    prepared = cmdmod.prepare_raw(
        ctx.cfg,
        req.body.get("command"),
        cwd=req.body.get("cwd"),
        requested_timeout=_body_int(req, "timeout_sec"),
        requested_mode=req.body.get("mode"),
    )
    return _launch(ctx, req, prepared)


def list_processes(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    status = req.query.get("status", [None])[0]
    alias = req.query.get("alias", [None])[0]
    limit = _q_int(req, "limit", 100, 1, 1000)
    records = ctx.registry.all()
    if status:
        wanted = {s.strip() for s in status.split(",")}
        records = [r for r in records if r.status in wanted]
    if alias:
        records = [r for r in records if r.alias == alias]
    records.sort(key=lambda r: r.start_time, reverse=True)
    return 200, {
        "total": len(records),
        "running": sum(1 for r in ctx.registry.all() if r.is_running),
        "jobs": [_job_view(r) for r in records[:limit]],
    }


def get_process(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    rec = ctx.registry.get(req.path_params["job_id"])
    if rec is None:
        raise JobNotFound("未知任务")
    return 200, _job_view(rec)


def get_output(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    rec = ctx.registry.get(req.path_params["job_id"])
    if rec is None:
        raise JobNotFound("未知任务")
    max_bytes = _q_int(req, "max_bytes", 65536, 1, 1048576)
    offset = _q_int(req, "offset", -1, -1, 2**40)
    try:
        size = os.path.getsize(rec.log_file)
    except OSError:
        return 200, {"job_id": rec.job_id, "size": 0, "offset": 0, "content": "", "eof": True}

    if offset < 0:
        # 默认给尾部，长任务的最新输出才是关注点。
        offset = max(size - max_bytes, 0)
    with open(rec.log_file, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(max_bytes)
    return 200, {
        "job_id": rec.job_id,
        "size": size,
        "offset": offset,
        "next_offset": offset + len(chunk),
        "eof": offset + len(chunk) >= size,
        # 任务输出未必是合法 UTF-8（二进制、截断的多字节字符），用 replace 保证
        # 响应总能序列化；磁盘上的原始字节不受影响。
        "content": chunk.decode("utf-8", errors="replace"),
    }


def kill_process(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    assert req.key is not None
    security.authorize_kill(req.key)
    sig = _parse_signal(req.body.get("signal"))
    result = ctx.executor.kill(
        req.path_params["job_id"],
        sig=sig,
        kill_group=bool(req.body.get("kill_group", True)),
        escalate_after_sec=float(req.body.get("escalate_after_sec", 10)),
        actor=req.key.id,
        request_id=req.request_id,
    )
    return 200, result


def kill_by_pid(ctx: AppContext, req: Request) -> tuple[int, dict[str, Any]]:
    assert req.key is not None
    security.authorize_kill(req.key)
    pid = _body_int(req, "pid")
    if pid is None or pid <= 0:
        raise ValidationError("pid 必须是正整数")
    rec = ctx.registry.find_by_pid(pid)
    if rec is None:
        # 默认只允许杀本服务启动的任务。放开这个限制等于把服务变成任意进程的杀手，
        # 而且没有 starttime 记录就无法防 PID 复用 —— 可能杀掉无关进程。
        if not ctx.cfg.security.allow_kill_untracked_pids:
            raise Forbidden("该 PID 不属于本服务管理的任务，已拒绝")
        raise Conflict("该 PID 未被跟踪，无法安全地确认目标身份")
    return kill_process(
        ctx,
        Request(**{**req.__dict__, "path_params": {"job_id": rec.job_id}}),
    )


def _parse_signal(raw: Any) -> signal.Signals:
    if raw is None:
        return signal.SIGTERM
    if not isinstance(raw, str):
        raise ValidationError("signal 必须是字符串，如 TERM / KILL")
    # 白名单而非 getattr(signal, name)：后者能取到 SIGSTOP 之类会把任务挂起却不
    # 结束的信号，让状态机陷入既没死也不动的中间态。
    got = _SIGNAL_ALLOWLIST.get(raw.strip().upper())
    if got is None:
        raise ValidationError(f"不支持的信号 {raw!r}，可用: {sorted(set(_SIGNAL_ALLOWLIST))}")
    return got


def _read_tail(path: str, max_bytes: int) -> str:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(size - max_bytes, 0))
            return fh.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""


# 路由表。`{job_id}` 为路径参数。
ROUTES: list[tuple[str, str, Handler, bool]] = [
    # (method, path pattern, handler, 是否需要密钥认证)
    ("GET", "/healthz", healthz, False),
    ("GET", "/v1/commands", list_commands, True),
    ("GET", "/v1/gpu", gpu_status, True),
    ("POST", "/v1/exec", exec_alias, True),
    ("POST", "/v1/exec/raw", exec_raw, True),
    ("GET", "/v1/processes", list_processes, True),
    ("POST", "/v1/processes/kill-by-pid", kill_by_pid, True),
    ("GET", "/v1/processes/{job_id}", get_process, True),
    ("GET", "/v1/processes/{job_id}/output", get_output, True),
    ("POST", "/v1/processes/{job_id}/kill", kill_process, True),
]
