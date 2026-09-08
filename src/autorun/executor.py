"""进程执行内核：启动、看护、超时升级、整树回收。

几个关键取舍，每个都对应一类实际会咬人的问题：

- **输出直接写文件 fd，不用管道。** 用 `PIPE` 就必须有人持续读，否则子进程写满
  64KB 管道缓冲区后永久阻塞。而本服务的任务可能跑几小时并输出大量日志，一旦守护
  进程重启，管道读端消失，子进程会卡死或收到 SIGPIPE。写文件没有这个问题。
- **`start_new_session=True`。** 让每个任务成为独立会话的组长，于是 `killpg` 能
  一次回收它派生出的整棵子进程树，而不是只杀掉最外层的 bash 留下一堆孤儿。
- **不用 `preexec_fn` 降权。** CPython 文档明确说明它在多线程进程中不安全（fork 后
  子进程里只有一个线程，若其他线程持有 malloc 锁就会死锁）。本服务是多线程的，
  所以改用 `setpriv` 前缀，把降权交给一个可审计的外部二进制。
- **deadline 用 `time.monotonic()`。** 用墙上时间的话，一次 NTP 校时跳变就可能让
  正常任务被误判超时而被杀。
"""

from __future__ import annotations

import os
import pwd
import shlex
import shutil
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from . import procutil
from .audit import AuditLog
from .commands import PreparedCommand
from .config import Config, RunAs
from .errors import Conflict, ExecutionError, ServiceUnavailable
from .logging_setup import get_logger
from .registry import JobRecord, Registry

_MONITOR_INTERVAL_SEC = 0.5
_SETPRIV = shutil.which("setpriv") or "/usr/bin/setpriv"

log = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _new_job_id() -> str:
    return f"j-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"


def _build_env(cfg: Config) -> dict[str, str]:
    """只透传白名单里的环境变量。

    直接继承服务进程的全部环境会把服务的密钥（AUTORUN_KEY_*）泄露给每个被执行的
    命令 —— 那等于把认证凭据交给了任务脚本。
    """
    env = {k: v for k in cfg.execution.env_passthrough if (v := os.environ.get(k)) is not None}
    env.update(cfg.execution.env_extra)
    return env


def _apply_run_as(argv: tuple[str, ...], run_as: RunAs) -> tuple[str, ...]:
    if not run_as.active:
        return argv
    if not Path(_SETPRIV).is_file():
        raise ExecutionError("配置了 run_as 但系统中找不到 setpriv")
    prefix = [_SETPRIV]
    if run_as.user:
        info = pwd.getpwnam(run_as.user)
        prefix += ["--reuid", str(info.pw_uid)]
    if run_as.group:
        import grp

        prefix += ["--regid", str(grp.getgrnam(run_as.group).gr_gid)]
    # --clear-groups 很关键：不清空附加组的话，降权后仍保留 root 的组权限，
    # 降权就是假的。
    prefix += ["--clear-groups", "--"]
    return (*prefix, *argv)


class Executor:
    def __init__(self, cfg: Config, registry: Registry, audit: AuditLog) -> None:
        self._cfg = cfg
        self._registry = registry
        self._audit = audit
        # job_id -> Popen。只包含本进程启动的任务；跨重启继承来的任务不在此表中，
        # 只能通过 /proc 判定状态。
        self._procs: dict[str, subprocess.Popen[bytes]] = {}
        self._escalate_at: dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._monitor: threading.Thread | None = None

    def update_config(self, cfg: Config) -> None:
        """SIGHUP 热加载：换掉配置引用。已在跑的任务保持其启动时的参数不变。"""
        self._cfg = cfg

    # --- 启动 -----------------------------------------------------------

    def launch(
        self,
        prepared: PreparedCommand,
        *,
        request_id: str,
        key_id: str,
        client_ip: str,
    ) -> JobRecord:
        cwd = prepared.cwd
        if not Path(cwd).is_dir():
            raise ExecutionError(f"工作目录不存在: {cwd}")

        job_id = _new_job_id()
        log_dir = Path(self._cfg.paths.job_log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{job_id}.log"

        argv = _apply_run_as(prepared.argv, prepared.run_as)
        env = _build_env(self._cfg)

        # 配额与 singleton 检查必须与登记在同一把锁内完成，否则两个并发请求会同时
        # 看到"还有余量"或"没有实例在跑"，各自起一个任务。
        with self._registry.transaction() as reg:
            if reg.running_count() >= self._cfg.execution.max_concurrent_jobs:
                raise ServiceUnavailable(
                    f"已达并发上限 {self._cfg.execution.max_concurrent_jobs}"
                )
            if prepared.singleton and prepared.alias and reg.has_running_alias(prepared.alias):
                raise Conflict(f"命令 {prepared.alias!r} 已有实例在运行（singleton）")

            try:
                out_fd = os.open(
                    log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o640
                )
            except OSError as exc:
                raise ExecutionError(f"无法创建任务日志 {log_path}: {exc}") from exc

            try:
                header = (
                    f"=== autoRun job {job_id} ===\n"
                    f"time: {_now_iso()}\n"
                    f"alias: {prepared.alias or '(raw)'}\n"
                    f"cwd: {cwd}\n"
                    f"command: {prepared.display}\n"
                    f"{'=' * 40}\n"
                )
                os.write(out_fd, header.encode("utf-8", errors="replace"))
                proc = subprocess.Popen(  # noqa: S603 - argv 已在 commands.py 完成校验
                    list(argv),
                    stdin=subprocess.DEVNULL,  # 后台任务若读 stdin 会永久挂起
                    stdout=out_fd,
                    stderr=out_fd,  # 合并到同一文件，保持输出的时间顺序
                    cwd=cwd,
                    env=env,
                    start_new_session=True,
                    close_fds=True,
                )
            except (OSError, ValueError) as exc:
                os.close(out_fd)
                # 启动失败不留半跟踪记录：要么有完整的任务记录，要么什么都没有。
                raise ExecutionError(f"启动失败: {exc}") from exc
            finally:
                # 子进程已继承该 fd，父进程留着它只会占用句柄。
                try:
                    os.close(out_fd)
                except OSError:
                    pass

            record = JobRecord(
                job_id=job_id,
                pid=proc.pid,
                pgid=proc.pid,  # start_new_session 使 pgid == pid
                alias=prepared.alias,
                command_display=prepared.display,
                argv=list(argv),
                cwd=cwd,
                start_time=_now_iso(),
                status="running",
                run_as=prepared.run_as.user,
                requested_by={
                    "key_id": key_id,
                    "client_ip": client_ip,
                    "request_id": request_id,
                },
                proc_starttime_ticks=procutil.read_starttime_ticks(proc.pid),
                timeout_sec=prepared.timeout_sec,
                # timeout_sec == 0 表示不限时：deadline 置 None，监控线程的超时分支
                # 会直接跳过它，任务只能由 kill 或自身退出来结束。
                deadline_monotonic=(
                    time.monotonic() + prepared.timeout_sec if prepared.timeout_sec else None
                ),
                log_file=str(log_path),
            )
            reg.stage(record)  # 已持锁；退出事务时统一落盘

        with self._lock:
            self._procs[job_id] = proc

        self._audit.command_start(
            request_id=request_id,
            record={
                "job_id": job_id,
                "alias": prepared.alias,
                "params": prepared.params,
                "argv": list(argv),
                "cwd": cwd,
                "pid": proc.pid,
                "pgid": proc.pid,
                "run_as": prepared.run_as.user,
                "timeout_sec": prepared.timeout_sec,
                "log_file": str(log_path),
                "key_id": key_id,
                "client_ip": client_ip,
            },
        )
        log.info("job %s started pid=%s alias=%s", job_id, proc.pid, prepared.alias)
        return record

    def wait_sync(self, job_id: str, budget_sec: float) -> tuple[JobRecord, bool]:
        """同步模式等待。返回 (记录, 是否已完成)。

        超出预算时**不杀进程** —— 任务继续在后台跑，响应里如实说明"尚未结束"。
        谎报一个结果比让调用方自己去查更危险。
        """
        with self._lock:
            proc = self._procs.get(job_id)
        deadline = time.monotonic() + budget_sec
        while time.monotonic() < deadline:
            if proc is not None and proc.poll() is not None:
                self._finalize(job_id, proc.returncode)
                rec = self._registry.get(job_id)
                assert rec is not None
                return rec, True
            time.sleep(0.05)
        rec = self._registry.get(job_id)
        assert rec is not None
        return rec, False

    # --- 终止 -----------------------------------------------------------

    def kill(
        self,
        job_id: str,
        *,
        sig: signal.Signals = signal.SIGTERM,
        kill_group: bool = True,
        escalate_after_sec: float = 10.0,
        actor: str = "",
        request_id: str = "",
    ) -> dict[str, Any]:
        rec = self._registry.get(job_id)
        if rec is None:
            from .errors import JobNotFound

            raise JobNotFound(f"未知任务: {job_id}")
        if not rec.is_running:
            # kill 与自然退出竞争时走到这里。返回 409 而不是给一个可能已被复用的
            # PID 发信号。
            raise Conflict(f"任务已结束（状态 {rec.status}），无法发送信号")

        # 发信号前必须确认目标仍是当初那个进程，否则可能杀掉复用了该 PID 的无关进程。
        if not procutil.is_same_process(rec.pid, rec.proc_starttime_ticks):
            self._registry.update(
                job_id,
                status="unknown",
                end_time=_now_iso(),
                note="发送信号前发现进程已消失或 PID 已被复用，实际结果不可知",
            )
            raise Conflict("目标进程已不存在（或 PID 已被复用），已将任务标记为 unknown")

        ok = (
            procutil.signal_process_group(rec.pgid, sig)
            if kill_group
            else procutil.signal_process(rec.pid, sig)
        )
        self._audit.kill(
            request_id=request_id,
            job_id=job_id,
            pid=rec.pid,
            pgid=rec.pgid,
            signal=sig.name,
            kill_group=kill_group,
            result="signalled" if ok else "not_found",
            actor=actor,
        )
        if ok and sig is not signal.SIGKILL and escalate_after_sec > 0:
            with self._lock:
                self._escalate_at[job_id] = time.monotonic() + escalate_after_sec
        # 同时清掉超时 deadline：已经在终止流程中了，超时分支再插一脚只会打乱
        # 升级计时。
        self._registry.update(job_id, deadline_monotonic=None, note=f"收到 {sig.name}")
        return {"job_id": job_id, "pid": rec.pid, "signal": sig.name, "signalled": ok}

    # --- 监控线程 -------------------------------------------------------

    def start_monitor(self) -> None:
        if self._monitor and self._monitor.is_alive():
            return
        self._stop.clear()
        self._monitor = threading.Thread(target=self._monitor_loop, name="job-monitor", daemon=True)
        self._monitor.start()

    def stop_monitor(self) -> None:
        self._stop.set()
        if self._monitor:
            self._monitor.join(timeout=5)

    def _monitor_loop(self) -> None:
        while not self._stop.wait(_MONITOR_INTERVAL_SEC):
            try:
                self._tick()
            except Exception:  # 监控线程绝不能死，否则所有任务都失去看护
                log.exception("监控线程本轮异常，继续下一轮")

    def _tick(self) -> None:
        now = time.monotonic()
        for rec in self._registry.running():
            with self._lock:
                proc = self._procs.get(rec.job_id)
                escalate_at = self._escalate_at.get(rec.job_id)

            if proc is not None:
                ret = proc.poll()
                if ret is not None:
                    self._finalize(rec.job_id, ret)
                    continue
            else:
                # 跨守护进程重启继承来的任务：不是本进程的子进程，拿不到退出码，
                # 只能靠 /proc 判断是否还活着。
                if not procutil.is_same_process(rec.pid, rec.proc_starttime_ticks):
                    self._registry.update(
                        rec.job_id,
                        status="unknown",
                        end_time=_now_iso(),
                        note="进程已退出，但因跨服务重启无法获取退出码",
                    )
                    self._audit.command_exit(
                        job_id=rec.job_id, pid=rec.pid, status="unknown", exit_code=None
                    )
                    continue

            if escalate_at is not None and now >= escalate_at:
                log.warning("job %s 未响应 SIGTERM，升级为 SIGKILL", rec.job_id)
                procutil.signal_process_group(rec.pgid, signal.SIGKILL)
                self._audit.emit(
                    "kill_escalated", job_id=rec.job_id, pid=rec.pid, signal="KILL"
                )
                with self._lock:
                    self._escalate_at.pop(rec.job_id, None)
                continue

            if rec.deadline_monotonic is not None and now >= rec.deadline_monotonic:
                log.warning("job %s 超时（%ss），发送 SIGTERM", rec.job_id, rec.timeout_sec)
                procutil.signal_process_group(rec.pgid, signal.SIGTERM)
                self._audit.emit(
                    "timeout", job_id=rec.job_id, pid=rec.pid, timeout_sec=rec.timeout_sec
                )
                # 必须清掉 deadline：否则下一轮又会命中超时分支，重发 TERM 并把
                # 升级时刻不断往后推，导致忽略 SIGTERM 的进程永远等不到 SIGKILL。
                self._registry.update(
                    rec.job_id,
                    deadline_monotonic=None,
                    signal="TERM_TIMEOUT",
                    note="超时，已发送 SIGTERM",
                )
                with self._lock:
                    self._escalate_at[rec.job_id] = now + 10.0
                continue

            self._check_output_limit(rec)

    def _check_output_limit(self, rec: JobRecord) -> None:
        try:
            size = os.stat(rec.log_file).st_size
        except OSError:
            return
        if size == rec.output_bytes:
            return
        self._registry.update(rec.job_id, output_bytes=size)
        limit = self._cfg.execution.max_output_bytes
        if size <= limit:
            return
        if self._cfg.execution.on_output_limit == "kill":
            log.warning("job %s 输出超过 %s 字节，终止", rec.job_id, limit)
            procutil.signal_process_group(rec.pgid, signal.SIGTERM)
            self._registry.update(rec.job_id, note=f"输出超过上限 {limit} 字节，已终止")
            self._audit.emit("output_limit", job_id=rec.job_id, bytes=size, action="kill")
            with self._lock:
                self._escalate_at[rec.job_id] = time.monotonic() + 10.0
        elif rec.note != "输出已超过上限（仅告警）":
            self._registry.update(rec.job_id, note="输出已超过上限（仅告警）")
            self._audit.emit("output_limit", job_id=rec.job_id, bytes=size, action="warn")

    def _finalize(self, job_id: str, returncode: int) -> None:
        """把 Popen 的 returncode 翻译成任务终态。"""
        with self._lock:
            self._procs.pop(job_id, None)
            self._escalate_at.pop(job_id, None)

        rec = self._registry.get(job_id)
        if rec is None or not rec.is_running:
            return

        sig_name: str | None = None
        exit_code: int | None = returncode
        if returncode < 0:
            # Popen 用负数表示"被信号杀死"。
            sig_name = signal.Signals(-returncode).name
            exit_code = None
            status = "timeout" if rec.signal == "TERM_TIMEOUT" else "killed"
        elif returncode == 0:
            status = "exited"
        else:
            status = "failed"

        try:
            size = os.stat(rec.log_file).st_size
        except OSError:
            size = rec.output_bytes

        end = _now_iso()
        self._registry.update(
            job_id,
            status=status,
            exit_code=exit_code,
            signal=sig_name,
            end_time=end,
            output_bytes=size,
        )
        started = time.mktime(time.strptime(rec.start_time[:19], "%Y-%m-%dT%H:%M:%S"))
        self._audit.command_exit(
            job_id=job_id,
            pid=rec.pid,
            exit_code=exit_code,
            signal=sig_name,
            status=status,
            output_bytes=size,
            duration_ms=round(max(time.time() - started, 0) * 1000, 1),
        )
        log.info("job %s finished status=%s exit=%s sig=%s", job_id, status, exit_code, sig_name)

    # --- 启动时对账 -----------------------------------------------------

    def reconcile(self) -> None:
        """服务启动时核对上次留下的运行中任务。

        守护进程重启后，之前启动的任务变成孤儿：它们可能还在跑（因为刻意做了会话
        分离），但已不是本进程的子进程，退出码无法再获取。这里如实把它们标为
        orphaned 或 unknown，而不是编一个退出码。
        """
        for rec in self._registry.running():
            alive = procutil.is_same_process(rec.pid, rec.proc_starttime_ticks)
            if alive:
                self._registry.update(
                    rec.job_id,
                    status="orphaned",
                    note="服务重启前启动，进程仍在运行；可以 kill，但退出码不可获取",
                )
                log.warning("job %s (pid %s) 仍在运行，标记为 orphaned", rec.job_id, rec.pid)
            else:
                self._registry.update(
                    rec.job_id,
                    status="unknown",
                    end_time=_now_iso(),
                    note="服务重启期间进程已结束，退出码不可知",
                )
                log.info("job %s (pid %s) 已结束，标记为 unknown", rec.job_id, rec.pid)

    def shutdown(self) -> None:
        self.stop_monitor()
        if not self._cfg.server.kill_jobs_on_shutdown:
            # 默认行为：让任务继续跑。服务重启不应打断进行中的部署。
            return
        for rec in self._registry.running():
            log.info("shutdown: 终止 job %s (pgid %s)", rec.job_id, rec.pgid)
            procutil.signal_process_group(rec.pgid, signal.SIGTERM)


def format_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
