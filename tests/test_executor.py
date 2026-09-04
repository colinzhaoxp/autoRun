"""执行内核测试：退出码、进程组回收、超时升级、输出上限、重启对账。"""

from __future__ import annotations

import os
import signal
import time

import pytest

from autorun import procutil
from autorun.audit import AuditLog
from autorun.commands import prepare_raw
from autorun.errors import Conflict, ExecutionError, ServiceUnavailable
from autorun.executor import Executor
from autorun.registry import Registry
from conftest import wait_until


def launch(ctx, command: str, **kw):
    prepared = prepare_raw(ctx.cfg, command, **kw)
    return ctx.executor.launch(prepared, request_id="t", key_id="admin", client_ip="127.0.0.1")


def pgid_of(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        return int(text[text.rfind(") ") + 2 :].split()[2])
    except (OSError, ValueError, IndexError):
        return -1


def test_exit_code_captured(ctx):
    rec = launch(ctx, "exit 7")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running)
    final = ctx.registry.get(rec.job_id)
    assert final.exit_code == 7
    assert final.status == "failed"


def test_zero_exit_marked_exited(ctx):
    rec = launch(ctx, "true")
    assert wait_until(lambda: ctx.registry.get(rec.job_id).status == "exited")
    assert ctx.registry.get(rec.job_id).exit_code == 0


def test_output_written_to_job_log(ctx):
    rec = launch(ctx, "echo marker-abc123")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running)
    assert "marker-abc123" in open(rec.log_file).read()


def test_new_session_gives_own_process_group(ctx):
    """start_new_session 让 pgid == pid，killpg 才能覆盖整棵子进程树。"""
    rec = launch(ctx, "sleep 30")
    assert rec.pgid == rec.pid
    assert pgid_of(rec.pid) == rec.pid


def test_kill_group_reaps_entire_tree(ctx):
    """派生了孙进程的任务，kill 后不能留下孤儿。"""
    rec = launch(ctx, "sleep 30 & sleep 30 & wait")
    assert wait_until(
        lambda: sum(1 for p in os.listdir("/proc") if p.isdigit() and pgid_of(int(p)) == rec.pgid) >= 3,
        timeout=5,
    )
    ctx.executor.kill(rec.job_id, sig=signal.SIGTERM, actor="test")
    assert wait_until(
        lambda: not any(p.isdigit() and pgid_of(int(p)) == rec.pgid for p in os.listdir("/proc"))
    ), "进程组中仍有残留进程"
    assert wait_until(lambda: ctx.registry.get(rec.job_id).status == "killed")


def test_timeout_escalates_term_to_kill(ctx):
    """忽略 SIGTERM 的进程必须最终被 SIGKILL 收掉。

    这里也覆盖了一个曾经存在的缺陷：若超时分支每轮都重发 TERM 并把升级时刻往后推，
    SIGKILL 就永远不会到来。
    """
    rec = launch(ctx, "trap '' TERM; sleep 60", requested_timeout=1)
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running, timeout=30)
    final = ctx.registry.get(rec.job_id)
    assert final.status == "timeout", final.status
    assert final.signal == "SIGKILL"
    assert not procutil.pid_exists(rec.pid)


def test_graceful_process_dies_on_term_without_kill(ctx):
    rec = launch(ctx, "sleep 60", requested_timeout=1)
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running, timeout=20)
    assert ctx.registry.get(rec.job_id).signal == "SIGTERM"


def test_output_limit_kills_job(ctx):
    object.__setattr__(ctx.cfg.execution, "max_output_bytes", 4096)
    try:
        rec = launch(ctx, "yes flooding-output")
        assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running, timeout=30)
        final = ctx.registry.get(rec.job_id)
        assert final.output_bytes > 4096
        assert "上限" in (final.note or "")
    finally:
        object.__setattr__(ctx.cfg.execution, "max_output_bytes", 52428800)


def test_concurrency_limit_enforced(ctx):
    object.__setattr__(ctx.cfg.execution, "max_concurrent_jobs", 2)
    try:
        launch(ctx, "sleep 30")
        launch(ctx, "sleep 30")
        with pytest.raises(ServiceUnavailable):
            launch(ctx, "sleep 30")
    finally:
        object.__setattr__(ctx.cfg.execution, "max_concurrent_jobs", 5)


def test_pid_reuse_guard_refuses_to_signal(ctx):
    """starttime 不匹配时必须拒绝发信号，否则可能杀掉复用该 PID 的无关进程。"""
    rec = launch(ctx, "sleep 30")
    ctx.registry.update(rec.job_id, proc_starttime_ticks=(rec.proc_starttime_ticks or 0) + 12345)
    with pytest.raises(Conflict):
        ctx.executor.kill(rec.job_id, actor="test")
    assert ctx.registry.get(rec.job_id).status == "unknown"
    # 真实进程未被误杀
    assert procutil.pid_exists(rec.pid)
    procutil.signal_process_group(rec.pgid, signal.SIGKILL)


def test_kill_already_finished_job_returns_conflict(ctx):
    rec = launch(ctx, "true")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running)
    with pytest.raises(Conflict, match="已结束"):
        ctx.executor.kill(rec.job_id, actor="test")


def test_bad_cwd_reports_clean_error(ctx):
    prepared = prepare_raw(ctx.cfg, "true", cwd="/no/such/dir/here")
    with pytest.raises(ExecutionError, match="工作目录"):
        ctx.executor.launch(prepared, request_id="t", key_id="admin", client_ip="127.0.0.1")
    # 失败的启动不留半跟踪记录
    assert ctx.registry.all() == [] or all(r.cwd != "/no/such/dir/here" for r in ctx.registry.all())


def test_env_does_not_leak_service_secrets(ctx, monkeypatch):
    """服务的密钥环境变量绝不能传给被执行的命令 —— 那等于把凭据交给任务脚本。"""
    monkeypatch.setenv("AUTORUN_KEY_SECRET_PROBE", "super-secret-value")
    rec = launch(ctx, "env")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running)
    assert "super-secret-value" not in open(rec.log_file).read()


def test_stdin_is_devnull(ctx):
    """后台任务若读 stdin 会永久挂起，因此必须接到 /dev/null。"""
    rec = launch(ctx, "cat; echo done-reading")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running, timeout=10)
    assert "done-reading" in open(rec.log_file).read()


def test_reconcile_marks_survivors_orphaned(ctx, cfg):
    """服务重启后，仍在运行的任务应标为 orphaned（可 kill，但退出码不可获取）。"""
    rec = launch(ctx, "sleep 60")
    ctx.executor.stop_monitor()

    registry2 = Registry(cfg.paths.state_dir, cfg.registry)
    executor2 = Executor(cfg, registry2, AuditLog(cfg.logging))
    try:
        executor2.reconcile()
        again = registry2.get(rec.job_id)
        assert again.status == "orphaned"
        assert "重启" in (again.note or "")
        # 孤儿任务仍可被终止
        assert executor2.kill(rec.job_id, actor="test")["signalled"]
        assert wait_until(lambda: not procutil.pid_exists(rec.pid), timeout=10)
    finally:
        registry2.close()


def test_reconcile_marks_dead_as_unknown(ctx, cfg):
    """重启期间已结束的任务：退出码不可知，如实标记 unknown 而不是编造结果。"""
    rec = launch(ctx, "true")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running)
    ctx.registry.update(rec.job_id, status="running")  # 模拟"崩溃时来不及落盘终态"
    ctx.executor.stop_monitor()

    registry2 = Registry(cfg.paths.state_dir, cfg.registry)
    executor2 = Executor(cfg, registry2, AuditLog(cfg.logging))
    try:
        executor2.reconcile()
        assert registry2.get(rec.job_id).status == "unknown"
    finally:
        registry2.close()


def test_shutdown_keeps_jobs_by_default(ctx):
    """默认不打断在跑的任务：服务重启不该中断进行中的部署。"""
    rec = launch(ctx, "sleep 30")
    ctx.executor.shutdown()
    time.sleep(0.5)
    assert procutil.pid_exists(rec.pid)
    procutil.signal_process_group(rec.pgid, signal.SIGKILL)


def test_shutdown_kills_when_configured(ctx):
    rec = launch(ctx, "sleep 30")
    object.__setattr__(ctx.cfg.server, "kill_jobs_on_shutdown", True)
    ctx.executor.shutdown()
    assert wait_until(lambda: not procutil.pid_exists(rec.pid), timeout=10)


def test_job_log_permissions(ctx):
    rec = launch(ctx, "echo x")
    assert wait_until(lambda: not ctx.registry.get(rec.job_id).is_running)
    assert os.stat(rec.log_file).st_mode & 0o777 == 0o640
