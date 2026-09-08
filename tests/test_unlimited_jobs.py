"""常驻型任务：timeout_sec: 0 表示不限时。

这个功能最容易出错的地方是把 0 当成假值。`spec_timeout or default` 会把显式配置的
"不限时"悄悄换成默认的 900 秒超时，任务在 15 分钟后被杀掉，而配置看起来完全正确 ——
所以下面专门有用例盯住这一点。
"""

from __future__ import annotations

import signal

import pytest

from autorun import procutil
from autorun.commands import prepare_alias, prepare_raw
from autorun.errors import ConfigError, ValidationError
from conftest import base_config, wait_until, write_config


def load_with_daemon(tmp_path, **alias_extra):
    from autorun import config

    data = base_config(tmp_path)
    data["commands"]["daemon"] = {
        "shell": "sleep 3600",
        "timeout_sec": 0,
        "singleton": True,
        **alias_extra,
    }
    return config.load(write_config(tmp_path, data))


def test_zero_timeout_means_unlimited_not_default(tmp_path):
    """核心用例：0 不能被当成假值退化为 default_timeout_sec。"""
    cfg = load_with_daemon(tmp_path)
    assert cfg.execution.default_timeout_sec == 30  # 夹具里的默认值
    prepared = prepare_alias(cfg, "daemon", {})
    assert prepared.timeout_sec == 0, "显式的不限时被换成了默认超时"


def test_zero_timeout_not_capped_by_max(tmp_path):
    """不限时是配置方的显式决定，不受 max_timeout_sec 约束。"""
    cfg = load_with_daemon(tmp_path)
    assert cfg.execution.max_timeout_sec == 60
    assert prepare_alias(cfg, "daemon", {}).timeout_sec == 0


def test_unlimited_job_has_no_deadline(ctx, cfg, tmp_path):
    """不限时任务的 deadline 必须是 None，否则监控线程会去比较一个假的期限。"""
    from autorun import config
    from autorun.executor import Executor

    cfg2 = load_with_daemon(tmp_path)
    ctx.executor.update_config(cfg2)
    prepared = prepare_alias(cfg2, "daemon", {})
    rec = ctx.executor.launch(prepared, request_id="t", key_id="admin", client_ip="127.0.0.1")
    try:
        assert rec.timeout_sec == 0
        assert rec.deadline_monotonic is None
    finally:
        procutil.signal_process_group(rec.pgid, signal.SIGKILL)


def test_unlimited_job_survives_monitor_ticks(ctx, tmp_path):
    """跑过若干个监控周期后仍在运行 —— 证明超时分支确实跳过了它。

    对照组用 1 秒超时的普通任务，确认监控线程本身是在工作的。
    """
    cfg2 = load_with_daemon(tmp_path)
    ctx.executor.update_config(cfg2)
    unlimited = ctx.executor.launch(
        prepare_alias(cfg2, "daemon", {}), request_id="t", key_id="admin", client_ip="127.0.0.1"
    )
    finite = ctx.executor.launch(
        prepare_raw(cfg2, "sleep 60", requested_timeout=1),
        request_id="t",
        key_id="admin",
        client_ip="127.0.0.1",
    )
    try:
        # 对照组应被超时终止
        assert wait_until(
            lambda: not ctx.registry.get(finite.job_id).is_running, timeout=20
        ), "监控线程没在工作，本用例的结论不成立"
        # 不限时任务不受影响
        assert ctx.registry.get(unlimited.job_id).is_running
        assert procutil.pid_exists(unlimited.pid)
    finally:
        procutil.signal_process_group(unlimited.pgid, signal.SIGKILL)


def test_unlimited_job_can_still_be_killed(ctx, tmp_path):
    """不限时不等于杀不掉 —— kill 仍然是回收它的正常手段。"""
    cfg2 = load_with_daemon(tmp_path)
    ctx.executor.update_config(cfg2)
    rec = ctx.executor.launch(
        prepare_alias(cfg2, "daemon", {}), request_id="t", key_id="admin", client_ip="127.0.0.1"
    )
    assert ctx.executor.kill(rec.job_id, actor="test")["signalled"]
    assert wait_until(lambda: not procutil.pid_exists(rec.pid), timeout=15)
    assert wait_until(lambda: ctx.registry.get(rec.job_id).status == "killed")


def test_client_cannot_request_unlimited(tmp_path):
    """客户端不能把有限任务改成不限时，否则任何调用方都能绕过服务端资源约束。"""
    from autorun import config

    cfg = config.load(write_config(tmp_path, base_config(tmp_path)))
    with pytest.raises(ValidationError, match="只能由服务端配置声明"):
        prepare_alias(cfg, "hello", {}, requested_timeout=0)
    with pytest.raises(ValidationError):
        prepare_alias(cfg, "hello", {}, requested_timeout=-1)


def test_client_can_narrow_an_unlimited_alias(tmp_path):
    """反过来，给不限时的别名指定一个有限超时是允许的（收窄总是安全的）。"""
    cfg = load_with_daemon(tmp_path)
    assert prepare_alias(cfg, "daemon", {}, requested_timeout=10).timeout_sec == 10


def test_negative_timeout_rejected_at_startup(tmp_path):
    from autorun import config

    data = base_config(tmp_path)
    data["commands"]["bad"] = {"shell": "sleep 1", "timeout_sec": -5}
    with pytest.raises(ConfigError, match="必须为正数，或为 0 表示不限时"):
        config.load(write_config(tmp_path, data))


def test_startup_warns_about_unlimited_aliases(tmp_path):
    """不限时任务不会被自动回收，必须让运维看见，避免"起了就忘"占满并发名额。"""
    cfg = load_with_daemon(tmp_path)
    assert any("不限时" in w and "daemon" in w for w in cfg.warnings)


def test_commands_endpoint_reports_unlimited(client, ctx, tmp_path):
    cfg2 = load_with_daemon(tmp_path)
    ctx.replace_config(cfg2)
    _, body, _ = client.get("/v1/commands")
    daemon = next(c for c in body["data"]["commands"] if c["alias"] == "daemon")
    assert daemon["unlimited_runtime"] is True
    assert daemon["timeout_sec"] == 0
    hello = next(c for c in body["data"]["commands"] if c["alias"] == "hello")
    assert hello["unlimited_runtime"] is False


def test_sync_mode_on_unlimited_alias_falls_back_to_socket_budget(client, ctx, tmp_path):
    """不限时 + sync 时预算只受 socket 超时约束，不能算成 0 秒立刻返回。"""
    from autorun import config

    data = base_config(tmp_path)
    data["server"]["socket_timeout_sec"] = 4
    data["commands"]["quick_daemon"] = {
        "shell": "sleep 0.3; echo finished-ok",
        "timeout_sec": 0,
        "mode": "sync",
    }
    ctx.replace_config(config.load(write_config(tmp_path, data)))
    status, body, _ = client.post("/v1/exec", {"alias": "quick_daemon"})
    assert status == 200, body
    assert body["data"]["exit_code"] == 0
    assert "finished-ok" in body["data"]["output_tail"]


def test_output_limit_warn_does_not_kill(ctx):
    """on_output_limit: warn —— 常驻任务持续输出日志时不应被终止。"""
    object.__setattr__(ctx.cfg.execution, "max_output_bytes", 2048)
    object.__setattr__(ctx.cfg.execution, "on_output_limit", "warn")
    try:
        rec = ctx.executor.launch(
            prepare_raw(ctx.cfg, "yes flooding | head -c 200000; sleep 30"),
            request_id="t",
            key_id="admin",
            client_ip="127.0.0.1",
        )
        assert wait_until(lambda: (ctx.registry.get(rec.job_id).output_bytes or 0) > 2048, timeout=15)
        assert wait_until(lambda: "仅告警" in (ctx.registry.get(rec.job_id).note or ""), timeout=15)
        assert ctx.registry.get(rec.job_id).is_running, "warn 模式下任务不应被终止"
        procutil.signal_process_group(rec.pgid, signal.SIGKILL)
    finally:
        object.__setattr__(ctx.cfg.execution, "max_output_bytes", 52428800)
        object.__setattr__(ctx.cfg.execution, "on_output_limit", "kill")
