"""GpuMonitor 去抖状态机：duration 去抖、cooldown 抑制、恢复通知、采样失败跳过，
以及 log/exec/email 三类动作触发（executor/notifier/audit 全用假对象）。

时间线用显式注入的 now 驱动 `_evaluate`，不依赖真实 GPU 波动，也不起真实线程。
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autorun.errors import Conflict  # noqa: E402
from autorun.gpu import GpuInfo, GpuSnapshot  # noqa: E402
from autorun.monitor import GpuMonitor  # noqa: E402


class FakeExecutor:
    def __init__(self, raise_exc=None):
        self.launched = []
        self._raise = raise_exc

    def launch(self, prepared, *, request_id, key_id, client_ip):
        if self._raise is not None:
            raise self._raise
        self.launched.append(prepared.alias)
        return SimpleNamespace(job_id="job-fake")


class FakeAudit:
    def __init__(self):
        self.events = []

    def emit(self, event, **fields):
        self.events.append((event, fields))

    def events_of(self, name):
        return [f for e, f in self.events if e == name]


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def send(self, subject, body, to):
        self.sent.append({"subject": subject, "to": to, "body": body})

    def update_config(self, cfg):
        pass


def _snap(*utils: float, ok: bool = True, threshold: float = 20.0) -> GpuSnapshot:
    gpus = tuple(
        GpuInfo(index=i, util=u, mem_used=1000, mem_total=81920, temp=40)
        for i, u in enumerate(utils)
    )
    return GpuSnapshot(
        ok=ok, sampled_at="2026-09-10T00:00:00+08:00",
        gpus=gpus, idle_util_threshold=threshold,
        error=None if ok else "sample failed",
    )


def _make(make_config, rules, *, with_smtp=False):
    over = {"gpu_monitor": {"enabled": True, "interval_sec": 15, "rules": rules}}
    if with_smtp:
        over["smtp"] = {
            "host": "smtp.example.com", "port": 465, "security": "ssl",
            "username": "u@x.com", "password": "pw", "from_addr": "a@x.com",
        }
    cfg = make_config(**over)
    execu = FakeExecutor()
    audit = FakeAudit()
    notifier = FakeNotifier()
    return GpuMonitor(cfg, execu, audit, notifier), execu, audit, notifier


LOG_RULE = [{
    "name": "idle", "metric": "avg_util", "comparator": "below", "threshold": 30,
    "duration_sec": 100, "cooldown_sec": 1000, "notify_resolved": True,
    "actions": [{"type": "log"}],
}]


def test_debounce_waits_for_duration(make_config):
    mon, _, audit, _ = _make(make_config, LOG_RULE)
    mon._evaluate(_snap(10), now=0)      # 首次命中，起计时
    assert audit.events_of("gpu_alert") == []
    mon._evaluate(_snap(10), now=50)     # 还没满 100s
    assert audit.events_of("gpu_alert") == []
    mon._evaluate(_snap(10), now=100)    # 满 100s，触发
    assert len(audit.events_of("gpu_alert")) == 1


def test_breach_timer_resets_when_recovered(make_config):
    mon, _, audit, _ = _make(make_config, LOG_RULE)
    mon._evaluate(_snap(10), now=0)
    mon._evaluate(_snap(90), now=50)     # 恢复，清空 breach_since
    mon._evaluate(_snap(10), now=60)     # 重新起计时
    mon._evaluate(_snap(10), now=120)    # 距新起点仅 60s < 100s，不触发
    assert audit.events_of("gpu_alert") == []


def test_cooldown_suppresses_repeat(make_config):
    mon, _, audit, _ = _make(make_config, LOG_RULE)
    mon._evaluate(_snap(10), now=0)
    mon._evaluate(_snap(10), now=100)    # 触发 @100
    mon._evaluate(_snap(10), now=500)    # 冷却期内（<1100），不重复
    assert len(audit.events_of("gpu_alert")) == 1
    mon._evaluate(_snap(10), now=1101)   # 冷却已过（100+1000），再次触发
    assert len(audit.events_of("gpu_alert")) == 2


def test_resolved_notification(make_config):
    rules = [{**LOG_RULE[0], "actions": [{"type": "log"}, {"type": "email", "to": ["ops@x.com"]}]}]
    mon, _, audit, notifier = _make(make_config, rules, with_smtp=True)
    mon._evaluate(_snap(10), now=0)
    mon._evaluate(_snap(10), now=100)    # 触发告警
    assert len(notifier.sent) == 1
    mon._evaluate(_snap(90), now=150)    # 恢复
    assert audit.events_of("gpu_resolved")
    assert any("恢复" in m["subject"] for m in notifier.sent)


def test_no_resolved_when_flag_off(make_config):
    rules = [{**LOG_RULE[0], "notify_resolved": False}]
    mon, _, audit, _ = _make(make_config, rules)
    mon._evaluate(_snap(10), now=0)
    mon._evaluate(_snap(10), now=100)
    mon._evaluate(_snap(90), now=150)
    assert audit.events_of("gpu_resolved") == []


def test_sample_failure_skips_evaluation(make_config):
    mon, _, audit, _ = _make(make_config, [{**LOG_RULE[0], "duration_sec": 0}])
    # duration=0 意味着命中即触发；但采样失败必须跳过，不能把失败当成利用率 0。
    mon._evaluate(_snap(ok=False), now=0)
    assert audit.events_of("gpu_alert") == []


def test_exec_action_launches(make_config):
    rules = [{
        "name": "idle", "metric": "avg_util", "comparator": "below", "threshold": 30,
        "duration_sec": 0, "cooldown_sec": 0,
        "actions": [{"type": "exec", "alias": "hello"}],
    }]
    mon, execu, _, _ = _make(make_config, rules)
    mon._evaluate(_snap(10), now=0)
    assert execu.launched == ["hello"]


def test_exec_conflict_is_swallowed(make_config):
    rules = [{
        "name": "idle", "metric": "avg_util", "comparator": "below", "threshold": 30,
        "duration_sec": 0, "cooldown_sec": 0,
        "actions": [{"type": "exec", "alias": "hello"}],
    }]
    cfg = make_config(gpu_monitor={"enabled": True, "rules": rules})
    mon = GpuMonitor(cfg, FakeExecutor(raise_exc=Conflict("已在运行")), FakeAudit(), None)
    # singleton 已在跑不应让本轮抛出（会被下一轮 try/except 记录，但这里直接调 _eval_rule）
    mon._evaluate(_snap(10), now=0)  # 不抛异常即通过


def test_email_action_sends(make_config):
    rules = [{
        "name": "idle", "metric": "avg_util", "comparator": "below", "threshold": 30,
        "duration_sec": 0, "cooldown_sec": 0,
        "actions": [{"type": "email", "to": ["ops@x.com", "sre@x.com"]}],
    }]
    mon, _, _, notifier = _make(make_config, rules, with_smtp=True)
    mon._evaluate(_snap(10), now=0)
    assert notifier.sent[0]["to"] == ["ops@x.com", "sre@x.com"]
    assert "idle" in notifier.sent[0]["subject"]


def test_above_comparator(make_config):
    rules = [{
        "name": "hot", "metric": "max_temp", "comparator": "above", "threshold": 80,
        "duration_sec": 0, "cooldown_sec": 0, "actions": [{"type": "log"}],
    }]
    mon, _, audit, _ = _make(make_config, rules)
    cool = GpuSnapshot(ok=True, sampled_at="t",
                       gpus=(GpuInfo(0, 100, 1000, 81920, 50),))
    hot = GpuSnapshot(ok=True, sampled_at="t",
                      gpus=(GpuInfo(0, 100, 1000, 81920, 95),))
    mon._evaluate(cool, now=0)
    assert audit.events_of("gpu_alert") == []
    mon._evaluate(hot, now=1)
    assert len(audit.events_of("gpu_alert")) == 1


def test_update_config_preserves_state_by_name(make_config):
    mon, _, audit, _ = _make(make_config, LOG_RULE)
    mon._evaluate(_snap(10), now=0)          # breach_since=0
    # 热加载同名规则：计时应延续，不从零开始。
    cfg2 = make_config(gpu_monitor={"enabled": True, "rules": LOG_RULE})
    mon.update_config(cfg2)
    mon._evaluate(_snap(10), now=100)        # 距原起点 100s，应触发
    assert len(audit.events_of("gpu_alert")) == 1


def test_status_and_health_summary(make_config):
    mon, _, _, _ = _make(make_config, LOG_RULE)
    mon._last_snapshot = _snap(10, 90)
    st = mon.status()
    assert st["enabled"] is True
    assert "idle" in st["rules"]
    hs = mon.health_summary()
    assert hs["avg_util"] == 50.0
    assert hs["idle_count"] == 1
