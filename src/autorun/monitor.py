"""GPU 利用率监控线程：周期采样 → 规则去抖状态机 → 触发动作。

与 executor 的监控线程同构（start/stop + 单 daemon 线程 + 每轮 try/except 兜底），
遵循同一条铁律：**监控线程绝不能死，也绝不能拖垮服务**。采样失败、动作失败、
邮件失败都只记日志，不向上抛。

去抖状态机（每条规则一份，以规则 name 为键）：

    未命中 ────命中───▶ breach_since=now
      ▲                      │ 持续 >= duration_sec 且冷却已过
      │恢复(可发通知)          ▼
    active=False ◀──────── 触发动作, active=True, last_fired=now

采样与规则求值刻意分离（`_evaluate(snapshot, now)`），使去抖/冷却/恢复逻辑可以用
注入的假快照序列测试，不依赖真实 GPU 波动。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from . import commands as cmdmod
from . import gpu
from .audit import AuditLog
from .config import Config, GpuRuleConfig
from .errors import AppError
from .executor import Executor
from .logging_setup import get_logger
from .notify import EmailNotifier, NotifyError

log = get_logger(__name__)


@dataclass
class _RuleState:
    """单条规则的去抖运行时状态。线程存活期间跨轮次保留。"""

    breach_since: float | None = None   # 首次命中的 monotonic 时刻
    last_fired: float | None = None     # 最近一次触发的 monotonic 时刻
    active: bool = False                 # 是否处于"已触发未恢复"态

    def snapshot(self, now: float) -> dict:
        """导出给 /v1/gpu 的可读状态。monotonic 差值转成"多少秒前"。"""
        return {
            "active": self.active,
            "breach_for_sec": (
                round(now - self.breach_since, 1) if self.breach_since is not None else None
            ),
            "last_fired_ago_sec": (
                round(now - self.last_fired, 1) if self.last_fired is not None else None
            ),
        }


def _matches(comparator: str, value: float, threshold: float) -> bool:
    return value < threshold if comparator == "below" else value > threshold


class GpuMonitor:
    def __init__(
        self,
        cfg: Config,
        executor: Executor,
        audit: AuditLog,
        notifier: EmailNotifier | None = None,
    ) -> None:
        self._cfg = cfg
        self._executor = executor
        self._audit = audit
        self._notifier = notifier
        self._nvidia_smi = gpu.resolve_nvidia_smi(cfg.gpu_monitor.nvidia_smi)

        self._states: dict[str, _RuleState] = {
            r.name: _RuleState() for r in cfg.gpu_monitor.rules
        }
        self._last_snapshot: gpu.GpuSnapshot | None = None
        self._lock = threading.Lock()

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- 生命周期 -------------------------------------------------------

    def start(self) -> None:
        if not self._cfg.gpu_monitor.enabled:
            log.info("gpu_monitor 未启用，监控线程不启动")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="gpu-monitor", daemon=True)
        self._thread.start()
        log.info(
            "gpu-monitor 已启动：interval=%ss rules=%d nvidia_smi=%s",
            self._cfg.gpu_monitor.interval_sec,
            len(self._cfg.gpu_monitor.rules),
            self._nvidia_smi or "(未找到)",
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def update_config(self, cfg: Config) -> None:
        """SIGHUP 热加载。规则名不变则延续去抖计时；新增规则从零开始；
        删除的规则丢弃状态。"""
        with self._lock:
            self._cfg = cfg
            self._nvidia_smi = gpu.resolve_nvidia_smi(cfg.gpu_monitor.nvidia_smi)
            new_states: dict[str, _RuleState] = {}
            for r in cfg.gpu_monitor.rules:
                new_states[r.name] = self._states.get(r.name, _RuleState())
            self._states = new_states
        if self._notifier and cfg.smtp is not None:
            self._notifier.update_config(cfg.smtp)

    # --- 对外读取（/v1/gpu、healthz） -----------------------------------

    def last_snapshot(self) -> gpu.GpuSnapshot | None:
        with self._lock:
            return self._last_snapshot

    def status(self) -> dict:
        """/v1/gpu 用：最近快照 + 每条规则当前状态。"""
        now = time.monotonic()
        with self._lock:
            snap = self._last_snapshot
            rules = self._cfg.gpu_monitor.rules
            states = {
                r.name: {
                    "metric": r.metric,
                    "comparator": r.comparator,
                    "threshold": r.threshold,
                    "duration_sec": r.duration_sec,
                    "cooldown_sec": r.cooldown_sec,
                    **self._states.get(r.name, _RuleState()).snapshot(now),
                }
                for r in rules
            }
        return {
            "enabled": self._cfg.gpu_monitor.enabled,
            "nvidia_smi": self._nvidia_smi,
            "snapshot": snap.to_dict() if snap else None,
            "rules": states,
        }

    def health_summary(self) -> dict | None:
        """healthz 概况。无采样时返回 None。"""
        with self._lock:
            snap = self._last_snapshot
        if snap is None:
            return None
        return {
            "ok": snap.ok,
            "avg_util": snap.avg_util,
            "idle_count": snap.idle_count,
            "sampled_at": snap.sampled_at,
        }

    # --- 采样循环 -------------------------------------------------------

    def _loop(self) -> None:
        # 启动即采一次，不必等第一个 interval 过去才有数据可看。
        self._sample_once()
        while not self._stop.wait(self._cfg.gpu_monitor.interval_sec):
            try:
                self._sample_once()
            except Exception:  # 监控线程绝不能死
                log.exception("gpu-monitor 本轮异常，继续下一轮")

    def _sample_once(self) -> None:
        gm = self._cfg.gpu_monitor
        snap = gpu.sample(
            self._nvidia_smi,
            timeout=gm.sample_timeout_sec,
            idle_util_threshold=gm.idle_util_threshold,
        )
        with self._lock:
            self._last_snapshot = snap
        self._evaluate(snap, time.monotonic())

    # --- 规则求值（可被测试用注入快照直接调用） -------------------------

    def _evaluate(self, snap: gpu.GpuSnapshot, now: float) -> None:
        """对一份快照求值所有规则。now 显式传入以便测试注入时间线。"""
        if not snap.ok:
            # 采样失败：不知道真实利用率，跳过求值。把失败当成"利用率为 0"会误报。
            # breach_since 保留不清：短暂失败不应重置正在累积的持续时间。
            log.warning("gpu 采样失败，跳过规则求值: %s", snap.error)
            return

        with self._lock:
            rules = self._cfg.gpu_monitor.rules
            # 复制引用，动作执行放到锁外，避免执行动作（可能起子进程/发邮件）时长期持锁。
            states = self._states

        for rule in rules:
            state = states.get(rule.name)
            if state is None:  # 热加载竞态兜底
                state = _RuleState()
                states[rule.name] = state
            self._eval_rule(rule, state, snap, now)

    def _eval_rule(
        self, rule: GpuRuleConfig, state: _RuleState, snap: gpu.GpuSnapshot, now: float
    ) -> None:
        value = snap.metric(rule.metric)
        if _matches(rule.comparator, value, rule.threshold):
            if state.breach_since is None:
                state.breach_since = now
            elapsed = now - state.breach_since
            if elapsed < rule.duration_sec:
                return  # 去抖：还没连续满足够久
            # 冷却：触发过且未到冷却期则不重复。
            if state.last_fired is not None and (now - state.last_fired) < rule.cooldown_sec:
                return
            self._fire(rule, snap, value)
            state.active = True
            state.last_fired = now
        else:
            # 未命中：条件不再满足。若之前处于告警态且要求恢复通知，发一封"已恢复"。
            if state.active and rule.notify_resolved:
                self._resolve(rule, snap, value)
            state.active = False
            state.breach_since = None

    # --- 动作 -----------------------------------------------------------

    def _fire(self, rule: GpuRuleConfig, snap: gpu.GpuSnapshot, value: float) -> None:
        log.warning(
            "gpu 规则命中: %s（%s %s %g，实测 %g）",
            rule.name, rule.metric, rule.comparator, rule.threshold, value,
        )
        for action in rule.actions:
            # 单个动作失败不影响其余动作，也不影响后续轮次。
            try:
                self._run_action(rule, action, snap, value)
            except Exception:
                log.exception("gpu 规则 %s 的动作 %s 执行失败", rule.name, action.type)

    def _run_action(self, rule, action, snap: gpu.GpuSnapshot, value: float) -> None:
        if action.type == "log":
            self._audit.emit(
                "gpu_alert",
                rule=rule.name,
                metric=rule.metric,
                comparator=rule.comparator,
                threshold=rule.threshold,
                value=value,
                snapshot=snap.to_dict(),
            )
        elif action.type == "exec":
            self._run_exec(rule, action.alias or "")
        elif action.type == "email":
            self._send_email(
                subject=self._alert_subject(rule, value),
                body=self._alert_body(rule, snap, value),
                to=list(action.to),
            )

    def _run_exec(self, rule: GpuRuleConfig, alias: str) -> None:
        ts = time.strftime("%Y%m%d-%H%M%S")
        try:
            prepared = cmdmod.prepare_alias(self._cfg, alias, {})
            rec = self._executor.launch(
                prepared,
                request_id=f"gpu-monitor-{ts}",
                key_id="gpu-monitor",
                client_ip="local",
            )
            log.info("gpu 规则 %s 触发 exec %s -> job %s", rule.name, alias, rec.job_id)
        except AppError as exc:
            # singleton 已在跑（Conflict）/ 并发已满（ServiceUnavailable）等属正常竞态，
            # 例如 pkill 别名已有实例，跳过即可，不算错误。
            log.info(
                "gpu 规则 %s 的 exec %s 未启动（%s）: %s",
                rule.name, alias, type(exc).__name__, exc,
            )

    def _send_email(self, subject: str, body: str, to: list[str]) -> None:
        if self._notifier is None:
            log.error("gpu email 动作被触发，但未配置 smtp/notifier，跳过")
            return
        try:
            self._notifier.send(subject, body, to)
            log.info("gpu 告警邮件已发送: %s", subject)
        except NotifyError as exc:
            # 邮件失败不影响 log/exec 等其他动作。
            log.error("gpu 告警邮件发送失败: %s", exc)

    def _resolve(self, rule: GpuRuleConfig, snap: gpu.GpuSnapshot, value: float) -> None:
        log.info("gpu 规则 %s 恢复正常（%s 实测 %g）", rule.name, rule.metric, value)
        self._audit.emit(
            "gpu_resolved",
            rule=rule.name,
            metric=rule.metric,
            value=value,
            snapshot=snap.to_dict(),
        )
        # 向该规则的 email 动作收件人发一封恢复通知。
        for action in rule.actions:
            if action.type == "email":
                self._send_email(
                    subject=f"[autoRun][恢复] GPU 规则 {rule.name} 已恢复正常",
                    body=self._resolved_body(rule, snap, value),
                    to=list(action.to),
                )

    # --- 文案 -----------------------------------------------------------

    @staticmethod
    def _alert_subject(rule: GpuRuleConfig, value: float) -> str:
        return (
            f"[autoRun][告警] GPU 规则 {rule.name}: "
            f"{rule.metric} {rule.comparator} {rule.threshold:g}（实测 {value:g}）"
        )

    @staticmethod
    def _per_gpu_lines(snap: gpu.GpuSnapshot) -> str:
        return "\n".join(
            f"  GPU{g.index}: util={g.util:g}%  mem={g.mem_used:.0f}/{g.mem_total:.0f}MiB"
            f"  temp={g.temp:g}C"
            for g in snap.gpus
        )

    @classmethod
    def _alert_body(cls, rule: GpuRuleConfig, snap: gpu.GpuSnapshot, value: float) -> str:
        return (
            f"GPU 监控规则触发\n"
            f"规则: {rule.name}\n"
            f"条件: {rule.metric} {rule.comparator} {rule.threshold:g}\n"
            f"实测: {value:g}\n"
            f"采样时刻: {snap.sampled_at}\n"
            f"平均利用率: {snap.avg_util}%  空闲卡数: {snap.idle_count}"
            f"（阈值 <{snap.idle_util_threshold:g}%）\n\n"
            f"各卡快照:\n{cls._per_gpu_lines(snap)}\n"
        )

    @classmethod
    def _resolved_body(cls, rule: GpuRuleConfig, snap: gpu.GpuSnapshot, value: float) -> str:
        return (
            f"GPU 监控规则已恢复正常\n"
            f"规则: {rule.name}\n"
            f"条件: {rule.metric} {rule.comparator} {rule.threshold:g}\n"
            f"当前实测: {value:g}\n"
            f"采样时刻: {snap.sampled_at}\n\n"
            f"各卡快照:\n{cls._per_gpu_lines(snap)}\n"
        )
