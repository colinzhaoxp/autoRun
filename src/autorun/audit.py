"""审计日志：结构化、只追加的 JSONL 流水。

这个文件是"出问题时能查清"的唯一依据，所以两个性质必须保证：

1. **关联性**。每个请求产生共享 `request_id` 的 request/response 两条；每个任务产生
   由 `job_id` 关联的 command_start/command_exit。出事时能从"谁在什么时候发了什么"
   一路追到"实际执行了什么、结果如何"。
2. **不泄密**。密钥本身、Authorization 头一律不写。命令文本和参数在序列化前经过
   脱敏正则处理，避免命令行里的密码被永久记录在日志中。
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import LoggingConfig
from .logging_setup import build_rotating_handler

AUDIT_LOGGER = "autorun.audit"


def _now_iso() -> str:
    """带时区的 ISO 8601 时间戳（毫秒精度）。

    带时区是刻意的：不带时区的时间戳在跨机器比对日志时无法确定实际时刻。
    """
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class Redactor:
    """对将要落盘的文本做脱敏替换。

    这是尽力而为的防护，不是保证 —— 它拦得住 `--password=xxx` 这类常见形态，
    拦不住任意编码后的密文。真正的解法是不要把密钥放进命令行，脱敏只是兜底。
    """

    def __init__(self, patterns: tuple[re.Pattern[str], ...]) -> None:
        self._patterns = patterns

    def text(self, value: str) -> str:
        out = value
        for pat in self._patterns:
            out = pat.sub("[REDACTED]", out)
        return out

    def value(self, node: Any) -> Any:
        """递归脱敏任意 JSON 结构中的字符串。"""
        if isinstance(node, str):
            return self.text(node)
        if isinstance(node, dict):
            return {k: self.value(v) for k, v in node.items()}
        if isinstance(node, (list, tuple)):
            return [self.value(v) for v in node]
        return node


class AuditLog:
    """审计写入器。线程安全，全进程唯一实例。"""

    def __init__(self, cfg: LoggingConfig) -> None:
        self._redactor = Redactor(cfg.redact_patterns)
        self._lock = threading.Lock()
        self._logger = logging.getLogger(AUDIT_LOGGER)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for h in list(self._logger.handlers):
            self._logger.removeHandler(h)
            h.close()
        handler = build_rotating_handler(Path(cfg.audit_file), cfg.rotation)
        # 审计行本身就是完整的 JSON，不要再加任何前缀，否则无法逐行 json.loads。
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def emit(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {"ts": _now_iso(), "event": event}
        record.update(self._redactor.value(fields))
        line = json.dumps(record, ensure_ascii=False, default=str, sort_keys=False)
        with self._lock:
            self._logger.info(line)

    # --- 语义化封装：固定字段名，避免各处拼错 key 导致日志无法查询 ---

    def request(
        self,
        *,
        request_id: str,
        client_ip: str,
        method: str,
        path: str,
        body_bytes: int,
        user_agent: str,
        ip_check: str,
        auth_result: str,
        key_id: str | None = None,
    ) -> None:
        self.emit(
            "request",
            request_id=request_id,
            client_ip=client_ip,
            method=method,
            path=path,
            body_bytes=body_bytes,
            user_agent=user_agent,
            ip_check=ip_check,
            auth={"result": auth_result, "key_id": key_id},
        )

    def response(self, *, request_id: str, status: int, duration_ms: float) -> None:
        self.emit("response", request_id=request_id, status=status, duration_ms=round(duration_ms, 2))

    def ip_denied(self, *, client_ip: str, path: str) -> None:
        self.emit("ip_denied", client_ip=client_ip, path=path, status=403)

    def auth_failure(self, *, request_id: str, client_ip: str, path: str, reason: str) -> None:
        # 刻意不记录所提交的密钥（哪怕是片段或哈希）：审计日志的读者远多于密钥的
        # 知情者，任何密钥material 落到这里都是一次泄露。
        self.emit(
            "auth_failure",
            request_id=request_id,
            client_ip=client_ip,
            path=path,
            reason=reason,
            status=401,
        )

    def authz_denied(
        self, *, request_id: str, client_ip: str, key_id: str, path: str, reason: str
    ) -> None:
        self.emit(
            "authz_denied",
            request_id=request_id,
            client_ip=client_ip,
            key_id=key_id,
            path=path,
            reason=reason,
            status=403,
        )

    def command_start(self, *, request_id: str, record: dict[str, Any]) -> None:
        self.emit("command_start", request_id=request_id, **record)

    def command_exit(self, **fields: Any) -> None:
        self.emit("command_exit", **fields)

    def kill(self, **fields: Any) -> None:
        self.emit("kill", **fields)

    def config_reload(self, *, result: str, detail: str = "") -> None:
        self.emit("config_reload", result=result, detail=detail)
