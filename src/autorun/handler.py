"""HTTP 请求处理：解析、中间件链、路由分发、统一响应封装。

基于标准库 `http.server`。官方文档明确说明它未针对恶意流量加固，因此这里补齐了几项
必要的防护：请求体上限、socket 读写超时、拒绝 chunked 编码、有界线程池（在 server.py）。
即便如此，仍应把本服务放在可信网络或反向代理之后 —— 这一点写在 README 的威胁模型里。
"""

from __future__ import annotations

import json
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import security
from .errors import (
    AppError,
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    PayloadTooLarge,
    RateLimited,
    ServiceUnavailable,
    Unauthorized,
    UnsupportedMediaType,
)
from .logging_setup import get_logger
from .routes import ROUTES, AppContext, Handler, Request

log = get_logger("autorun.http")

_PARAM_RE = re.compile(r"\{([a-z_]+)\}")


def _compile_routes() -> list[tuple[str, re.Pattern[str], Handler, bool]]:
    out = []
    for method, pattern, handler, needs_auth in ROUTES:
        regex = "^" + _PARAM_RE.sub(lambda m: f"(?P<{m.group(1)}>[^/]+)", pattern) + "$"
        out.append((method, re.compile(regex), handler, needs_auth))
    return out


_COMPILED = _compile_routes()


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "autoRun"
    sys_version = ""  # 不回显 Python 版本，减少给攻击者的侦察信息
    protocol_version = "HTTP/1.1"

    ctx: AppContext  # 由 server.py 在类上注入

    # --- HTTP 方法入口 ---------------------------------------------------

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._reject_method()

    def do_DELETE(self) -> None:
        self._reject_method()

    def do_PATCH(self) -> None:
        self._reject_method()

    def _reject_method(self) -> None:
        self._send(405, {"ok": False, "error": {"code": "METHOD_NOT_ALLOWED", "message": "不支持的方法"}}, request_id="-")

    # --- 主流程 -----------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        started = time.monotonic()
        request_id = f"r-{uuid.uuid4().hex[:12]}"
        ctx = self.ctx
        cfg = ctx.cfg
        split = urlsplit(self.path)
        path = split.path.rstrip("/") or "/"
        peer = self.client_address[0] if self.client_address else "0.0.0.0"
        client_ip = peer
        status = 500
        key = None

        try:
            # === 1. 确定真实客户端 IP ===
            addr = security.parse_client_ip(cfg, peer, self.headers.get("X-Forwarded-For"))
            client_ip = str(addr)

            # === 2. IP 白名单（第一道关，先于一切） ===
            try:
                security.check_ip_whitelist(cfg, addr)
            except Forbidden:
                ctx.audit.ip_denied(client_ip=client_ip, path=path)
                raise

            # === 3. 路由匹配 ===
            handler, needs_auth, path_params = self._match(method, path)

            # === 4. 限流（先于认证，让暴力破解也被节流） ===
            ctx.rate_limiter.check(addr, None)

            # === 5. 认证 ===
            if needs_auth or cfg.security.health_requires_auth:
                presented = self.headers.get(cfg.auth.header)
                try:
                    key = security.authenticate(cfg, presented)
                except Unauthorized as exc:
                    ctx.audit.auth_failure(
                        request_id=request_id,
                        client_ip=client_ip,
                        path=path,
                        reason="missing_key" if not presented else "bad_key",
                    )
                    raise exc
                # 按 key 的额外 IP 收窄
                try:
                    security.authorize_ip_for_key(key, addr)
                except Forbidden as exc:
                    ctx.audit.authz_denied(
                        request_id=request_id,
                        client_ip=client_ip,
                        key_id=key.id,
                        path=path,
                        reason="key_ip_restricted",
                    )
                    raise exc
                # 认证后再按 key 计一次配额，避免单个 key 挤占全部容量
                ctx.rate_limiter.check(addr, key.id)

            # === 6. 读取并解析请求体 ===
            body, raw_len = self._read_body(method, cfg.server.max_request_body_bytes)

            ctx.audit.request(
                request_id=request_id,
                client_ip=client_ip,
                method=method,
                path=path,
                body_bytes=raw_len,
                user_agent=self.headers.get("User-Agent", ""),
                ip_check="allow",
                auth_result="ok" if key else "skipped",
                key_id=key.id if key else None,
            )

            # === 7. 执行端点（内部再做授权与载荷校验） ===
            req = Request(
                method=method,
                path=path,
                query=parse_qs(split.query),
                body=body,
                raw_body_len=raw_len,
                client_ip=client_ip,
                request_id=request_id,
                key=key,
                headers={k.lower(): v for k, v in self.headers.items()},
                path_params=path_params,
            )
            status, data = handler(ctx, req)
            self._send(status, {"ok": True, "request_id": request_id, "data": data}, request_id)

        except AppError as exc:
            status = exc.status
            headers = {}
            if isinstance(exc, (RateLimited, ServiceUnavailable)):
                headers["Retry-After"] = str(exc.retry_after)
            self._send(
                status,
                {
                    "ok": False,
                    "request_id": request_id,
                    "error": {"code": exc.code, "message": exc.message},
                },
                request_id,
                extra_headers=headers,
            )
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            # 客户端断开或超时，不必留错误日志噪音。
            return
        except Exception:
            # 未预期异常：客户端只拿到通用信息 + request_id，堆栈只进服务日志，
            # 两者由 request_id 关联。绝不把内部路径或配置回显给调用方。
            status = 500
            log.exception("request %s 处理失败 path=%s", request_id, path)
            self._send(
                status,
                {
                    "ok": False,
                    "request_id": request_id,
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "服务内部错误，请凭 request_id 联系管理员查日志",
                    },
                },
                request_id,
            )
        finally:
            try:
                self.ctx.audit.response(
                    request_id=request_id,
                    status=status,
                    duration_ms=(time.monotonic() - started) * 1000,
                )
            except Exception:
                pass

    def _match(self, method: str, path: str) -> tuple[Handler, bool, dict[str, str]]:
        path_matched = False
        for route_method, regex, handler, needs_auth in _COMPILED:
            m = regex.match(path)
            if not m:
                continue
            path_matched = True
            if route_method == method:
                return handler, needs_auth, m.groupdict()
        if path_matched:
            raise MethodNotAllowed(f"{method} 不适用于 {path}")
        raise NotFound(f"未知路径: {path}")

    def _read_body(self, method: str, cap: int) -> tuple[dict[str, Any], int]:
        if method not in ("POST", "PUT", "PATCH"):
            return {}, 0

        # http.server 不解码 chunked 编码，若放行会导致把编码块当成 JSON 解析。
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            raise BadRequest("不支持 chunked 传输编码，请提供 Content-Length")

        raw_len_header = self.headers.get("Content-Length")
        if raw_len_header is None:
            return {}, 0
        try:
            declared = int(raw_len_header)
        except ValueError as exc:
            raise BadRequest("Content-Length 非法") from exc
        if declared < 0:
            raise BadRequest("Content-Length 非法")
        if declared > cap:
            # 只看声明值就拒绝，一个字节都不读。读完再拒绝等于配合攻击者消耗带宽。
            raise PayloadTooLarge(f"请求体超过上限 {cap} 字节")
        if declared == 0:
            return {}, 0

        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype and ctype != "application/json":
            raise UnsupportedMediaType("Content-Type 必须是 application/json")

        raw = self.rfile.read(declared)
        if len(raw) != declared:
            raise BadRequest("请求体长度与 Content-Length 不一致")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BadRequest(f"JSON 解析失败: {exc}") from exc
        if not isinstance(parsed, dict):
            raise BadRequest("请求体必须是 JSON 对象")
        return parsed, declared

    # --- 响应 -------------------------------------------------------------

    def _send(
        self,
        status: int,
        payload: dict[str, Any],
        request_id: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Request-Id", request_id)
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt: str, *args: Any) -> None:
        # 默认实现直接写 stderr，会绕过日志配置也无法轮转。改为走服务日志。
        log.debug("%s - %s", self.client_address[0] if self.client_address else "-", fmt % args)

    def log_error(self, fmt: str, *args: Any) -> None:
        log.warning("%s - %s", self.client_address[0] if self.client_address else "-", fmt % args)
