"""HTTP 服务器：端口绑定、可选 TLS、有界线程池、优雅退出。

用有界线程池而非 `ThreadingHTTPServer` 默认的"每请求一线程"：后者在被大量并发连接
冲击时会创建无上限的线程，最终耗尽内存或文件描述符。有界池在饱和时让新连接排队，
是可预期的降级。
"""

from __future__ import annotations

import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer
from typing import Any

from .config import Config
from .errors import ConfigError
from .handler import RequestHandler
from .logging_setup import get_logger
from .routes import AppContext

log = get_logger("autorun.server")


class BoundedThreadingHTTPServer(HTTPServer):
    """把每个连接交给固定大小的线程池处理。"""

    daemon_threads = True
    allow_reuse_address = True  # 重启时避免 TIME_WAIT 导致 bind 失败

    def __init__(self, addr: tuple[str, int], handler_cls: type, max_workers: int) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="http-worker"
        )
        super().__init__(addr, handler_cls)

    def process_request(self, request: Any, client_address: Any) -> None:
        self._pool.submit(self._handle, request, client_address)

    def _handle(self, request: Any, client_address: Any) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # 默认实现把 traceback 打到 stderr。这里降级为日志，避免污染前台输出。
        log.debug("连接处理异常 from %s", client_address, exc_info=True)

    def server_close(self) -> None:
        super().server_close()
        self._pool.shutdown(wait=False, cancel_futures=True)


class AddressFamilyServer(BoundedThreadingHTTPServer):
    """支持 IPv6 绑定。"""

    address_family = socket.AF_INET6


def _build_ssl_context(cfg: Config) -> ssl.SSLContext:
    tls = cfg.tls
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=tls.cert_file or "", keyfile=tls.key_file or "")
    except (ssl.SSLError, OSError) as exc:
        raise ConfigError(f"加载 TLS 证书失败: {exc}") from exc
    if tls.client_ca_file:
        # mTLS：要求客户端出示由指定 CA 签发的证书。这是本服务最强的访问控制手段，
        # 比共享密钥更难被泄露复用。
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=tls.client_ca_file)
    return context


def create_server(ctx: AppContext) -> BoundedThreadingHTTPServer:
    cfg = ctx.cfg
    RequestHandler.ctx = ctx
    RequestHandler.timeout = cfg.server.socket_timeout_sec

    is_v6 = ":" in cfg.server.host
    server_cls = AddressFamilyServer if is_v6 else BoundedThreadingHTTPServer
    try:
        httpd = server_cls(
            (cfg.server.host, cfg.server.port),
            RequestHandler,
            cfg.server.max_worker_threads,
        )
    except OSError as exc:
        # 端口占用是最常见的启动失败原因，给出可操作的信息而不是抛裸 traceback。
        raise ConfigError(
            f"无法绑定 {cfg.server.host}:{cfg.server.port} -> {exc}。"
            f"端口可能已被占用（`ss -lntp | grep {cfg.server.port}`），"
            f"或服务已在运行。"
        ) from exc

    # socket 层超时：慢速读写（slowloris）会长期占用 worker 线程，超时是唯一解药。
    httpd.socket.settimeout(cfg.server.socket_timeout_sec)

    if cfg.tls.enabled:
        context = _build_ssl_context(cfg)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        log.info("TLS 已启用（mTLS=%s）", bool(cfg.tls.client_ca_file))

    return httpd


def serve_forever(httpd: BoundedThreadingHTTPServer, stop_event: threading.Event) -> None:
    thread = threading.Thread(target=httpd.serve_forever, name="http-accept", daemon=True)
    thread.start()
    log.info("开始监听 %s", httpd.server_address)
    try:
        stop_event.wait()
    finally:
        log.info("正在关闭监听")
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
