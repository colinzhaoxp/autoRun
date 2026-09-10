"""邮件通知：标准库 smtplib，支持 ssl(465) / starttls(587) / none。

与主体一致的取舍：

- **零新依赖**：只用 smtplib / email / ssl，不引入任何第三方邮件库。
- **失败即抛 NotifyError**，由 monitor 捕获记日志 —— 邮件挂掉不能影响其他告警动作
  （log、exec）。发邮件本身有超时保护，SMTP 服务器无响应时不会卡住监控线程太久。
- **密码从不出现在日志里**：SmtpConfig 的 password 来自 ${SMTP_PASS}（.env），
  这里只用于登录，不打印、不入审计。
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate
from urllib.parse import urlparse

from .config import SmtpConfig


class NotifyError(Exception):
    """邮件发送失败。monitor 捕获后记日志，不向上冒泡。"""


def _open_tunnel(proxy_url: str, host: str, port: int, timeout: float) -> socket.socket:
    """对 HTTP 正向代理发 CONNECT，建立到 host:port 的原始 TCP 隧道。

    内网节点常常没有直连公网的出口，只有一个 HTTP 代理。smtplib 只会做原生 TCP
    直连、不认 http_proxy 环境变量，所以这里手动走 CONNECT：先连代理，发
    `CONNECT host:port`，代理回 200 后这个 socket 就是一条透明隧道，上层再照常
    做 SSL/STARTTLS 与 SMTP 对话即可。零新依赖。
    """
    pu = urlparse(proxy_url)
    if pu.scheme not in ("http", "https") or not pu.hostname:
        raise OSError(f"非法代理地址: {proxy_url!r}")
    ps = socket.create_connection((pu.hostname, pu.port or 80), timeout=timeout)
    try:
        req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Proxy-Connection: keep-alive\r\n\r\n"
        )
        ps.sendall(req.encode("ascii"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = ps.recv(4096)
            if not chunk:
                raise OSError("代理在 CONNECT 响应完成前关闭了连接")
            resp += chunk
            if len(resp) > 65536:  # 正常 CONNECT 响应只有几行，超了必是异常
                raise OSError("代理 CONNECT 响应过大，疑似非法代理")
        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(None, 2)
        if len(parts) < 2 or parts[1] != "200":
            raise OSError(f"代理 CONNECT 未成功: {status_line}")
        return ps
    except Exception:
        ps.close()
        raise


class _ProxySMTP(smtplib.SMTP):
    """走 CONNECT 隧道的明文 SMTP（none / starttls 用）。"""

    def __init__(self, proxy: str, *args, **kwargs) -> None:
        self._proxy = proxy
        super().__init__(*args, **kwargs)

    def _get_socket(self, host, port, timeout):  # noqa: D102 - 覆盖 smtplib 内部
        return _open_tunnel(self._proxy, host, port, timeout)


class _ProxySMTP_SSL(smtplib.SMTP_SSL):
    """走 CONNECT 隧道再包 SSL 的 SMTP（ssl 用）。镜像 cpython 的 _get_socket。"""

    def __init__(self, proxy: str, *args, **kwargs) -> None:
        self._proxy = proxy
        super().__init__(*args, **kwargs)

    def _get_socket(self, host, port, timeout):  # noqa: D102 - 覆盖 smtplib 内部
        raw = _open_tunnel(self._proxy, host, port, timeout)
        return self.context.wrap_socket(raw, server_hostname=self._host)


class EmailNotifier:
    def __init__(self, cfg: SmtpConfig) -> None:
        self._cfg = cfg

    def update_config(self, cfg: SmtpConfig) -> None:
        self._cfg = cfg

    def send(self, subject: str, body: str, to: list[str]) -> None:
        cfg = self._cfg
        if cfg is None:
            raise NotifyError("未配置 smtp，无法发送邮件")
        if not to:
            raise NotifyError("收件人列表为空")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg.from_addr
        msg["To"] = ", ".join(to)
        msg["Date"] = formatdate(localtime=True)
        msg.set_content(body)

        try:
            self._deliver(msg, to)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            # 统一收敛成 NotifyError，附类型名便于排查，但不含密码。
            raise NotifyError(f"发送邮件失败（{type(exc).__name__}）: {exc}") from exc

    def _deliver(self, msg: EmailMessage, to: list[str]) -> None:
        cfg = self._cfg
        timeout = cfg.timeout_sec
        proxy = cfg.proxy
        if cfg.security == "ssl":
            context = ssl.create_default_context()
            smtp = (
                _ProxySMTP_SSL(proxy, cfg.host, cfg.port, timeout=timeout, context=context)
                if proxy
                else smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=timeout, context=context)
            )
            with smtp:
                self._login_and_send(smtp, msg, to)
        elif cfg.security == "starttls":
            context = ssl.create_default_context()
            smtp = (
                _ProxySMTP(proxy, cfg.host, cfg.port, timeout=timeout)
                if proxy
                else smtplib.SMTP(cfg.host, cfg.port, timeout=timeout)
            )
            with smtp:
                smtp.starttls(context=context)
                self._login_and_send(smtp, msg, to)
        else:  # none —— 明文，仅用于内网 relay，config 校验已提示风险
            smtp = (
                _ProxySMTP(proxy, cfg.host, cfg.port, timeout=timeout)
                if proxy
                else smtplib.SMTP(cfg.host, cfg.port, timeout=timeout)
            )
            with smtp:
                self._login_and_send(smtp, msg, to)

    def _login_and_send(self, smtp: smtplib.SMTP, msg: EmailMessage, to: list[str]) -> None:
        cfg = self._cfg
        # 有 username 才登录：内网 relay 常常不需要认证。
        if cfg.username:
            smtp.login(cfg.username, cfg.password)
        smtp.send_message(msg, from_addr=cfg.from_addr, to_addrs=to)
