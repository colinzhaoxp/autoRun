"""notify.EmailNotifier 的三种 security 模式，全程 mock smtplib（不真发邮件）。

验证：ssl 用 SMTP_SSL、starttls 走 SMTP+starttls、none 不加密；有 username 才登录；
失败被收敛成 NotifyError；密码不出现在异常信息里。
"""

from __future__ import annotations

import smtplib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autorun.config import SmtpConfig  # noqa: E402
from autorun.notify import EmailNotifier, NotifyError  # noqa: E402


class FakeSMTP:
    """记录调用序列的假 SMTP。用作 SMTP 与 SMTP_SSL 的替身。"""

    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.started_tls = False
        self.logged_in = None
        self.sent = None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.sent = {"from": from_addr, "to": to_addrs, "subject": msg["Subject"]}


@pytest.fixture(autouse=True)
def _reset():
    FakeSMTP.instances = []
    yield


def _cfg(**over):
    base = dict(
        host="smtp.example.com", port=465, security="ssl",
        username="u@example.com", password="secret-pass",
        from_addr="alert@example.com", timeout_sec=5,
    )
    base.update(over)
    return SmtpConfig(**base)


def test_ssl_uses_smtp_ssl(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    EmailNotifier(_cfg(security="ssl", port=465)).send("s", "b", ["ops@x.com"])
    inst = FakeSMTP.instances[-1]
    assert inst.port == 465
    assert inst.context is not None            # SSL 上下文已建立
    assert not inst.started_tls
    assert inst.logged_in == ("u@example.com", "secret-pass")
    assert inst.sent["to"] == ["ops@x.com"]


def test_starttls_upgrades(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    EmailNotifier(_cfg(security="starttls", port=587)).send("s", "b", ["ops@x.com"])
    inst = FakeSMTP.instances[-1]
    assert inst.started_tls is True
    assert inst.logged_in is not None


def test_none_no_tls_no_login_when_anonymous(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    EmailNotifier(_cfg(security="none", port=25, username="")).send("s", "b", ["ops@x.com"])
    inst = FakeSMTP.instances[-1]
    assert inst.started_tls is False
    assert inst.logged_in is None              # 无 username 时不登录（内网 relay）


def test_empty_recipients_rejected():
    with pytest.raises(NotifyError):
        EmailNotifier(_cfg()).send("s", "b", [])


def test_failure_wrapped_and_password_not_leaked(monkeypatch):
    class Boom(FakeSMTP):
        def send_message(self, *a, **k):
            raise smtplib.SMTPException("upstream refused")

    monkeypatch.setattr(smtplib, "SMTP_SSL", Boom)
    with pytest.raises(NotifyError) as ei:
        EmailNotifier(_cfg()).send("s", "b", ["ops@x.com"])
    assert "secret-pass" not in str(ei.value)


# --- 代理 CONNECT 隧道 -----------------------------------------------------

from autorun import notify as notify_mod  # noqa: E402


class FakeProxySock:
    """假代理端 socket：记录 CONNECT 请求，按预设状态行回应。"""

    def __init__(self, status=b"HTTP/1.1 200 Connection established\r\n\r\n"):
        self.status = status
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        # 一次性把响应给完，之后返回空表示对端不再有数据
        if self.status:
            out, self.status = self.status, b""
            return out
        return b""

    def close(self):
        self.closed = True


def test_open_tunnel_success(monkeypatch):
    fake = FakeProxySock()
    monkeypatch.setattr(notify_mod.socket, "create_connection", lambda *a, **k: fake)
    sock = notify_mod._open_tunnel("http://proxy:8188", "smtp.163.com", 465, 5)
    assert sock is fake
    assert b"CONNECT smtp.163.com:465 HTTP/1.1" in fake.sent
    assert b"Host: smtp.163.com:465" in fake.sent


def test_open_tunnel_proxy_refuses(monkeypatch):
    fake = FakeProxySock(status=b"HTTP/1.1 403 Forbidden\r\n\r\n")
    monkeypatch.setattr(notify_mod.socket, "create_connection", lambda *a, **k: fake)
    with pytest.raises(OSError) as ei:
        notify_mod._open_tunnel("http://proxy:8188", "smtp.163.com", 465, 5)
    assert "403" in str(ei.value)
    assert fake.closed  # 失败时释放到代理的连接


def test_open_tunnel_rejects_bad_proxy_url():
    with pytest.raises(OSError):
        notify_mod._open_tunnel("not-a-url", "h", 25, 5)


class FakeProxySMTP(FakeSMTP):
    """替身：签名与 _ProxySMTP_SSL 一致（首参为 proxy）。"""

    def __init__(self, proxy, host, port, timeout=None, context=None):
        self.proxy = proxy
        super().__init__(host, port, timeout=timeout, context=context)


def test_ssl_with_proxy_uses_tunnel_class(monkeypatch):
    # 有 proxy 时走 _ProxySMTP_SSL，且把代理地址透传下去；不碰直连的 SMTP_SSL。
    monkeypatch.setattr(notify_mod, "_ProxySMTP_SSL", FakeProxySMTP)

    def _boom(*a, **k):
        raise AssertionError("配了 proxy 不应直连 SMTP_SSL")

    monkeypatch.setattr(smtplib, "SMTP_SSL", _boom)
    EmailNotifier(_cfg(proxy="http://proxy:8188")).send("s", "b", ["ops@x.com"])
    inst = FakeSMTP.instances[-1]
    assert isinstance(inst, FakeProxySMTP)
    assert inst.proxy == "http://proxy:8188"
    assert inst.logged_in == ("u@example.com", "secret-pass")


def test_no_proxy_uses_direct(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)

    def _boom(*a, **k):
        raise AssertionError("未配 proxy 不应走隧道类")

    monkeypatch.setattr(notify_mod, "_ProxySMTP_SSL", _boom)
    EmailNotifier(_cfg(proxy=None)).send("s", "b", ["ops@x.com"])
    assert isinstance(FakeSMTP.instances[-1], FakeSMTP)
