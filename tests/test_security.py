"""访问控制测试。重点是**中间件顺序**这一安全属性，而不只是单个检查是否生效。"""

from __future__ import annotations

import ipaddress

import pytest

from autorun import security
from autorun.config import KeyConfig
from autorun.errors import Forbidden, RateLimited, Unauthorized
from conftest import TEST_KEY_ADMIN, TEST_KEY_CI, read_audit


def test_valid_key_from_non_whitelisted_ip_still_forbidden(make_config, cfg):
    """核心用例：白名单在认证之前。

    持有**完全正确**的密钥，但来源 IP 不在白名单内，必须得到 403 而不是 200。
    如果实现把认证放在了前面，这个用例就会挂 —— 而那意味着端点可以被任意来源用作
    密钥探测器。
    """
    outside = ipaddress.ip_address("203.0.113.9")
    with pytest.raises(Forbidden):
        security.check_ip_whitelist(cfg, outside)
    # 密钥本身是有效的，证明拒绝原因确实是 IP 而非密钥。
    assert security.authenticate(cfg, TEST_KEY_ADMIN).id == "admin"


def test_e2e_non_whitelisted_ip_rejected(make_config):
    """端到端：把白名单改成不含 127.0.0.1，即使带正确密钥也必须 403。"""
    cfg = make_config(security={"ip_whitelist": ["10.99.0.0/24"], "allow_raw_commands": True})
    import threading

    from autorun import logging_setup, server
    from autorun.audit import AuditLog
    from autorun.executor import Executor
    from autorun.registry import Registry
    from autorun.routes import AppContext
    from autorun.security import IdempotencyCache, RateLimiter
    from conftest import Client

    logging_setup.setup(cfg.logging)
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    ctx = AppContext(
        config=cfg,
        registry=registry,
        executor=Executor(cfg, registry, AuditLog(cfg.logging)),
        audit=AuditLog(cfg.logging),
        rate_limiter=RateLimiter(cfg),
        idempotency=IdempotencyCache(),
    )
    httpd = server.create_server(ctx)
    stop = threading.Event()
    t = threading.Thread(target=server.serve_forever, args=(httpd, stop), daemon=True)
    t.start()
    try:
        c = Client(f"http://{cfg.server.host}:{cfg.server.port}")
        status, body, _ = c.post("/v1/exec", {"alias": "hello"}, key=TEST_KEY_ADMIN)
        assert status == 403, body
        assert body["error"]["code"] == "FORBIDDEN"
        # /healthz 同样要过白名单
        assert c.get("/healthz", key=None)[0] == 403
        events = {e["event"] for e in read_audit(cfg)}
        assert "ip_denied" in events
        assert "auth_failure" not in events, "IP 被拒后不应再走认证"
    finally:
        stop.set()
        t.join(timeout=5)
        registry.close()


def test_wrong_key_returns_401_without_leaking_key(client, cfg):
    status, body, _ = client.post("/v1/exec", {"alias": "hello"}, key="wrong-key-but-long-enough-xx")
    assert status == 401
    assert body["error"]["code"] == "UNAUTHORIZED"
    lines = "\n".join(str(e) for e in read_audit(cfg))
    assert "wrong-key-but-long-enough-xx" not in lines, "审计日志泄露了提交的密钥"
    assert TEST_KEY_ADMIN not in lines, "审计日志泄露了配置中的密钥"


def test_missing_key_returns_401(client):
    status, body, _ = client.post("/v1/exec", {"alias": "hello"}, key=None)
    assert status == 401


def test_auth_failure_reason_recorded(client, cfg):
    client.post("/v1/exec", {"alias": "hello"}, key=None)
    client.post("/v1/exec", {"alias": "hello"}, key="x" * 40)
    reasons = {e.get("reason") for e in read_audit(cfg) if e["event"] == "auth_failure"}
    assert reasons == {"missing_key", "bad_key"}


def test_forwarded_for_cannot_bypass_whitelist(cfg):
    """trust_proxy 为 false 时，XFF 必须被完全忽略。

    这是最经典的白名单绕过：无条件采信 XFF 的服务，任何人加一个
    `X-Forwarded-For: 127.0.0.1` 就能冒充白名单来源。
    """
    got = security.parse_client_ip(cfg, "203.0.113.9", "127.0.0.1")
    assert str(got) == "203.0.113.9"
    with pytest.raises(Forbidden):
        security.check_ip_whitelist(cfg, got)


def test_forwarded_for_only_honored_from_trusted_proxy(make_config):
    cfg = make_config(
        security={
            "ip_whitelist": ["127.0.0.1/32", "10.0.0.0/8"],
            "trust_proxy": True,
            "trusted_proxies": ["10.1.1.1/32"],
        }
    )
    # 来自可信代理 -> 采信 XFF
    assert str(security.parse_client_ip(cfg, "10.1.1.1", "10.0.0.5")) == "10.0.0.5"
    # 来自非可信对端 -> 忽略 XFF
    assert str(security.parse_client_ip(cfg, "203.0.113.9", "10.0.0.5")) == "203.0.113.9"
    # XFF 多级时取最左（原始客户端）
    assert str(security.parse_client_ip(cfg, "10.1.1.1", "10.0.0.7, 10.1.1.1")) == "10.0.0.7"


def test_trust_proxy_without_trusted_proxies_refuses_to_start(make_config):
    from autorun.errors import ConfigError

    with pytest.raises(ConfigError, match="trusted_proxies"):
        make_config(security={"trust_proxy": True, "trusted_proxies": []})


def test_alias_acl_enforced(client):
    """最小权限：ci 密钥只能跑 hello。"""
    assert client.post("/v1/exec", {"alias": "hello"}, key=TEST_KEY_CI)[0] == 200
    status, body, _ = client.post("/v1/exec", {"alias": "rollback", "params": {"tag": "v1.0.0"}}, key=TEST_KEY_CI)
    assert status == 403
    assert "无权执行" in body["error"]["message"]


def test_raw_requires_per_key_permission(client):
    """全局开关打开时，仍需该 key 的 allow_raw。双重开关是刻意设计。"""
    assert client.post("/v1/exec/raw", {"command": "echo ok", "mode": "sync"})[0] == 200
    status, body, _ = client.post("/v1/exec/raw", {"command": "echo ok"}, key=TEST_KEY_CI)
    assert status == 403


def test_kill_requires_permission(client):
    status, _, _ = client.post("/v1/exec", {"alias": "slow"})
    assert status == 202
    jobs = client.get("/v1/processes?status=running")[1]["data"]["jobs"]
    job_id = jobs[0]["job_id"]
    assert client.post(f"/v1/processes/{job_id}/kill", {}, key=TEST_KEY_CI)[0] == 403
    assert client.post(f"/v1/processes/{job_id}/kill", {})[0] == 200


def test_commands_list_filtered_by_key(client):
    admin = client.get("/v1/commands")[1]["data"]["commands"]
    ci = client.get("/v1/commands", key=TEST_KEY_CI)[1]["data"]["commands"]
    assert {c["alias"] for c in ci} == {"hello"}
    assert len({c["alias"] for c in admin}) > 1


def test_per_key_ip_narrowing():
    key = KeyConfig(id="k", key="x" * 32, allowed_ips=(ipaddress.ip_network("10.0.0.0/24"),))
    security.authorize_ip_for_key(key, ipaddress.ip_address("10.0.0.5"))
    with pytest.raises(Forbidden):
        security.authorize_ip_for_key(key, ipaddress.ip_address("127.0.0.1"))
    # 未配置 allowed_ips 时不额外限制
    assert KeyConfig(id="k", key="x" * 32).ip_allowed(ipaddress.ip_address("1.2.3.4"))


def test_rate_limit_buckets_unauthenticated_together(make_config):
    """未认证请求共享一个桶：更换密钥猜测不能绕开配额。"""
    cfg = make_config(rate_limit={"enabled": True, "requests_per_minute": 60, "burst": 3})
    limiter = security.RateLimiter(cfg)
    addr = ipaddress.ip_address("127.0.0.1")
    for _ in range(3):
        limiter.check(addr, None)
    with pytest.raises(RateLimited) as exc:
        limiter.check(addr, None)
    assert exc.value.retry_after >= 1


def test_rate_limit_returns_retry_after_header(make_config):
    import threading

    from autorun import logging_setup, server
    from autorun.audit import AuditLog
    from autorun.executor import Executor
    from autorun.registry import Registry
    from autorun.routes import AppContext
    from autorun.security import IdempotencyCache, RateLimiter
    from conftest import Client

    cfg = make_config(rate_limit={"enabled": True, "requests_per_minute": 60, "burst": 2})
    logging_setup.setup(cfg.logging)
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    ctx = AppContext(
        config=cfg,
        registry=registry,
        executor=Executor(cfg, registry, AuditLog(cfg.logging)),
        audit=AuditLog(cfg.logging),
        rate_limiter=RateLimiter(cfg),
        idempotency=IdempotencyCache(),
    )
    httpd = server.create_server(ctx)
    stop = threading.Event()
    t = threading.Thread(target=server.serve_forever, args=(httpd, stop), daemon=True)
    t.start()
    try:
        c = Client(f"http://{cfg.server.host}:{cfg.server.port}")
        codes = [c.get("/healthz")[0] for _ in range(6)]
        assert 429 in codes
        status, _, headers = c.get("/healthz")
        assert status == 429
        assert "Retry-After" in headers
    finally:
        stop.set()
        t.join(timeout=5)
        registry.close()


def test_authenticate_rejects_empty(cfg):
    for bad in (None, ""):
        with pytest.raises(Unauthorized):
            security.authenticate(cfg, bad)
