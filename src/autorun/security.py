"""访问控制：IP 白名单、限流、密钥认证、按 key 授权。

**中间件的执行顺序本身就是一项安全属性**，顺序是：

    IP 白名单 → 限流 → 认证 → 按 key 授权 → 载荷校验

两个原因让这个顺序不可调换：

- 白名单在认证之前，所以未授权来源的请求根本走不到密钥比对。否则任何人都能拿这个
  端点当"密钥探测器"，用响应差异来判断猜测是否接近正确。
- 限流在认证之前，所以暴力破解密钥的尝试会被节流；放在认证之后，攻击者的失败请求
  不消耗配额，等于没有限流。
"""

from __future__ import annotations

import hmac
import ipaddress
import threading
import time
from collections import OrderedDict
from typing import Any

from .config import Config, KeyConfig
from .errors import Forbidden, RateLimited, Unauthorized

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_client_ip(cfg: Config, peer_ip: str, forwarded_for: str | None) -> IPAddress:
    """确定客户端真实 IP。

    只有当 `trust_proxy` 为真**且**直接对端本身在 `trusted_proxies` 中时，才采信
    `X-Forwarded-For`。否则一律以 socket 对端为准。

    这是最经典的白名单绕过洞：无条件信任 XFF 的服务，任何人加一个
    `X-Forwarded-For: 127.0.0.1` 头就能冒充白名单内的来源。
    """
    peer = ipaddress.ip_address(_strip_scope(peer_ip))
    if not cfg.security.trust_proxy or not forwarded_for:
        return peer
    if not any(peer in net for net in cfg.security.trusted_proxies):
        # 对端不是可信代理，说明这个头是客户端自己加的，直接忽略。
        return peer
    # XFF 是 "client, proxy1, proxy2" 形式，最左侧是原始客户端。
    first = forwarded_for.split(",")[0].strip()
    try:
        return ipaddress.ip_address(_strip_scope(first))
    except ValueError:
        return peer


def _strip_scope(value: str) -> str:
    """去掉 IPv6 的 scope id（如 fe80::1%eth0）与 IPv4 映射前缀。"""
    v = value.split("%")[0]
    if v.startswith("::ffff:") and v.count(".") == 3:
        return v[len("::ffff:") :]
    return v


def check_ip_whitelist(cfg: Config, addr: IPAddress) -> None:
    """第一道关。不通过则请求到此为止，不会进入后续任何环节。"""
    if not any(addr in net for net in cfg.security.ip_whitelist):
        raise Forbidden("来源 IP 不在白名单内")


class RateLimiter:
    """令牌桶限流。按 (IP, key_id) 或仅按 IP 分桶。

    未认证请求的 key_id 为 None，因此所有猜密钥的尝试共享同一个桶，无法通过更换
    密钥猜测来绕开配额。
    """

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._buckets: OrderedDict[tuple[str, str | None], tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_buckets = 4096

    def update_config(self, cfg: Config) -> None:
        self._cfg = cfg

    def check(self, addr: IPAddress, key_id: str | None) -> None:
        rl = self._cfg.rate_limit
        if not rl.enabled:
            return
        bucket_key = (str(addr), key_id if rl.per_key else None)
        rate_per_sec = rl.requests_per_minute / 60.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(bucket_key, (float(rl.burst), now))
            tokens = min(rl.burst, tokens + (now - last) * rate_per_sec)
            if tokens < 1.0:
                self._buckets[bucket_key] = (tokens, now)
                retry_after = max(int((1.0 - tokens) / rate_per_sec) + 1, 1)
                raise RateLimited("请求过于频繁", retry_after=retry_after)
            self._buckets[bucket_key] = (tokens - 1.0, now)
            self._buckets.move_to_end(bucket_key)
            # 有界字典：否则攻击者用大量伪造源 IP 就能把内存打满。
            while len(self._buckets) > self._max_buckets:
                self._buckets.popitem(last=False)


def authenticate(cfg: Config, presented: str | None) -> KeyConfig:
    """验证共享密钥。

    两个细节：
    - 用 `hmac.compare_digest` 而非 `==`，避免通过响应时间差异逐字节猜出密钥。
    - 遍历**所有**已配置密钥而不是命中即返回，让耗时与"匹配到第几个"无关。
    """
    if not presented:
        raise Unauthorized("缺少认证密钥")
    matched: KeyConfig | None = None
    for kc in cfg.auth.keys:
        if hmac.compare_digest(kc.key, presented):
            matched = kc
    if matched is None:
        # 不区分"密钥不存在"与"密钥错误"，也不回显所提交的内容。
        raise Unauthorized("认证失败")
    return matched


def authorize_ip_for_key(key: KeyConfig, addr: IPAddress) -> None:
    """在全局白名单之上按 key 再收窄来源。"""
    if not key.ip_allowed(addr):
        raise Forbidden("该密钥不允许从此 IP 使用")


def authorize_alias(key: KeyConfig, alias: str) -> None:
    if not key.may_run(alias):
        raise Forbidden(f"密钥 {key.id!r} 无权执行 {alias!r}")


def authorize_raw(cfg: Config, key: KeyConfig) -> None:
    """裸命令需要"全局开关 + 该 key 许可"双重同意。

    双重开关是刻意的：全局开关让运维能一键关闭整个高危能力，per-key 许可让最小权限
    的调用方（如 CI）即使在开关打开时也拿不到这个能力。
    """
    if not cfg.security.allow_raw_commands:
        raise Forbidden("本服务未开启裸命令执行")
    if not key.allow_raw:
        raise Forbidden(f"密钥 {key.id!r} 无权执行裸命令")


def authorize_kill(key: KeyConfig) -> None:
    if not key.allow_kill:
        raise Forbidden(f"密钥 {key.id!r} 无权终止任务")


class IdempotencyCache:
    """幂等键缓存：把重复提交映射回首次的结果。

    解决的是运维里代价最高的一类事故：客户端因超时重试 `deploy`，结果起了两个并发
    部署。有了它，携带同一个 `X-Idempotency-Key` 的重试会拿到原任务而不是新任务。
    """

    def __init__(self, ttl_sec: float = 600.0, max_entries: int = 1024) -> None:
        self._ttl = ttl_sec
        self._max = max_entries
        self._data: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> dict[str, Any] | None:
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            ts, payload = item
            if now - ts > self._ttl:
                del self._data[key]
                return None
            return payload

    def put(self, key: str, payload: dict[str, Any]) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), payload)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
