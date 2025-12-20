from __future__ import annotations

import time
from ipaddress import ip_address, ip_network
from typing import Mapping, Optional

from redis.asyncio import Redis

from threat_thinker.serve.config import RateLimitConfig


class RateLimiter:
    """Simple fixed-window rate limiter backed by Redis."""

    def __init__(self, redis: Redis, config: RateLimitConfig) -> None:
        self.redis = redis
        self.config = config

    async def allow(self, key: str) -> bool:
        if not self.config.enabled:
            return True
        minute = int(time.time() // 60)
        redis_key = f"tt:rl:{key}:{minute}"
        count = await self.redis.incr(redis_key)
        if count == 1:
            await self.redis.expire(redis_key, 60)
        return count <= self.config.requests_per_minute

    def scope_key(self, client_ip: Optional[str], api_key: Optional[str]) -> str:
        if self.config.scope == "api_key" and api_key:
            return f"api_key:{api_key}"
        return f"ip:{client_ip or 'unknown'}"


def resolve_client_ip(
    client_host: Optional[str],
    headers: Mapping[str, str],
    config: RateLimitConfig,
) -> Optional[str]:
    if not _should_trust_proxy_headers(client_host, config):
        return client_host

    forwarded_for = headers.get("x-forwarded-for")
    if forwarded_for:
        forwarded_ip = _first_valid_ip(forwarded_for)
        if forwarded_ip:
            return forwarded_ip

    real_ip = headers.get("x-real-ip")
    if real_ip:
        real_ip = _first_valid_ip(real_ip)
        if real_ip:
            return real_ip

    return client_host


def _should_trust_proxy_headers(
    client_host: Optional[str],
    config: RateLimitConfig,
) -> bool:
    if not config.trust_proxy_headers:
        return False
    if not client_host:
        return False
    if not config.trusted_proxies:
        return True
    try:
        client_ip = ip_address(client_host)
    except ValueError:
        return False
    for proxy in config.trusted_proxies:
        try:
            network = ip_network(proxy, strict=False)
        except ValueError:
            continue
        if client_ip in network:
            return True
    return False


def _first_valid_ip(value: str) -> Optional[str]:
    for part in value.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            return str(ip_address(candidate))
        except ValueError:
            continue
    return None
