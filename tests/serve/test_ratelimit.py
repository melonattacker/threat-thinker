import pytest
import fakeredis.aioredis

from threat_thinker.serve.config import RateLimitConfig
from threat_thinker.serve.ratelimit import RateLimiter, resolve_client_ip


@pytest.mark.asyncio
async def test_rate_limiter_blocks_after_threshold():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter = RateLimiter(redis, RateLimitConfig(enabled=True, scope="ip", requests_per_minute=2))

    assert await limiter.allow("client1")
    assert await limiter.allow("client1")
    assert not await limiter.allow("client1")


def test_resolve_client_ip_uses_forwarded_for_when_trusted():
    config = RateLimitConfig(
        trust_proxy_headers=True,
        trusted_proxies=["10.0.0.1"],
    )
    headers = {"x-forwarded-for": "203.0.113.9, 10.0.0.1"}

    assert resolve_client_ip("10.0.0.1", headers, config) == "203.0.113.9"


def test_resolve_client_ip_ignores_forwarded_for_when_untrusted():
    config = RateLimitConfig(trust_proxy_headers=True, trusted_proxies=["10.0.0.2"])
    headers = {"x-forwarded-for": "203.0.113.9"}

    assert resolve_client_ip("10.0.0.1", headers, config) == "10.0.0.1"
