import pytest
import fakeredis.aioredis

from threat_thinker.serve.config import RateLimitConfig
from threat_thinker.serve.ratelimit import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_blocks_after_threshold():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    limiter = RateLimiter(redis, RateLimitConfig(enabled=True, scope="ip", requests_per_minute=2))

    assert await limiter.allow("client1")
    assert await limiter.allow("client1")
    assert not await limiter.allow("client1")
