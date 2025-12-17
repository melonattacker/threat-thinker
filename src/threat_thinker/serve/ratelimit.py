from __future__ import annotations

import time
from typing import Optional

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
