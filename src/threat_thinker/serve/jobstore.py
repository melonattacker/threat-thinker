from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from redis import Redis as SyncRedis
from redis.asyncio import Redis as AsyncRedis

from threat_thinker.serve.config import QueueConfig
from threat_thinker.serve.schemas import JobStatus

STATUS_QUEUED: JobStatus = "queued"
STATUS_RUNNING: JobStatus = "running"
STATUS_SUCCEEDED: JobStatus = "succeeded"
STATUS_FAILED: JobStatus = "failed"
STATUS_EXPIRED: JobStatus = "expired"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_key(prefix: str, job_id: str) -> str:
    return f"{prefix}:{job_id}"


def _result_key(prefix: str, job_id: str) -> str:
    return f"{prefix}:{job_id}:result"


class AsyncJobStore:
    def __init__(self, redis: AsyncRedis, config: QueueConfig) -> None:
        self.redis = redis
        self.config = config

    async def enqueue(self, payload: Dict[str, Any]) -> str:
        job_id = str(uuid.uuid4())
        now = _utc_now()
        job_key = _job_key(self.config.job_key_prefix, job_id)
        mapping: Dict[str, Any] = {
            "status": STATUS_QUEUED,
            "created_at": now,
            "updated_at": now,
            "payload": json.dumps(payload),
        }
        await self.redis.hset(job_key, mapping=mapping)
        await self.redis.expire(job_key, self.config.job_ttl_seconds)
        await self.redis.rpush(self.config.queue_key, job_id)
        return job_id

    async def get_status(self, job_id: str) -> Dict[str, Any]:
        job_key = _job_key(self.config.job_key_prefix, job_id)
        data = await self.redis.hgetall(job_key)
        if not data:
            return {"job_id": job_id, "status": STATUS_EXPIRED}
        status = data.get("status", STATUS_EXPIRED)
        return {
            "job_id": job_id,
            "status": status,
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "error": data.get("error"),
        }

    async def get_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        job_key = _job_key(self.config.job_key_prefix, job_id)
        data = await self.redis.hgetall(job_key)
        if not data:
            return None
        if data.get("status") != STATUS_SUCCEEDED:
            return None
        raw = await self.redis.get(_result_key(self.config.job_key_prefix, job_id))
        if not raw:
            return None
        try:
            result = json.loads(raw)
        except Exception:
            return None
        result["job_id"] = job_id
        result.setdefault("model", data.get("model"))
        result.setdefault("duration_ms", data.get("duration_ms"))
        return result


class SyncJobStore:
    def __init__(self, redis: SyncRedis, config: QueueConfig) -> None:
        self.redis = redis
        self.config = config

    def dequeue(self, timeout: int = 5) -> Optional[str]:
        result = self.redis.brpop(self.config.queue_key, timeout=timeout)
        if result is None:
            return None
        _, job_id = result
        return job_id

    def load_payload(self, job_id: str) -> Optional[Dict[str, Any]]:
        job_key = _job_key(self.config.job_key_prefix, job_id)
        data = self.redis.hgetall(job_key)
        if not data:
            return None
        payload = data.get("payload")
        if not payload:
            return None
        try:
            return json.loads(payload)
        except Exception:
            return None

    def mark_running(self, job_id: str) -> None:
        job_key = _job_key(self.config.job_key_prefix, job_id)
        now = _utc_now()
        mapping = {"status": STATUS_RUNNING, "updated_at": now}
        self.redis.hset(job_key, mapping=mapping)
        self.redis.expire(job_key, self.config.job_ttl_seconds)

    def mark_failed(self, job_id: str, error: str) -> None:
        job_key = _job_key(self.config.job_key_prefix, job_id)
        now = _utc_now()
        mapping = {"status": STATUS_FAILED, "updated_at": now, "error": error}
        self.redis.hset(job_key, mapping=mapping)
        self.redis.expire(job_key, self.config.job_ttl_seconds)

    def save_success(
        self, job_id: str, result: Dict[str, Any], duration_ms: Optional[int] = None
    ) -> None:
        job_key = _job_key(self.config.job_key_prefix, job_id)
        now = _utc_now()
        meta: Dict[str, Any] = {
            "status": STATUS_SUCCEEDED,
            "updated_at": now,
        }
        if "model" in result:
            meta["model"] = result["model"]
        if duration_ms is not None:
            meta["duration_ms"] = duration_ms

        self.redis.hset(job_key, mapping=meta)
        self.redis.expire(job_key, self.config.job_ttl_seconds)
        self.redis.set(
            _result_key(self.config.job_key_prefix, job_id),
            json.dumps(result),
            ex=self.config.job_ttl_seconds,
        )
