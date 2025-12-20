import json
import pytest
import fakeredis
import fakeredis.aioredis

from threat_thinker.serve.config import QueueConfig
from threat_thinker.serve.jobstore import AsyncJobStore, SyncJobStore, STATUS_SUCCEEDED


@pytest.mark.asyncio
async def test_async_jobstore_roundtrip():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = AsyncJobStore(redis, QueueConfig())
    job_id = await store.enqueue(
        {"input": {"type": "mermaid", "content": "graph LR;A-->B"}, "options": {}}
    )
    status = await store.get_status(job_id)
    assert status["status"] == "queued"

    await redis.hset(
        f"{store.config.job_key_prefix}:{job_id}",
        mapping={"status": STATUS_SUCCEEDED, "updated_at": "now"},
    )
    await redis.set(
        f"{store.config.job_key_prefix}:{job_id}:result",
        json.dumps({"reports": [{"report_format": "markdown", "content": "ok"}]}),
    )
    result = await store.get_result(job_id)
    assert result["reports"][0]["content"] == "ok"


def test_sync_jobstore_load_payload_and_status():
    redis = fakeredis.FakeRedis(decode_responses=True)
    cfg = QueueConfig()
    store = SyncJobStore(redis, cfg)
    job_id = "job123"
    redis.hset(
        f"{cfg.job_key_prefix}:{job_id}",
        mapping={"payload": json.dumps({"hello": "world"})},
    )

    payload = store.load_payload(job_id)
    assert payload == {"hello": "world"}
