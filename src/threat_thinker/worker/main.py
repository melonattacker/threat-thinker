from __future__ import annotations

import argparse
import logging
import time
from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeout,
    wait,
    FIRST_COMPLETED,
)
from dataclasses import asdict
from typing import Optional

from redis import from_url as redis_from_url

from threat_thinker.service.analyzer import AnalysisError, analyze_job
from threat_thinker.serve.config import ServeConfig, load_config
from threat_thinker.serve.jobstore import SyncJobStore

logger = logging.getLogger(__name__)


def _process_job(job_id: str, store: SyncJobStore, config: ServeConfig) -> None:
    payload = store.load_payload(job_id)
    if not payload:
        logger.warning("Job %s payload missing or expired", job_id)
        store.mark_failed(job_id, "Job payload missing or expired.")
        return

    store.mark_running(job_id)
    start = time.time()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            analyze_job, payload, config.engine, config.security.timeouts
        )
        try:
            result = future.result(timeout=config.security.timeouts.analyze_seconds)
        except FuturesTimeout:
            logger.error(
                "Job %s timed out after %ss",
                job_id,
                config.security.timeouts.analyze_seconds,
            )
            store.mark_failed(job_id, "Analysis timed out.")
            return
        except AnalysisError as exc:
            logger.error("Job %s failed: %s", job_id, exc)
            store.mark_failed(job_id, str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("Job %s failed with unexpected error", job_id)
            store.mark_failed(job_id, f"Unhandled error: {exc}")
            return

    duration_ms = int((time.time() - start) * 1000)
    store.save_success(job_id, asdict(result), duration_ms=duration_ms)
    logger.info("Job %s completed in %sms", job_id, duration_ms)


def run_worker(config: ServeConfig) -> None:
    redis = redis_from_url(config.queue.redis_url, decode_responses=True)
    store = SyncJobStore(redis, config.queue)
    max_workers = max(1, config.security.concurrency.max_in_flight_per_worker)
    logger.info(
        "Worker started. Listening on queue %s (max_in_flight_per_worker=%s)",
        config.queue.queue_key,
        max_workers,
    )
    futures = {}
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while True:
                if len(futures) < max_workers:
                    job_id = store.dequeue(timeout=5)
                    if job_id:
                        future = executor.submit(_process_job, job_id, store, config)
                        futures[future] = job_id
                        continue
                if futures:
                    done, _ = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                    for future in done:
                        job_id = futures.pop(future, None)
                        if job_id is None:
                            continue
                        try:
                            future.result()
                        except Exception:  # noqa: BLE001
                            logger.exception(
                                "Job %s failed with unexpected error", job_id
                            )
                else:
                    time.sleep(0.2)
    except KeyboardInterrupt:
        logger.info("Worker interrupted, shutting down.")
    finally:
        try:
            redis.close()
        except Exception:  # noqa: BLE001
            pass


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Threat Thinker worker")
    parser.add_argument(
        "--config", type=str, required=True, help="Path to serve config YAML"
    )
    args = parser.parse_args(argv)
    config = load_config(args.config)
    logging.basicConfig(level=config.observability.log_level.upper())
    run_worker(config)


if __name__ == "__main__":
    main()
