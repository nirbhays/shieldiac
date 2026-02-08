"""
ShieldIaC — Redis Job Queue Service

Manages async scan jobs using Redis.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from backend.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class QueueService:
    """Redis-backed job queue for asynchronous scan processing."""

    def __init__(self):
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                )
            except ImportError:
                logger.error("redis package not installed")
                return None
        return self._redis

    async def enqueue_scan(self, scan_request: Dict[str, Any]) -> str:
        """Add a scan job to the queue. Returns the job ID."""
        redis = await self._get_redis()
        if not redis:
            raise RuntimeError("Redis not available")

        job_id = str(uuid.uuid4())
        job = {
            "id": job_id,
            "status": "queued",
            "created_at": datetime.utcnow().isoformat(),
            **scan_request,
        }

        await redis.lpush(settings.redis_scan_queue, json.dumps(job))
        await redis.set(f"shieldiac:job:{job_id}", json.dumps(job), ex=settings.redis_result_ttl)

        logger.info("Enqueued scan job %s", job_id)
        return job_id

    async def dequeue_scan(self, timeout: int = 10) -> Optional[Dict[str, Any]]:
        """Block-pop the next scan job from the queue."""
        redis = await self._get_redis()
        if not redis:
            return None

        result = await redis.brpop(settings.redis_scan_queue, timeout=timeout)
        if result:
            _, payload = result
            return json.loads(payload)
        return None

    async def update_job_status(self, job_id: str, status: str, result: Optional[Dict] = None):
        """Update a job's status and optionally store its result."""
        redis = await self._get_redis()
        if not redis:
            return

        job_data = await redis.get(f"shieldiac:job:{job_id}")
        if job_data:
            job = json.loads(job_data)
            job["status"] = status
            job["updated_at"] = datetime.utcnow().isoformat()
            if result:
                job["result"] = result
            await redis.set(
                f"shieldiac:job:{job_id}",
                json.dumps(job),
                ex=settings.redis_result_ttl,
            )

    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get the current status of a job."""
        redis = await self._get_redis()
        if not redis:
            return None

        data = await redis.get(f"shieldiac:job:{job_id}")
        if data:
            return json.loads(data)
        return None

    async def get_queue_length(self) -> int:
        """Return the number of pending jobs."""
        redis = await self._get_redis()
        if not redis:
            return 0
        return await redis.llen(settings.redis_scan_queue)
