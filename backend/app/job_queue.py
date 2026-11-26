"""M50 Redis Streams job queue with durable status and tenant-scoped reads.

Payloads are retained in Redis while jobs run. Production deployments must use
private networking, TLS, authentication, persistence, backups and an explicit
retention policy appropriate to the data classification.
"""
from __future__ import annotations
import json, os, time
from uuid import uuid4
from typing import Any
from .config import settings

STREAM = "datalineage:jobs:quality-profile"
GROUP = "datalineage-quality-workers"
STATUS_PREFIX = "datalineage:job:"
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
STATUS_TTL_SECONDS = 7 * 24 * 60 * 60

class QueueUnavailable(RuntimeError):
    pass

def _client():
    if not settings.redis_url:
        raise QueueUnavailable("Redis is required for distributed jobs; configure DATALINEAGE_REDIS_URL")
    try:
        import redis
        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2,
            socket_timeout=5, decode_responses=True)
        client.ping()
        return client
    except Exception as exc:
        raise QueueUnavailable("Distributed job queue is unavailable") from exc

def enqueue_quality_profile(payload: dict[str, Any], owner: str, tenant_id: str | None) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError("Job payload exceeds the 8 MiB queue limit")
    client = _client()
    job_id = str(uuid4())
    status_key = STATUS_PREFIX + job_id
    now = str(int(time.time()))
    pipe = client.pipeline()
    pipe.hset(status_key, mapping={"job_id":job_id,"status":"queued","owner":owner,
        "tenant_id":tenant_id or "","created_at":now,"updated_at":now,"result":"","error":""})
    pipe.expire(status_key, STATUS_TTL_SECONDS)
    pipe.xadd(STREAM, {"job_id":job_id,"payload":encoded}, maxlen=10000, approximate=True)
    pipe.execute()
    return job_id

def get_job(job_id: str, owner: str, tenant_id: str | None) -> dict[str, Any] | None:
    client = _client()
    data = client.hgetall(STATUS_PREFIX + job_id)
    if not data or data.get("owner") != owner or data.get("tenant_id", "") != (tenant_id or ""):
        return None
    out = {"job_id":job_id,"status":data.get("status","unknown"),
           "created_at":data.get("created_at"),"updated_at":data.get("updated_at")}
    if data.get("status") == "completed" and data.get("result"):
        out["result"] = json.loads(data["result"])
    if data.get("status") == "failed":
        out["error"] = data.get("error") or "Job failed"
    return out

def queue_status() -> dict[str, Any]:
    client = _client()
    try:
        info = client.xinfo_groups(STREAM)
        groups = [{"name":g.get("name"),"pending":g.get("pending"),"consumers":g.get("consumers")} for g in info]
    except Exception:
        groups = []
    return {"backend":"redis_streams","status":"ok","stream_length":client.xlen(STREAM),"groups":groups}

def run_worker(consumer: str, block_ms: int = 5000) -> None:
    from .data_quality import profile_dataset
    client = _client()
    try:
        client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    while True:
        batches = client.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=1, block=block_ms)
        if not batches:
            continue
        for _stream, messages in batches:
            for message_id, fields in messages:
                job_id = fields.get("job_id", "")
                status_key = STATUS_PREFIX + job_id
                try:
                    client.hset(status_key, mapping={"status":"running","updated_at":str(int(time.time()))})
                    payload = json.loads(fields["payload"])
                    result = profile_dataset(payload.get("rows"), payload.get("required_columns"),
                        payload.get("unique_columns"), payload.get("allowed_values"))
                    client.hset(status_key, mapping={"status":"completed","result":json.dumps(result),
                        "error":"","updated_at":str(int(time.time()))})
                except Exception as exc:
                    # Do not expose raw exception text or user data in job status.
                    client.hset(status_key, mapping={"status":"failed",
                        "error":f"Analysis failed ({type(exc).__name__})","updated_at":str(int(time.time()))})
                finally:
                    client.expire(status_key, STATUS_TTL_SECONDS)
                    client.xack(STREAM, GROUP, message_id)
