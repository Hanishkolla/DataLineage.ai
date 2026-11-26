import json
import pytest
from app import job_queue as q

class FakePipe:
    def __init__(self, client): self.client=client; self.ops=[]
    def hset(self,key,mapping): self.ops.append(("hset",key,mapping)); return self
    def expire(self,key,ttl): self.ops.append(("expire",key,ttl)); return self
    def xadd(self,stream,fields,**kwargs): self.ops.append(("xadd",stream,fields)); return self
    def execute(self):
        for op in self.ops:
            if op[0]=="hset": self.client.hashes.setdefault(op[1],{}).update(op[2])
            elif op[0]=="xadd": self.client.stream.append(op[2])
        return True
class FakeRedis:
    def __init__(self): self.hashes={}; self.stream=[]
    def ping(self): return True
    def pipeline(self): return FakePipe(self)
    def hgetall(self,key): return self.hashes.get(key,{})
    def xinfo_groups(self,stream): return []
    def xlen(self,stream): return len(self.stream)

@pytest.fixture
def fake(monkeypatch):
    client=FakeRedis(); monkeypatch.setattr(q,"_client",lambda:client); return client

def test_enqueue_persists_owner_tenant_and_payload(fake):
    job=q.enqueue_quality_profile({"rows":[{"id":1}]},"owner@example.com","tenant-1")
    data=fake.hashes[q.STATUS_PREFIX+job]
    assert data["status"]=="queued" and data["owner"]=="owner@example.com"
    assert data["tenant_id"]=="tenant-1"
    assert json.loads(fake.stream[0]["payload"])["rows"]==[{"id":1}]

def test_job_status_is_tenant_and_owner_scoped(fake):
    job=q.enqueue_quality_profile({"rows":[]},"owner","tenant")
    assert q.get_job(job,"owner","tenant")["status"]=="queued"
    assert q.get_job(job,"other","tenant") is None
    assert q.get_job(job,"owner","other") is None

def test_oversized_payload_rejected(monkeypatch):
    monkeypatch.setattr(q,"_client",lambda: pytest.fail("Redis must not be called"))
    with pytest.raises(ValueError): q.enqueue_quality_profile({"blob":"x"*(q.MAX_PAYLOAD_BYTES+1)},"u",None)

def test_queue_status_reports_stream_length(fake):
    fake.stream.append({"job_id":"x"})
    status=q.queue_status()
    assert status["backend"]=="redis_streams" and status["stream_length"]==1
