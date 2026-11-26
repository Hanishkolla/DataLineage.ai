# DataLineage AI — M61 Graph Benchmark

- Measured at: `2026-11-13T09:14:02.582906+00:00`
- Python: `3.13.5`
- NetworkX: `3.6.1`
- Platform: `Linux-6.18.57-x86_64-with-glibc2.41`

## Workload and integrity

- Nodes: 10,000
- Edges: 20,000
- DAG validation: passed
- Concurrent read workers / queries: 4 / 4

## Measurements

- Graph build: 0.125415 seconds
- DAG validation: 0.024981 seconds
- Concurrent read queries: 0.087836 seconds
- Read query throughput: 45.54 queries/second
- Python traced peak memory: 11,288,602 bytes

## Measurement limits

- Synthetic in-memory NetworkX graph only; SQL parsing and FastAPI request overhead are not measured.
- Python tracemalloc does not capture every native allocation or total process RSS.
- Concurrent checks are read-only graph traversals in one process, not multi-user or multi-instance load tests.
- Results depend on machine, Python, NetworkX version and runtime conditions; repeat on customer-like infrastructure.

## Reproduction

```powershell
cd backend
python ..\scripts\enterprise_validation.py --nodes 10000 --edges 20000 --workers 4 --queries 4
```
