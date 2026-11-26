"""Run with: python -m scripts_m50_worker"""
import os, socket
from app.job_queue import run_worker

if __name__ == "__main__":
    run_worker(os.getenv("DATALINEAGE_WORKER_NAME", socket.gethostname()))
