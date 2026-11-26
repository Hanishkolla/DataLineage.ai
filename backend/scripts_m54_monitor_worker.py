"""Run the M54 scheduled governance monitor worker.

Run from backend: python -m scripts_m54_monitor_worker
"""
from __future__ import annotations
import logging, os, time
from app.governance_monitoring import run_once

logging.basicConfig(level=os.getenv("DATALINEAGE_LOG_LEVEL", "INFO"))
log = logging.getLogger("datalineage.m54_monitor")


def main():
    poll_seconds = max(5, min(int(os.getenv("DATALINEAGE_M54_POLL_SECONDS", "30")), 300))
    log.info("M54 governance monitor worker started; poll_seconds=%s", poll_seconds)
    while True:
        try:
            result = run_once()
            if result["claimed"]:
                log.info("M54 monitor batch: %s", result)
        except Exception:
            log.exception("M54 monitor poll failed")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
