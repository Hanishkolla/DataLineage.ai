#!/usr/bin/env python3
"""CLI wrapper for M64 two-tenant persistence isolation validation."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.tenant_isolation_validation import main

if __name__ == "__main__":
    raise SystemExit(main())
