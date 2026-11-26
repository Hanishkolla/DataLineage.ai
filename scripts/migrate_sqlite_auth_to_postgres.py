#!/usr/bin/env python3
import argparse, json, os, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
from app.user_auth_migration import migrate_sqlite_auth_to_postgres
def main():
 p=argparse.ArgumentParser(description="Migrate SQLite users/auth tokens to PostgreSQL")
 p.add_argument("--source",required=True); g=p.add_mutually_exclusive_group(required=True); g.add_argument("--dry-run",action="store_true"); g.add_argument("--apply",action="store_true"); p.add_argument("--batch-size",type=int,default=500); a=p.parse_args()
 url=os.getenv("DATALINEAGE_DATABASE_URL","")
 if a.apply and not url: p.error("--apply requires DATALINEAGE_DATABASE_URL")
 result=migrate_sqlite_auth_to_postgres(a.source,url or "postgresql://dry-run:dry-run@localhost/dry-run",dry_run=a.dry_run,batch_size=a.batch_size)
 print(json.dumps(result,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
