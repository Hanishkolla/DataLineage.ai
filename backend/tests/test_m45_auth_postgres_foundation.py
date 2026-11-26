import sqlite3
import pytest
from app import user_store
from app.user_auth_migration import sqlite_auth_summary, migrate_sqlite_auth_to_postgres

def test_user_store_sqlite_default_and_email_verification(tmp_path,monkeypatch):
 monkeypatch.delenv("DATALINEAGE_DATABASE_URL",raising=False); monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH",str(tmp_path/"users.sqlite3"))
 created=user_store.create_user("Person@Example.com","Correct-Horse-12!")
 assert created["email"]=="person@example.com" and user_store.user_exists("PERSON@example.com")
 assert not user_store.authenticate_user("person@example.com","Correct-Horse-12!")
 raw,_=user_store.issue_token("person@example.com","verify_email",600)
 assert user_store.consume_verification_token(raw) and user_store.authenticate_user("person@example.com","Correct-Horse-12!")

def test_duplicate_user_contract_is_preserved(tmp_path,monkeypatch):
 monkeypatch.delenv("DATALINEAGE_DATABASE_URL",raising=False); monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH",str(tmp_path/"users.sqlite3"))
 user_store.create_user("same@example.com","Correct-Horse-12!")
 with pytest.raises(ValueError,match="already exists"): user_store.create_user("SAME@example.com","Correct-Horse-12!")

def test_migration_dry_run_counts_without_connecting(tmp_path,monkeypatch):
 path=tmp_path/"users.sqlite3"; monkeypatch.delenv("DATALINEAGE_DATABASE_URL",raising=False); monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH",str(path))
 user_store.create_user("a@example.com","Correct-Horse-12!"); user_store.issue_token("a@example.com","verify_email",600)
 assert sqlite_auth_summary(path)=={"integrity":"ok","users":1,"auth_tokens":1}
 out=migrate_sqlite_auth_to_postgres(path,"postgresql://unused:unused@localhost/unused",dry_run=True)
 assert out["mode"]=="dry_run" and out["target_changed"] is False

def test_migration_rejects_bad_target_and_batch_size(tmp_path):
 path=tmp_path/"users.sqlite3"; c=sqlite3.connect(path); c.execute("CREATE TABLE users(email TEXT PRIMARY KEY,password_hash TEXT NOT NULL,created_at TEXT NOT NULL)"); c.commit(); c.close()
 with pytest.raises(ValueError): migrate_sqlite_auth_to_postgres(path,"mysql://localhost/db",dry_run=True)
 with pytest.raises(ValueError): migrate_sqlite_auth_to_postgres(path,"postgresql://x:x@localhost/db",dry_run=True,batch_size=0)
