import sqlite3
from pathlib import Path

ORG_ID = "b3891a3a-d90f-4ff2-9a99-cc1a6b98897c"

OLD = Path(r"C:\Users\hanis\Downloads\datalineage-ai-m22-fresh\datalineage-ai-milestone22\backend\data")
NEW = Path("data")

old_saas = sqlite3.connect(OLD / "saas.sqlite3")
old_users = sqlite3.connect(OLD / "users.sqlite3")
new_saas = sqlite3.connect(NEW / "saas.sqlite3")
new_users = sqlite3.connect(NEW / "users.sqlite3")

def columns(db, table):
    return [r[1] for r in db.execute(f"PRAGMA table_info({table})")]

try:
    assert old_saas.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert old_users.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert new_saas.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert new_users.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    tables = [
        "organizations", "memberships", "subscriptions",
        "audit_events", "invitations", "usage_events",
        "usage_reservations", "billing_events",
        "github_connections", "trial_activations"
    ]

    for table in tables:
        assert columns(old_saas, table) == columns(new_saas, table), (
            f"Schema mismatch: {table}"
        )

    assert columns(old_users, "users") == columns(new_users, "users")

    org = old_saas.execute(
        "SELECT id FROM organizations WHERE id=?", (ORG_ID,)
    ).fetchone()
    assert org, "Source organization not found"

    memberships = old_saas.execute(
        "SELECT email FROM memberships WHERE org_id=?", (ORG_ID,)
    ).fetchall()
    assert len(memberships) == 1, "Expected exactly one membership"

    email = memberships[0][0]
    user = old_users.execute(
        "SELECT * FROM users WHERE lower(email)=lower(?)", (email,)
    ).fetchone()
    assert user, "Matching source user not found"

    assert old_saas.execute(
        "SELECT 1 FROM organizations WHERE id=?", (ORG_ID,)
    ).fetchone()
    assert not new_saas.execute(
        "SELECT 1 FROM organizations WHERE id=?", (ORG_ID,)
    ).fetchone(), "Destination organization already exists"

    assert not new_users.execute(
        "SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)
    ).fetchone(), "Destination user already exists"

    print("DRY RUN PASSED")
    print("All four databases passed integrity checks.")
    print("Shared SaaS schemas match.")
    print("User schemas match.")
    print("Source organization: found")
    print("Source membership: 1")
    print("Matching user: found")
    print("User email verified:", bool(user[3]))
    print("Razorpay table preserved:", "razorpay_subscriptions" in [
        r[0] for r in new_saas.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    ])
    for table in tables:
        count = (
            old_saas.execute(
                f"SELECT COUNT(*) FROM {table} WHERE id=?", (ORG_ID,)
            ).fetchone()[0]
            if table == "organizations"
            else old_saas.execute(
                f"SELECT COUNT(*) FROM {table} WHERE org_id=?", (ORG_ID,)
            ).fetchone()[0]
        )
        if count:
            print(f"{table}: {count} record(s) to restore")

finally:
    old_saas.close()
    old_users.close()
    new_saas.close()
    new_users.close()
