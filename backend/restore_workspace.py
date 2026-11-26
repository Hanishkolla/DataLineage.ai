import sqlite3
from pathlib import Path

ORG_ID = "b3891a3a-d90f-4ff2-9a99-cc1a6b98897c"

SOURCE = Path(
    r"C:\Users\hanis\Downloads\datalineage-ai-m22-fresh"
    r"\datalineage-ai-milestone22\backend\data"
)

TARGET = Path("data")

db = sqlite3.connect(TARGET / "saas.sqlite3")
db.execute("PRAGMA foreign_keys = ON")

try:
    db.execute("ATTACH DATABASE ? AS source_saas",
               (str(SOURCE / "saas.sqlite3"),))
    db.execute("ATTACH DATABASE ? AS source_users",
               (str(SOURCE / "users.sqlite3"),))
    db.execute("ATTACH DATABASE ? AS target_users",
               (str(TARGET / "users.sqlite3"),))

    membership = db.execute(
        "SELECT email FROM source_saas.memberships WHERE org_id=?",
        (ORG_ID,)
    ).fetchone()

    if not membership:
        raise RuntimeError("Source membership not found")

    email = membership[0]

    user = db.execute(
        """SELECT email, email_verified
           FROM source_users.users
           WHERE lower(email)=lower(?)""",
        (email,)
    ).fetchone()

    if not user or user[1] != 1:
        raise RuntimeError("Matching verified source user not found")

    checks = [
        ("organization", """
            SELECT 1 FROM main.organizations WHERE id=?
        """, (ORG_ID,)),
        ("workspace slug", """
            SELECT 1 FROM main.organizations
            WHERE slug=(SELECT slug FROM source_saas.organizations
                        WHERE id=?)
        """, (ORG_ID,)),
        ("user", """
            SELECT 1 FROM target_users.users WHERE lower(email)=lower(?)
        """, (email,)),
        ("membership", """
            SELECT 1 FROM main.memberships WHERE org_id=?
        """, (ORG_ID,)),
        ("subscription ID", """
            SELECT 1 FROM main.subscriptions
            WHERE id IN (SELECT id FROM source_saas.subscriptions
                         WHERE org_id=?)
        """, (ORG_ID,)),
        ("audit event ID", """
            SELECT 1 FROM main.audit_events
            WHERE id IN (SELECT id FROM source_saas.audit_events
                         WHERE org_id=?)
        """, (ORG_ID,))
    ]

    for name, sql, params in checks:
        if db.execute(sql, params).fetchone():
            raise RuntimeError(f"Destination conflict: {name}")

    expected = {
        "organizations": 1,
        "memberships": 1,
        "subscriptions": 1,
        "audit_events": 1,
    }

    for table, count in expected.items():
        actual = db.execute(
            f"SELECT COUNT(*) FROM source_saas.{table} WHERE "
            + ("id=?" if table == "organizations" else "org_id=?"),
            (ORG_ID,)
        ).fetchone()[0]
        if actual != count:
            raise RuntimeError(
                f"Unexpected {table} count: {actual}; expected {count}"
            )

    db.execute("BEGIN IMMEDIATE")

    db.execute("""
        INSERT INTO target_users.users
        SELECT * FROM source_users.users
        WHERE lower(email)=lower(?)
    """, (email,))
    if db.execute("SELECT changes()").fetchone()[0] != 1:
        raise RuntimeError("User import failed")

    for table in [
        "organizations",
        "memberships",
        "subscriptions",
        "audit_events",
    ]:
        where = "id=?" if table == "organizations" else "org_id=?"
        db.execute(
            f"INSERT INTO main.{table} "
            f"SELECT * FROM source_saas.{table} WHERE {where}",
            (ORG_ID,)
        )
        if db.execute("SELECT changes()").fetchone()[0] != 1:
            raise RuntimeError(f"{table} import failed")

    db.commit()

    print("MIGRATION SUCCESSFUL")
    print("User account restored: 1")
    print("Organization restored: 1")
    print("Membership restored: 1")
    print("Subscription restored: 1")
    print("Audit event restored: 1")
    print("Authentication tokens copied: 0")
    print("Razorpay table preserved.")

except Exception:
    db.rollback()
    print("MIGRATION FAILED — changes rolled back.")
    raise

finally:
    db.close()
