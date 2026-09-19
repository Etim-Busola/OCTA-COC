"""
database.py - Creates the OCTA-CoC SQLite database and its tables.

WORM rule (Write Once, Read Many):
    CustodyRecord and AuditLog rows can be ADDED and READ, but never
    CHANGED or DELETED. SQLite has no user permissions (no GRANT/REVOKE),
    so the rule is enforced with triggers stored inside the database file.
    Any UPDATE or DELETE on those tables is rejected by the database itself,
    no matter which program tries it.

Run this file directly to see the WORM protection in action:
    python database.py
"""

import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).parent / "octa_coc.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS "Case" (
    case_id      TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    description  TEXT
);

CREATE TABLE IF NOT EXISTS "User" (
    user_id  TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    role     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Location (
    location_id  TEXT PRIMARY KEY,
    description  TEXT
);

CREATE TABLE IF NOT EXISTS Evidence (
    asset_id          TEXT PRIMARY KEY,
    case_id           TEXT NOT NULL REFERENCES "Case"(case_id),
    file_name         TEXT NOT NULL,
    hash_value        TEXT NOT NULL,
    hash_algorithm    TEXT NOT NULL,
    storage_location  TEXT REFERENCES Location(location_id),
    registered_by     TEXT REFERENCES "User"(user_id),
    registered_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS CustodyRecord (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        TEXT NOT NULL REFERENCES Evidence(asset_id),
    from_custodian  TEXT NOT NULL REFERENCES "User"(user_id),
    to_custodian    TEXT NOT NULL REFERENCES "User"(user_id),
    new_state       TEXT NOT NULL,
    timestamp       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS AuditLog (
    case_id        TEXT NOT NULL REFERENCES "Case"(case_id),
    sequence       INTEGER NOT NULL,
    entry_data     TEXT NOT NULL,
    timestamp      TEXT NOT NULL,
    previous_hash  TEXT NOT NULL,
    entry_hash     TEXT NOT NULL,
    PRIMARY KEY (case_id, sequence)
);

-- WORM triggers: block every UPDATE and DELETE on the two protected tables.
CREATE TRIGGER IF NOT EXISTS custody_no_update
BEFORE UPDATE ON CustodyRecord
BEGIN
    SELECT RAISE(ABORT, 'Records are immutable');
END;

CREATE TRIGGER IF NOT EXISTS custody_no_delete
BEFORE DELETE ON CustodyRecord
BEGIN
    SELECT RAISE(ABORT, 'Records are immutable');
END;

CREATE TRIGGER IF NOT EXISTS auditlog_no_update
BEFORE UPDATE ON AuditLog
BEGIN
    SELECT RAISE(ABORT, 'Records are immutable');
END;

CREATE TRIGGER IF NOT EXISTS auditlog_no_delete
BEFORE DELETE ON AuditLog
BEGIN
    SELECT RAISE(ABORT, 'Records are immutable');
END;
"""


def get_connection(db_file=DB_FILE):
    """Open the database and make sure all tables and triggers exist."""
    try:
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row          # rows behave like dictionaries
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)
        return conn
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not open database '{db_file}': {error}") from error


def demo_worm_protection():
    """Insert sample rows, then show that UPDATE and DELETE are rejected."""
    conn = get_connection(":memory:")           # temporary database in memory
    now = "2026-09-19T09:00:00+00:00"

    conn.execute('INSERT INTO "Case" VALUES (?, ?, ?)', ("CASE-001", now, "Demo case"))
    conn.execute('INSERT INTO "User" VALUES (?, ?, ?)', ("U1", "Officer A", "Investigator"))
    conn.execute('INSERT INTO "User" VALUES (?, ?, ?)', ("U2", "Officer B", "Analyst"))
    conn.execute("INSERT INTO Evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 ("EV-001", "CASE-001", "disk.img", "abc123", "sha256", None, "U1", now))
    conn.execute("INSERT INTO CustodyRecord (asset_id, from_custodian, to_custodian,"
                 " new_state, timestamp) VALUES (?, ?, ?, ?, ?)",
                 ("EV-001", "U1", "U2", "In Transit", now))
    conn.execute("INSERT INTO AuditLog VALUES (?, ?, ?, ?, ?, ?)",
                 ("CASE-001", 0, "Evidence logged", now, "genesis-hash", "entry-hash"))
    conn.commit()
    print("Sample rows inserted into CustodyRecord and AuditLog.\n")

    attacks = [
        "UPDATE AuditLog SET entry_data = 'tampered'",
        "DELETE FROM AuditLog",
        "UPDATE CustodyRecord SET to_custodian = 'U1'",
        "DELETE FROM CustodyRecord",
    ]
    all_blocked = True
    for sql in attacks:
        try:
            conn.execute(sql)
            print(f"  NOT BLOCKED  {sql}")
            all_blocked = False
        except sqlite3.IntegrityError as error:
            print(f"  BLOCKED      {sql}\n               -> {error}")

    conn.close()
    print("\nResult:", "PASS - records are immutable" if all_blocked else "FAIL")
    return all_blocked


if __name__ == "__main__":
    demo_worm_protection()
