"""
database.py - Creates the OCTA-CoC SQLite database and its tables.

The tables follow the project ERD: User, Case, Evidence, Location,
CustodyRecord and AuditLog.

Two changes were made to the ERD, both explained in the project document:
  1. AuditLog gained Sequence, PreviousHash and EntryHash. These hold the
     hash chain from the design note - without them there is nowhere to
     store the link between one entry and the next. It also gained CaseID,
     which the ERD drew as a relationship but did not list as a column.
  2. Evidence has no CurrentStatus column. An item's state is taken from its
     latest CustodyRecord (NewState) instead, so evidence rows never change.

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
CREATE TABLE IF NOT EXISTS "User" (
    UserID            TEXT PRIMARY KEY,
    FullName          TEXT NOT NULL,
    Email             TEXT,
    Role              TEXT NOT NULL,
    Dept              TEXT,
    PhoneNo           TEXT,
    DigitalSignature  TEXT,
    Status            TEXT DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS Location (
    LocationID    TEXT PRIMARY KEY,
    LocationName  TEXT NOT NULL,
    Address       TEXT,
    RoomNumber    TEXT,
    StorageType   TEXT
);

CREATE TABLE IF NOT EXISTS "Case" (
    CaseID             TEXT PRIMARY KEY,
    UserID             TEXT REFERENCES "User"(UserID),
    CaseTitle          TEXT NOT NULL,
    CaseNumber         TEXT,
    CaseDescription    TEXT,
    InvestigationType  TEXT,
    DateOpened         TEXT NOT NULL,     -- used to build the genesis hash
    Status             TEXT DEFAULT 'Open'
);

CREATE TABLE IF NOT EXISTS Evidence (
    EvidenceID          TEXT PRIMARY KEY,
    CaseID              TEXT NOT NULL REFERENCES "Case"(CaseID),
    LocationID          TEXT REFERENCES Location(LocationID),
    EvidenceName        TEXT NOT NULL,
    EvidenceType        TEXT,
    Description         TEXT,
    DeviceType          TEXT,
    CollectionDate      TEXT NOT NULL,
    CollectionLocation  TEXT,
    HashAlgorithm       TEXT NOT NULL,
    HashValue           TEXT NOT NULL,
    FileSize            INTEGER,
    FileFormat          TEXT
);

CREATE TABLE IF NOT EXISTS CustodyRecord (
    CustodyID           INTEGER PRIMARY KEY AUTOINCREMENT,
    EvidenceID          TEXT NOT NULL REFERENCES Evidence(EvidenceID),
    FromUserID          TEXT NOT NULL REFERENCES "User"(UserID),
    ToUserID            TEXT NOT NULL REFERENCES "User"(UserID),
    NewState            TEXT NOT NULL,    -- the item's state after this transfer
    TransferDate        TEXT NOT NULL,
    TransferTime        TEXT NOT NULL,
    TransferReason      TEXT,
    Signature           TEXT,
    VerificationStatus  TEXT
);

CREATE TABLE IF NOT EXISTS AuditLog (
    LogID              INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseID             TEXT NOT NULL REFERENCES "Case"(CaseID),
    Sequence           INTEGER NOT NULL,  -- entry number in the case: 0, 1, 2...
    UserID             TEXT REFERENCES "User"(UserID),
    EvidenceID         TEXT REFERENCES Evidence(EvidenceID),
    ActionPerformed    TEXT NOT NULL,
    Timestamp          TEXT NOT NULL,
    IPAddress          TEXT,
    DeviceInformation  TEXT,
    Result             TEXT,
    PreviousHash       TEXT NOT NULL,     -- fingerprint of the entry before
    EntryHash          TEXT NOT NULL,     -- this entry's own fingerprint
    UNIQUE (CaseID, Sequence)
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

    conn.execute('INSERT INTO "User" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 ("U1", "Officer A", "a@octagon.ng", "Investigator",
                  "Forensics", "08010000001", "sig-A", "Active"))
    conn.execute('INSERT INTO "User" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 ("U2", "Officer B", "b@octagon.ng", "Analyst",
                  "Forensics", "08010000002", "sig-B", "Active"))
    conn.execute("INSERT INTO Location VALUES (?, ?, ?, ?, ?)",
                 ("LOC-01", "Evidence Room", "12 Lagos Road", "R3", "Safe"))
    conn.execute('INSERT INTO "Case" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 ("CASE-001", "U1", "Laptop theft", "OC/2026/001",
                  "Stolen company laptop", "Internal", now, "Open"))
    conn.execute("INSERT INTO Evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 ("EV-001", "CASE-001", "LOC-01", "Seized laptop disk", "Disk image",
                  "Full image of the laptop drive", "Laptop", now, "Head office",
                  "sha256", "abc123", 512000, "dd"))
    conn.execute("INSERT INTO CustodyRecord (EvidenceID, FromUserID, ToUserID, NewState,"
                 " TransferDate, TransferTime, TransferReason, Signature,"
                 " VerificationStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 ("EV-001", "U1", "U2", "In Transit", "2026-09-19", "09:30",
                  "Taken to the lab", "sig-A", "Verified"))
    conn.execute("INSERT INTO AuditLog (CaseID, Sequence, UserID, EvidenceID,"
                 " ActionPerformed, Timestamp, IPAddress, DeviceInformation, Result,"
                 " PreviousHash, EntryHash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 ("CASE-001", 0, "U1", "EV-001", "Evidence logged", now,
                  "127.0.0.1", "Lab workstation", "Success", "genesis-hash", "hash-0"))
    conn.commit()
    print("Sample rows inserted into CustodyRecord and AuditLog.\n")

    attacks = [
        "UPDATE AuditLog SET ActionPerformed = 'tampered'",
        "DELETE FROM AuditLog",
        "UPDATE CustodyRecord SET ToUserID = 'U1'",
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
