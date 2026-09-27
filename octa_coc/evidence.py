"""
evidence.py - Booking evidence into the system, and looking it up.

Registering an item does three things in one go:
  1. fingerprints the file (coc_hash_chain.hash_file),
  2. saves the Evidence row,
  3. writes the first audit entry for the case ("Evidence logged").

Evidence rows are never changed after they are written, so an item's current
state and current custodian are worked out from its custody records instead.

Run this file directly to see an item registered end to end:
    python evidence.py
"""

import sqlite3
import tempfile
from pathlib import Path

import coc_hash_chain as chain
import database

FIRST_STATE = "Logged"


def register_evidence(conn, case_id, evidence_id, file_path, custodian_id,
                      location_id=None, evidence_type=None, device_type=None,
                      description=None, collection_location=None,
                      anchor_file=chain.ANCHOR_FILE):
    """Book one evidence item in. Returns its fingerprint."""
    evidence_file = Path(file_path)

    case = conn.execute('SELECT CaseID FROM "Case" WHERE CaseID = ?',
                        (case_id,)).fetchone()
    if case is None:
        raise ValueError(f"Case '{case_id}' does not exist")

    custodian = conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                             (custodian_id,)).fetchone()
    if custodian is None:
        raise ValueError(f"User '{custodian_id}' does not exist")

    already = conn.execute("SELECT EvidenceID FROM Evidence WHERE EvidenceID = ?",
                           (evidence_id,)).fetchone()
    if already is not None:
        raise ValueError(f"Evidence '{evidence_id}' is already registered")

    hash_value = chain.hash_file(evidence_file)          # fingerprint the file
    file_size = evidence_file.stat().st_size
    file_format = evidence_file.suffix.lstrip(".") or None
    collected_at = chain.now_utc()

    try:
        conn.execute(
            "INSERT INTO Evidence (EvidenceID, CaseID, LocationID, EvidenceName,"
            " EvidenceType, Description, DeviceType, CollectionDate,"
            " CollectionLocation, HashAlgorithm, HashValue, FileSize, FileFormat)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, case_id, location_id, evidence_file.name, evidence_type,
             description, device_type, collected_at, collection_location,
             "sha256", hash_value, file_size, file_format))
        conn.commit()
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not save the evidence record: {error}") from error

    chain.add_entry(conn, case_id, "Evidence logged", custodian_id, evidence_id,
                    anchor_file=anchor_file)
    return hash_value


def get_evidence(conn, evidence_id):
    """Return one evidence row, or raise if it is not registered."""
    row = conn.execute("SELECT * FROM Evidence WHERE EvidenceID = ?",
                       (evidence_id,)).fetchone()
    if row is None:
        raise ValueError(f"Evidence '{evidence_id}' does not exist")
    return row


def list_case_evidence(conn, case_id):
    """Return every evidence item registered under one case."""
    return conn.execute("SELECT * FROM Evidence WHERE CaseID = ? ORDER BY EvidenceID",
                        (case_id,)).fetchall()


def current_status(conn, evidence_id):
    """Return (state, custodian) for an item, from its latest custody record."""
    get_evidence(conn, evidence_id)                      # raises if unknown
    last = conn.execute(
        "SELECT NewState, ToUserID FROM CustodyRecord WHERE EvidenceID = ?"
        " ORDER BY CustodyID DESC LIMIT 1", (evidence_id,)).fetchone()
    if last is not None:
        return last["NewState"], last["ToUserID"]

    # No transfers yet: the item is still with whoever logged it.
    logged = conn.execute(
        "SELECT UserID FROM AuditLog WHERE EvidenceID = ?"
        " AND ActionPerformed = 'Evidence logged' ORDER BY Sequence LIMIT 1",
        (evidence_id,)).fetchone()
    return FIRST_STATE, (logged["UserID"] if logged else None)


def verify_evidence_file(conn, evidence_id, file_path):
    """Re-fingerprint a file and compare it with the one stored at registration."""
    stored = get_evidence(conn, evidence_id)["HashValue"]
    current = chain.hash_file(file_path)
    if current == stored:
        return True, "File matches the fingerprint taken at registration"
    return False, "File does NOT match the fingerprint taken at registration"


# ---------------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------------

def demo_register_evidence():
    """Register one item, then show the record, the chain and a file check."""
    demo_anchor = Path(tempfile.gettempdir()) / "octa_coc_demo_anchor.txt"
    demo_anchor.unlink(missing_ok=True)
    conn = database.get_connection(":memory:")           # temporary database
    case_id = "CASE-001"

    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U1', 'Officer A', 'Investigator')")
    conn.execute("INSERT INTO Location (LocationID, LocationName, StorageType)"
                 " VALUES ('LOC-01', 'Evidence Room', 'Safe')")
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, DateOpened, Status)'
                 " VALUES (?, 'U1', 'Laptop theft', ?, 'Open')",
                 (case_id, chain.now_utc()))
    conn.commit()

    sample = Path(tempfile.gettempdir()) / "octa_coc_seized_laptop.img"
    sample.write_text("Contents of the seized laptop image")

    print("1. REGISTERING THE EVIDENCE\n")
    fingerprint = register_evidence(conn, case_id, "EV-001", sample, "U1",
                                    location_id="LOC-01", evidence_type="Disk image",
                                    device_type="Laptop",
                                    description="Full image of the laptop drive",
                                    collection_location="Head office",
                                    anchor_file=demo_anchor)
    item = get_evidence(conn, "EV-001")
    print(f"  Evidence ID : {item['EvidenceID']}")
    print(f"  File        : {item['EvidenceName']}  ({item['FileSize']} bytes)")
    print(f"  Algorithm   : {item['HashAlgorithm']}")
    print(f"  Fingerprint : {fingerprint}")
    print(f"  Stored at   : {item['LocationID']}\n")

    print("2. THE FIRST AUDIT ENTRY\n")
    for entry in chain.get_chain(conn, case_id):
        print(f"  #{entry['Sequence']}  {entry['ActionPerformed']}"
              f"  by {entry['UserID']}  on {entry['EvidenceID']}")
        print(f"       previous: {entry['PreviousHash'][:16]}...")
        print(f"       this    : {entry['EntryHash'][:16]}...")
    genesis = chain.genesis_hash(case_id, conn.execute(
        'SELECT DateOpened FROM "Case" WHERE CaseID = ?', (case_id,)).fetchone()[0])
    first = chain.get_chain(conn, case_id)[0]
    print(f"\n  Entry #0 links to the case genesis hash: {first['PreviousHash'] == genesis}\n")

    print("3. CURRENT STATUS\n")
    state, custodian = current_status(conn, "EV-001")
    print(f"  State     : {state}")
    print(f"  Custodian : {custodian}\n")

    print("4. CHECKING THE FILE LATER\n")
    print(f"  Untouched file : {verify_evidence_file(conn, 'EV-001', sample)[1]}")
    sample.write_text("Contents of the seized laptop image (edited)")
    file_ok, file_message = verify_evidence_file(conn, "EV-001", sample)
    print(f"  Edited file    : {file_message}\n")

    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    print(f"  Chain check : {chain_message}")

    conn.close()
    sample.unlink(missing_ok=True)
    demo_anchor.unlink(missing_ok=True)
    passed = chain_ok and not file_ok and state == FIRST_STATE
    print("\nResult:", "PASS - evidence registered, chained and checkable"
          if passed else "FAIL - something did not behave as expected")
    return passed


if __name__ == "__main__":
    demo_register_evidence()
