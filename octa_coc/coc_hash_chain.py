"""
coc_hash_chain.py - Fingerprints (hashes) and the tamper-evident audit chain.

A hash is a file's or a record's digital fingerprint. Change one byte and the
fingerprint changes completely. We use SHA-256, never the broken MD5 or SHA-1.

Two rules from the design note:

    genesis_hash = SHA256("GENESIS|" + CaseID + "|" + DateOpened)
    entry_hash   = SHA256(previous_hash + entry_data + timestamp)

Each case starts from its own genesis hash, so a chain is tied to the case it
belongs to. Every audit entry then stores the fingerprint of the entry before
it, so altering an old entry breaks the links that follow it.

Every new fingerprint is also copied to an anchor file outside the database
(design note 3.1). That catches someone with database access who alters an
entry and recalculates every later fingerprint to hide it.

Run this file directly to see all of it demonstrated:
    python coc_hash_chain.py
"""

import hashlib
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import database

ANCHOR_FILE = Path(__file__).parent / "anchors" / "anchor_log.txt"


def now_utc():
    """Return the current UTC time as text, e.g. 2026-09-23T10:15:30+00:00."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(text):
    """Return the SHA-256 fingerprint of a piece of text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_file(file_path, algorithm="sha256"):
    """Return the fingerprint of a file, read in small pieces so big files fit."""
    if algorithm not in ("sha256", "sha3_256", "blake2b"):
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    digest = hashlib.new(algorithm)
    try:
        with open(file_path, "rb") as evidence_file:
            while True:
                chunk = evidence_file.read(65536)      # 64 KB at a time
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as error:
        raise RuntimeError(f"Could not read evidence file '{file_path}': {error}") from error
    return digest.hexdigest()


def genesis_hash(case_id, date_opened):
    """Return the starting fingerprint of a case's chain."""
    return sha256_text(f"GENESIS|{case_id}|{date_opened}")


def build_entry_data(action, user_id, evidence_id, result):
    """Join an entry's details into one piece of text, ready to be fingerprinted."""
    return f"{action}|{user_id}|{evidence_id}|{result}"


def entry_hash(previous_hash, entry_data, timestamp):
    """Return an entry's own fingerprint: previous + contents + time."""
    return sha256_text(previous_hash + entry_data + timestamp)


# ---------------------------------------------------------------------------
# The anchor file: a copy of each fingerprint kept outside the database.
# ---------------------------------------------------------------------------

def write_anchor(case_id, sequence, hash_value, anchor_file=ANCHOR_FILE):
    """Append one fingerprint to the anchor file."""
    try:
        anchor_file.parent.mkdir(parents=True, exist_ok=True)
        with open(anchor_file, "a", encoding="utf-8") as log:
            log.write(f"{case_id}|{sequence}|{hash_value}\n")
    except OSError as error:
        raise RuntimeError(f"Could not write the anchor file '{anchor_file}': {error}") from error


def read_anchors(case_id, anchor_file=ANCHOR_FILE):
    """Return {sequence: fingerprint} for one case, from the anchor file."""
    anchors = {}
    if not Path(anchor_file).exists():
        return anchors
    with open(anchor_file, encoding="utf-8") as log:
        for line in log:
            parts = line.strip().split("|")
            if len(parts) == 3 and parts[0] == case_id:
                anchors[int(parts[1])] = parts[2]
    return anchors


# ---------------------------------------------------------------------------
# Writing to and checking the chain.
# ---------------------------------------------------------------------------

def add_entry(conn, case_id, action, user_id=None, evidence_id=None,
              result="Success", anchor_file=ANCHOR_FILE):
    """Add one entry to a case's audit chain. Returns (sequence, fingerprint)."""
    last = conn.execute(
        "SELECT Sequence, EntryHash FROM AuditLog WHERE CaseID = ?"
        " ORDER BY Sequence DESC LIMIT 1", (case_id,)).fetchone()

    if last is None:                       # first entry: start from the genesis hash
        case = conn.execute('SELECT DateOpened FROM "Case" WHERE CaseID = ?',
                            (case_id,)).fetchone()
        if case is None:
            raise ValueError(f"Case '{case_id}' does not exist")
        sequence = 0
        previous_hash = genesis_hash(case_id, case["DateOpened"])
    else:
        sequence = last["Sequence"] + 1
        previous_hash = last["EntryHash"]

    timestamp = now_utc()
    entry_data = build_entry_data(action, user_id, evidence_id, result)
    this_hash = entry_hash(previous_hash, entry_data, timestamp)

    try:
        conn.execute(
            "INSERT INTO AuditLog (CaseID, Sequence, UserID, EvidenceID, ActionPerformed,"
            " Timestamp, Result, PreviousHash, EntryHash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (case_id, sequence, user_id, evidence_id, action, timestamp,
             result, previous_hash, this_hash))
        conn.commit()
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not write the audit entry: {error}") from error

    write_anchor(case_id, sequence, this_hash, anchor_file)
    return sequence, this_hash


def get_chain(conn, case_id):
    """Return every audit entry for a case, oldest first."""
    return conn.execute("SELECT * FROM AuditLog WHERE CaseID = ? ORDER BY Sequence",
                        (case_id,)).fetchall()


def verify_chain(conn, case_id):
    """Recalculate the chain. Returns (True, message) or (False, message)."""
    case = conn.execute('SELECT DateOpened FROM "Case" WHERE CaseID = ?',
                        (case_id,)).fetchone()
    if case is None:
        return False, f"Case '{case_id}' does not exist"

    expected_previous = genesis_hash(case_id, case["DateOpened"])
    entries = get_chain(conn, case_id)

    for position, entry in enumerate(entries):
        if entry["Sequence"] != position:
            return False, f"Entry {position} is missing: an entry was removed"
        if entry["PreviousHash"] != expected_previous:
            return False, (f"Entry {entry['Sequence']} does not link to the entry"
                           " before it: the chain was broken")
        entry_data = build_entry_data(entry["ActionPerformed"], entry["UserID"],
                                      entry["EvidenceID"], entry["Result"])
        recalculated = entry_hash(entry["PreviousHash"], entry_data, entry["Timestamp"])
        if recalculated != entry["EntryHash"]:
            return False, f"Entry {entry['Sequence']} was altered after it was written"
        expected_previous = entry["EntryHash"]

    return True, f"Chain is intact ({len(entries)} entries checked)"


def verify_against_anchor(conn, case_id, anchor_file=ANCHOR_FILE):
    """Compare the chain with the anchor file. Returns (True/False, message)."""
    anchors = read_anchors(case_id, anchor_file)
    entries = get_chain(conn, case_id)

    if entries and not anchors:
        return False, "No anchor records found for this case"

    for entry in entries:
        anchored = anchors.get(entry["Sequence"])
        if anchored is None:
            continue                        # newer entry, not anchored yet
        if anchored != entry["EntryHash"]:
            return False, (f"Entry {entry['Sequence']} does not match the anchor file:"
                           " the chain was rewritten")

    for sequence in anchors:
        if sequence >= len(entries):
            return False, f"Entry {sequence} is in the anchor file but missing from the database"

    return True, f"Chain matches the anchor file ({len(anchors)} fingerprints checked)"


# ---------------------------------------------------------------------------
# DEMO - shows the chain working, then being tampered with.
# ---------------------------------------------------------------------------

def rebuild_chain(conn, case_id):
    """ATTACK SIMULATION: recalculate every fingerprint to hide a change.

    This is what someone with full database access could do. It is here only
    to prove the anchor file catches it.
    """
    conn.executescript("DROP TRIGGER IF EXISTS auditlog_no_update;"
                       " DROP TRIGGER IF EXISTS auditlog_no_delete;")
    case = conn.execute('SELECT DateOpened FROM "Case" WHERE CaseID = ?',
                        (case_id,)).fetchone()
    previous_hash = genesis_hash(case_id, case["DateOpened"])
    for entry in get_chain(conn, case_id):
        entry_data = build_entry_data(entry["ActionPerformed"], entry["UserID"],
                                      entry["EvidenceID"], entry["Result"])
        new_hash = entry_hash(previous_hash, entry_data, entry["Timestamp"])
        conn.execute("UPDATE AuditLog SET PreviousHash = ?, EntryHash = ? WHERE LogID = ?",
                     (previous_hash, new_hash, entry["LogID"]))
        previous_hash = new_hash
    conn.commit()


def show_chain(conn, case_id):
    """Print the chain in a readable way (fingerprints shortened to 12 characters)."""
    for entry in get_chain(conn, case_id):
        print(f"  #{entry['Sequence']}  {entry['ActionPerformed']:<22}"
              f"  previous: {entry['PreviousHash'][:12]}..."
              f"  this: {entry['EntryHash'][:12]}...")
    print()


def demo_hash_chain():
    """Demonstrate file fingerprints, the chain, and how tampering is caught."""
    demo_anchor = Path(tempfile.gettempdir()) / "octa_coc_demo_anchor.txt"
    demo_anchor.unlink(missing_ok=True)         # start each demo with a clean file
    conn = database.get_connection(":memory:")  # temporary database in memory
    case_id = "CASE-001"

    print("1. A FILE'S FINGERPRINT\n")
    sample = Path(tempfile.gettempdir()) / "octa_coc_sample_evidence.txt"
    sample.write_text("Evidence file contents")
    print(f"  Original file : {hash_file(sample)}")
    sample.write_text("Evidence file contents.")     # one full stop added
    print(f"  After one dot : {hash_file(sample)}")
    print("  One character changed, and the fingerprint is completely different.\n")
    sample.unlink(missing_ok=True)

    print("2. BUILDING THE CHAIN\n")
    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U1', 'Officer A', 'Investigator')")
    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U2', 'Officer B', 'Analyst')")
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, DateOpened, Status)'
                 " VALUES (?, 'U1', 'Laptop theft', ?, 'Open')", (case_id, now_utc()))
    conn.execute("INSERT INTO Evidence (EvidenceID, CaseID, EvidenceName, CollectionDate,"
                 " HashAlgorithm, HashValue)"
                 " VALUES ('EV-001', ?, 'Seized laptop disk', ?, 'sha256', 'abc123')",
                 (case_id, now_utc()))
    conn.commit()
    date_opened = conn.execute('SELECT DateOpened FROM "Case" WHERE CaseID = ?',
                               (case_id,)).fetchone()["DateOpened"]
    print(f"  Genesis hash for {case_id}:")
    print(f"  {genesis_hash(case_id, date_opened)}\n")

    add_entry(conn, case_id, "Evidence logged", "U1", "EV-001", anchor_file=demo_anchor)
    add_entry(conn, case_id, "Custody transferred", "U1", "EV-001", anchor_file=demo_anchor)
    add_entry(conn, case_id, "Analysis completed", "U2", "EV-001", anchor_file=demo_anchor)
    show_chain(conn, case_id)

    print("3. CHECKING AN UNTOUCHED CHAIN\n")
    print(f"  Chain check  : {verify_chain(conn, case_id)[1]}")
    print(f"  Anchor check : {verify_against_anchor(conn, case_id, demo_anchor)[1]}\n")

    print("4. SOMEONE ALTERS AN ENTRY IN THE DATABASE\n")
    conn.executescript("DROP TRIGGER IF EXISTS auditlog_no_update;")
    conn.execute("UPDATE AuditLog SET ActionPerformed = 'Evidence destroyed'"
                 " WHERE CaseID = ? AND Sequence = 1", (case_id,))
    conn.commit()
    print("  Entry #1 was changed to 'Evidence destroyed'.")
    print(f"  Chain check  : {verify_chain(conn, case_id)[1]}\n")

    print("5. THE ATTACKER RECALCULATES THE WHOLE CHAIN TO HIDE IT\n")
    rebuild_chain(conn, case_id)
    chain_ok, chain_message = verify_chain(conn, case_id)
    anchor_ok, anchor_message = verify_against_anchor(conn, case_id, demo_anchor)
    print(f"  Chain check  : {chain_message}")
    print(f"  Anchor check : {anchor_message}\n")

    conn.close()
    demo_anchor.unlink(missing_ok=True)
    passed = chain_ok and not anchor_ok
    print("Result:", "PASS - the chain alone was fooled, the anchor file caught it"
          if passed else "FAIL - the tampering was not detected as expected")
    return passed


if __name__ == "__main__":
    demo_hash_chain()
