"""
main.py - The terminal menu for OCTA-CoC.

This file holds no business logic. It asks the questions, calls the functions
in the other modules, and prints the answers. Every action is wrapped in error
handling, so a wrong file name or a refused transfer prints a clear message
and returns to the menu instead of crashing.

Run it with:
    python main.py
"""

import sqlite3
import sys
from pathlib import Path

import coc_hash_chain as chain
import database
import evidence
import state_machine

MENU = """
==================================================
  OCTA-CoC  -  Chain of Custody Tracker
==================================================
  1. Register new evidence
  2. Transfer custody
  3. View case audit trail
  4. Generate compliance report
  5. Run threshold / alert check
  6. Verify chain integrity
  7. Add a user
  8. Open a case
  9. Load sample data (for a demo)
  0. Exit
"""


def ask(question, required=True):
    """Ask one question. An empty answer to a required question cancels."""
    answer = input(f"  {question}: ").strip()
    if required and not answer:
        raise ValueError("Cancelled - nothing was entered")
    return answer or None


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def action_register_evidence(conn):
    """1. Register new evidence."""
    case_id = ask("Case ID")
    evidence_id = ask("Evidence ID")
    file_path = ask("Path to the evidence file")
    custodian_id = ask("Your user ID (custodian)")
    location_id = ask("Storage location ID", required=False)
    evidence_type = ask("Evidence type (e.g. Disk image)", required=False)
    device_type = ask("Device type (e.g. Laptop)", required=False)

    fingerprint = evidence.register_evidence(
        conn, case_id, evidence_id, file_path, custodian_id,
        location_id=location_id, evidence_type=evidence_type,
        device_type=device_type)

    print(f"\n  Registered {evidence_id} under {case_id}")
    print(f"  SHA-256: {fingerprint}")
    print("  Audit entry written and anchored.")


def action_transfer_custody(conn):
    """2. Transfer custody."""
    evidence_id = ask("Evidence ID")
    state, custodian = evidence.current_status(conn, evidence_id)
    allowed = state_machine.allowed_next_states(state)

    print(f"\n  {evidence_id} is currently '{state}', held by {custodian}")
    if not allowed:
        print("  This state is final - the item cannot be moved again.\n")
        return
    print(f"  It may move to: {', '.join(allowed)}\n")

    new_state = ask("New state")
    from_user_id = ask("Releasing custodian ID")
    to_user_id = ask("Receiving custodian ID")
    reason = ask("Reason for the transfer", required=False)

    state_machine.transfer_custody(conn, evidence_id, new_state,
                                   from_user_id, to_user_id, reason=reason)
    print(f"\n  {evidence_id} is now '{new_state}', held by {to_user_id}")


def action_view_audit_trail(conn):
    """3. View case audit trail."""
    case_id = ask("Case ID")
    entries = chain.get_chain(conn, case_id)
    if not entries:
        print("\n  This case has no audit entries yet.\n")
        return

    print(f"\n  Audit trail for {case_id}\n")
    for entry in entries:
        print(f"  #{entry['Sequence']}  {entry['Timestamp']}  [{entry['Result']}]")
        print(f"      {entry['ActionPerformed']}")
        print(f"      user: {entry['UserID']}   evidence: {entry['EvidenceID']}")
        print(f"      previous: {entry['PreviousHash'][:16]}...")
        print(f"      this    : {entry['EntryHash'][:16]}...\n")


def action_generate_report(conn):
    """4. Generate compliance report."""
    print("\n  The PDF report is built in Phase 7 and is not available yet.\n")


def action_check_alerts(conn):
    """5. Run threshold / alert check."""
    print("\n  Threshold alerts are built in Phase 6 and are not available yet.\n")


def action_verify_chain(conn):
    """6. Verify chain integrity."""
    case_id = ask("Case ID")
    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    anchor_ok, anchor_message = chain.verify_against_anchor(conn, case_id)
    print(f"\n  Chain check  : {'PASS' if chain_ok else 'FAIL'} - {chain_message}")
    print(f"  Anchor check : {'PASS' if anchor_ok else 'FAIL'} - {anchor_message}\n")


def action_add_user(conn):
    """7. Add a user."""
    user_id = ask("User ID")
    full_name = ask("Full name")
    role = ask("Role (e.g. Investigator, Analyst, Evidence Custodian)")
    email = ask("Email", required=False)
    dept = ask("Department", required=False)
    phone = ask("Phone number", required=False)

    if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                    (user_id,)).fetchone() is not None:
        raise ValueError(f"User '{user_id}' already exists")

    conn.execute('INSERT INTO "User" (UserID, FullName, Email, Role, Dept, PhoneNo,'
                 ' Status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (user_id, full_name, email, role, dept, phone, "Active"))
    conn.commit()
    print(f"\n  Added {user_id} ({full_name}, {role})\n")


def action_open_case(conn):
    """8. Open a case."""
    case_id = ask("Case ID")
    title = ask("Case title")
    owner_id = ask("Lead investigator's user ID")
    case_number = ask("Case number", required=False)
    investigation_type = ask("Investigation type", required=False)
    description = ask("Description", required=False)

    if conn.execute('SELECT CaseID FROM "Case" WHERE CaseID = ?',
                    (case_id,)).fetchone() is not None:
        raise ValueError(f"Case '{case_id}' already exists")
    if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                    (owner_id,)).fetchone() is None:
        raise ValueError(f"User '{owner_id}' does not exist - add the user first")

    opened_at = chain.now_utc()
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, CaseNumber,'
                 ' CaseDescription, InvestigationType, DateOpened, Status)'
                 " VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')",
                 (case_id, owner_id, title, case_number, description,
                  investigation_type, opened_at))
    conn.commit()
    print(f"\n  Opened {case_id} ({title})")
    print(f"  Genesis hash: {chain.genesis_hash(case_id, opened_at)}\n")


def action_load_sample_data(conn):
    """9. Load sample data, so a demo can start straight away."""
    users = [("U1", "Officer A", "Investigator"),
             ("U2", "Officer B", "Analyst"),
             ("U3", "Officer C", "Evidence Custodian")]
    for user_id, name, role in users:
        if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                        (user_id,)).fetchone() is None:
            conn.execute('INSERT INTO "User" (UserID, FullName, Role, Status)'
                         " VALUES (?, ?, ?, 'Active')", (user_id, name, role))

    if conn.execute("SELECT LocationID FROM Location WHERE LocationID = 'LOC-01'"
                    ).fetchone() is None:
        conn.execute("INSERT INTO Location (LocationID, LocationName, RoomNumber,"
                     " StorageType) VALUES ('LOC-01', 'Evidence Room', 'R3', 'Safe')")
    conn.commit()

    sample_folder = Path(__file__).parent / "mock_evidence"
    sample_folder.mkdir(exist_ok=True)
    sample_file = sample_folder / "sample_disk_image.txt"
    if not sample_file.exists():
        sample_file.write_text("Sample evidence file for OCTA-CoC demonstrations.\n")

    print("\n  Sample data ready:")
    for user_id, name, role in users:
        print(f"    {user_id}  {name}  ({role})")
    print("    LOC-01  Evidence Room")
    print(f"    {sample_file}")
    print("\n  Next: open a case (8), then register evidence (1).\n")


ACTIONS = {
    "1": action_register_evidence,
    "2": action_transfer_custody,
    "3": action_view_audit_trail,
    "4": action_generate_report,
    "5": action_check_alerts,
    "6": action_verify_chain,
    "7": action_add_user,
    "8": action_open_case,
    "9": action_load_sample_data,
}


# ---------------------------------------------------------------------------
# The menu loop
# ---------------------------------------------------------------------------

def run_action(conn, choice):
    """Run one menu action and turn any problem into a readable message."""
    try:
        ACTIONS[choice](conn)
    except (ValueError, RuntimeError) as error:
        print(f"\n  Error: {error}\n")
    except sqlite3.Error as error:
        print(f"\n  Database error: {error}\n")
    except KeyboardInterrupt:
        print("\n\n  Cancelled.\n")
    except Exception as error:                      # never crash the menu
        print(f"\n  Unexpected error: {type(error).__name__}: {error}\n")


def main():
    """Open the database and run the menu until the user exits."""
    try:
        conn = database.get_connection()
    except RuntimeError as error:
        print(f"Could not start: {error}")
        return 1

    print(f"\nDatabase: {database.DB_FILE}")
    while True:
        print(MENU)
        try:
            choice = input("  Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if choice == "0":
            print("\nGoodbye.")
            break
        if choice in ACTIONS:
            run_action(conn, choice)
        else:
            print("\n  Please choose a number from the menu.\n")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
