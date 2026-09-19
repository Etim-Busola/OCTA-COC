# OCTA-CoC — Build Spec (Agent Reference)
**Type:** Standalone Python CLI application. NOT a web app — no HTTP server, no browser,
no Flask/FastAPI/Streamlit. Single process, run via `python main.py` in a terminal.

**Project:** Automated Digital Forensics Chain-of-Custody Tracker for Octagon
Cybersecurity Nig. Ltd. Internal tool for logging evidence, tracking custody transfers,
and producing tamper-evident PDF audit reports.

---

## 1. Non-negotiable constraints

- No web framework of any kind. No server, no localhost, no browser rendering.
- Interface is a terminal menu loop using `input()`/`print()` only.
- Database is a local SQLite file (`octa_coc.db`), no networked DB.
- `AuditLog` and `CustodyRecord` tables must be INSERT/READ only — UPDATE and DELETE
  must fail at the database level (via SQLite triggers, since SQLite has no
  role-based GRANT/REVOKE), not just be "avoided" in application code.
- Hashing: SHA-256 only (or SHA-3/BLAKE2 as alternates) — never MD5/SHA-1.
- Every custody transfer requires two custodian IDs (dual-authorization) before it
  is written.
- Genesis hash for each case's audit chain must be derived from `SHA256("GENESIS|" +
  case_id + "|" + case_created_at)` — never a shared global constant.
- Python 3.11+, PEP 8 compliant, modular (one concern per file), thorough exception
  handling — this is scored directly in the project's KPIs.

## 2. File structure

```
octa_coc/
├── main.py              # CLI entry point — menu loop only, no business logic
├── database.py          # Schema, connection handling, WORM triggers
├── coc_hash_chain.py    # Already built — hashing + chain logic (see below)
├── evidence.py          # register_evidence(), evidence lookups
├── state_machine.py     # Custody state transitions + validation
├── alerts.py            # Threshold checks, access-violation logging
├── reporting.py         # PDF generation via ReportLab
├── reports/             # Output folder for generated PDFs
└── mock_evidence/        # Sample files for demo/test runs (non-destructive)
```

## 3. Already built — do not rewrite, only integrate

`coc_hash_chain.py` exists and is tested. It currently stores ledger entries
**in-memory** (`CaseLedger._entries` is a Python list). The only required change in
Phase 2 is to back `CaseLedger` with real SQLite reads/writes instead of the in-memory
list — the hashing and verification logic itself should not change.

Existing public API to preserve:
```python
hash_file(path, algorithm="sha256", chunk_size=65536) -> str
genesis_hash(case_id, case_created_at) -> str
CaseLedger(case_id, case_created_at=None, anchor_log_path=None)
CaseLedger.add_entry(entry_data: dict, timestamp=None) -> LedgerEntry
CaseLedger.verify() -> VerificationResult
CaseLedger.export() -> list[dict]
verify_against_anchor(ledger, anchor_log_path) -> bool
```

## 4. Database schema (`database.py`)

Six entities (from Month 1 ERD):

| Table | Key columns | Mutability |
|---|---|---|
| `Case` | case_id (PK), created_at, description | Insert + Read |
| `Evidence` | asset_id (PK), case_id (FK), hash_value, hash_algorithm, storage_location | Insert + Read |
| `CustodyRecord` | id (PK), asset_id (FK), from_custodian, to_custodian, timestamp | **Insert + Read only** |
| `AuditLog` | sequence (PK per case), case_id (FK), entry_data, timestamp, previous_hash, entry_hash | **Insert + Read only** |
| `User` | user_id (PK), name, role | Insert + Read |
| `Location` | location_id (PK), description | Insert + Read |

WORM enforcement: create `BEFORE UPDATE` and `BEFORE DELETE` triggers on
`CustodyRecord` and `AuditLog` that `RAISE(ABORT, 'Records are immutable')`.

Provide a small `test_worm.py` (or inline test in `database.py` under
`if __name__ == "__main__":`) that inserts a row, attempts an UPDATE, and asserts it
raises an error.

## 5. Business logic modules

### `evidence.py`
```python
def register_evidence(case_id: str, asset_id: str, file_path: str,
                       custodian_id: str, location: str) -> None:
    """
    Hashes the file (coc_hash_chain.hash_file), inserts an Evidence row,
    and writes the first AuditLog entry via CaseLedger for this case
    (state = 'Logged').
    """
```

### `state_machine.py`
Define allowed transitions explicitly — reject anything not listed:
```python
TRANSITIONS = {
    "Logged": ["In Transit"],
    "In Transit": ["Under Analysis", "Secured Storage"],
    "Under Analysis": ["Secured Storage", "In Transit"],
    "Secured Storage": ["Disposed", "In Transit"],
    "Disposed": [],
}

def transfer_custody(asset_id: str, new_state: str,
                      from_custodian: str, to_custodian: str) -> None:
    """
    Validates the transition against TRANSITIONS, requires both custodian
    IDs (dual-authorization), inserts a CustodyRecord row, and appends an
    AuditLog entry via CaseLedger.
    """
```

### `alerts.py`
```python
def check_thresholds(hours_limit: int = 48) -> list[dict]:
    """Return all assets currently 'In Transit' longer than hours_limit."""

def log_access_violation(user_id: str, asset_id: str) -> None:
    """Writes an AuditLog entry recording an unauthorized access attempt."""
```

### `reporting.py`
```python
def generate_report(case_id: str) -> str:
    """
    Pulls the full AuditLog + CustodyRecord trail for case_id, renders a
    PDF via ReportLab to reports/{case_id}_report.pdf, embeds the current
    CaseLedger.verify() result on the report, returns the file path.
    """
```

## 6. `main.py` — CLI menu

Thin wrapper only — no business logic here, just calling the functions above and
handling `input()`/`print()`.

```
1. Register new evidence      -> evidence.register_evidence(...)
2. Transfer custody            -> state_machine.transfer_custody(...)
3. View case audit trail       -> print CaseLedger(case_id).export()
4. Generate compliance report  -> reporting.generate_report(case_id)
5. Run threshold/alert check   -> alerts.check_thresholds()
6. Verify chain integrity      -> CaseLedger(case_id).verify()
0. Exit
```

Wrap every menu action in try/except, print a clean error message on failure
(e.g. invalid state transition, file not found), and return to the menu — never
let an unhandled exception crash the loop.

## 7. Build order (do not skip ahead)

1. `database.py` + WORM trigger test — confirm UPDATE/DELETE fail.
2. Re-point `CaseLedger` to SQLite instead of in-memory list; re-run the existing
   tamper-detection demo against the DB file directly.
3. `evidence.py` — register one evidence item end-to-end, confirm AuditLog entry #0
   is written correctly.
4. `state_machine.py` — transfer custody twice, confirm chain has 3 entries and
   `verify()` passes.
5. `main.py` — wire the menu to the above; full manual session should work with no
   crashes.
6. `alerts.py` — threshold check against mock data with an old "In Transit" timestamp.
7. `reporting.py` — generate one PDF, visually confirm it's readable.
8. Pen-test pass: attempt raw SQL UPDATE/DELETE, attempt an invalid state transition
   via `transfer_custody()` directly — confirm both are rejected. Document results.

## 8. Reference materials already on file
- `genesis_hash_design_note.md` — genesis hash derivation rationale + external
  anchoring rationale (Section 3 covers the chain-rewrite threat model, relevant to
  Phase 2 above).
- `coc_hash_chain.py` — working, tested crypto core (Section 3 of this doc).