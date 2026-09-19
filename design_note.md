# Design Note: Per-Case Genesis Hashing & Chain Integrity Anchoring
**Project:** OCTA-CoC — Automated Digital Forensics Chain-of-Custody Tracker
**Author:** Busola Etim
**Related to:** Month 2 — Cryptographic Layer & Base Core

## 1. Problem

The Month 2 research report defines log-chaining as:

```
entry_hash = SHA256(previous_entry_hash + entry_data + timestamp)
```

with the first entry in a chain linking to "a fixed starting value (a genesis hash)." Left
unspecified, this raises two implementation questions that need to be settled before
Month 3 coding begins:

1. **Is there one genesis hash for the whole system, or one per case?**
2. **What stops someone with database access from rewriting an entire chain — including
   recomputing every downstream hash — so the tampering is internally consistent?**

Both directly affect the `Case` and `Audit Log` entities from the Month 1 ERD, so they
belong in the Month 2 deliverable rather than being discovered mid-Month 3.

## 2. Decision: Genesis hash is per-case, not global

**A single global genesis hash is rejected.** If every case's audit log starts from the
same fixed constant, two problems follow:

- **Cross-case ambiguity.** Two cases opened on the same day could produce colliding
  early-chain structures if entry data is thin, weakening the "this hash uniquely
  identifies this case's history" guarantee that courts and auditors rely on.
- **No cryptographic binding between a case and its own evidence trail.** A global
  genesis says nothing about *which* case a chain belongs to — that association would
  live only in a database column, which is exactly the kind of soft, editable metadata
  the hash chain is supposed to make irrelevant.

**Chosen approach:** derive the genesis hash *from* the case itself:

```
genesis_hash = SHA256(f"GENESIS|{case_id}|{case_creation_timestamp}")
```

This means:
- Each case's chain is cryptographically bound to that case's identity and creation time
  from the first entry onward.
- Two cases can never accidentally or deliberately produce the same chain root.
- The genesis hash can be independently recomputed and checked against the `Case`
  entity's stored `CaseID` and `CreatedAt` fields — it isn't itself a floating secret
  that needs separate protection.

No salt or system secret is mixed in deliberately: the genesis hash's job is
*case-binding*, not confidentiality. Case ID and creation timestamp are already
non-sensitive, queryable fields, so deriving from them keeps the genesis value
independently verifiable by any auditor with read access — a secret-based genesis would
require trusting whoever holds the secret, which works against the "provably unaltered"
goal from the Month 2 report.

## 3. The gap this doesn't close: chain rewriting

Sequential hash-chaining detects a *single altered entry sitting among otherwise
untouched neighbors* — the mismatch propagates forward and is easy to spot. It does
**not**, on its own, detect an attacker who:

1. Has direct database access (not just application access),
2. Alters an old entry, and
3. Recomputes every hash from that point forward to keep the chain internally consistent.

Because the whole chain lives in one place under one party's control, an attacker who
controls that place can regenerate a chain that verifies perfectly against itself. The
Month 2 report's WORM/least-privilege access layer (Section 3) makes this harder — but
it is a *procedural* control (permissions, code paths), not a *cryptographic* one. If it
is ever bypassed — a misconfigured role, a restored backup, an insider with elevated
access — the hash chain by itself provides no independent proof of what the chain looked
like before.

### 3.1 Recommended mitigation: periodic external anchoring

The standard fix (and the one implied by NIST SP 800-86 and by Schneier & Kelsey's
original secure-audit-log model) is to **periodically publish the current chain tip
somewhere outside the system's own write path**, so there is a copy of "what the chain
looked like at time T" that the database owner cannot silently rewrite.

Practical options, roughly in order of implementation cost:

| Option | Mechanism | Cost |
|---|---|---|
| **Append-only external log file** | Write each new chain-tip hash + case ID + timestamp to a separate, write-permission-locked file/log on a different volume or service | Low — fits current Month 2 scope |
| **RFC 3161 trusted timestamp** | Submit the chain tip hash to a Time-Stamping Authority (TSA); receive a signed token proving the hash existed at that time | Medium — needs an external TSA client |
| **Anchor to a public append-only structure** | Periodically publish the chain tip hash to something outside Octagon's control (e.g. a public blockchain or transparency log) | High — likely out of scope for a 6-month internal tool |

**Recommendation for this project:** implement the append-only external log file now
(Month 2), and document RFC 3161 timestamping as a "Phase 2 / production hardening"
recommendation in the final handover report. This satisfies the KPI for "engineering
initiative... beyond baseline criteria" without expanding Month 2's scope.

### 3.2 What this adds to the ERD

- `Case` entity: genesis hash becomes a derivable, checkable value — not a separate
  stored secret.
- `Audit Log` entity: gains an implicit external checkpoint — the anchor log is not a new
  ERD entity, just a mirrored, separately-permissioned append target for each chain tip.

## 4. Summary of decisions

1. Genesis hash = `SHA256("GENESIS|" + case_id + "|" + case_created_at)` — derived, not
   stored as a secret.
2. Log-chaining (as already designed) detects single-point tampering within a chain.
3. Log-chaining alone does **not** detect full chain regeneration by someone with DB
   write access — this is a known, accepted limitation of hash-chaining schemes and is
   addressed procedurally (WORM/least-privilege) and cryptographically (external
   anchoring), not by the chain structure itself.
4. Month 2 deliverable: implement per-case genesis + local append-only anchor log.
   Document RFC 3161 anchoring as a future hardening step.