# Terminology Standard (v2)

This is the canonical vocabulary for the SOC Playbook Handbook. Every second-pass reviewer must enforce these exact terms and flag (not silently ignore) anywhere the manuscript drifts from them.

## Case disposition / closure outcomes

Use exactly these nine, exactly as spelled here, nothing else:

- True Positive
- False Positive
- Benign Positive
- Expected Activity
- Insufficient Evidence
- Duplicate
- Test Activity
- Policy Violation
- Incident

Do not introduce synonyms ("True Positive - Benign", "Non-Issue", "Confirmed Malicious") for these. If a chapter needs a nuance not covered by this list, it must argue for adding to this canonical list rather than inventing a local variant.

## Depth markers

Exactly this format, bold, bracketed, all caps, on their own line:

`**[STAKEHOLDER]**`, `**[ANALYST]**`, `**[ENGINEERING]**`, `**[MANAGEMENT]**`

Not `[Stakeholder]`, not `**STAKEHOLDER:**`, not `(Stakeholder view)`.

## Severity scale

Exactly five levels, in this order: Informational, Low, Medium, High, Critical.

## Escalation / approval tiers

**Correction (second pass, applied book-wide):** the original v1 standard specified "L1, L2, L3" as the canonical escalation-tier label. That was wrong - it described a convention the book never actually adopted. An independent book-wide audit found "Tier 1 / Tier 2 / Tier 3" used consistently across 88 files (the dominant, pre-existing convention from the original authoring pass) versus "L1/L2/L3" in only 25 files (introduced by second-pass reviewers correctly-but-mistakenly following the flawed standard as written). Rather than rewrite the 88-file majority, the standard itself is corrected here to match reality, and the 25-file minority has been converted to match.

Canonical form: **Tier 1, Tier 2, Tier 3, SOC Manager, Client, CISO** for escalation-path narrative text ("escalate to Tier 2", "Tier 3 analyst", "Tier 1 handles..."). Named roles (SOC Lead, IR Lead, Identity Team, Endpoint Team, Application Owner, etc.) appear as additional approval-matrix rows/columns where relevant - this was already consistent practice and remains unchanged.

## Preferred term per concept (avoid unnecessary synonym drift)

| Use this | Not this |
|---|---|
| Password Spraying | Password Spray, Spray Attack, Credential Spray, Account Spray |
| Brute Force | Brute-Forcing, Credential Brute Force (unless distinguishing from web-layer brute force explicitly) |
| Kerberoasting | Kerberos Roasting, Service Ticket Roasting |
| AS-REP Roasting | ASREP Roasting, AS-REQ Roasting |
| Pass the Hash | Pass-the-Hash, PtH (PtH acceptable as a parenthetical abbreviation on first use only) |
| Pass the Ticket | Pass-the-Ticket, PtT |
| Business Email Compromise (BEC) | Email Compromise, CEO Fraud (CEO Fraud only inside the Executive Impersonation playbook, as a named sub-case) |
| Indicator of Compromise (IOC) | Indicator, IoC (lowercase o) |
| Logon Type | Login Type |
| Event ID | EventID, Event Code |
| MITRE ATT&CK | MITRE ATTACK, Att&ck, ATT&CK (bare, on first use per chapter spell out MITRE ATT&CK) |
| Data Loss Prevention (DLP) | Data Leak Prevention |

## Known inconsistency requiring a real fix, not just documentation: Playbook IDs

The v1 build let each category-writing agent invent its own ID prefix convention independently. The result, confirmed directly against BOOK-INDEX.md, is genuinely inconsistent:

- Identity/AD: mixes `IAM-AUTH-04`, `PB-IAM-BF-001`, `IAM-AUTH-004`, `ID-AD-01`, `AD-ACC-06`, `IAM-AD-014`
- Kerberos: mixes `PB-IAM-KRB-01`, `AD-KRB-003`, `PB-AD-KRB-04`, `IDN-KRB-11`
- Endpoint: mixes `PB-END-EXE-001`, `PB-EXEC-014`, `EP-EXEC-004`, `EP-EXE-014`, `END-EXE-014`
- Email: mostly `EML-*` and `PB-EMAIL-*` inconsistently
- Cloud: mostly `PB-CLD-*` and `CLD-17.*` (dot-notation vs dash-notation)
- AI Security: mostly `AISEC-*`, `AI-SEC-*`, `PB-AI-18-*` (three different conventions in one category)

**This is not cosmetic.** Inconsistent IDs break the "See Playbook PB-ID-017" cross-reference system the second pass is supposed to add, and they make the coverage matrix harder to audit.

**Assigned fix:** the dedicated Cross-Reference & Playbook-ID System agent (global pass) defines one scheme:

`<DOMAIN>-<NNN>` where DOMAIN is one of `IAM` (Identity/AD, both account and Kerberos playbooks), `EP` (Endpoint), `NW` (Network), `WEB`, `EML` (Email), `CLD` (Cloud), `AI` (AI Security), `INS` (Insider Threat), `RAN`/`MAL`/`EXF` (the three non-AI master playbooks; the AI master playbook keeps an `AI-` id), and `NNN` is a zero-padded sequential number unique within that domain, assigned in the order the playbook already appears in BOOK-INDEX.md (so numbering stays stable and predictable).

That agent must produce `PLAYBOOK-ID-MIGRATION-MAP.md` (old ID -> new ID, one row per playbook) before changing a single file, then apply the new IDs, then verify no file was missed.
