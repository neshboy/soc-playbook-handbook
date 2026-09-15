# Response: The Stakeholder Notification Chain and Bridge Call Discipline

Ransomware incidents die or survive on communication discipline, not tooling. The moment encryption is confirmed, the technical response and the notification response run in parallel tracks, and the incident commander (IC) owns both. Get the notification chain wrong - too slow, too loud, wrong sequence - and you create a second incident: a legal, regulatory, or reputational one that outlives the malware.

## Who Gets Called, and In What Order

Notification is not a broadcast. It is a sequenced pull of specific people into specific decisions.

| Order | Stakeholder | Why they're pulled in now | What they own |
|---|---|---|---|
| 1 | Incident Commander | Declares the incident, opens the bridge | Overall response authority, single source of truth |
| 2 | Legal Counsel (internal + outside breach counsel if retained) | Privilege needs to attach before anyone writes anything down | Attorney-client privilege over investigation notes, regulatory clock, law enforcement contact, insurer notification |
| 3 | Senior Management / Executive Sponsor (CISO, CIO, sometimes CEO) | Needs situational awareness before it hears about it from a business unit or the press | Resourcing, external comms approval, ultimately the pay/not-pay call |
| 4 | Business / Application Owners for affected systems | They know the real business impact of downtime, IT often doesn't | Impact statements, RTO/RPO tolerance, prioritization input |
| 5 | Backup / Infrastructure Teams | Restore feasibility has to be assessed before anyone promises a recovery time | Backup integrity verification, restore sequencing, isolation of backup infrastructure |

**[STAKEHOLDER]** - Senior management's first question on the bridge is never "how did this happen," it's "are we still operating and are we going to get sued for it." Answer that first, in plain terms, before touching root cause.

**[MANAGEMENT]** - Notification timing should be pre-defined in the IR plan, not improvised live. A common working threshold: legal and executive sponsor are notified the moment ransomware is *suspected* (not confirmed) if it affects more than a single endpoint, or immediately regardless of scope if evidence of file encryption (T1486) or backup/shadow-copy deletion (T1490) is present, since that combination changes the legal and business calculus instantly.

## Running the Bridge

The bridge call is the incident's nervous system. It needs a rhythm or it becomes a shouting match.

- **IC opens every call the same way**: current confirmed facts, current unknowns, current decisions needed, in that order. Facts before speculation, always.
- **A dedicated scribe** (not the IC, not an analyst mid-investigation) keeps a running decision log - timestamped, one line per decision, who made it, what authority they had to make it. Legal will ask for this log later; treat it as a legal artifact from minute one.
- **Cadence**: 30-minute standups in the first few hours, stretching to hourly or twice-daily once containment holds. Publish the cadence explicitly so people stop pinging the IC between updates.
- **Speaking order matters**: technical findings from the analyst/engineering track, then legal risk framing, then business impact, then decisions. Business owners should not hear raw forensic speculation before it's been triaged - "we think" statements from an analyst mid-triage, repeated verbatim by an executive to a regulator, is how false statements happen.
- **One person authorizes external statements.** Nobody on the bridge talks to a customer, a journalist, or a regulator off-script. That authority sits with legal and the executive sponsor jointly, never with IT or SOC.

**[ANALYST]** - What you hand up the chain is evidence and confidence level, not conclusions. "Encryption confirmed on 40 hosts in the Finance VLAN, ransom note present, no evidence of exfiltration yet, still validating" is usable. "It's a ransomware attack and they definitely stole data" from an analyst two hours into triage is not - and it will get quoted back to you if it's wrong.

## Backup and Infrastructure: the Line Nobody Should Cross Early

Business owners will ask for a restore ETA on the first call. Do not give one. **[ENGINEERING]** - Backup/infrastructure teams must verify backup integrity (last known-good clean point, isolation from the compromised network segment, confirmation backups weren't themselves encrypted or deleted) before any restore timeline goes upward on the bridge. Restoring onto still-compromised infrastructure or from a backup taken after initial access is the single most common cause of reinfection in ransomware recoveries.

## A Working Notification Log Template

```
Incident: RAN-2026-0914-MERIDIAN
Time (UTC) | Party Notified        | Method     | Notified By | Ack'd By
14:02      | Legal Counsel (J.Rai) | Phone      | IC (M.Osei)  | Y
14:11      | CISO (D. Ferro)       | Bridge     | IC           | Y
14:35      | App Owner - ERP (S.Klein) | Bridge | IC           | Y
15:10      | Backup Team Lead (T.Nakamura) | Bridge | IC       | Y
```

Every row needs an ack, not just a send - "notified" and "confirmed aware" are legally different states once discovery or regulatory timelines get scrutinized.
