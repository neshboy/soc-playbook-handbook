# INS-012: Bulk Deletion of Data

## Playbook ID & Name
**INS-012 — Bulk Deletion of Data (Anomalous Mass Deletion / Data Destruction by an Insider)**

## Business Risk
**[STAKEHOLDER]** - Every other playbook in this category worries about data leaving the building. This one worries about data disappearing entirely. A disgruntled employee, a soon-to-be-former admin, or someone trying to cover their tracks after a policy violation doesn't need to exfiltrate anything if they can just delete the evidence — customer records, project files, financial history, an entire mailbox, a database table. The damage model is different from a download: it's availability and integrity, not confidentiality, and it's frequently combined with an attempt to also wipe the backups so there's nothing to restore from. Decision owner for account action is HR/Legal/data owner, same as elsewhere in this category, but the recovery decision (can we restore, from what point, at what cost) sits with IT/backup ownership and needs to start in parallel with the investigation, not after it.

## Severity / Priority Default
**High** by default — deletion is harder to walk back than a download, and every hour of delay narrows the recovery window (backup retention, recycle bin/soft-delete expiry, version history purge cycles). Escalates to **Critical** when backups, shadow copies, or version history are also targeted (this is the "they meant to make it unrecoverable" signal), when the deleted content is production/regulated data, or when the identity involved has a resignation/termination event within the surrounding 30 days.

## MITRE ATT&CK Techniques
- **T1485** — Data Destruction (Impact) — the primary technique for this playbook: deleting files, records, or objects in bulk to render them unrecoverable through normal means, distinct from encrypting them (T1486) or attacking only the recovery path (T1490)
- **T1490** — Inhibit System Recovery (deletion of shadow copies, backup catalogs, version history, or retention/legal-hold configuration — the "make it unrecoverable" step, and the strongest single signal that this is sabotage rather than a mistake)
- **T1531** — Account Access Removal (when the deletion spree extends to user accounts, mailboxes, or group objects — denying access rather than, or in addition to, destroying content)
- **T1078.002 / T1078.004** — Valid Accounts: Domain Accounts / Cloud Accounts (the deletion is almost always performed with a legitimate, often privileged, credential the person already had — there's usually no exploit here)
- **T1562.001** — Impair Defenses: Disable or Modify Tools (disabling audit logging, mailbox auditing, versioning, or a retention/legal-hold policy immediately before or during the deletion, to reduce what's recoverable and what's logged)

T1485 covers the deletion of the primary data itself; use T1490/T1531/T1562.001 for the specific aggravating behaviors (recovery-path destruction, access denial, log tampering) that often ride alongside it.

## Trigger / Detection Logic Summary
Fires primarily as a volumetric/behavioral detection: a single identity's delete-operation count or delete-byte-equivalent in a rolling window (typically 15-60 minutes) exceeds a multiple of that identity's own baseline, or a fixed ceiling for low-baseline accounts. In parallel, run discrete high-confidence rules for specific high-risk actions regardless of volume threshold: shadow copy deletion (`vssadmin delete shadows`), backup catalog deletion (`wbadmin delete catalog`/`delete systemstatebackup`), a mailbox `HardDelete`/`Purge` action, a `DROP TABLE`/`TRUNCATE TABLE` against a production database, or a batch `DeleteObjects` call against a cloud storage bucket. A single "delete shadow copies" event is worth alerting on by itself — you don't need volume for that one, it's a red flag regardless of count.

## Required Log Sources & Event IDs
| Source | Event ID / Field Source | Purpose |
|---|---|---|
| Windows Security (file server / DFS) | **4663** (object access attempt, Accesses = DELETE or WriteData/DeleteChild), **4660** (an object was deleted — correlate to the preceding 4663 via Handle ID to recover the object name), **4656** (handle requested) | Bulk file/folder delete on shares |
| Windows Security (Domain Controller) | **4726** (a user account was deleted) | Confirms account-deletion component if present (T1531) |
| Sysmon | **Event ID 23** (FileDelete, when configured to archive), **Event ID 1** (Process Create — captures `vssadmin`, `wbadmin`, `Remove-Item -Recurse`, `robocopy /mir`, `aws s3 rm --recursive` command lines) | Local delete evidence and the tooling used to do it |
| M365 Unified Audit Log (Microsoft Purview Audit) | Operations such as `FileDeleted`, `FileVersionsAllDeleted`, `HardDelete`, `FolderDeleted`, `SiteDeleted` (SharePoint/OneDrive); mailbox audit `HardDelete`, `SoftDelete`, `MoveToDeletedItems`, `Purge` | Cloud-native bulk delete, including mailbox destruction |
| Cloud storage audit (AWS CloudTrail, Azure Storage logs) | `DeleteObject`, `DeleteObjects` (batch), `DeleteBucket`, lifecycle-policy changes | Bulk object deletion in cloud storage |
| Database audit logs | `DROP TABLE`, `TRUNCATE TABLE`, DELETE row-count spikes, backup-job deletion | Structured-data destruction |
| Backup/recovery platform | Backup job/catalog deletion, retention policy change, shadow copy removal | Confirms whether recovery path was also attacked (T1490) |
| DLP/CASB | Mass-delete policy trigger, where the platform supports one | Purpose-built detection, often the primary trigger |
| EDR | Process creation, command-line arguments, script execution | Confirms method and intent (scripted vs manual) |

## Key Fields to Inspect
**[ANALYST]**
- Identity performing the deletion — is it the data owner, an admin with legitimate delete rights, or someone whose access was only recently granted or escalated
- Object type deleted: files/folders, mailbox items, database rows/tables, cloud objects, or accounts/groups
- Delete count and rate versus that identity's own historical baseline — one person deleting 15 files a day is normal for a cleanup task; the same person deleting 4,000 objects in 20 minutes is not
- Permanent delete vs. recoverable (recycle bin/soft-delete) — a "Shift+Delete" pattern or a `HardDelete`/`Purge` operation is a materially stronger signal than a soft delete
- Whether backups, shadow copies, version history, or retention/legal-hold settings were touched in the same session (T1490) — this is the single most important field to check and is frequently the difference between "cleanup" and "sabotage"
- Command-line arguments if a script or CLI tool was used — recursive flags, `/mir`, `--recursive`, `-Force`, `-Recurse` are all worth flagging
- HR/IT context: resignation or termination date, PIP status, recent dispute, recent removal from a project, or a very recent grant of delete permissions that wasn't there a week ago
- Any audit-logging or versioning configuration change immediately preceding the deletion (T1562.001)

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| A handful of stale files, old drafts, or expired records cleaned up periodically, consistent with the user's role and historical pattern | Hundreds to thousands of objects deleted in a single short session, far outside the user's own baseline |
| Deletion stays within the recycle bin/soft-delete window and is recoverable for the standard retention period | Deletion is permanent (`HardDelete`, `Purge`, Shift+Delete pattern) or the recycle bin itself is emptied immediately after |
| Backups, shadow copies, and version history are untouched | Shadow copy deletion, backup catalog deletion, or a retention/legal-hold policy change occurs in the same window |
| Tied to a documented cleanup task, offboarding checklist, data-retention policy, or approved migration | No corresponding ticket, and the timing lines up with a resignation, termination, PIP, or access dispute |
| Delete activity matches role (e.g., records-management team purging per retention schedule) | Delete activity is outside the user's normal folder/system scope entirely |

## Investigation Steps
1. **Confirm scope and permanence first.** Pull the exact object list, count, and timestamps from the source system (file server SACL events, M365 UAL, database audit log, CloudTrail). Establish whether this is soft-delete (recoverable) or hard/permanent delete — this drives your recovery timeline more than anything else in the investigation.
2. **Check the recovery path immediately, in parallel with triage.** Confirm whether shadow copies, backup jobs/catalogs, or version history in the same environment were also deleted or disabled. If T1490 indicators are present, treat this as active sabotage and loop in the backup/IT team now, not after the investigation concludes — every hour matters for restore feasibility.
3. **Establish the baseline.** Compare the delete count/rate against that identity's own 30/90-day history, not a flat org-wide number. A records-management or DBA role will legitimately delete a lot; a marketing analyst suddenly deleting a database table will not.
4. **Verify the account and access path.** Confirm this was the legitimate account holder (T1078.002/T1078.004) and not a session showing signs of compromise (impossible travel, new device, MFA anomaly) — a compromised account destroying data reads very differently from an employee doing it themselves, and should be cross-checked against account-compromise playbooks if anything looks off.
5. **Correlate HR/IT context.** Check resignation/termination date, PIP status, recent access grants or role changes, and whether delete permissions on this system were recently and unusually broadened for this identity.
6. **Look for logging/audit tampering.** Check whether mailbox auditing, file-share SACL auditing, or a retention/legal-hold policy was disabled or modified shortly before the deletion (T1562.001) — this is a strong intent signal and also affects how much evidence you'll actually have.
7. **Check for account/group deletion alongside data deletion.** If accounts, mailboxes, or security groups were also removed (T1531), this may be a denial-of-access sabotage pattern rather than pure data destruction — scope both angles.
8. **Document precisely and hand off for recovery planning.** Exact object manifest, exact timestamps, exact backup status — Legal, HR, and the data owner all need this, and the backup team needs it to scope a restore, which may itself take hours to days depending on retention tier.

## True Positive Indicators
- Delete volume/rate is a genuine outlier against the identity's own history, not just an org-wide threshold trip
- Deletion is permanent (hard delete/purge) rather than recoverable, or the recycle bin/deleted-items folder was emptied immediately afterward
- Shadow copies, backup catalogs, version history, or a retention/legal-hold policy were also deleted or modified in the same window
- Timing aligns with a resignation, termination, denied request, PIP, or a known dispute
- Audit logging, mailbox auditing, or versioning was disabled shortly before the event

## False Positive / Benign Positive Indicators
- Approved data-retention/records-management purge running on schedule, with policy documentation to match
- Legitimate offboarding cleanup or project archival with a change ticket or manager sign-off
- Migration or platform-cutover task where source data is deleted post-verified-copy, per a documented runbook
- Backup/DR test that intentionally exercises deletion and restore, with the maintenance window logged in advance
- Sync-client or application re-index misreported as a delete storm — confirm against the source system directly before treating raw counts as real deletions

## Escalation Criteria
Escalate immediately to Insider Threat Program lead, IT/backup ownership, and Legal/HR if: backups, shadow copies, or version history were also targeted (T1490); the deletion is permanent and outside a documented retention/cleanup process; the identity has a pending or recent resignation/termination; audit logging or a legal-hold policy was disabled beforehand; or the deletion affects regulated data, legal-hold content, or a system already under litigation hold. Escalate to IR in parallel if any authentication-context anomaly suggests the account itself may be compromised rather than misused by its owner.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Preserve everything that's left, immediately**: freeze remaining logs, backup catalogs, and any recoverable soft-delete items before they age out of retention. Approval: SOC lead can act immediately; notify Legal same-day.
- **Suspend further delete/write access for the account**: fast enough to stop an ongoing spree without a full account disable. Approval: SOC lead can act on emergency authority if deletion is active and backups are also under attack; notify HR/Legal within the day.
- **Full account disable / credential revocation**: standard case, not an active-sabotage emergency. Approval: HR + Legal + people-manager sign-off.
- **Initiate backup restore assessment**: start scoping in parallel with the investigation, don't wait for a verdict. Approval: IT/backup ownership + data owner; SOC provides the object manifest and timeline.
- **Forensic image of the endpoint or admin workstation used**: before any user notification. Approval: Legal, with chain-of-custody procedure.

Do not tip off the user before HR/Legal has cleared next steps, and do not let the deletion investigation delay starting the recovery/restore process — they run in parallel, not in sequence.

## Example Query
**[ENGINEERING]** - Splunk SPL correlating Windows Security 4663 (delete-intent access) with the corresponding 4660 (object deleted) on a file server, flagging delete storms by user:

```spl
index=wineventlog EventCode=4663 Accesses="*DELETE*" OR Accesses="*WriteData*"
| join HandleId [ search index=wineventlog EventCode=4660 ]
| bucket _time span=15m
| stats dc(ObjectName) as objects_deleted by SubjectUserName, _time
| where objects_deleted > 100
| sort - objects_deleted
```

Tune the `100`-object threshold against your own environment's records-management/cleanup baseline before enabling this in production — a nightly retention job will otherwise fire it every night.

## Closure Criteria
Close as **Incident** when deletion scope, backup/recovery targeting, and HR/timing context together support intent (data destruction/sabotage), with full handoff to Legal/HR/Insider Threat Program and a parallel-tracked recovery effort. Close as **Benign Positive** when a documented retention policy, migration runbook, or manager-approved cleanup fully accounts for the pattern — record the justification so the same account doesn't re-trip this rule next cycle. Close as **Insufficient Evidence** when volume is anomalous but no backup-targeting, HR trigger, or confirmed lack of authorization exists — keep the account on a watchlist and re-open if the pattern recurs.

**Example case note:**

> 2026-09-15 03:10 UTC — Account m.delgado (IT Systems Admin, termination effective 2026-09-18 per HR feed received 2026-09-12) deleted 3,406 files across \\FS01\Finance\Reporting in an 11-minute window, followed within 4 minutes by execution of `vssadmin delete shadows /all` on FS01 (Sysmon Event ID 1, confirmed via EDR command-line capture) and a mailbox-audit `HardDelete` operation against their own mailbox. No approved change ticket found; manager confirms no authorized cleanup task. Backup team confirms last full backup of the affected share completed 2026-09-14 22:00 UTC and is intact on a separate retention tier, restore ETA 6 hours. Escalated to Insider Threat Program and Legal/HR as confirmed sabotage ahead of scheduled termination; account access suspended under emergency authority; endpoint imaged prior to any user contact; ref# ITP-2026-0104.
