# INS-002: Large Download / Bulk Data Staging

## Playbook ID & Name
**INS-002 — Large Download (Anomalous Bulk Data Access & Local Staging)**

## Business Risk
**[STAKEHOLDER]** - An employee, contractor, or compromised account pulls down a volume of files, records, or mailbox content far outside their normal pattern — the classic precursor to IP theft, a resignation "grab everything on the way out," or a compromised account being staged for exfiltration. The risk isn't the download itself, it's what leaves the building next: customer lists to a competitor, source code to a personal cloud account, M&A documents before a public announcement. Decision owner for legal/HR escalation is typically Legal + HR + the data owner, not SOC alone.

## Severity / Priority Default
**Medium** on detection (pending context), escalates to **High** if the account is a resignation/termination case, has access to regulated data (PII, PCI, source code, financials), or the destination is external/personal cloud storage. Escalates to **Critical** if paired with credential misuse indicators or occurs within 30 days of a known resignation/RIF event.

## MITRE ATT&CK Techniques
- **T1119** — Automated Collection (scripted/bulk pull of files or records)
- **T1530** — Data from Cloud Storage (bulk object/bucket download)
- **T1567** — Exfiltration Over Web Service (personal cloud storage, webmail upload as next stage)
- **T1048** — Exfiltration Over Alternative Protocol (if paired with non-standard egress)
- **T1114.003** — Email Forwarding Rule (if bulk download is mailbox export/PST rather than file share)
- **T1552.001** — Unsecured Credentials in Files (frequently what's *in* the download — credential dumps, config files, keys)

This playbook covers the **collection/staging** stage. If a confirmed external upload follows, hand off to the corresponding exfiltration playbook rather than duplicating that logic here — this one owns detection of the pull, not the push.

## Trigger / Detection Logic Summary
Fires when a single identity's file-access, database-query, or object-storage-download volume in a rolling window exceeds a baseline threshold by a defined multiplier (commonly 3-5x the user's own 30-day rolling average, or a fixed absolute ceiling for low-baseline accounts). Triggers on volume in GB/MB, file/object *count*, or record-row-count for structured data pulls — count matters as much as size, since someone quietly pulling 40,000 small customer records is not a "large download" by byte count but absolutely is one by intent.

## Required Log Sources & Event IDs
| Source | Event ID / Field Source | Purpose |
|---|---|---|
| Windows Security (file server / DFS) | **4663** (object access attempt), **4656** (handle requested) with Object Type = File | Bulk file reads on file shares |
| Sysmon | **Event ID 11** (FileCreate) on endpoint if files copied to local disk/removable media | Local staging evidence |
| Cloud storage audit logs (SharePoint/OneDrive, Google Drive, S3 access logs, Azure Storage logs) | Download/GetObject/File Downloaded events | Cloud-native bulk pull |
| DLP / CASB | Bulk download policy alert, "mass download" heuristic | Purpose-built detection, usually the primary trigger |
| Proxy / firewall | Bytes-out per session, per destination | Corroborates volume leaving the endpoint |
| VPN / remote access logs | Session start/end, source IP, geo | Context — off-hours or off-VPN access |
| Database audit logs | Query row-count, export/bulk-select events | Structured-data equivalent of file download |
| EDR | Process creation, USB/removable media mount events | Confirms local copy method |

## Key Fields to Inspect
**[ANALYST]**
- User/account (UPN or sAMAccountName), and whether it's a human account, service account, or shared/generic login
- Source host, source IP, VPN/geo at time of activity
- Destination: file share path, SharePoint site, S3 bucket/prefix, database name/table
- Total bytes transferred and total object/file count in the window
- File types pulled — source code, spreadsheets, PDFs, database exports, PST/mailbox exports
- Timestamp pattern — clustered in minutes (scripted) vs spread over hours (manual browsing)
- Access method — mapped drive, browser download, `Invoke-WebRequest`/`curl`, sync client, API token
- HR/IT context: recent role change, PIP, resignation notice, termination date, access-review flags

## Normal vs Suspicious Pattern
**Normal:** A analyst downloading a handful of case files per day, a developer pulling their own repo, a finance user exporting a monthly report of a few hundred rows — consistent with role, consistent with historical baseline for *that specific user*.

**Suspicious:** Volume/count spikes far above the individual's own baseline (not just above a flat org-wide number — a data engineer's baseline is naturally huge, so compare against their own history, not a generic ceiling); downloads outside job function (HR person pulling engineering source); download immediately followed by compression (zip creation) or copy to USB; activity clustered late at night, weekend, or immediately before/after a resignation notice; access to files/folders the user hasn't touched in months or ever.

## Investigation Steps
1. Pull the DLP/CASB or file-server alert detail — confirm exact volume, object count, and time window, not just the summary line.
2. Establish the user's own 30/60/90-day baseline for the same activity type before calling anything "anomalous" — compare against themselves, not the org average.
3. Identify destination: internal share vs. personal cloud (Dropbox, personal Gmail, personal OneDrive) vs. removable media vs. sanctioned corporate tool.
4. Check HR/IT context — resignation, PIP, termination date, recent role/manager change, or an access review flagging excess entitlements (T1069 Permission Groups Discovery territory if the access itself looks over-provisioned).
5. Review authentication context for the session — was this the legitimate user (T1078 Valid Accounts) or does the download coincide with signs of account compromise (impossible travel, new device, MFA anomalies) worth cross-checking against account-compromise playbooks?
6. Inspect file/query content sampling (with data owner or legal involvement per policy) — is this regulated data, source code, credentials-in-files (T1552.001), or routine business documents?
7. Check for follow-on staging behavior: archive creation, encryption/renaming of files, USB mount events, or an immediate upload attempt to an external service.
8. Document scope precisely — exact file list or query set, not "a lot of files" — legal and HR will need this for any downstream action.

## True Positive Indicators
- Volume/count is a genuine outlier against the user's own history, not just an org-wide threshold trip
- Destination is personal cloud storage, personal email, or removable media
- Timing correlates with resignation notice, termination date, or a known dispute/PIP
- Content sampling shows sensitive/regulated data or source code with no job-function justification
- Scripted/automated pull pattern (uniform timestamps, tool signatures) rather than manual browsing

## False Positive / Benign Positive Indicators
- Approved bulk export for a legitimate business task (migration, audit, backup job, scheduled report)
- Baseline miscalibration — new hire in a role that's naturally high-volume, or a role change not yet reflected in the peer-group baseline
- IT/admin service account performing a scheduled sync or backup misclassified as a human user event
- Data owner confirms the destination is a sanctioned corporate tool (approved partner SFTP, corporate-managed cloud tenant) rather than personal storage
- One-time legitimate project need (e.g., disaster-recovery test, migration to new platform) with change-ticket backing

## Escalation Criteria
Escalate to Insider Threat / HR / Legal immediately if: destination is personal/unsanctioned storage, timing aligns with resignation or termination, content sample includes regulated data or IP, or the user denies or can't explain the activity when contacted through proper channels (never contact the subject directly without HR/Legal sign-off — that's their call, not SOC's). Escalate to IR if there's any indicator the account itself may be compromised rather than misused by its owner.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Preserve, don't tip off**: forensic preservation of logs, endpoint image, and access records happens before any account action — HR/Legal typically want evidence locked down first. Approval: SOC lead + Legal.
- **Disable/suspend account access**: only after HR/Legal/data-owner sign-off, given employment-law exposure. Approval: HR + Legal + CISO or designee.
- **Revoke active sessions / rotate credentials**: can proceed faster if compromise (not misuse) is suspected. Approval: SOC lead, notify IR.
- **Block destination (personal cloud domain, USB policy enforcement)**: can be applied broadly via DLP/proxy policy without singling out the user, lower approval bar. Approval: SOC lead.
- SLA: HR/Legal decision on account action expected within same business day for active-exfiltration-risk cases; routine baseline-anomaly cases can sit in a 3-5 business day review queue.

## Example Query
```kql
// Microsoft Sentinel — bulk SharePoint/OneDrive download anomaly
OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| where TimeGenerated > ago(1d)
| summarize FileCount = dcount(SourceFileName), TotalUsers = dcount(UserId) by UserId, bin(TimeGenerated, 1h)
| where FileCount > 200
| join kind=leftouter ( 
    OfficeActivity | where TimeGenerated > ago(30d)
    | summarize AvgHourly = avg(1.0) by UserId ) on UserId
| project TimeGenerated, UserId, FileCount
| order by FileCount desc
```

## Closure Criteria
Close as **True Positive** (insider threat referred) once HR/Legal has taken ownership of the personnel action and evidence package is handed off; SOC's part ends at detection, evidence preservation, and referral, not the HR outcome. Close as **Benign Positive** when the data owner or line manager confirms legitimate business need with documentation (ticket, project sign-off). Close as **Insufficient Evidence** if the user/manager can't be reached within SLA and no corroborating destination/content risk exists — reopen if the pattern recurs.

**Example case note:** *"User jdoe@example.com downloaded 1,840 files (4.2 GB) from \\fileserver01\Engineering\Source in a 22-minute window on 2026-09-12 22:41 UTC, 9 days after submitting resignation notice effective 2026-09-25. Destination confirmed as local Downloads folder, followed by a 3.9 GB zip archive creation (Sysmon Event ID 11) at 22:58 UTC. No corresponding upload to external services detected on proxy logs as of case open. Referred to HR/Legal with full file manifest and endpoint image preserved; SOC access-review flag added pending offboarding date."*
