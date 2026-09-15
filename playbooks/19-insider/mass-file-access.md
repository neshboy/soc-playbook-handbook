# Playbook INS-001: Mass File Access

## Overview

| Field | Detail |
|---|---|
| **Playbook ID & Name** | INS-001 — Mass File Access (Anomalous Bulk File/Object Access) |
| **Category** | Insider Threat |
| **Severity/Priority (default)** | Medium, auto-escalate to High when the accessed content is classified/regulated or the user has a pending resignation/termination flag, and to Critical if paired with confirmed staging or exfiltration activity |
| **MITRE ATT&CK** | T1119 (Automated Collection) — primary; T1530 (Data from Cloud Storage) — when the bulk access is against SharePoint/OneDrive/cloud file repositories rather than on-prem shares; T1078.002 (Valid Accounts: Domain Accounts) — the access vector is almost always a legitimate, unrevoked credential; T1087 (Account Discovery) — only if recon of shares/permissions precedes the bulk pull |

**[STAKEHOLDER]** - This is the alert that catches someone loading up before they leave, or someone poking around a repository they have technical access to but no business reason to touch at scale. A single file opened means nothing; a few thousand files touched in an afternoon by someone whose job doesn't involve them is how IP theft, customer-list poaching, and pre-termination "insurance" copying actually look in the logs. Catching it here is materially cheaper than finding out from a competitor's product launch or a lawsuit.

## Trigger / Detection Logic Summary

Fires when a single identity accesses (reads, opens, or downloads) an unusually high count of distinct file objects within a rolling window, relative to that user's own 30/90-day baseline and/or their peer group, and the access spans folders, sites, or repositories outside the user's normal working set. This is a volumetric/behavioral detection, not a signature — it depends on UEBA baselining or a fixed threshold tuned per environment (fixed thresholds catch obvious spikes but miss "low and slow" collection spread across days, which is why this playbook should be paired with a longer-window trend job, not just a real-time spike rule).

## Required Log Sources & Event/Operation Data

| Source | What it gives you |
|---|---|
| File server access auditing (Windows Security Object Access auditing enabled via SACL on the target shares) | Object/handle access events: accessing account, source host, share path, object name, access mask (read/write/delete) |
| Microsoft 365 Unified Audit Log (now branded Microsoft Purview Audit) | Operations such as `FileAccessed`, `FileDownloaded`, `FileSyncDownloadedFull`, `FileCopied`, `SharingSet` against SharePoint Online/OneDrive, with `ObjectId`, `SiteUrl`, `UserId`, `ClientIP` |
| DLP / CASB platform | Bulk-access or mass-download policy triggers, sensitivity-label hit counts |
| EDR file/process telemetry | Local bulk copy/read operations, archive-utility execution (7-Zip, WinRAR, `tar`), command-line arguments |
| UEBA/identity analytics | Peer-group and self-baseline deviation score for the session |
| HR feed | Resignation date, termination date, PIP status, role/department |

Note the deliberate lack of specific numeric Windows Event IDs here — file-share object access auditing on this platform is configured per-environment via SACLs, and the exact event numbering your SIEM parses depends on your log source and audit policy version. Confirm the actual field mappings in your own parser before building the correlation rule; don't assume the vendor's default CIM/schema mapping matches what's documented elsewhere in this book for a different data source.

## Key Fields to Inspect

**[ANALYST]**
- `UserId` / `SamAccountName` and whether it's a service account, shared account, or a named human identity
- `ObjectId` / file path, and the folder/library/site it belongs to (is this the user's own department's repository, or Legal's, or Engineering's source code share?)
- Distinct file count in window vs. that user's historical daily average
- `ClientIP` / source host — on-network endpoint, VPN, or an unfamiliar egress point
- Time of day / day of week relative to that user's normal working pattern
- Sensitivity label or DLP classification tag on the touched content
- Whether an archive/compression tool or bulk-copy utility launched immediately after the access spike
- HR status flag for the identity (notice given, PIP, recent role change, recent access grant)

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Tens of files per day, within the user's own department's folder scope, during business hours | Hundreds to thousands of distinct files in a single session, often within minutes to a few hours |
| Access pattern matches role and matches the user's own 90-day history | Access spans repositories the user has never previously touched (finance, HR, M&A, source code) |
| Consistent with a known scheduled task, backup job, or migration ticket | No corresponding change ticket, migration project, or manager-authorized bulk task |
| Coincides with normal business activity (audit, reporting cycle, handover) | Coincides with a resignation/termination notice, PIP, or a disciplinary event on the HR feed |
| Followed by normal application use | Followed by archive creation, renaming, or an upload/print/USB event shortly after |

## Investigation Steps

1. **Validate the count.** Deduplicate events — sync clients re-indexing, antivirus/DLP re-scans, and backup agents can inflate raw event counts without any human "touching" anything. Confirm this is genuine bulk human access, not a scheduled job running under a personal or delegated account.
2. **Rebuild the full session timeline.** Pull every object accessed by that user/session across the trigger window from the SIEM or the M365 Unified Audit Log — folder paths, timestamps, access type (read/copy/download), and total distinct file count.
3. **Classify what was touched.** Check DLP/sensitivity labels or folder ownership. Source code, financials, HR records, customer lists, M&A material, and legal-hold content each carry very different escalation weight than a shared marketing asset library.
4. **Correlate identity and HR context.** Check role, department, manager, and — critically — the HR feed for resignation/termination dates, PIP status, or a very recent role change. A bulk pull three days before a documented last day of employment reads very differently than the same pull mid-tenure.
5. **Compare against baseline.** Pull the UEBA risk score or the user's own historical access pattern (30/90-day). Is this genuinely novel for this person, or is it a known quarterly-reporting spike you've seen every year from this same account?
6. **Hunt for staging or exfil indicators.** Look for archive/compression tool execution, USB mount events, personal cloud storage uploads, personal webmail attachments, or a print-spool spike immediately following the access. If found, this case now also feeds Large Download (`02-large-download.md`), USB Copying (`03-usb-copying.md`), or Cloud Storage Upload (`04-cloud-storage-upload.md`) as applicable — don't try to close all of it under this one playbook.
7. **Loop in HR/Legal before any user-facing action.** Confirm whether there's a legitimate business reason (approved handover, e-discovery export, manager-authorized reorg pull) before treating this as adversarial. This step is frequently the bottleneck — expect to sit on a live finding for hours while approvals happen, and don't tip off the user in the interim.
8. **Document verdict and hand off.** If confirmed malicious, package the timeline, HR context, and any staging/exfil evidence for the Insider Threat Program and Legal. If benign, record the justification so the next analyst doesn't re-open the same pattern from this account.

## True Positive Indicators

- Bulk access clearly outside the user's role and folder scope, with no supporting ticket or manager authorization
- Timing aligned with a resignation/termination notice, a denied promotion, a PIP, or a known grievance
- Followed by archiving, renaming to non-descriptive names, or an upload/copy/print event outside company channels
- Prior history of policy violations, or the account was already on a watchlist
- Access to content this specific user's history shows they have never opened before, despite technical permission

## False Positive / Benign Positive Indicators

- Authorized migration, backup, or reorg task running under the user's delegated credentials, with a matching change ticket
- Legitimate e-discovery or legal-hold export performed by authorized Compliance/Legal staff
- Recent role transition where a manager-approved bulk handover or reorganization is expected
- DLP/AV re-scan or sync-client re-index inflating the raw count without actual human review of the content
- Scheduled reporting job or dashboard refresh that touches many objects by design

## Escalation Criteria

- Confirmed access to regulated or classified data (PII, PCI, source code, M&A material, legal-hold content)
- User has a pending or already-submitted resignation/termination
- Any staging or exfiltration indicator (archive creation, personal cloud upload, USB copy, personal email) found in step 6
- Repeat pattern from the same identity after a prior "benign" closure
- Privileged or executive account involved

Escalate to the Insider Threat Program lead and Legal/HR within your program's defined SLA — this category cannot be closed unilaterally by the SOC once staging/exfil is confirmed.

## Containment Options & Approval Authority

**[MANAGEMENT]** - Containment here is rarely a unilateral SOC call, because disabling a live employee's access is an HR/Legal-governed action, not a pure security one.

| Action | Approval required |
|---|---|
| Preserve/extend retention on relevant logs and audit trail (litigation hold) | SOC lead can initiate immediately; notify Legal |
| Increase monitoring / silent watchlist on the account (no visible change to user) | SOC lead, informational notice to Insider Threat Program |
| Suspend account access to specific shares/sites | HR + Legal + people-manager sign-off (except in active-exfil scenarios where Security Director can act on emergency authority, with HR/Legal notified same-day) |
| Full account disable / forced logoff | HR + Legal + people-manager, coordinated with physical security if on-site |
| Forensic image of endpoint | Legal approval, chain-of-custody procedure, before any user notification |

Do not notify the user or their manager informally before HR/Legal has cleared the next step — premature tip-off is one of the most common ways these cases get spoiled.

## Example Query

**[ENGINEERING]** - Splunk SPL example against M365 Unified Audit Log data, flagging users touching an unusually high count of distinct files in a rolling hour:

```spl
index=o365_audit sourcetype=o365:management:activity
Operation IN ("FileAccessed","FileDownloaded","FileSyncDownloadedFull")
| bucket _time span=1h
| stats dc(ObjectId) as unique_files, values(SiteUrl) as sites by UserId, _time
| where unique_files > 200
| sort - unique_files
```

Tune the `200` threshold against your own per-role baselines — a records-management or e-discovery team will blow through this every week as their normal job.

## Closure Criteria

Close as **True Positive** when access scope, HR context, and staging/exfil evidence together support intent, with referral to Legal/HR and the Insider Threat Program. Close as **Benign Positive** when a legitimate ticket, e-discovery export, or manager-authorized task fully accounts for the pattern — document the justification so it whitelists cleanly next time. Close as **Insufficient Evidence** when the access scope is anomalous but no staging/exfil, HR trigger, or manager confirmation of intent exists — keep the account on a 90-day UEBA watchlist rather than closing it cold.

**Example case note:**

> 2026-09-15 14:20 UTC — User j.tran (Finance, resignation submitted 2026-09-10) accessed 1,842 distinct files across the Finance and M&A SharePoint sites in a 45-minute window, against a 12-files/day historical baseline. A DLP alert 10 minutes later flagged a zip archive uploaded from the same session to a personal Google Drive tenant. Escalated to Legal/HR as confirmed insider data collection; SharePoint/OneDrive access suspended under emergency authority pending investigation; case referred to Insider Threat Program, ref# ITP-2026-0091; cross-referenced to Cloud Storage Upload playbook for the exfil leg.
