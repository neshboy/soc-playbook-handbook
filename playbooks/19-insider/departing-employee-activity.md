# Departing-Employee Activity

**Category:** Insider Threat
**Playbook ID:** INS-009

## Business Risk

**[STAKEHOLDER]** - An employee who knows they're leaving - whether they resigned, were told today, or have a start date at a competitor already lined up - has both motive and standing access to take data, sabotage systems, or leave a backdoor before their last day; the financial and legal exposure (trade secret loss, regulatory breach notification, contract disputes with the new employer) is driven almost entirely by how fast HR tells Security and how fast Security acts on that notice, not by any single technical control.

## Severity / Priority Default

**High** for any departure flagged as involuntary, contentious, or going to a direct competitor. **Medium** for standard voluntary resignations with a cooperative transition. Escalate one level automatically if the employee holds privileged access (domain admin, DBA, source code repo owner, finance approver) or has a two-week notice window that has already passed the midpoint - most exfiltration happens in the final 3-5 working days, not the first.

## MITRE ATT&CK Techniques

T1567 (Exfiltration Over Web Service), T1052.001 (Exfiltration Over Physical Medium - Exfiltration over USB, when the departing-employee watchlist flags removable-media write spikes rather than a network-based exfil channel), T1114.003 (Email Collection - Email Forwarding Rule), T1530 (Data from Cloud Storage), T1552.001 (Unsecured Credentials - Credentials In Files), T1119 (Automated Collection), T1136 (Create Account), T1098.002 (Account Manipulation - Additional Email Delegate Permissions), T1531 (Account Access Removal - if the departing employee disables or removes *other* users'/shared accounts, mailboxes, or group access before leaving, rather than just their own access being handled by offboarding), T1078.002/.004 (Valid Accounts - Domain/Cloud Accounts), T1027 (Obfuscated Files or Information), T1562.001 (Impair Defenses - Disable or Modify Tools).

## Trigger / Detection Logic Summary

This playbook is triggered two ways, and both matter:

1. **HR-driven (proactive):** HR or the hiring manager submits a departure notice (resignation, termination, layoff) through the offboarding ticket queue or HRIS-to-ticketing integration. This should auto-open a case and place the identity on a watchlist for the remainder of employment plus a 30-day look-back on close.
2. **Telemetry-driven (reactive):** behavioral analytics flags a user already on the departure watchlist for one or more of: mass file download/sync from SharePoint/OneDrive/Google Drive, unusual volume to personal cloud storage or webmail, creation of a new mail forwarding/delegate rule, USB mass-storage write spikes, or access to systems/repos outside the user's normal job function in the final two weeks.

Don't wait for HR paperwork to start monitoring critical roles - if IT or a manager verbally confirms a resignation, open the case on that word and backfill the HR ticket number later.

## Required Log Sources & Event IDs

| Source | Event IDs / Fields |
|---|---|
| Windows Security (DC/endpoint) | 4624/4625 (logon), 4648 (explicit creds), 4720 (account created), 4738 (account changed), 4726 (account deleted), 4663 (object access, file share auditing) |
| Microsoft 365 / Exchange Online (Unified Audit Log, now branded Microsoft Purview Audit) | `New-InboxRule`, `Set-Mailbox` (ForwardingSmtpAddress), `MailItemsAccessed`, `Send`, `FileDownloaded`, `FileSyncDownloadedFull` |
| Entra ID sign-in logs | Interactive/non-interactive sign-ins, conditional access result, device compliance state |
| DLP / CASB | Upload-to-personal-cloud events, USB write policy hits, sensitive-label file movement |
| Proxy / firewall | Destination categories: webmail, personal cloud storage, file-sharing, job boards, competitor domains |
| VPN / remote access | Session start/end, source geolocation vs. HR-recorded work location |
| EDR | USB device insertion, archive tool execution (7z, WinRAR, rclone), removable media write count |
| Physical access (badge) | Entry/exit logs for the final week - correlates with off-hours logical access |

## Key Fields to Inspect [ANALYST]

**[ANALYST]** Pull the identity's baseline first - 30/60/90-day average for data volume moved, apps touched, and login hours - before you decide anything is "unusual." A departing employee's normal Tuesday download of a shared project folder looks identical to exfiltration in a raw log line; the delta from their own baseline is what tells the story.

- `UserPrincipalName` / `SamAccountName`, `TargetFileName`, `SourceFileName`, `Workload` (SharePoint/OneDrive/Exchange), `ClientIP`, `UserAgent`
- Volume fields: bytes uploaded/downloaded, file count per session, distinct file extensions touched
- Mail rule fields: `Parameters` (ForwardTo, RedirectTo, DeleteMessage), rule creator vs. mailbox owner
- Time-of-day and day-of-week relative to badge/VPN records
- Destination domain/category for outbound transfers (personal Gmail, Dropbox, WeTransfer, competitor's IP range if known)

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Downloading files the employee has always owned/edited, during work hours, from a corporate device | Bulk download of files never previously accessed by that user (finance models, customer lists, source code they don't maintain) |
| Occasional forwarding of a single email to a personal address with manager awareness | Silent creation of a forwarding rule or delegate with no ticket, especially targeting a personal domain |
| USB use consistent with role (e.g., hardware engineer) | First-ever USB mass-storage write on an account with no prior USB history, timed to the last 48 hours |
| Standard offboarding-day access review | Attempted logon after HR's stated termination effective time/date, or use of a shared/service account to route around a disabled personal account |

## Investigation Steps

1. Confirm departure status, last working day, and access-removal date directly with HR/manager - do not rely on rumor or an out-of-office message.
2. Pull the user's activity baseline (30/60/90-day) across file access, email, VPN, and badge systems for comparison.
3. Review Unified Audit Log for new inbox rules, delegate/forwarding changes (T1114.003, T1098.002), and mailbox permission grants in the last 30 days.
4. Query DLP/CASB and proxy logs for uploads to personal cloud storage, webmail, or file-sharing sites (T1567) and for any archive/compression tool execution preceding a transfer (T1027).
5. Check EDR for USB insertion events and correlate volume/file count against badge presence - remote "exfil" claims with no matching VPN session are a red flag for a shared account or stolen credential, not the departing user.
6. Review AD/Entra logs for any account creation (T1136), permission-group changes (T1098), or credential-sharing indicators (T1552.001, e.g., passwords left in scripts or shared drives) that could enable post-termination access.
7. Verify access-removal ticket status - confirm the account was actually disabled (not just password-reset) and check for lingering active sessions or valid tokens after the offboarding time (T1078.002/.004). Separately, check whether the departing employee disabled, deleted, or locked out any *other* accounts, shared mailboxes, or group memberships before their access was cut (T1531) - a sabotage pattern distinct from their own account simply not being fully offboarded.
8. Interview the manager for business context - some "suspicious" transfers are legitimate handover of work product; document the answer either way.

## True Positive Indicators

- Large, atypical download volume (order-of-magnitude above baseline) in the final 5 business days, concentrated on files outside the user's normal scope.
- New forwarding rule/delegate to a personal or competitor domain created without a change ticket.
- Archive tool execution followed immediately by upload to personal storage or webmail.
- Active logon or VPN session after HR's confirmed termination timestamp.
- Deliberate log-clearing or EDR tampering attempt (T1562.001) timed to the departure window.

## False Positive / Benign Positive Indicators

- Manager-approved handover of project files to a shared team location (not personal storage).
- Scheduled backup jobs or sync clients (recognized service accounts) misattributed to the human user.
- Legitimate personal-email forward set up long before resignation, unrelated to departure (check rule creation date against notice date).
- IT-initiated bulk data migration for a role transfer, documented in a change ticket.

## Escalation Criteria

Escalate to Legal, HR, and the insider-threat/Legal-hold process immediately when: destination includes a known competitor domain or personal device tied to a new employer; volume/sensitivity meets the org's data-classification threshold for "material" (source code, customer PII, financial forecasts, M&A material); or there is any post-termination access attempt. Loop in Legal before taking any action that could be construed as evidence tampering (e.g., wiping the device) - preserve, don't remediate, until counsel signs off on next steps.

## Containment Options & Approval Authority [MANAGEMENT]

**[MANAGEMENT]** Standard offboarding (disable account, revoke tokens/MFA, remove group memberships, forward mailbox to manager) is pre-approved and executed by IT/Security on the HR-confirmed effective date/time - no case-by-case sign-off needed. Anything beyond that requires escalation:

| Action | Approval |
|---|---|
| Immediate account disable ahead of scheduled date | Security lead + HR/manager verbal confirmation, ticket backfilled same day |
| Device forensic image / legal hold | Legal + HR joint approval |
| Preservation of personal cloud/webmail evidence (subpoena-adjacent) | Legal only |
| Notifying the new employer or law enforcement | Legal + executive sponsor |
| SLA: initial triage within 4 hours of HR notice; full evidence package within 3 business days for High severity | Security Manager owns SLA tracking; monthly insider-threat metrics reviewed with HR/Legal |

## Example Query (Microsoft Sentinel / KQL)

```kql
OfficeActivity
| where UserId =~ "j.reyes@example.com"
| where TimeGenerated > ago(7d)
| where Operation in ("FileDownloaded","FileSyncDownloadedFull","New-InboxRule","Set-Mailbox")
| project TimeGenerated, Operation, ClientIP, OfficeObjectId, Parameters
| order by TimeGenerated desc
```

## Closure Criteria

Close as **True Positive** only after Legal/HR review and evidence preservation are complete; close as **Benign Positive** when activity maps to documented handover or approved job function; close as **Insufficient Evidence** when logs are incomplete (common with short retention on personal-device webmail categories or missing DLP coverage on a newly acquired subsidiary) - note the gap explicitly rather than guessing at intent.

**Example case note:** "User j.reyes (Senior DevOps Eng., resignation effective 2026-09-19) downloaded 4.2GB from `/Infra/Deploy-Scripts` (previously 0 access in 90-day baseline) via OneDrive sync on 2026-09-14 22:10 local, no matching VPN or badge presence that evening - escalated to HR/Legal for device hold; account disabled ahead of schedule per Security Manager approval."
