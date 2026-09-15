# Cloud Storage Upload of Sensitive Data

## Playbook ID & Name
**INS-004 — Insider Threat: Cloud Storage Upload of Sensitive Data**

## Business Risk

**[STAKEHOLDER]** - An employee, contractor, or compromised account moves regulated, proprietary, or competitively sensitive data out of the corporate environment into a personal or unsanctioned cloud storage account, creating exposure that legal, privacy, and IP-protection teams cannot control once the data leaves — this is the scenario that ends up in a resignation-plus-lawsuit conversation with HR and outside counsel, not just a security ticket.

## Severity / Priority Default

**High** (Priority 2). Escalates to **Critical (P1)** when the data classification includes regulated categories (PCI, PHI, PII at scale) or when the account involved is a departing employee, someone on a PIP, or has active access to source code / M&A material. Downgrade to Medium only after the destination and content are confirmed as sanctioned business use.

## MITRE ATT&CK Technique(s)

| ID | Technique | Relevance |
|---|---|---|
| T1530 | Data from Cloud Storage | Adversary/insider stages data by pulling it from internal cloud storage/repositories before or during upload to an external destination. |
| T1567 | Exfiltration Over Web Service | Primary technique — upload to Dropbox, Google Drive, personal OneDrive, Mega, etc. via browser or sync client. |
| T1048 | Exfiltration Over Alternative Protocol | Covers cases where upload happens over a non-HTTP channel (e.g., rclone over SFTP/WebDAV, or an API client instead of browser). |
| T1071 | Application Layer Protocol | The upload traffic itself rides HTTPS/DNS — relevant for the proxy/firewall detection layer. |
| T1090 | Proxy | Insider or accomplice tooling routes upload traffic through a proxy/VPN to bypass corporate egress controls or geo-based DLP rules. |
| T1572 | Protocol Tunneling | Seen when someone tunnels a sync client or CLI tool through SSH/VPN to dodge SSL-inspection or CASB enforcement. |
| T1114.003 | Email Forwarding Rule | Frequently paired activity — an autoforward rule set up alongside cloud upload as a second exfil channel; worth a cross-check. |
| T1552.001 | Unsecured Credentials In Files | Common precursor — insider harvests API keys/service account creds from file shares before bulk-pulling data into a script that then uploads it. |

## Trigger / Detection Logic Summary

Fires when a single user account uploads an anomalous volume, count, or classification-tag combination of files to a cloud storage destination that is either (a) unsanctioned/unmanaged, or (b) a sanctioned tenant but a **personal/consumer instance** of it (e.g., corporate Google Workspace is approved, but the destination tenant ID resolves to a free Gmail account). Correlation typically combines:

- DLP policy match (classification label, regex for PII/PCI, keyword match) on outbound web traffic or endpoint file event.
- CASB/proxy category match for cloud storage/file-sharing destinations.
- Volume or file-count threshold breach against a rolling baseline for that user/role.
- Tenant-ID mismatch (uploads landing in a cloud tenant not on the corporate allow-list).

## Required Log Sources & Event IDs

| Source | What it provides |
|---|---|
| DLP (endpoint or network) | Policy match events with classification tags, file hash, file path, destination URL |
| Secure Web Gateway / Proxy (e.g., Zscaler, Netskope, Blue Coat) | URL category, bytes uploaded, destination domain, user, source IP, TLS SNI |
| CASB | Cloud app risk score, tenant instance ID (corporate vs. personal), activity type (upload/share), file/folder metadata |
| Firewall / NGFW | Outbound connection logs, bytes-out, destination IP/ASN, application signature |
| Windows Security Event Log | Event ID 4663 (object access - file read on sensitive share prior to upload), Event ID 4688 (process creation - sync client or browser launch), Event ID 4624 (logon type, for correlating session) |
| Sysmon | Event ID 1 (process creation - e.g., rclone.exe, OneDriveConsumer, browser with unusual command line), Event ID 3 (network connection to cloud storage IP ranges), Event ID 11 (file creation - staged archive files like .zip/.7z in temp/user profile) |
| Cloud storage app logs (Google Workspace, M365 Unified Audit Log/Microsoft Purview Audit, Dropbox Business) | If corporate tenant, confirms whether upload is going to a foreign/consumer tenant vs. internal one |
| Endpoint EDR | File access chronology, USB/removable media correlation (to rule out or confirm parallel exfil path), archive/compression tool usage |
| Identity provider / SSO logs | Session risk score, impossible-travel or new-device flags around the same timeframe |

## Key Fields to Inspect

**[ANALYST]**
- Source user (UPN/SAMAccountName) and whether it matches the file owner or a shared/service account
- Destination domain / cloud app name and **tenant ID** (this is the field that separates "uploaded to our sanctioned OneDrive" from "uploaded to a personal Gmail-linked Drive")
- File classification tags, file name patterns, and file hash (dedupe against known project/document names)
- Bytes uploaded vs. the user's 30/60/90-day rolling baseline
- Number of distinct files/folders touched in the session, and whether a compression tool (7z, WinRAR) staged an archive immediately beforehand
- Time of activity relative to normal work hours, and relative to HR events (resignation date, notice period, PIP status) if HR case flag exists
- Source IP/egress path — on-corp-network vs. VPN vs. unmanaged/BYOD device
- Process command line for the upload mechanism — browser upload form post vs. sync client vs. CLI tool (rclone, curl, aws s3 cp used against a personal bucket)
- Prior file access (Event ID 4663 / EDR file-read telemetry) to confirm the files uploaded were actually opened/read by this user beforehand, not just present on a shared drive by coincidence

## Normal vs. Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Small, steady uploads to the sanctioned corporate cloud tenant (e.g., company OneDrive/Drive) during business hours | Bulk upload (dozens to thousands of files, or multi-GB) in a short window to a personal/consumer tenant |
| Files consistent with the user's normal job function and project assignment | Files pulled from shares/repos outside the user's normal working set (finance analyst suddenly touching source code repo) |
| Destination matches the corporate CASB allow-list | Destination is a personal Gmail/Yahoo-linked Drive, Mega, a brand-new unmanaged SaaS tenant, or a personal Dropbox |
| Upload volume tracks with the user's historical baseline | Volume is a step-change outlier (10x+ baseline) with no corresponding project/business justification |
| No archive staging beforehand | A .zip/.7z/.rar archive is created in Temp or user profile minutes before the upload event |
| Activity timed with normal work patterns | Activity clustered late at night, on a weekend, or immediately before/after a resignation or termination notice |

## Investigation Steps

1. **Pull the triggering event context** - confirm the DLP/CASB/proxy alert details: user, destination domain, tenant ID, file count, bytes, classification tags, and timestamp (normalize to UTC, watch for timezone drift between DLP and proxy logs — this trips people up constantly).
2. **Validate the destination tenant.** Resolve whether the cloud storage instance is the sanctioned corporate tenant or a personal/consumer instance. CASB tenant-ID metadata is the authoritative field here — domain name alone (e.g., "drive.google.com") is not enough to distinguish corporate from personal.
3. **Reconstruct the file access chain.** Use EDR/Windows Event ID 4663 (or equivalent file-read telemetry) to determine where the uploaded files came from — a specific file share, a source code repo, an email attachment saved locally — and whether that data falls inside the user's normal duties.
4. **Check for archive staging and tooling.** Look for Sysmon Event ID 11 file-creation of compressed archives, and Sysmon Event ID 1 / Windows Event ID 4688 process creation for sync clients, browsers, or CLI tools (rclone, curl, aws-cli) used around the upload window.
5. **Baseline the user's normal cloud usage.** Compare this session's volume/frequency/destination against 30-90 day history for the same user and, if useful, their peer group/role — a step-change with no ticket, project, or manager justification is the strongest signal.
6. **Check for accompanying exfil channels.** Cross-reference T1114.003 email forwarding rule creation, USB/removable-media events, and printer logs in the same timeframe — insiders rarely use exactly one channel.
7. **Correlate with HR/personnel context** (through your case-management/HR-liaison process, not by directly querying HR systems yourself) — resignation notice, PIP status, or a recent access-review flag materially changes both severity and next steps.
8. **Interview or escalate per policy** - depending on findings and organizational policy, this may require legal/HR sign-off before any user contact; do not confront the user directly without that authorization.

## True Positive Indicators

- Confirmed upload of classified/regulated data to a personal or unmanaged cloud tenant, with no ticket, project code, or manager approval on file
- Archive staging immediately preceding the upload, especially with generic/obfuscated file names
- Activity timing correlated with resignation notice, termination timeline, or a competitor job offer noted in HR case system
- File access chain shows the user accessing data clearly outside their job scope shortly before the upload
- Repeated attempts to use the same unsanctioned destination after a prior DLP block (shows intent, not accident)

## False Positive / Benign Positive Indicators

- Destination resolves to the corporate-sanctioned tenant, just miscategorized by the CASB/proxy signature
- User has a documented, approved business reason (client deliverable, vendor handoff via an approved sharing workflow) with change/ticket reference
- File classification tag is a mislabel — content on review does not actually contain sensitive data (common with template files or "confidential" watermarked but public-facing sales collateral)
- Bulk upload is part of an approved migration project (IT-led tenant migration, backup job) that wasn't communicated to SOC in advance
- Automated/service account performing scheduled sync, misidentified as a human user session

## Escalation Criteria

Escalate immediately to Insider Threat Program lead, Legal, and HR liaison (per your organization's IRP escalation matrix) when any of the following apply: confirmed regulated-data classification (PCI/PHI/PII at volume), the user is in a departure/termination window, source code or M&A-related material is involved, or the destination is confirmed as a personal account and the user has previously triggered a DLP alert for the same behavior.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- **Immediate network-layer block** of the destination domain/tenant at proxy/firewall - SOC on-call analyst authority, no pre-approval needed for a first-time block on a clearly consumer destination.
- **Session/credential revocation or forced re-authentication** - requires IT security manager or Insider Threat Program lead approval; higher-impact action.
- **Account suspension or access removal ahead of termination** - requires HR + Legal + IT security manager joint sign-off; do not act unilaterally even with strong evidence — this is a legal exposure decision, not a purely technical one.
- **Device/endpoint isolation** (EDR containment) - SOC lead approval; use when there's evidence of an ongoing session actively uploading data.
- **Preservation/legal hold** on user's mailbox, endpoint image, and cloud audit logs - Legal directs this; SOC's job is to flag the need early, not to decide on it.

## One Short Example Query

Sample using a Splunk-style search against combined proxy/CASB and DLP indices:

```spl
index=casb OR index=dlp
| where destination_category="cloud_storage" AND tenant_type="personal"
| stats sum(bytes_out) as total_bytes, dc(file_name) as file_count,
        values(dlp_classification) as tags by user, destination_domain, _time
| where total_bytes > 500000000 OR file_count > 50
| sort - total_bytes
```

## Closure Criteria

Close as **True Positive** only after destination tenant, file classification, and lack of business justification are all independently verified, and case has been handed to Insider Threat Program/HR/Legal for disposition. Close as **Benign Positive** when destination is verified sanctioned or business justification is documented with a ticket/approval reference. Close as **Insufficient Evidence** when proxy/DLP telemetry lacks the tenant-ID or classification detail needed to make a determination — flag the logging gap for the detection engineering backlog rather than force a verdict.

**Example case note:**
> "2026-09-12 14:32 UTC — jsmith@example.com uploaded 74 files (612 MB) tagged DLP:Confidential-IP to drive.google.com; CASB confirms destination tenant is personal Gmail-linked, not corporate Workspace. Sysmon EID 11 shows a 7z archive staged in %TEMP% 6 minutes prior. HR liaison confirms jsmith submitted resignation notice 2026-09-10. Escalated to Insider Threat Program lead and Legal per INS-004 escalation criteria; endpoint isolated pending Legal hold guidance."
