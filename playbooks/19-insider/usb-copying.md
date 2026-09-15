# USB Copying (Removable Media Exfiltration)

**Category:** Insider Threat - Data Exfiltration Channels
**Playbook ID:** INS-003

This is the mirror image of the endpoint-execution USB playbook elsewhere in this book (`usb-triggered-execution.md`, EP-015) - that one covers something running *from* a USB drive onto your network, this one covers data moving *onto* a USB drive and out of your network. Different direction, different intent model, different evidence trail. Nobody needs a zero-day for this. A resigning employee with legitimate read access to a shared drive, a $12 flash drive from the drugstore, and twenty quiet minutes at their desk is a complete exfiltration toolkit. There's no malware to hash and no C2 to pivot from - the entire case usually comes down to volume, timing, content sensitivity, and whether the device itself was ever supposed to be there.

## Business Risk

**[STAKEHOLDER]** - Removable media is the one exfiltration channel that doesn't touch your network egress at all - no proxy log, no email gateway, no CASB visibility, nothing to alert a SOC that only watches wire traffic. A single USB stick can walk out with the entire customer database, the M&A due-diligence folder, or the source repo for your flagship product, and unless endpoint telemetry or DLP caught the copy in the moment, there may be no second chance to detect it - the device leaves the building and the evidence trail leaves with it. The business exposure here isn't theoretical: it's the difference between "we have logs proving what left and can quantify the loss for legal and regulatory purposes" and "we genuinely don't know what that person took."

## Severity / Priority Default

**Medium** as a baseline for a DLP/device-control policy match on removable storage with unremarkable volume and no HR flags. Escalate to **High** when the copied content matches a sensitivity label (PII, PCI, source code, legal/M&A), the device is personal/unencrypted rather than company-issued, or the user is inside a resignation/termination notice window. Escalate to **Critical** when large-volume, sensitivity-labeled data leaves on an unrecoverable personal device with no company control (BitLocker To Go, MDM enrollment) and the user has already separated or is uncontactable.

## MITRE ATT&CK Techniques

- **T1052 / T1052.001** - Exfiltration Over Physical Medium: Exfiltration over USB - the primary technique for this playbook; covers copying data to a removable device (USB drive, external hard drive) as the exfiltration mechanism itself
- **T1119** - Automated Collection (a script or batch tool stages/gathers files across folders immediately before the copy, rather than manual browsing)
- **T1027** - Obfuscated Files or Information (files renamed, archived, or password-protected right before the copy - a common move to defeat content-inspection DLP rules)
- **T1562.001** - Impair Defenses: Disable or Modify Tools (DLP agent, EDR device-control policy, or removable-storage GPO disabled/tampered with shortly before the transfer)
- **T1552.001** - Unsecured Credentials: Credentials In Files (relevant if the copied set includes config files, password vaults, or scripts with embedded secrets - common in departing-engineer cases)

## Trigger / Detection Logic Summary

Primary trigger is a DLP or endpoint device-control policy match for file writes to removable storage, tuned on either volume (file count/size within a rolling window) or content classification (sensitivity-labeled documents, regex/content matches for PII/PCI patterns, source-file extensions). A secondary, telemetry-based trigger fires on Sysmon FileCreate events landing on a drive letter outside the fixed-volume baseline, correlated against a preceding Security object-access event on an audited sensitive share - the pairing tells you both that data left a protected location and that it landed on removable media, not just one or the other.

Tune thresholds by role and baseline, not a flat number - a document-control specialist copying 200 files a week is normal for that job; the same volume from someone in sales who's never touched removable media before is not. Layer in the HR notice-period/termination flag wherever your integration supports it; a large chunk of real cases in this category cluster in the two weeks before or after a resignation is submitted.

## Required Log Sources & Event IDs

| Source | Event ID / Field | Why |
|---|---|---|
| Windows Security (Audit PNP Activity) | 6416 | New external device recognized - anchor event for device connect, carries device description/VID-PID if enabled |
| Windows Security (Object Access, SACL required) | 4663 | Attempt to access an object - confirms which file/folder on the audited sensitive share was actually touched |
| Windows Security | 4656 / 4658 | Handle requested / handle closed - brackets the 4663 access window, useful for timeline reconstruction |
| Sysmon | 11 (FileCreate) | File landing on the removable drive letter - the actual copy-out event, with `TargetFilename` and timestamp |
| Sysmon | 1 (Process Creation) | Captures `explorer.exe`, `robocopy.exe`, `xcopy.exe`, or `powershell.exe Copy-Item` performing the transfer |
| Sysmon | 13 (Registry, Value Set) | `USBSTOR`/`MountedDevices` artifacts - forensic corroboration of device identity even after removal |
| DLP / endpoint device-control (Microsoft Purview Endpoint DLP, CrowdStrike Falcon Device Control, Forcepoint, Symantec DLP, etc.) | Policy alert (vendor-specific, non-numeric) | Direct policy match with file count, size, content classification, and device serial/VID-PID |
| EDR device inventory / asset management | n/a | Confirms whether the device is company-issued and encrypted vs. personal/unknown |
| HR feed / IAM lifecycle integration | n/a | Notice-period, termination-date, or PIP flag on the account |

## Key Fields to Inspect

**[ANALYST]**
- `TargetFilename` (Sysmon 11) - full path including drive letter; confirm it's genuinely removable media, not a mapped network share, mounted ISO, or a legitimate second internal partition
- Volume serial number / device VID-PID (from Security 6416 or EDR device telemetry) - the actual device fingerprint, needed to answer "is this the same stick as last time"
- `ObjectName` and `AccessMask` on the correlated 4663 - which specific share/folder was read, and was it a read consistent with the user's job, or a folder they rarely touch
- File count and total size within the alerting window, benchmarked against that user's historical baseline for the same activity
- Sensitivity/classification label (Microsoft Purview Information Protection, or equivalent DLP content match) on the copied files - volume alone doesn't tell you exposure, content does
- Device encryption/enrollment status - BitLocker To Go, MDM-managed, or asset-tagged company peripheral vs. unknown personal drive
- HR status flag - active notice period, recent resignation, PIP, or role change in the last 30-60 days
- Related same-session indicators - mass file access spikes, personal webmail uploads, or printing spikes touching the same source files (cross-reference `01-mass-file-access.md`, `05-personal-email-transfer.md`, `07-printing-sensitive-files.md`)

## Normal vs. Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Small, occasional copy (a handful of files) consistent with the user's documented role | Bulk copy - hundreds to thousands of files - in a single short window, well outside historical baseline |
| Company-issued, encrypted (BitLocker To Go) drive, asset-tagged in inventory | Unlabeled personal drive, or a device never seen in asset records for that user |
| Copy occurs during normal working hours, matches an active project or approved backup task | Copy occurs late at night, on a weekend, or immediately after a resignation letter/termination notice |
| Files are ordinary working documents with no sensitivity label | Files carry a sensitivity label (PII, PCI, IP, M&A) or match DLP content-inspection rules for regulated data |
| No prior related alerts on the account | Same session or same week also shows a mass file access spike, personal email upload, or print spike on the same source data |
| DLP/EDR device-control agent active and functioning throughout | DLP agent or device-control policy disabled or shows a tamper/uninstall event shortly before the copy |

## Investigation Steps

1. Pull the DLP or device-control alert in full: policy matched, file count and total size, content classification, and device identifiers (VID-PID/serial).
2. Confirm device identity and provenance - check asset management and EDR device inventory for company-issued/encrypted status versus an unregistered personal drive.
3. Correlate Sysmon FileCreate (11) and the paired Security object-access (4663, bracketed by 4656/4658) to establish exactly which source folder was touched and confirm the files copied match what the DLP alert flagged.
4. Pull the user's historical baseline for removable-media use and their HR lifecycle status - active employment, notice period, recent PIP, or role change - since this materially changes both risk and how you're allowed to proceed.
5. Establish timing: work hours vs. off-hours, and whether the copy clusters around a resignation date, negative review, or other HR event.
6. Check for related same-window indicators - mass file access, personal webmail or cloud upload activity, or a printing spike touching the same data set - a single-channel copy reads very differently from a multi-channel exfiltration pattern.
7. Before any direct contact with the employee, route through your insider-threat SOP - notify HR and Legal per policy and let them decide on timing and method of contact; premature outreach can tip off a genuine bad actor or create legal exposure if handled outside process.
8. Determine actual content sensitivity (via DLP content match or file sampling under appropriate authorization) - a large file count of non-sensitive personal photos is a very different case than a smaller set of source-controlled engineering files.

## True Positive Indicators

- Bulk copy of sensitivity-labeled or regulated data to a personal, unencrypted device
- Copy occurs off-hours or clusters tightly around a resignation, termination, or negative HR event
- DLP agent or device-control policy shows a disable/tamper event shortly before the transfer
- Files renamed, archived, or password-protected immediately before the copy (content-inspection evasion)
- Corroborating activity on the same data via another exfiltration channel (personal email, cloud upload, printing) in the same window
- User gives an evasive, inconsistent, or unverifiable account of the device or the reason for the copy when interviewed

## False Positive / Benign Positive Indicators

- Company-issued, encrypted, asset-inventoried drive used for a routine, role-consistent backup or approved data-migration task with a change ticket on file
- Volume and file types match the user's established historical pattern for that role
- Files are personal (photos, resumes, non-work documents) with no sensitivity label and no related-channel indicators
- IT/AV team performing an authorized imaging or deployment task
- DLP content-match was a false positive on a template or non-sensitive document that happens to match a regex pattern (e.g., an internal invoice template flagged for a credit-card-number-shaped placeholder)

## Escalation Criteria

Escalate to Tier 2/insider-threat lead (and loop in HR/Legal per your organization's insider-threat SOP) immediately when: the copied content is confirmed sensitivity-labeled or regulated data; the device is personal/unencrypted and has already left the premises with no recovery path; the user is inside a resignation/termination notice window or was recently placed on a PIP; the same behavior recurs across multiple sessions or devices; there's evidence of anti-forensic behavior (renaming, archiving, encrypting files pre-copy); or the DLP/EDR agent was disabled shortly before the event. Any one of these on its own can justify escalation - don't wait for all of them to line up.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Remote device-control block (disable USB mass storage port on the endpoint via EDR policy) - Tier 1/2 can act unilaterally under standard SOC authority; log the action and notify the on-call insider-threat lead.
- Preserve endpoint forensic artifacts (Sysmon logs, Security event exports, DLP alert detail) - Tier 2, standard evidence-preservation step, no separate approval needed.
- Physical retrieval of the device for forensic imaging - requires manager or security-lead approval and formal chain-of-custody documentation from the point of seizure; coordinate timing with HR/Legal if the device belongs to a departing or already-separated employee.
- Suspend or restrict the user's account/access pending investigation - joint approval from HR, Legal, and security leadership; this is a personnel action, not a unilateral SOC decision, given the employment-law exposure.
- Direct employee interview or confrontation - HR/Legal-led, on their timeline, not the SOC's; the analyst's job ends at evidence and escalation, not interrogation.
- Org-wide removable-storage restriction via GPO or device-control policy - a policy/change-management decision for IT and security leadership, not something to trigger off a single case.

## Example Query (Splunk SPL, Sysmon source)

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| rex field=TargetFilename "^(?<drive>[D-Z]):\\\\"
| where isnotnull(drive)
| bin _time span=15m
| stats dc(TargetFilename) as files_written, sum(eval(1)) as events by _time, Computer, User, drive
| where files_written > 75
| sort - files_written
```

## Closure Criteria

Close as **True Positive** when the copied content is confirmed sensitivity-labeled or regulated, the device and timing align with elevated-risk indicators (personal device, notice period, related-channel corroboration), and findings are handed to HR/Legal for personnel action alongside standard evidence preservation. Close as **Benign Positive** when the device is confirmed company-issued/encrypted and the copy matches an approved, role-consistent task with no sensitivity-label match. Close as **Insufficient Evidence** when the device was removed before retrieval, SACL auditing wasn't enabled on the source share so no 4663 correlation exists, or DLP content classification couldn't determine what was actually in the copied files - log the telemetry gap as a follow-up item for expanding object-access auditing or DLP content-inspection coverage rather than forcing a verdict the evidence doesn't support.

**Example case note:** *"User k.alvarez (Finance, submitted resignation 2026-09-08, last day 2026-09-19) - DLP Endpoint policy 'Copied to removable USB device' fired 2026-09-14 22:41 UTC on host WKS-FIN-027, 1,140 files, 3.8 GB, classification match: Confidential - Finance. Sysmon 11 confirms writes to F:\\ (device VID-PID matches an unregistered personal drive, not in asset inventory). Paired Security 4663 on \\\\fs01\\Finance\\Contracts shows AccessMask read on the full contracts folder tree in the 20 minutes prior - well outside this user's normal access pattern for that share. No DLP or device-control tamper event observed. No corroborating personal-email or cloud-upload alerts in the same window. Case escalated to insider-threat lead and HR per SOP; HR confirmed active notice period. Device-control block applied to host pending physical retrieval; chain-of-custody log CoC-2314 opened. Verdict pending HR/Legal review - provisional True Positive on data-handling policy violation, T1119/T1027 not observed (no evidence of staging or file obfuscation), final disposition tracked under HR case HR-2026-0917."*
