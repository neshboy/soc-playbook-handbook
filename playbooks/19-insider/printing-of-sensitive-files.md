# Printing of Sensitive Files

**Category:** Insider Threat
**Playbook ID:** INS-007

Printing is the exfiltration channel most SOCs forget exists until Legal asks "did anyone print the customer list before the account was disabled?" and the honest answer is "we don't log that." Hardcopy has no file hash, doesn't traverse the proxy, and doesn't need a USB port - it walks out in a bag. This playbook is really two problems stitched together: catching the print event itself (which most environments under-instrument), and then figuring out whether it was a departing salesperson archiving a Rolodex or a paralegal collecting evidence for a lawsuit against the company.

## Business Risk

**[STAKEHOLDER]** - A printed document is unrecoverable once it leaves the building - no remote wipe, no DLP block after the fact, no way to prove it was destroyed. For regulated data (customer PII, source code, M&A material, health records) a single confirmed print-and-remove event can trigger breach notification obligations even without a network trace. The business decision here isn't "stop all printing" - it's knowing which prints matter enough to review before the paper is gone, which requires DLP/label-aware print monitoring to be switched on *before* the incident, not after.

## Severity/Priority Default

**Medium** on initial trigger - a labeled or DLP-matched document printed by a valid, in-scope employee, no other context yet. Escalates to **High** when the user is in a resignation/termination window, the volume is a clear outlier against their own baseline, the destination is a "Print to PDF"/virtual driver rather than a physical device, or the print is one of several exfil-adjacent signals (USB activity, personal webmail, cloud upload) in the same session.

## MITRE ATT&CK Techniques

- **T1119** - Automated Collection (scripted or looped printing across many files/records rather than a single manual print job)
- **T1078.002** - Valid Accounts: Domain Accounts (the account doing the printing is legitimate; the investigation has to separate "authorized user, unauthorized purpose" from a compromised account behaving the same way)

MITRE ATT&CK has no dedicated technique for exfiltration via printed hardcopy. T1052 *Exfiltration Over Physical Medium* is the closest-sounding concept, but its actual scope (per attack.mitre.org) is removable digital storage — USB drives, external hard drives — not paper; see `03-usb-copying.md` for that technique. Hardcopy removal itself is described here by name only, without an ID.

## Trigger/Detection Logic Summary

Two independent detection surfaces feed this playbook and rarely arrive together in one log stream:

1. **Native Windows print telemetry** - Microsoft-Windows-PrintService/Operational Event ID 307 fires on every completed job (per-printer, per-user, includes document title, owner, printer, port, byte size, page count). This log is not enabled by default on most builds - confirm it's turned on before assuming absence of alerts means absence of printing.
2. **DLP/label-aware print monitoring** - Microsoft Purview Endpoint DLP (or equivalent third-party DLP with a print channel: Forcepoint, Symantec, Proofpoint) inspects content at print time against sensitive information types and MIP sensitivity labels, logging matches to the unified audit log with the policy action taken (Audit, Warn, Block, User-override).

Trigger the alert on: a DLP policy match on a print activity for a document carrying a Confidential/Restricted label or a matched sensitive-info-type pattern (SSN, card number, source-code marker, customer-record fingerprint); OR a page-count/job-count outlier against the user's own 30/90-day print baseline; OR any print job routed to a "Microsoft Print to PDF"/"Microsoft XPS Document Writer" driver for a labeled document, since that converts protected content into a portable, unprotected file rather than producing paper.

## Required Log Sources & Event IDs

| Source | Event ID / Field | Why |
|---|---|---|
| Microsoft-Windows-PrintService/Operational | 307 | Core job record - document, owner, printer, port, size, pages |
| Microsoft Purview Endpoint DLP / M365 Unified Audit Log (Microsoft Purview Audit) | Operation: DLP print-channel match | Content classification, sensitivity label, policy action at time of print |
| Print server (if centralized) | 307 (server-side copy) | Confirms job routed through server queue vs. local direct-attach printer |
| Sysmon | 1 (Process Creation) | Application/process that had the file open and issued the print (Word, Acrobat, a script calling `Out-Printer`) |
| EDR / DLP endpoint agent | Print channel event | Third-party DLP equivalent where Purview isn't deployed |
| Physical access control | Badge log | Confirms user's location matched the printer's location at job time |

## Key Fields to Inspect

**[ANALYST]**
- Document title/filename and sensitivity label - does the label match the content risk (or was the label absent/stripped before printing?)
- Owner/account - is this the account's own document, a shared drive item, or something outside their normal entitlement?
- Printer name/port - physical device vs. `PORTPROMPT:`/virtual PDF driver; physical device location vs. the user's assigned office/floor
- Pages printed and byte size - single-digit page counts are routine; hundreds of pages or dozens of jobs in a short window are not
- Timestamp vs. business hours and vs. the user's HR lifecycle status (notice period, PIP, role change effective date)
- DLP policy action - Audit-only tells you it was logged but not stopped; Block-with-override tells you the user actively bypassed a warning

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| A handful of pages/day, consistent with role (contracts, invoices, meeting notes) | Dozens of documents or hundreds of pages in a single session, no matching ticket or task |
| Printed to the physical device nearest the user's desk | Printed to a device in another building/floor with no badge access match, or to a virtual PDF driver |
| Document matches the user's job function and normal data access | Source code, customer master data, or M&A material printed by someone outside that function |
| Occurs during working hours on a normal cadence | Printed off-hours, or a burst right before a resignation date takes effect |
| DLP shows Audit with no override, content matches routine templates | DLP shows Block-then-override, or repeated attempts against a Confidential label |

## Investigation Steps

1. Pull the 307 record and/or DLP print-match event: document title, label, printer/port, pages, bytes, timestamp, source device and user.
2. Baseline the user's print volume and cadence over the trailing 30-90 days - is this event an outlier in size, frequency, or content sensitivity?
3. Pull Sysmon 1 process context from the source workstation to see what application or script generated the job - a manual single-document print looks very different from a script looping `Out-Printer` across a folder.
4. Confirm entitlement - does the user's role and current group membership justify legitimate access to this content at all (rule out stale/over-provisioned access before assuming intent)?
5. Check the destination: physical printer with a badge-access match, or a virtual PDF/XPS driver that turns a labeled document into a portable unprotected file.
6. Check HR/lifecycle status - resignation notice, termination date, PIP, or recent role change, and whether the timing correlates.
7. Pivot to adjacent insider channels in the same window - USB activity, personal webmail, cloud upload - printing rarely stands alone when intent is malicious.
8. Loop in HR/Legal per policy before any user contact, device seizure, or physical retrieval of printed material.

## True Positive Indicators

- Bulk or scripted printing of labeled/sensitive content, volume well outside the user's own baseline
- Timing correlates with resignation/termination notice or a known grievance
- Printed to a virtual PDF driver for a Confidential-labeled document with no articulable business reason
- Content has no relationship to the user's job function or current project assignment
- DLP shows a Block-then-user-override rather than a routine audit hit
- Corroborating exfil activity (USB, personal email, cloud upload) in the same session

## False Positive/Benign Positive Indicators

- Volume matches a known recurring task (month-end binder, board packet, legal production, contracts requiring wet signature)
- Manager-approved or ticket-backed printing (compliance retention job, audit prep, HR paperwork)
- Printer and timing match the user's normal desk, role, and working hours
- DLP match is a template/example pattern (sample SSN in a training doc) rather than real data
- User readily explains the print with a verifiable, unremarkable business reason

## Escalation Criteria

Escalate to Tier 2/Insider Risk and notify HR/Legal when sensitivity-labeled or DLP-matched content is printed by a user in a departure window, when volume is a sharp outlier with no ticket or manager sign-off, when the destination is a virtual PDF driver for labeled content, or when the print event co-occurs with another exfil-adjacent signal. If the account shows unrelated compromise indicators (impossible-travel login, unfamiliar device), redirect the case to credential-compromise handling before treating it as insider intent.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Tighten the relevant DLP print policy from Audit to Block for the matched sensitivity label - DLP policy owner approval, change-managed.
- Retrieve print-server job logs and, where feasible, the physical printer's retained job queue - Tier 2, no separate approval, log in the case.
- Suspend the user's print-to-virtual-driver capability or restrict printer access pending review - manager/security lead approval, coordinate with the user's manager given workflow impact.
- Physical retrieval of printed material from the device output tray or mailroom - requires HR/Legal sign-off and chain-of-custody documentation.
- Account access review or suspension tied to the broader case - HR + Legal + manager approval, given employment implications.

## Example Query (Microsoft Sentinel / KQL)

```kql
Event
| where Source == "Microsoft-Windows-PrintService" and EventID == 307
| extend Doc = extract(@"Document\s+(.+?),", 1, RenderedDescription)
| extend Pages = toint(extract(@"Pages Printed:\s+(\d+)", 1, RenderedDescription))
| where Pages > 100 or hourofday(TimeGenerated) !between (7 .. 19)
| project TimeGenerated, Computer, Doc, Pages
| order by TimeGenerated desc
```

## Closure Criteria

Close as **True Positive** once the document's sensitivity, the user's lack of legitimate business need, and (where present) corroborating exfil signals are confirmed, and containment/HR actions are logged. Close as **Benign Positive** when a manager-approved or policy-driven business reason accounts for the volume and content. Close as **Insufficient Evidence** when the PrintService operational log wasn't enabled, the print server retains no job history past its rotation window, or DLP coverage didn't extend to that printer/device - log the telemetry gap as a follow-up so print auditing gets enabled going forward rather than silently accepting the blind spot.

**Example case note:** *"User j.alvarez (Sales, WKS-SLS-022) submitted 14 print jobs to \\PRNSRV01\\HP-Floor3 between 21:40-22:10 local, totaling 340 pages. Microsoft Purview DLP logged a match against the 'Customer PII' sensitive-info-type on 11 of the 14 documents, policy action Audit. Sysmon shows the jobs originated from `EXCEL.EXE` iterating over exported CRM reports, consistent with a scripted export-then-print pattern (T1119). HR confirms j.alvarez submitted resignation notice three days prior, last day in 11 days. Printer floor matches badge location at the time. No corroborating USB or webmail activity found in the same window. Case escalated to Insider Risk and HR/Legal; printed output retrieval requested from Facilities under CoC-3104. Verdict: True Positive, T1119/T1078.002, pending HR/Legal disposition."*
