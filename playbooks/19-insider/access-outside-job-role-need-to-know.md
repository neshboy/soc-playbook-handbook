# Playbook INS-011: Access Outside Job Role / Need-to-Know

## Overview

| Field | Detail |
|---|---|
| **Playbook ID & Name** | INS-011 — Access Outside Job Role / Need-to-Know |
| **Category** | Insider Threat |
| **Severity/Priority (default)** | Medium, auto-escalate to High when the out-of-scope resource is regulated/classified data (PII, PCI, HR/compensation, M&A, legal-hold, source code) or the account holds elevated/privileged rights, and to Critical when paired with a resignation/termination flag or any staging/exfil indicator |
| **MITRE ATT&CK** | T1078.002 (Valid Accounts: Domain Accounts) and T1078.004 (Valid Accounts: Cloud Accounts) — primary, the access vector is almost always a legitimate credential the user is entitled to authenticate with, just not entitled to use against this resource; T1087 (Account Discovery) and T1069 (Permission Groups Discovery) — when the user is enumerating who has access to what before pivoting; T1530 (Data from Cloud Storage) and T1538 (Cloud Service Dashboard) — for SaaS/cloud repositories and admin consoles touched outside role; T1119 (Automated Collection) — when a script or scheduled job is doing the out-of-scope pull rather than manual browsing; T1552.001 (Unsecured Credentials: Credentials In Files) — when the access was enabled by finding shared/hardcoded credentials rather than the user's own entitlement; T1098.002 (Account Manipulation: Additional Email Delegate Permissions) — the mailbox-delegation variant of this pattern |

**[STAKEHOLDER]** - This is the "technically allowed, functionally wrong" case: an account that authenticates just fine, that IT would say has valid access, reaching into a system, folder, or mailbox that has nothing to do with that person's job. It's the HR generalist who opens the executive compensation folder, the helpdesk tech who reads the CEO's mailbox after being granted broad delegate rights for a one-time ticket, the contractor who still has read access to the M&A dataroom eight months after the deal closed. None of it necessarily involves malware or a stolen password — it's almost always a least-privilege and access-review failure that an actual human then exploited, or simply stumbled into. Catching it protects against data misuse, and it's also the evidence trail regulators and auditors ask for when they want proof that need-to-know controls actually function, not just exist on paper.

## Trigger / Detection Logic Summary

Fires when an identity's access — file open, folder browse, mailbox read, cloud console/dashboard view, database query, SaaS record view — lands on a resource whose owning department, data classification, or ACL/group scope does not match that identity's HR-recorded job title, department, or cost center. This requires a **role-to-resource mapping** as ground truth: either an explicit entitlement matrix, a resource-owner tag, or a statistically derived "who normally touches this" peer baseline. Unlike volumetric detections (see Mass File Access), a single out-of-scope touch is enough to trigger here — the anomaly is *what* was accessed, not *how much*. Tune for a grace period around role changes (new transfers retain stale group membership for days to weeks) and for approved cross-functional work (audit, e-discovery, incident response) before this becomes a useful low-noise rule rather than a constant false-positive generator.

## Required Log Sources & Event/Operation Data

| Source | What it gives you |
|---|---|
| Active Directory / Entra ID group membership and access review records | Current group/role membership, and — critically — *when* a given membership was granted, so you can tell a fresh grant from years-old entitlement drift |
| Windows Security auditing (Object Access / Account Management subcategories on the target share's SACL) | Access attempts and permission changes on the specific file/folder; confirm exact event numbering against your own audit policy and parser rather than assuming a fixed ID |
| Microsoft 365 Unified Audit Log (now branded Microsoft Purview Audit) | `FileAccessed`, `FileDownloaded`, `MailItemsAccessed`, `Add-MailboxPermission`, `New-InboxRule` against SharePoint, OneDrive, and Exchange Online, with `UserId`, `ObjectId`/`MailboxOwnerUPN`, `SiteUrl` |
| Cloud platform audit logs (Azure Activity Log, AWS CloudTrail, GCP Audit Logs) | Console/dashboard views, resource `Get`/`List`/`Describe` calls against projects or accounts outside the identity's assigned scope |
| DLP / CASB | Sensitivity-label access outside a defined authorized-user group |
| HRIS / IAM feed | Job title, department, cost center, manager, effective date of last role change, contractor end date |
| Access review / attestation tooling | Last certified entitlement, whether this access was flagged and retained, denied, or never reviewed |

## Key Fields to Inspect

**[ANALYST]**
- Accessing identity's current HR department/title vs. the resource owner's department/classification tag
- `ObjectId`/folder path or mailbox UPN accessed, and who the designated owner/authorized-user group actually is
- Date the accessing identity was granted the underlying group membership or permission — fresh grant, or years of stale entitlement nobody revoked
- Whether the access was a single manual view, a repeated pattern, or a scripted/automated pull (check for a service-account or scheduled-task actor vs. an interactive logon)
- Mailbox delegation changes (`Add-MailboxPermission`, `New-InboxRule` with forwarding) and who requested/approved them
- Ticket/change record correlating to the access (audit engagement, incident response, approved cross-functional project)
- Prior access-review outcome for this specific grant — was it certified, flagged, or never reviewed at all

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Access falls within the user's own department's resource scope, or a documented cross-functional role (auditor, IR responder, HRBP) | Access to a resource clearly owned by an unrelated department, with no matching ticket or delegated role |
| Underlying group membership was granted recently for a specific, time-bound project | Group membership is old, was never revoked after a project/role ended, and is now being actively used again |
| Mailbox delegation matches a documented, approved need (assistant, coverage during leave) | Self-service or undocumented delegate grant, followed shortly by reading unrelated mail or setting a forwarding rule |
| One-off access consistent with a known audit/e-discovery cycle | Repeated, escalating access to the same out-of-scope resource over multiple sessions |
| Access-review record shows the entitlement was certified by the resource owner | No record the resource owner ever knew this person had access |

## Investigation Steps

1. **Confirm the mismatch is real.** Pull the accessing identity's current HR job title, department, and manager, and compare against the resource's documented owner/classification. Some "mismatches" are stale HR data, not access violations — verify against the IAM/HRIS system of record, not just what's cached in the SIEM.
2. **Trace the entitlement's origin.** Find out how and when the underlying permission was granted — direct ACL grant, group membership, mailbox delegation, or a shared/found credential. A grant from a two-year-old project that was never revoked reads very differently from a delegation set up yesterday.
3. **Check for a legitimate business reason.** Look for a change ticket, audit engagement, e-discovery hold, incident response activity, or a manager-approved cross-functional assignment that would explain the access before assuming misuse.
4. **Assess what was actually touched, not just that access occurred.** A folder opened and immediately closed is different from files read in sequence, a mailbox searched with keywords, or records exported. Pull the full session detail from the relevant audit log.
5. **Check for repetition and escalation.** Is this a single instance, or has the same identity touched this resource (or expanded to adjacent out-of-scope resources) multiple times? Escalating pattern is a stronger signal than a one-off.
6. **Correlate with HR/lifecycle context.** Recent resignation, PIP, denied promotion, role change, or contractor end date materially changes the read on intent.
7. **Verify with the resource owner and the user's manager — through the correct channel.** Don't tip off the accessing user directly; route through HR/Legal per your insider threat program's process, especially if the resource is regulated data or the mailbox belongs to an executive.
8. **Document and route the access-hygiene finding regardless of intent.** Even a fully benign closure (approved audit work) should generate an access-review action if the underlying entitlement is stale — this playbook doubles as a feed into your least-privilege remediation backlog.

## True Positive Indicators

- Access to a resource with no ticket, no manager approval, and no legitimate cross-functional role explaining it
- Stale entitlement (old project, former role, expired contractor grant) actively exercised long after it should have been revoked
- Self-service mailbox delegation or inbox rule set up by the user without an approval trail, followed by reading unrelated content
- Escalating or repeated access to the same or related out-of-scope resources over time
- Timing aligned with resignation notice, denied promotion, PIP, or a known grievance

## False Positive / Benign Positive Indicators

- Documented audit, e-discovery, incident response, or compliance activity performed by authorized staff under an approved engagement
- Recent role transfer where the new team's access hasn't yet been granted and old access is being used transiently with manager awareness
- Assistant/coverage mailbox delegation set up through the correct approval workflow
- Access-review record showing this exact entitlement was certified by the resource owner as intentional
- Automated job or integration account misclassified as a human identity in the alert

## Escalation Criteria

- Confirmed access to regulated or classified data with no legitimate business justification
- Executive, HR, Legal, or Finance mailbox/dataset accessed by an unrelated department
- Any mailbox delegation or forwarding rule change the account owner did not request or is unaware of
- User has a pending resignation/termination, or the case surfaces alongside any staging/exfil indicator
- Repeat pattern from the same identity after a prior "benign" closure, or the entitlement was flagged in a prior access review and never remediated

Escalate to the Insider Threat Program lead, and loop in HR/Legal before any user-facing action — mailbox and dataroom access cases in particular tend to involve executives or legal-sensitive matters where the wrong first move (a direct user contact, a visible account change) can cause more damage than the original access.

## Containment Options & Approval Authority

**[MANAGEMENT]** - The right first move here is almost always access remediation, not account suspension — the goal is closing the entitlement gap, not necessarily punishing the user, unless intent is already established.

| Action | Approval required |
|---|---|
| Revoke the specific stale group membership/ACL grant | Resource owner + IAM team can act on standard change control; no HR/Legal gate needed if clearly stale/unused |
| Revoke a self-service mailbox delegation or inbox rule | SOC/IT can act immediately if the mailbox owner did not authorize it (treat as account manipulation, not policy discussion) |
| Suspend broader account access pending review | HR + Legal + people-manager sign-off; Security Director emergency authority only if active exfil is confirmed |
| Formal access-review remediation ticket | SOC lead can open; IAM/resource-owner closes per your access-governance cadence |
| Forensic preservation of mailbox/dataset access logs | Legal approval, chain-of-custody procedure, before any user notification |

## Example Query

**[ENGINEERING]** - Microsoft Sentinel KQL joining SharePoint/OneDrive file access against an HR department reference table (ingested as a watchlist) to surface cross-department access:

```kql
OfficeActivity
| where Operation in ("FileAccessed","FileDownloaded")
| extend AccessorUPN = tolower(UserId)
| join kind=inner (
    _GetWatchlist('HR_RoleMap') | project AccessorUPN=tolower(UPN), HR_Dept
  ) on AccessorUPN
| where SiteUrl has_any ("/sites/Finance","/sites/HR","/sites/MandA")
      and HR_Dept !in ("Finance","HR","Corporate Development")
| project TimeGenerated, AccessorUPN, HR_Dept, SiteUrl, SourceFileName, Operation
```

Maintain the `HR_RoleMap` watchlist from your HRIS feed rather than hand-editing it — stale department mappings are the single biggest source of noise in this rule.

## Closure Criteria

Close as **True Positive** (access-scope violation confirmed) when access scope, entitlement history, and HR/lifecycle context together show no legitimate justification, with referral to the Insider Threat Program and, where regulated data is involved, Legal and Privacy. Close as **Benign Positive** when an approved audit, e-discovery, IR, or delegated-coverage engagement fully accounts for the access — document it and, if the underlying entitlement is genuinely time-bound, schedule its removal rather than leaving it standing. Close as **Insufficient Evidence** when the mismatch is real but no owner confirmation, ticket, or intent signal exists either way — open an access-review remediation ticket regardless of the investigative outcome, since the stale entitlement itself is the finding worth fixing even absent misuse.

**Example case note:**

> 2026-09-15 09:40 UTC — User r.okafor (Helpdesk Support, no HR role) accessed the "Compensation_2026" folder on the HR SharePoint site three times over two days, reading four salary-band documents. Entitlement traced to a mailbox-delegation ticket from March 2026 (one-time password reset assist for an HR staff member) that granted broader SharePoint co-access as a side effect and was never revoked. No forwarding rule, download, or external-sharing event found; no HR lifecycle flag on the account. Reported to HR and IAM; delegation and residual SharePoint access revoked same day; access-review remediation ticket AR-2026-0447 opened to audit for similar side-effect grants from the helpdesk ticketing workflow. Closed as Insufficient Evidence for malicious intent; access-hygiene gap confirmed and remediated.
