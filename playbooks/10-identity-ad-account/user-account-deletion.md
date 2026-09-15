# User Account Deletion

## Playbook ID & Name

**IAM-009 — User Account Deletion**
Category: Identity & Active Directory — Account & Authentication

## Business Risk

**[STAKEHOLDER]** - Deleting a user account is one of the few AD actions that is genuinely hard to reverse cleanly. Group memberships, permissions, mailbox delegation, and SID references can be lost even when the account itself is restored from the AD Recycle Bin, which means a malicious or mistaken deletion can knock out access for a real employee, break a service that authenticates as that account, or — the scenario that actually keeps IAM leads up at night — be used deliberately by an attacker to lock legitimate admins out of a domain or destroy evidence of an account they created earlier in the intrusion.

## Severity / Priority Default

**Medium** as a baseline (routine HR-driven deletions are extremely common and mostly benign). Auto-escalates to **High/Critical** when the target is a privileged account, a service account with production dependencies, or the deletion falls outside a recognized offboarding workflow.

## MITRE ATT&CK Technique(s)

- **T1531** — Account Access Removal (primary technique — deletion used to deny access or disrupt operations)
- **T1098** — Account Manipulation (deletion is frequently the tail end of a manipulation sequence — group strip, then delete)
- **T1078.002** — Valid Accounts: Domain Accounts (the account performing the deletion is itself a compromised valid account in a large share of true positives)
- **T1136** — Create Account (relevant when deletion is followed by recreation of an account under the same or a similar name to reset SID history or hide provisioning activity)
- **T1562.001** — Impair Defenses: Disable or Modify Tools (relevant when the deletion is bracketed by audit log clearing or logging changes)

## Trigger / Detection Logic Summary

Fires on any **4726 (User account deleted)** event, then enriches and filters based on: who the Subject is, whether the target account was privileged or a service account, whether the deletion happened inside an approved change window / ticket, and whether it correlates with suspicious precursor or follow-on activity (group membership removal, audit log clear, off-hours admin logon).

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Security log (DC) | **4726** | Account deletion — the core trigger |
| Security log (DC) | **4725** | Account disabled — often precedes deletion by minutes to weeks |
| Security log (DC) | **4738** | Account changed — check for attribute stripping just before deletion |
| Security log (DC) | **4729 / 4733** | Member removed from global/local group — common precursor as attacker or admin strips access before deleting |
| Security log (DC) | **4720** | Account created — relevant if a look-alike account appears shortly after deletion |
| Security log | **1102** | Audit log cleared — extremely high signal if it brackets a deletion |
| Security log (admin workstation/DC) | **4624 / 4634 / 4647** | Session context for who was logged on and how the session was closed |
| Security log | **4648** | Explicit-credential logon — flags use of RunAs or an alternate privileged account to perform the deletion |
| Security log | **4688** | Process creation — `dsa.msc`, `powershell.exe`, `net.exe`, `csvde.exe`, `ldifde.exe`, ADUC snap-ins |
| Microsoft-Windows-PowerShell/Operational | **4103 / 4104** | Captures `Remove-ADUser` / `Remove-ADObject` cmdlet invocation, including scripted bulk deletions |

## Key Fields to Inspect

**[ANALYST]**

- **Target Account Name / SID / Domain** (4726) — confirm exactly which object was removed; SID matters more than name if a same-named account gets recreated later
- **Subject Account Name / Logon ID** (4726, 4725, 4738) — who actually performed the action, tie the Logon ID back to the originating 4624 to get logon type and source
- **Source Network Address / Workstation Name** (from the correlated 4624) — was this done from the admin's normal jump host, or from an unfamiliar workstation/IP
- **Command Line** on the 4688 for `powershell.exe`, `dsa.msc`, `csvde.exe`, `ldifde.exe` — bulk-deletion scripts usually show up here if command-line auditing is on
- **ScriptBlockText** (4104) — look for `Remove-ADUser`, `Remove-ADObject -Recursive`, or loops reading from a CSV of usernames
- **Changed Attributes** on any 4738 in the hours before deletion — attacker-driven deletions are often preceded by removing group memberships or manager/owner fields
- **Time-of-day and ticket reference** — legitimate offboarding almost always has a HR/ITSM ticket number logged in the change record or IAM tool audit trail; deletions with no matching ticket are the ones to chase

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Deletion performed by the IAM/HelpDesk service account or a named IAM admin, during business hours, tied to an offboarding ticket | Deletion performed by a personal admin account with no ticket reference, or by an account that has never touched user lifecycle objects before |
| Target is a standard user account with a resignation/termination date on file | Target is a Domain Admin, service account, or an account with an SPN, or an account used by a critical application |
| Preceded by a normal 4725 disable during a standard 30/60/90-day offboarding cadence | Deletion happens within seconds/minutes of account creation, group membership changes, or a 1102 audit-log-clear event |
| Single deletion, isolated event | Bulk deletions (multiple 4726 in a short window) or a scripted loop visible in 4104 |
| Deletion during a known migration/cleanup project with change record | Deletion from an unfamiliar workstation, over RDP from an external-facing jump box, or outside the org's normal admin hours |

## Investigation Steps

1. Pull the full 4726 event: capture Target Account Name/SID and Subject Account Name/Logon ID exactly as logged.
2. Correlate the Subject's Logon ID back to its originating **4624** to establish logon type, source workstation/IP, and whether **4648** shows the admin using alternate/explicit credentials rather than their own.
3. Check the IAM/ITSM system (ServiceNow, Jira Service Desk, or equivalent) for a matching offboarding ticket referencing the target account and the timeframe — no ticket is a strong indicator to keep digging.
4. Review the preceding 30 minutes to 24 hours for **4725** (disable), **4738** (attribute changes), and **4729/4733** (group removals) on the same Target Account — establish the full lifecycle sequence, not just the final delete.
5. Check whether the target was privileged (member of Domain Admins, Enterprise Admins, or any Tier-0 group at time of deletion, from historical group-membership data) or a service account (SPN present, used by a scheduled task or service per 4697/7045 history if available elsewhere in the case).
6. Search for a **1102** audit-log-clear event within the same session or a tight window around the deletion — treat any hit as a separate critical finding, not a coincidence.
7. Check for a subsequent **4720** creating an account with the same or a confusingly similar name/UPN, which can indicate SID-history reset or an attempt to quietly re-provision access under a fresh identity.
8. If the Subject account itself looks compromised (unusual source IP, off-hours, credentials used via 4648), pivot the investigation to that account's broader activity before closing — this may no longer be an "account deletion" case, it's an account-compromise case that happens to include a deletion.

## True Positive Indicators

- Deletion performed by an account with no prior history of AD administration, or from a source IP/workstation outside the normal admin fleet
- Target was a privileged, service, or break-glass account
- No corresponding HR/ITSM ticket, or ticket exists but dates/approver don't match
- Deletion bracketed by a 1102 log clear or preceded by group-membership stripping minutes earlier
- Bulk deletion pattern visible across multiple 4726 events in a short window, or a scripted loop in 4104

## False Positive / Benign Positive Indicators

- Automated offboarding pipeline (HR system triggers a service account to run scheduled `Remove-ADUser` jobs) — expect a recurring Subject and a regular cadence, easy to allow-list once verified
- AD hygiene/cleanup project with a documented change record and IAM sign-off
- Test/lab account cleanup by a known engineer, consistent with prior low-risk activity from that account
- Duplicate 4726 for the same object due to multi-DC replication logging — check Domain Controller name field before treating as two separate deletions

## Escalation Criteria

Escalate immediately to Tier 2 / IR if any of the following are true: target was a privileged or service account; deletion has no matching change ticket and the Subject cannot be reached or does not recall performing it; a 1102 event brackets the deletion; the deletion is part of a bulk/scripted pattern; or the Subject account shows other signs of compromise (unfamiliar source, 4648 explicit-credential usage inconsistent with the admin's normal workflow).

## Containment Options & Approval Authority

**[MANAGEMENT]**

- **Restore from AD Recycle Bin (if enabled) or backup** — fastest reversal, but confirm group memberships and SID-dependent permissions come back intact; approval: IAM team lead
- **Disable the Subject account pending investigation** — approval: Security Operations Manager, notify HR/IT if it's an employee-facing admin account
- **Force password reset and session revocation for the Subject account** — approval: Security Operations Manager
- **Freeze all AD write access for the Subject's role/group temporarily** — approval: IAM Director / CISO, reserved for confirmed-compromise scenarios
- **Legal/HR notification** — required whenever the deleted account belonged to an employee under an active termination or investigation, coordinate before any restoration

## Example Query (Microsoft Sentinel / KQL)

```kql
SecurityEvent
| where EventID == 4726
| extend TargetUser = TargetUserName, DeletedBy = SubjectUserName
| join kind=leftanti (
    SecurityEvent
    | where EventID == 1102
    | project TimeGenerated, DeletedBy = SubjectUserName
) on DeletedBy
| where DeletedBy !in ("SVC-IAM-Offboard", "SVC-HR-Deprovision")
| project TimeGenerated, TargetUser, DeletedBy, Computer
```

*(anti-joins out the routine offboarding service accounts, then surfaces any deletion whose Subject also has an unrelated 1102 event for manual correlation — adjust the allow-list to your environment's actual automation accounts.)*

## Closure Criteria

Close as **True Positive** only once the Subject's authorization (or lack of it) has been confirmed against the ticketing system and, where privileged/service accounts are involved, the account has been restored or the business impact formally accepted by the resource owner. Close as **Expected Activity** when the deletion matches a verifiable offboarding ticket or documented cleanup project with no anomalous precursor/follow-on activity. Use **Insufficient Evidence** when command-line auditing was disabled, the ITSM ticket system was unreachable, or the Subject could not be reached to confirm intent within SLA — do not force a verdict just to close the queue.

**Example case note:** *"4726 deleted user jsanders (S-1-5-21-...-1147) at 2026-09-15 14:02 UTC, Subject=amiller (Logon ID 0x4F2A1, source 10.20.4.55, standard admin workstation). Matches ITSM ticket OFF-88213 (termination effective 2026-09-14). No group-membership anomalies, no 1102 in surrounding 24h. No SPN, non-privileged standard user. Closed as Expected Activity — offboarding SLA met."*
