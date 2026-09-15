# New Account Creation

**Playbook ID:** IAM-008
**Category:** Identity & Active Directory - Account & Authentication

## Business Risk

**[STAKEHOLDER]** - Every new account is a new key cut for the building. Most of them are legitimate - HR onboarded someone, IT stood up a service account, a contractor started Monday. The risk isn't the volume, it's the small percentage that aren't legitimate: an attacker who already has a foothold creating a backup account so they survive password resets and offboarding, or a departing admin planting a account nobody will notice for months. This playbook exists so that account creation is *reconciled*, not just logged - someone with authority confirms every new identity was supposed to exist.

## Severity / Priority Default

**Medium** as a baseline (informational-to-medium for routine HR-driven creation reconciled against ticketing). Escalates to **High** when the creating account is not a designated identity-management service or a small, named group of Tier 0 admins, when creation happens outside business-change windows, when the new account is immediately added to a privileged group, or when creation follows suspicious authentication activity from the same actor within the prior few hours.

## MITRE ATT&CK Techniques

- **T1136** Create Account (primary technique for this playbook; sub-technique for on-prem AD accounts is Domain Account creation, cloud identity provider account creation maps to the cloud-account variant)
- **T1078.002** Valid Accounts: Domain Accounts (the created account becomes the persistence mechanism going forward)
- **T1098** Account Manipulation (frequently chained immediately after creation - group membership added, attributes set, mailbox delegation configured)
- **T1069** Permission Groups Discovery (often precedes creation, as the actor enumerates which group grants the access level they want)

## Trigger / Detection Logic Summary

Alert fires on **Event ID 4720** (user account created) correlated against an allow-list of expected creator identities (your HR-joiner-process service account, your identity governance platform's service account, or a defined Tier 0 admin group). A secondary, higher-priority path fires when a 4720 is followed within a short window (recommend 15-30 minutes, tune to your environment) by **4728/4732** (group membership added) placing the new account into a privileged or sensitive group before any legitimate onboarding workflow (mailbox provisioning, ticket closure) would reasonably have run.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Domain Controller Security log | 4720 | Account created - the core trigger |
| Domain Controller Security log | 4722 | Account enabled (created accounts are enabled by default in most tooling, but flows that create-then-enable separately are worth noting) |
| Domain Controller Security log | 4738 | Account changed - attribute tampering shortly after creation (UPN, SPN, description, userAccountControl flags) |
| Domain Controller Security log | 4728 / 4732 | Added to global / local security-enabled group - privilege assignment |
| Domain Controller Security log | 4724 | Password reset by someone else - watch for the creator immediately resetting the password again post-creation |
| Domain Controller Security log | 4672 | Special privileges assigned - if the new account authenticates and already holds admin-equivalent rights |
| Domain Controller Security log | 4624 / 4625 | First successful/failed logon of the new account - tells you if and when it was actually used |
| Domain Controller Security log | 4768 | Kerberos TGT request - confirms first real authentication and source IP |
| Domain Controller Security log | 1102 | Audit log cleared - if this precedes or follows creation, treat the whole chain as high severity |
| PowerShell Operational log | 4104 | Script block content if `New-ADUser`, `New-LocalUser`, or a bulk-provisioning script was used interactively |
| HR / ITSM ticketing system | N/A | The out-of-band source of truth - was there an approved request tied to this identity |

## Key Fields to Inspect

**[ANALYST]**
- **Subject Account Name / SID / Domain** on the 4720 - who actually ran the creation, not who they claim to be. Cross-check this against your list of approved provisioning identities.
- **New Account Name, SAM Account Name, SID, Domain** - does the naming convention match your standard (e.g., `firstname.lastname` vs an oddly generic name like `svc_temp` or `admin2`)?
- **Target Account attributes on the paired 4738** if one closely follows - watch for `userAccountControl` flag changes (password never expires, smartcard not required), `servicePrincipalName` additions (SPN on a "user" account is a Kerberoasting setup, T1558.003), or UPN changes that could enable UPN-spoofing style confusion attacks.
- **Group Name/SID on any 4728/4732** immediately after - Domain Admins, Enterprise Admins, Backup Operators, or any group with GPO-linked rights are the ones to jump on immediately.
- **Logon Type and Source Network Address on the first 4624** for the new account - a first logon from an unfamiliar subnet, a VPN egress IP, or a jump host you don't associate with onboarding is a red flag.
- **Workstation Name and Process Name on the 4720 itself** - was this done from a domain controller console directly, from a normal admin workstation via RSAT, or from a scripting host that has no business creating accounts?

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Creator identity | HR-integration service account, identity governance platform, named Tier 0 admin during a scheduled onboarding batch | A helpdesk account, a server/workstation service account, or a Tier 0 admin acting outside their normal hours/pattern |
| Timing | Business hours, aligned to a documented start date or change ticket | Nights, weekends, immediately after a security incident, or immediately after that same admin account showed unusual authentication behavior |
| Naming convention | Matches HR-driven standard (`jdoe`, `jane.doe`) | Generic, deceptive, or near-duplicate of an existing privileged account (`administrator1`, `svc-backup2`) |
| Group assignment timing | Assigned hours/days later through the normal access-request workflow, often a different actor than the creator | Assigned to a privileged group within minutes of creation by the same actor who created it |
| First use | First logon days later, from an expected corporate subnet or VPN pool, matching a device the new hire was issued | First logon minutes after creation, from an unexpected source, or never followed by any HR onboarding artifacts (mailbox creation, welcome email) at all |
| Ticket correlation | Ticket number present, approver named, matches the account details | No corresponding ticket, or a ticket that was self-approved |

## Investigation Steps

1. Pull the raw 4720 event. Record Subject Account Name/SID, New Account Name/SID, timestamp, and the DC that processed it.
2. Check the creator identity against your approved-provisioner list. If it's not on the list, treat this as a priority investigation regardless of anything else you find.
3. Query the ticketing/HR system for a matching request. No ticket, mismatched name, or a self-approved request all warrant escalation.
4. Pivot on the new account's SID and look for every 4738/4728/4732/4724 event in the following 24-48 hours. Build a timeline of exactly what was done to this identity and by whom.
5. Check for the account's first authentication (4624/4768). Note source IP, logon type, and whether it lines up with an issued device/location for that user.
6. Check whether the creating account itself has any preceding anomalies in the prior 24-72 hours - failed logons (4625), unusual 4648 explicit-credential usage, new 4688 process activity, or PowerShell script-block logs (4104) referencing `New-ADUser`, `dsadd`, or bulk-import scripts you don't recognize.
7. If the creating account is a service account, verify whether it was used from its expected host only. A service account authenticating interactively from an unexpected workstation is a strong sign of credential theft, not legitimate automation.
8. Confirm with HR/hiring manager or the named ticket approver directly if anything remains ambiguous after log review - don't let the case sit on "probably fine."

## True Positive Indicators

- Creator account is outside the approved provisioner list and cannot produce a corresponding ticket/approval.
- New account added to a privileged group (Domain Admins, Enterprise Admins, DNSAdmins, Account Operators, any Tier 0 GPO-scoped group) within minutes of creation.
- New account's `userAccountControl` set to password-never-expires or similar persistence-friendly flags, or an SPN attached to what should be a normal user object.
- First authentication comes from an IP/ASN with no relationship to the organization, or via VPN/proxy infrastructure the legitimate new hire would have no reason to use yet.
- Creation immediately follows a 1102 log-clear event, a disabling of audit policy (4719), or known compromise indicators on the creator's own account.

## False Positive / Benign Positive Indicators

- Creator is the HR provisioning pipeline or identity governance tool, timestamp matches a documented start date, ticket exists and is approved.
- Batch creation event - multiple 4720s in a tight window from the same identity-management service account, consistent with a bulk onboarding run (new cohort, contractor batch, M&A migration).
- Service account creation by an approved platform team during a documented change window, with naming matching your `svc_` or equivalent standard, and group membership limited to what the change ticket specifies.
- Test/lab account creation in a non-production OU, clearly scoped and time-boxed, per a documented testing procedure.

## Escalation Criteria

Escalate to Tier 2/IR immediately if: the creator is not an approved provisioner and there is no ticket; the new account is placed into any Tier 0 group; the sequence correlates with a 1102 log-clear or recent audit-policy change (4719); or the creator identity shows any independent sign of compromise (impossible-travel logons, unusual 4648 usage, prior alert history). Escalate to identity/IAM engineering (not necessarily IR) if the pattern looks like a broken automation (e.g., the HR pipeline double-firing) rather than malicious activity - still needs a fix, just not a P1.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- **Disable the account (4725-equivalent action)** - SOC Tier 2 can execute unilaterally on any account with no verified business owner or ticket; requires no additional sign-off given the low blast radius of disabling an unused/unverified identity.
- **Remove from privileged group** - SOC Tier 2 can execute immediately if the addition itself is unauthorized; notify the domain admin team lead within the hour regardless of outcome.
- **Full account deletion** - requires IAM team or domain admin approval; SOC does not unilaterally delete identities, since a mistaken deletion can be more disruptive than a temporary disable.
- **Force password reset / session revocation for the creator account** - requires IR lead approval if the creator is a human admin identity (this is a personnel-sensitive action); can be automatic if the creator is a service account and integrity of the automation is suspect.
- **SLA:** unauthorized privileged-group additions require containment action within 1 hour of confirmed detection; standard unauthorized-creation cases within 4 business hours. Governance review of the approved-provisioner allow-list itself: quarterly, owned by IAM engineering with SOC input.

## Example Query (Microsoft Sentinel / KQL)

```kql
SecurityEvent
| where EventID == 4720
| extend Creator = SubjectUserName, NewAccount = TargetUserName, CreationTime = TimeGenerated
| where Creator !in (ApprovedProvisionerAccounts)
| join kind=leftouter (
    SecurityEvent
    | where EventID in (4728, 4732)
    | project NewAccount = MemberName, GroupName = TargetUserName, GroupChangeTime = TimeGenerated
) on NewAccount
| where isnotempty(GroupName) and GroupChangeTime between (CreationTime .. (CreationTime + 30m))
| project CreationTime, GroupChangeTime, Creator, NewAccount, GroupName, Computer
```

## Closure Criteria

Close as **True Positive** and hand to IR only when unauthorized creation is tied to a compromised admin account or an active persistence attempt with no legitimate ticket. Close as **Expected Activity** when the creator is validated against the provisioner allow-list and a matching approved ticket exists, even if the alert fired due to allow-list gaps that need fixing. Close as **Insufficient Evidence** only after the ticketing system, HR, and the named approver have all been checked and none can confirm or deny the request - re-open immediately if the account authenticates or gains further privilege before that confirmation lands.

**Example case note:** "4720 for new account `r.delgado` created by `svc-hrprovision` at 2026-09-15 09:12 UTC on DC02; matches approved ticket HR-88213 (start date 2026-09-15, hiring manager J. Alvarez); no group membership changes outside standard `Domain Users` and `VPN-Users`; first logon pending, expected day 1 - closing as Expected Activity, no further action."
