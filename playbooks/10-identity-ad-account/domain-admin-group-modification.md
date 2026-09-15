# Playbook: Domain Admin Group Modification

**Playbook ID:** IAM-014
**Category:** Identity & Active Directory — Account & Authentication
**Applies to:** On-prem Active Directory (Domain Admins, Enterprise Admins, Schema Admins, and Builtin\Administrators on Domain Controllers)

## Business Risk

**[STAKEHOLDER]** - Domain Admins is the keys-to-the-kingdom group. Anyone who lands in it can read or reset every credential in the domain, push group policy to every endpoint, and stand up their own persistence long after the initial foothold is cleaned up. A single unauthorized addition here is functionally equivalent to a full domain compromise, and it's usually the pivot point right before ransomware deployment or mass data theft. This is one of the handful of alerts in the entire SOC catalog that justifies waking someone up at 3 a.m.

## Severity / Priority Default

**Critical (P1)** for any *unexpected* addition to Domain Admins, Enterprise Admins, or Schema Admins. Downgrade to **High (P2)** only after the change is confirmed to map to an approved, ticketed change request performed by a known Tier 0 administrator from an approved PAW (Privileged Access Workstation).

## MITRE ATT&CK Mapping

- **T1098** Account Manipulation — adding an existing account to a privileged group
- **T1136** Create Account — precursor pattern: attacker creates a throwaway account, then promotes it
- **T1078.002** Valid Accounts: Domain Accounts — abuse of the resulting privileged account for further access
- **T1531** Account Access Removal — removal from Domain Admins used destructively (locking out legitimate admins, sabotage)
- **T1003.006** OS Credential Dumping: DCSync — common follow-on once Domain Admin rights are obtained

## Trigger / Detection Logic Summary

Fires on any **4728** (member added to security-enabled global group) or **4732** (member added to security-enabled local group) event where the Group Name matches Domain Admins, Enterprise Admins, Schema Admins, or Builtin\Administrators on a Domain Controller. A parallel rule should fire on **4729/4733** (removal) for the same groups — removal of a legitimate admin is just as serious as addition of an illegitimate one. Correlate the Subject of the change event against a known-admin allowlist and an approved-change-ticket list; anything not on both lists escalates automatically.

## Required Log Sources & Event IDs

| Source | Event ID(s) | Purpose |
|---|---|---|
| Security log (DC) | 4728, 4729 | Domain Admins / Enterprise Admins / Schema Admins membership change (global group) |
| Security log (DC) | 4732, 4733 | Builtin\Administrators membership change (local group on DC) |
| Security log (DC) | 4624, 4672 | Logon session and privilege context of the Subject performing the change |
| Security log (DC) | 4720, 4738 | Precursor account creation or attribute change (new account promoted shortly after creation) |
| Security log (DC/mgmt host) | 4688 | Process used to make the change (dsa.msc, PowerShell, net.exe, ldifde) |
| PowerShell/Operational | 4103, 4104 | `Add-ADGroupMember` / `Add-ADPrincipalGroupMembership` invocation and script block content |
| Security log | 1102 | Log clearing immediately before/after the change (anti-forensics) |
| Security log (DC) | 4769 | Follow-on Kerberos service ticket requests indicating DCSync abuse (Directory Replication Service) |

## Key Fields to Inspect

**[ANALYST]**
- **Subject Account Name / Domain / Logon ID** on the 4728/4732 event — who made the change, and tie the Logon ID back to the originating 4624 to get logon type, source IP, and workstation.
- **Member Name / Member SID** — the account being added or removed. Check creation date (4720), whether it's a service account, a stale/dormant account, or a newly minted account.
- **Group Name / Group SID** — confirm it's actually Domain Admins/Enterprise Admins/Schema Admins/Administrators and not a similarly-named custom group.
- **Source Network Address / Workstation Name** on the correlated 4624 — was this done from a Tier 0 PAW, a jump host, or a random workstation/laptop that has no business touching AD?
- **Process Name** on 4688 — dsa.msc and PowerShell ISE from a PAW is normal; `net.exe group "Domain Admins" /add` run from a workstation is a red flag.
- **4104 script block text** — full command used, including any `-Credential` flag pointing at an account other than the interactive user (possible use of stolen creds).

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Change tied to an approved ticket number, performed during a scheduled change window | No ticket, off-hours (nights/weekends), performed under investigation pressure to move fast |
| Subject is a known Tier 0 admin, logging on from a designated PAW | Subject is a helpdesk/service account, or a workstation-tier asset never seen touching AD before |
| Member added is an existing, known human admin account with a documented business reason | Member added is newly created (4720 minutes earlier), a service account, or an account with no prior domain activity |
| Single, isolated addition | Addition followed by DCSync-pattern 4769 requests, or by 1102 log clearing, or by removal of other legitimate admins (T1531) |

## Investigation Steps

1. Pull the raw 4728/4732 (or 4729/4733) event and confirm the exact Group Name/SID and Member Name/SID — rule out a similarly named non-privileged group as a false alarm source.
2. Identify the Subject and correlate the Logon ID to the originating 4624/4672 to establish source IP, workstation, logon type, and whether the session already carried admin-equivalent privileges.
3. Check whether the change maps to a documented change ticket. Contact the named admin directly (out of band — not over an account that may be compromised) to confirm they performed the action.
4. Review the Member account's history: 4720 creation time, last logon, group memberships, whether it's flagged as a service account or dormant/orphaned account (T1136/T1078.002 precursor chain).
5. Pull 4688/4103/4104 around the timestamp on the Subject's host to identify the exact command or GUI tool used, and whether it was scripted/automated (batch changes suggest tooling, not a human clicking through ADUC).
6. Search the surrounding 15–30 minutes on the same DC/domain for 1102 (log clearing), 4725/4726 (other accounts disabled/deleted), or 4729/4733 removals affecting other legitimate admins.
7. Check for DCSync indicators: 4769 requests for the `krbtgt` or Directory Replication service from the newly-privileged account or its source host shortly after the addition.
8. If the account is confirmed rogue, pivot to lateral-movement telemetry (4624/4648 with the compromised or newly-privileged account) to scope how far it's already moved.

## True Positive Indicators

- No matching change ticket, and the named admin denies performing the action.
- Member added is a newly created, service, or previously-dormant account.
- Change originates from a non-PAW asset or an unusual geographic/source IP.
- Followed by 1102 log clearing, DCSync-pattern 4769 activity, or removal of legitimate admins.

## False Positive / Benign Positive Indicators

- Change matches an approved ticket, performed by the named admin from their usual PAW during a change window.
- Routine access review/re-certification cycle (e.g., quarterly access recertification adding a newly promoted sysadmin).
- Automated identity governance tooling (e.g., PAM/PIM just-in-time elevation) performing a scoped, time-boxed addition that auto-expires — confirm the removal event fires on schedule.

## Escalation Criteria

Escalate immediately to Incident Response / CISO if: the Subject denies the action, the added account cannot be attributed to a known employee, 1102 or DCSync indicators are present, or a legitimate admin was *removed* without a change ticket. Any confirmed unauthorized Domain Admin addition is a sev-1 incident — treat as active domain compromise until scoped otherwise, not a routine ticket.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- **Immediate removal from the privileged group** — AD Tier 0 admin team, no approval delay required once confirmed unauthorized (standing emergency authority, documented after the fact to CISO).
- **Disable the offending account** — Tier 0 admin lead; if the account is a legitimate employee's compromised account, coordinate with HR/Legal before disabling if it's tied to an active investigation.
- **Force krbtgt password reset (twice)** — requires IR lead + AD architecture sign-off; only for confirmed Golden Ticket/DCSync exposure, done in a controlled maintenance window given domain-wide impact.
- **Isolate source host** — SOC on-call authority, standard containment SLA.
- Post-incident: mandatory review of all Domain Admins/Enterprise Admins members and password reset for the entire Tier 0 group if compromise scope is unclear.

## Example Query (Sentinel/KQL)

```kql
SecurityEvent
| where EventID in (4728, 4729, 4732, 4733)
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| extend Actor = SubjectUserName, MemberChanged = MemberName
| where Actor !in (KnownTier0Admins) // reference watchlist
| project TimeGenerated, EventID, Computer, Actor, MemberChanged, TargetUserName
```

## Closure Criteria

Close as **True Positive** only after the unauthorized member is removed, the source of the change is contained, and DCSync/log-clearing follow-on activity has been ruled out or separately actioned. Close as **Benign Positive** when the change matches an approved ticket and named admin confirmation, or as **Expected Activity** for PIM/PAM-driven just-in-time elevations that expire on schedule.

**Example case note:** *"4728 on DC01 added svc-backup-01 to Domain Admins at 02:14 local, no change ticket on file. Subject jdoe-adm confirmed via phone he did not perform this action; jdoe-adm's session (Logon ID 0x3F2A1) originated from 10.12.44.201, a marketing-subnet laptop, not his usual PAW. Removed svc-backup-01 from Domain Admins, disabled account, isolated source host. 4769 review shows one Directory Replication-style request from svc-backup-01 12 minutes after the addition — escalated to IR as confirmed DCSync, krbtgt reset scheduled."*
