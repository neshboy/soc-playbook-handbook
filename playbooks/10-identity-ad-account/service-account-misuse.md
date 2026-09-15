# Service Account Misuse

**Category:** Identity & Active Directory - Account & Authentication
**Playbook ID:** IAM-011

Service accounts are the accounts nobody watches, which is exactly why they're worth watching. There's no human sitting behind `svc-sql-backup` who'll notice their own session looks weird, no MFA prompt to defeat, and in most environments the password was set once during a project three years ago and never touched again because rotating it risks breaking whatever batch job depends on it. Add in the fact that plenty of service accounts sit in privileged groups "temporarily" from some migration that finished eighteen months ago, and you've got a class of identity that's simultaneously high-value and low-scrutiny - a combination attackers like a lot. This playbook isn't about every 4624 a service account generates (that's most of your DC's logon volume on some domains); it's about the account doing something outside the narrow, boring, repetitive pattern it's supposed to have.

## Business Risk

**[STAKEHOLDER]** - Service accounts routinely hold access that would make a human user's security team nervous: database read/write across an entire application estate, backup agent rights that touch every file share, or in some cases Active Directory replication rights used by backup and identity-sync tooling (the same rights DCSync abuses). Because there's no person attached, misuse doesn't show up in the places anomaly detection usually looks - no unusual travel, no new device enrollment, no help-desk password reset call. A compromised or misconfigured service account is one of the quieter routes to broad data access or domain-level compromise, and it's often discovered only after something downstream breaks or an auditor asks why an account no one recognizes has Domain Admin.

## Severity / Priority Default

- **Default:** High (P2) - deviation from a service account's documented behavior pattern starts here.
- **Escalates to Critical (P1)** when the account authenticates with an interactive logon type, shows a Kerberoasting-consistent ticket-request pattern against a privileged/SPN-bearing account, or is used to install a service or scheduled task on a host outside its normal footprint.
- **De-escalates to Medium (P3)** only once the app/service owner confirms the activity against a change record or the service-account inventory - never de-escalate on "probably just the backup job" without checking.

## MITRE ATT&CK Techniques

- **T1078 Valid Accounts** (.002 Domain Accounts) - the account is legitimate; the abuse is in how it's being used or who's using it
- **T1558 Steal or Forge Kerberos Tickets** (.003 Kerberoasting) - service accounts with an SPN registered are the direct target of this technique; offline cracking of the harvested ticket happens well outside your telemetry
- **T1003 OS Credential Dumping** (.006 DCSync) - relevant where the service account holds Replicating Directory Changes / Replicating Directory Changes All rights, common for backup and identity-sync tooling
- **T1550 Use Alternate Authentication Material** (.002 Pass the Hash) - static, rarely-rotated service account passwords are attractive hash-reuse targets
- **T1021 Remote Services** (.002 SMB/Windows Admin Shares) - lateral movement using a service account's admin-share access
- **T1053 Scheduled Task/Job** (.005 Scheduled Task) and **T1543 Create or Modify System Process** (.003 Windows Service) - persistence mechanisms built to run under a harvested service account's credentials
- **T1087 Account Discovery** / **T1069 Permission Groups Discovery** - reconnaissance that typically precedes targeting a specific service account once its privileges are mapped

## Trigger / Detection Logic Summary

Fires when an account tagged as a service account (naming convention, dedicated OU, or a maintained service-account inventory/CMDB tag - group managed service accounts included) generates one or more of:

1. A 4624 with a Logon Type outside the account's documented expected type (interactive Type 2/10 on an account that should only ever show Type 4/batch or Type 5/service).
2. A 4624/4648 from a source host not on the account's approved host list (the fixed app/DB/backup server set it should run from).
3. A spike in 4769 requests for the account's SPN with Ticket Encryption Type RC4 (0x17), especially from a single requesting source in a short window (Kerberoasting signature).
4. Use of the account to install a service (4697/7045) or scheduled task (4698) on a host outside its normal footprint.
5. A 4738 change to the account showing SPN added/removed, "Password Never Expires" toggled, or pre-authentication requirements altered.

## Required Log Sources & Event IDs

| Source | Event IDs | Why |
|---|---|---|
| Domain Controller Security log | 4624, 4625, 4634, 4647 | Logon lifecycle - confirms logon type, source, and whether the session ended normally |
| Domain Controller Security log | 4672 | Special privileges on the token - should almost never appear on a standard-tier service account |
| Domain Controller Security log | 4768, 4769, 4771 | Kerberos TGT/service-ticket requests - ticket encryption type is the Kerberoasting tell |
| Domain Controller Security log | 4776 | NTLM fallback validation and source workstation for legacy auth paths |
| Source/target endpoint Security log | 4648, 4688 | Explicit-credential use and what actually ran under the account's Logon ID |
| Security log (SCM) / System log | 4697 / 7045 | New service installed using this account as the run-as identity |
| Domain Controller Security log | 4698 | Scheduled task created to run as this account |
| Domain Controller Security log | 4738, 4728, 4732 | Attribute or group-membership changes affecting the account's privilege footprint |
| Endpoint PowerShell logs | 4103, 4104 | Scripted activity executed in the account's session context |

## Key Fields to Inspect

**[ANALYST]**
- **Logon Type on 4624** - a service account should sit on a narrow, boring set (Type 5/service, Type 4/batch, sometimes Type 3/network for a defined app tier). Type 2 or Type 10 showing up is the single strongest anomaly this playbook watches for.
- **Workstation Name / Source Network Address** - compare against the account's documented host list. Service accounts shouldn't roam; if one shows up authenticating from a laptop subnet, that's not a rounding error.
- **Ticket Encryption Type (4769)** - RC4 (0x17) requests against an SPN-bearing account, particularly in volume or clustered from one source touching several service accounts, is the Kerberoasting pattern. One request isn't noise-free either, but volume and breadth matter more than a single hit.
- **Process Name on 4688** under the account's Logon ID - expected is the application binary (`sqlservr.exe`, `backupexec.exe`, `veeamagent.exe`); `powershell.exe`, `cmd.exe`, `whoami.exe`, or unsigned binaries are not.
- **Account Whose Credentials Were Used (4648)** - explicit use of a service account's credentials from an interactive human session is a strong lateral-movement/credential-theft indicator, not routine app behavior.
- **Changed Attributes on 4738** - watch specifically for SPN additions/removals, `PasswordNeverExpires` flips, or `Do not require Kerberos preauthentication` being enabled (sets up AS-REP roasting).
- **Service Account field on 4697/7045** - confirms whether a newly installed service is running under this identity somewhere it's never run before.

## Normal vs Suspicious Pattern

| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Logon Type | Consistent Type 4/5, occasionally Type 3 for a documented app tier | Type 2 or Type 10 (interactive/RDP) on an account with no interactive-use case |
| Source host | Fixed, small set of app/DB/backup servers, unchanged for months | New host, workstation subnet, or an external/unfamiliar IP |
| Kerberos ticket pattern | Low, steady 4769 volume tied to normal app authentication cycles | RC4 spike against the SPN, especially from one source hitting multiple service accounts |
| Process activity post-logon | Expected application binary only | Interpreter/shell activity, discovery commands, credential-access tooling |
| Account attributes | Stable - SPN, password policy, group membership unchanged for long periods | Recent SPN change, preauth flag flipped, sudden group membership change |
| Privilege level | Scoped to what the app actually needs | Broad/unexplained membership in Domain Admins, Account Operators, or replication-rights groups |

## Investigation Steps

1. Confirm the account is a designated service account - check the service-account inventory/CMDB, AD description field, or OU placement - and pull its documented owner, purpose, and approved host list.
2. Baseline expected logon type, source host(s), and schedule from that inventory or from 60-90 days of historical 4624 activity if no formal baseline exists.
3. Compare the triggering event(s) against baseline: flag deviations in logon type, source host, and timing specifically, not just "an alert fired."
4. Pull 4769 volume for the account's SPN over the prior 24-72 hours - check ticket encryption type and whether one source is requesting service tickets for several different accounts (broader roasting sweep vs. isolated request).
5. Review 4688 process creation under the account's Logon ID on the source host - expected application binary, or interpreter/recon/lateral-movement tooling.
6. Check for account manipulation (4738, 4728/4732) and persistence artifacts (4697/7045, 4698) created by or targeting this account.
7. Contact the app/service owner and check change records - service account "owners" turn over constantly, so verify against tickets, not memory alone.
8. Map the account's actual reach (group membership, database/share ACLs) so containment decisions account for blast radius, not just the credential itself.

## True Positive Indicators

- Interactive logon (Type 2/10) confirmed on an account documented as service-only, with no owner explanation.
- Kerberoasting-consistent ticket pattern: RC4 requests against a privileged SPN account, especially clustered with requests against other service accounts from the same source.
- 4648 shows the service account's credentials used explicitly from a human's interactive session.
- Process creation under the account shows PowerShell, command shell, or discovery/credential-access tooling instead of the expected application.
- New service (4697/7045) or scheduled task (4698) created to run under the account on a host outside its normal footprint.
- Account holds `PasswordNeverExpires` plus broad privileged group membership or replication rights - a high-value finding on its own, warranting a remediation ticket even absent active misuse.

## False Positive / Benign Positive Indicators

- New deployment, migration, or DR failover legitimately shifts the account's source host - confirm against the change ticket or DR runbook before dismissing.
- Off-hours batch run matches a documented maintenance/backup window.
- Kerberoasting-pattern ticket requests trace back to an authorized vulnerability scanner, PAM discovery tool, or SIEM asset-enumeration job - check the scanning/PAM tool inventory, this is one of the most common false-positive sources for this exact detection.
- Account recently onboarded to a new host as part of documented infrastructure work, just not yet reflected in the service-account inventory - benign, but log it as an inventory-tuning gap.

## Escalation Criteria

Escalate to Tier 2 / IR immediately if:
- Interactive logon is confirmed with no owner or change-ticket explanation.
- A Kerberoasting-consistent pattern targets a privileged or replication-rights-holding service account.
- Post-logon process activity shows credential-dumping or discovery tooling.
- A service or scheduled task is created using this account's identity on an unexpected host.
- The account holds DCSync-equivalent replication rights and any anomalous activity is present at all - treat these as Tier-0-adjacent regardless of the account's mundane name.

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Approval Needed | Notes |
|---|---|---|
| Kill active session (Logon ID) | Tier 2 analyst, standard SOP on suspected TP | Fast, low-collateral first step |
| Reset service account password | App/service owner + change coordination, IAM team execute | Coordinate timing - resetting blind can break the dependent application; gMSA-managed accounts rotate automatically and need a different response path |
| Restrict "Log on to these workstations" / apply logon-restriction GPO | IAM/AD platform owner | Scopes the account to its approved hosts going forward |
| Disable account | IR lead + app owner joint sign-off | Outage risk is real - confirm nothing production-critical breaks first, unless active compromise outweighs that risk |
| Review/reduce group membership and ACL scope | IAM owner, governance track | Longer-term fix once the account's actual required access is confirmed against what it currently holds |

Review cadence: service-account inventory and privilege scope reviewed quarterly by the IAM owner; any confirmed misuse finding feeds a standing remediation backlog item (least-privilege cleanup, gMSA migration where feasible) tracked outside the incident itself.

## Example Query (Splunk SPL)

```spl
index=wineventlog EventCode=4769
| lookup service_account_watchlist Account_Name OUTPUT is_service_account
| where is_service_account="true" AND Ticket_Encryption_Type="0x17"
| stats count dc(Account_Name) as distinct_targets by Client_Address
| where distinct_targets > 3 OR count > 20
```

## Closure Criteria

Close as **True Positive** once source, logon-type deviation or ticket-request pattern, and any follow-on process/persistence activity are fully scoped, containment applied (session kill, password reset, or logon restriction), and the app owner and IAM team notified. Close as **Benign Positive** when a change ticket, DR event, or authorized scanning tool fully explains the deviation - update the service-account inventory so the same pattern doesn't re-alert. Close as **Insufficient Evidence** only when the app owner cannot be reached within SLA and no follow-on indicators (credential dumping, persistence, privileged ticket-request patterns) appear after 24 hours - keep the account on active watch rather than closing clean.

**Example case note:**
`2026-09-15 04:22 UTC - svc-web-app (tagged service account, owner: Platform-Eng) generated 4624 Logon Type 10 from 10.12.4.87, a host outside its documented approved list (APP01/APP02 only). Preceding 4769 activity shows 5 RC4-encrypted service-ticket requests against distinct SPN accounts from the same source in an 8-minute window. 4688 on 10.12.4.87 shows powershell.exe spawned under the account's Logon ID immediately after logon. Platform-Eng could not confirm initiating the session. Escalated to Tier 2 - session killed, password reset coordinated with app team, host 10.12.4.87 referred for EDR triage. Pending scope of Kerberoasting sweep before final disposition.`
