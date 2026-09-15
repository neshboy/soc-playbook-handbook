# Playbook: Admin Group Membership Change

## Playbook ID & Name

**IAM-007 — Admin Group Membership Change (Domain and Local Privileged Groups)**

Category: Identity & Active Directory — Account & Authentication

## Business Risk

**[STAKEHOLDER]** - Group membership is where access control actually lives. An attacker doesn't need a zero-day if they can just add their foothold account to Domain Admins or the local Administrators group on a Tier 0 server — from that point they can read every mailbox, deploy ransomware fleet-wide, or quietly grant themselves a second, less obvious admin account as a fallback. This is also one of the highest-value insider-risk and process-failure signals in the environment: a surprising number of "unauthorized" admin adds turn out to be a departing employee's parting gift, a contractor who was never offboarded from a delegated group, or a help desk script that over-provisions by accident. Whoever can add a member to a privileged group can, in one action, undo every other control in this book.

## Severity/Priority Default

- **Medium** — addition/removal on a scoped, low-blast-radius local group (e.g., local Administrators on a single non-Tier-0 workstation) performed by a known IT account, no ticket found yet but plausible operational reason.
- **High** — any addition to Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, DnsAdmins, or the built-in Administrators group on a domain controller, where the actor cannot be immediately matched to an approved change; any removal of a legitimate admin account (possible T1531-style access denial or sabotage).
- **Critical** — privileged group change immediately preceded by suspicious authentication (spray/guess success, Pass the Hash/Pass the Ticket indicators), change made by a non-admin token, or change followed by 1102 (audit log cleared) or 4719 (audit policy change) — strong anti-forensics signal that the actor is trying to cover the modification.

## MITRE ATT&CK Techniques

- **T1098 Account Manipulation** — the core technique; adding, removing, or re-scoping group membership on an existing account
- **T1069 Permission Groups Discovery** — frequently precedes the change; attacker enumerates who's already in the target group and what it grants before touching it
- **T1078.002 Valid Accounts: Domain Accounts** — what the attacker is building toward: a durable, "legitimate-looking" privileged identity to operate from afterward
- **T1136 Create Account** — common two-step pattern: create a new account first, then add it to the privileged group in a separate, sometimes delayed, action
- **T1207 Rogue Domain Controller (DCShadow)** — the evasive path; a compromised account with replication rights can inject a group membership change via a rogue DC role, which can suppress the normal 4728/4732 audit trail on the legitimate DCs. If group membership on a critical account changes with no corresponding 4728/4732/4738 anywhere in the domain, don't assume the event is missing on purpose — check replication metadata (`whenChanged`, `uSNChanged`, `Last Originating Change`) instead of trusting the absence of a log entry
- Downstream risk to flag, not detect here: **T1003.006 OS Credential Dumping: DCSync** — a freshly granted replication-capable membership is frequently the setup step for a DCSync pull minutes or hours later

## Trigger / Detection Logic Summary

Correlation rule fires on any of:

- `4728` (member added to a security-enabled **global** group) or `4732` (member added to a security-enabled **local/domain-local** group) where **Group Name** matches a maintained watchlist: Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Server Operators, Print Operators, DnsAdmins, Administrators (Builtin), or the local Administrators group on any asset tagged Tier 0/Tier 1 in CMDB.
- Same logic on removals — `4729`/`4733` against the same watchlist, scored separately since removal of a *legitimate* admin is a different risk (denial of access, T1531) than removal of an attacker's own planted account (cleanup).
- `4738` on a privileged account showing a **Changed Attributes** delta that includes `adminCount` flipping to `1` outside a known provisioning window, or `primaryGroupID` changed to a privileged RID (e.g., 512/519/518) — a quieter path to the same outcome that some analysts miss because they only watch 4728/4732.
- Enrichment, not a standalone trigger: correlate the **Subject** on the 4728/4732 event against an approved-changes list (ITSM ticket, PAM workflow record). No match within a configurable window (default 4 hours) escalates severity automatically.

## Required Log Sources & Event IDs

| Source | Event IDs | Purpose |
|---|---|---|
| Domain Controller Security log | 4728, 4729, 4732, 4733, 4738 | Core group membership add/remove and account attribute change |
| Domain Controller Security log | 4672, 4624, 4648 | Was the actor's own session privileged, and how did they authenticate/connect to make the change |
| Domain Controller Security log | 4719, 1102 | Anti-forensics precursor/follow-up — audit policy tampering or log clearing around the change |
| Domain Controller Security log | 4768, 4769, 4771, 4776 | Authentication context for the Subject account immediately before the change |
| Member server/workstation Security log | 4732, 4733, 4688 | Local Administrators group changes off the DC, and the process (`net.exe`, `PowerShell`, `dsa.msc`) used to make the change |
| PowerShell Operational log | 4103, 4104 | Captures `Add-ADGroupMember`, `net localgroup administrators /add`, or obfuscated equivalents, including de-obfuscated script block text |
| PAM/vault system logs | N/A (vendor-specific) | Confirms whether the change ran through an approved just-in-time elevation workflow |

## Key Fields to Inspect

**[ANALYST]** -

- `4728`/`4732`/`4729`/`4733`: **Member Name**, **Member SID**, **Group Name**, **Group SID**, **Subject** (Account Name/Domain/Logon ID of whoever made the change)
- `4738`: **Changed Attributes**, specifically `adminCount`, `primaryGroupID`, `userAccountControl`, `sAMAccountName` — a rename right before a group add is a known technique to blend a rogue account into normal-looking history
- `4672` correlated to the *Subject's* own Logon ID from the group-change event — confirms whether the person making the change actually held an admin-equivalent token, or whether this was made possible by a delegation misconfiguration
- `4688`: **Command Line** (if auditing enabled) for `net group`, `net localgroup`, `dsadd`, `dsmod`, `Add-ADGroupMember`, ADSIEdit invocation
- `4104`: full script block text — catch `-EncodedCommand` PowerShell wrapping an `Add-ADGroupMember` or `[ADSI]` LDAP manipulation call
- Timing: elapsed time between the Subject's own logon (`4624`/`4768`) and the group change — a change made seconds after an unusual logon (new source, off-hours, new workstation) is a different animal than one made mid-shift from a known admin jump box

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| 4728 add to Domain Admins, Subject = a Tier 0 admin account, tied to an open change ticket, during a scheduled maintenance window | 4728/4732 add with Subject = a service account, help desk account, or any identity not on the Tier 0 admin roster |
| 4732 add to local Administrators on a new server build, immediately after 7045/4697 service install activity as part of provisioning automation | 4732 add on a production server outside any build/change window, especially late night/weekend |
| 4738 adminCount flip during a documented account-tiering migration project | 4738 adminCount flip on a single, otherwise unremarkable user account, with no matching group-add event visible anywhere — check replication metadata for DCShadow-style tampering |
| Removal (4729/4733) of a departed contractor as part of routine offboarding, matched to an HR ticket | Removal (4729/4733) of an active, still-employed admin's account with no offboarding ticket — possible sabotage or attacker clearing a rival/witness admin |
| Change made from the DC console or a hardened PAW, Subject already had 4672 privileges before the change | Change made via `4648` explicit-credential connection from an unusual workstation, or made by an account with no prior 4672 privileged-logon history that session |

## Investigation Steps

1. Pull the raw `4728`/`4729`/`4732`/`4733` event and record **Subject**, **Member Name**, **Group Name**, timestamp, and source (which DC or host logged it).
2. Check the Subject's own authentication trail in the same session: `4624`/`4768` for how they logged on, `4672` to confirm they held a privileged token, and `4648` if the change was made remotely against a DC or server from another host.
3. Validate against change management: is there an approved ticket, PAM elevation request, or known project (Tier 0 migration, new hire onboarding) that accounts for this specific add/remove? No match is not automatically malicious, but it removes the fastest path to a Benign closure.
4. Pull `4688`/`4103`/`4104` around the same timestamp on the Subject's originating host to see exactly what tool or script performed the change — GUI (`dsa.msc`), command line (`net group`), or PowerShell (`Add-ADGroupMember`), including any encoded/obfuscated script block content.
5. Check for anti-forensics bracketing the event: `4719` audit policy changes or `1102` log clearing within the same session or shortly after — either one should push severity to Critical regardless of what else is found.
6. If the Member Name is unfamiliar or recently created, pull its own account history (`4720` creation, prior `4738` changes, first `4624`) — a brand-new account added straight into a privileged group is a strong T1136 → T1098 chain.
7. Assess blast radius: what does this group actually grant (replication rights, local admin on how many hosts, GPO edit rights), and has the newly privileged account/session been used yet — check for `4769` service-ticket requests, `4688` process activity, or EDR telemetry on Tier 0 assets since the grant.
8. Determine disposition and, if confirmed malicious or unauthorized, capture full scope (all groups touched, all accounts added/removed by the same Subject in the surrounding time window — attackers rarely make just one change).

## True Positive Indicators

- Subject has no prior privileged-logon history (no 4672) or authenticated from an unusual source immediately before making the change
- Member added is a recently created, dormant, service, or otherwise unexpected account
- No corresponding change ticket, PAM workflow record, or project after reasonable follow-up with the named Subject/team
- Change bracketed by 4719 audit policy tampering or 1102 log clearing
- Rapid follow-on activity from the newly privileged account (service ticket requests, remote logons, further account/group changes)
- Removal of a currently active, legitimately employed admin account with no offboarding record

## False Positive / Benign Positive Indicators

- Verified, ticketed onboarding of a new sysadmin or promotion of an existing admin to a broader scope
- PAM/JIT elevation tool programmatically adding and later automatically removing membership (Member Name = the requesting admin, Subject = the PAM service account, add/remove pair matches the tool's known elevation-window duration)
- Scheduled Tier 0 account hygiene/migration project already communicated to the SOC (adminCount normalization, RID cleanup)
- HR-driven offboarding removal matched to a termination or role-change ticket
- Build/provisioning automation adding a service account to local Administrators as part of a documented server template, correlated with expected 7045/4697 install events at the same time

## Escalation Criteria

Escalate to Incident Response immediately when: the Subject account cannot be matched to any legitimate admin identity or approved workflow; the change targets Domain Admins, Enterprise Admins, Schema Admins, or DC-local Administrators specifically; 1102 or 4719 appears in the same window; the newly privileged account shows any post-grant activity on Tier 0 assets; or a legitimate, currently-employed admin is removed without an offboarding record. Also escalate — separately, as a process/GRC finding rather than a security incident — any confirmed Benign case where the approving control (change ticket, PAM workflow) was itself missing, since that's a control gap independent of intent.

## Containment Options & Approval Authority

**[MANAGEMENT]** -

| Action | Who Can Approve | Notes |
|---|---|---|
| Remove the added member from the privileged group | SOC Analyst / IAM on-call (standing authority) if unauthorized and no ticket found | Fast, low-risk reversal; log the exact group/member/timestamp reverted |
| Disable the Subject account that made the unauthorized change | IAM team lead or IR lead sign-off | Requires business-impact check if Subject is itself a legitimate admin whose credentials may be compromised |
| Force credential reset + session revoke on Subject and Member accounts | IAM lead + IR lead joint approval | Standard when compromise is suspected rather than pure process failure |
| Restore a wrongly removed legitimate admin | IAM team lead (expedited, same-day) | Time-sensitive — a removed admin may be locked out of tools needed for the response itself |
| Full DC-level forensic review / replication metadata audit (suspected DCShadow) | IR lead + AD/Infrastructure engineering lead | Not a same-shift action; requires domain architecture expertise and possibly vendor/Microsoft engagement |

## Example Query (Microsoft Sentinel — KQL)

```kql
SecurityEvent
| where EventID in (4728, 4732, 4729, 4733)
| where TargetUserName in ("Domain Admins", "Administrators", "Account Operators", "Backup Operators", "DnsAdmins")
| extend Actor = SubjectUserName, ActorDomain = SubjectDomainName
| where Actor !in ("SVC-PAM-JIT", "SVC-ADSYNC")  // tune to known automation/PAM accounts
| project TimeGenerated, Computer, EventID, TargetUserName, MemberName, Actor, ActorDomain
| order by TimeGenerated desc
```

## Closure Criteria

Close as **True Positive** only after the unauthorized member has been removed (or the wrongly removed admin restored), the Subject account has been reset/disabled as warranted, and full scope of all group changes by the same Subject in the surrounding window is documented. Close as **Benign Positive** when the change matches a verified ticket, PAM workflow, or communicated project, with the approving ticket number or workflow ID recorded in the case note. Close as **Insufficient Evidence** only when the Subject cannot be reached for confirmation and no anti-forensics indicators or post-grant abuse are present — flag the account/group pair for a 24-hour follow-up rather than closing silently.

**Example case-note line:** *"2026-09-15 02:41 UTC — 4728 added user svc-backup-temp to Domain Admins, Subject = jsmith-adm (no prior 4672 for this account in 90 days, logon at 02:38 via 4648 from 10.10.40.17, not a known admin jump box); no matching change ticket found after 30 min follow-up with jsmith; 1102 log-clear attempt logged 02:44 same DC — escalated to IR as confirmed compromise (T1098 → T1207 suspected), membership reverted, jsmith-adm disabled pending forensic review, AD/Infra engineering engaged for replication metadata audit."*
