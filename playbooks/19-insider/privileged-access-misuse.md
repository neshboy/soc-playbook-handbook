# Privileged Access Misuse

## Playbook ID & Name
**INS-010 — Privileged Access Misuse (Authorized-Access Abuse by Privileged Accounts)**

## Business Risk
**[STAKEHOLDER]** - Your domain admins, DBAs, cloud tenant admins, and help-desk staff with elevated rights already have the keys to nearly everything — this playbook covers what happens when one of them uses those keys for something outside their job, whether that's browsing the CEO's mailbox, resetting a coworker's password to snoop on their account, granting themselves a permission nobody approved, or quietly disabling the logging that would have caught them. There's no perimeter to defend here; the access is legitimate, so the only signal is intent and scope. Decision owner for personnel action is HR + Legal + the resource owner (e.g., IT director for AD, CISO for cloud tenant); SOC's job is detection, evidence, and referral.

## Severity/Priority Default
**High** by default — privileged accounts have the reach to cause damage far beyond a standard user, so err toward High even before context confirms intent. Escalates to **Critical** if the activity touches Domain Admin/Enterprise Admin rights, cloud Global Admin/Owner roles, DCSync-equivalent replication rights, or coincides with a resignation/termination/HR-dispute case. Downgrade to Medium only after the access owner and data owner both confirm the action was authorized and in-scope.

## MITRE ATT&CK Technique(s)
- **T1078.002 / T1078.004** — Valid Accounts: Domain Accounts / Cloud Accounts (the access vector is a legitimate, unrevoked privileged credential — this is what makes the category hard)
- **T1098 (.002 Additional Email Delegate Permissions)** — Account Manipulation, e.g., granting mailbox delegate/send-as rights to self or a third party without a ticket
- **T1136** — Create Account (rogue or backdoor account created using admin rights, often outside change management)
- **T1531** — Account Access Removal (disabling/locking a coworker's or subordinate's account outside a legitimate offboarding action — retaliation pattern)
- **T1003.006** — OS Credential Dumping: DCSync (admin/service account requesting directory replication rights it doesn't operationally need)
- **T1207** — Rogue Domain Controller (DCShadow — rare, but the most severe form of privileged AD abuse, used to push unauthorized changes while evading standard change-tracking)
- **T1069 / T1087** — Permission Groups Discovery / Account Discovery (self-enumeration of what the account *can* reach, often preceding scope creep)
- **T1562.001** — Impair Defenses: Disable or Modify Tools (clearing audit logs, disabling EDR/AV on a host, turning off mailbox audit logging to cover tracks)
- **T1538** — Cloud Service Dashboard (admin console browsing well outside the resource scope their role covers — reading other business units' billing, storage, or IAM config with no ticket)
- **T1021.002** — Remote Services: SMB/Windows Admin Shares (using admin rights to browse file shares/home directories the account has no operational reason to touch)

## Trigger / Detection Logic Summary
Fires on privileged-account activity that is technically permitted by the account's entitlements but falls outside its documented job function, approved change ticket, or historical usage pattern. Detection is almost entirely behavioral: a Tier-0 admin account accessing a resource it has never touched before, a privilege grant with no linked change record, a permission change made outside the account's normal working hours/geography, or an admin account querying/exporting data it has no operational reason to hold (HR records, executive mailboxes, another admin's home directory). Unlike most detections in this book, the alert almost never fires on a single event — it fires on the *combination* of "has access" + "used access" + "no business justification on file."

## Required Log Sources & Event IDs
| Source | Event ID / Field Source | Purpose |
|---|---|---|
| Windows Security (DC + member servers) | **4672** (special privileges assigned at logon) | Confirms admin-equivalent token was issued |
| Windows Security | **4648** (logon using explicit credentials — runas) | Admin account operating under a different context |
| Windows Security | **4728 / 4732 / 4756** (member added to global/local/universal security group) | Privilege escalation via group membership |
| Windows Security | **4720 / 4722 / 4725 / 4738** (account created/enabled/disabled/changed) | T1136 / T1531 signatures |
| Windows Security (DC) | **4662** (operation performed on object), filtered on Properties GUIDs for `DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All` | DCSync detection (T1003.006) |
| Windows Security | **5136** (directory service object modified), **4670** (permissions on object changed) | Unauthorized AD/ACL changes |
| Windows Security | **1102** (audit log cleared), **4719** (audit policy changed) | Cover-tracks behavior (T1562.001) |
| Exchange/M365 Unified Audit Log (Microsoft Purview Audit) | `Add-MailboxPermission`, `Add-RecipientPermission`, mailbox audit-log actions on non-owner mailboxes | Mailbox delegate misuse (T1098.002) |
| Entra ID / Azure AD Audit Log | "Add member to role", "Add eligible member to role" (PIM), Global Admin/Owner sign-ins | Cloud privilege grants and console access (T1538) |
| PAM/vault (CyberArk, BeyondTrust, HashiCorp Vault) | Checkout/checkin events, session recordings | Ground truth for who *should* have had elevated access and when |
| EDR | Process creation, tool execution under admin token | Corroborates what the elevated session was actually used for |

## Key Fields to Inspect
**[ANALYST]**
- Account name and whether it's a named admin account, shared/generic admin login, or service account riding a human's session
- Privilege/right actually exercised — SeDebugPrivilege, SeBackupPrivilege, DS-Replication rights, mailbox delegate grant, group membership change
- Target object — whose mailbox, whose home directory, which server, which group, which cloud subscription/tenant
- Linked change ticket or approval record (ServiceNow/Jira change number) — its absence is the single most useful field in this whole playbook
- Time of activity vs. the account's own historical working pattern (hours, days, source host, source IP)
- Whether the action was reversed/self-corrected quickly (sloppy troubleshooting) or left in place and reused
- Any log-clearing or audit-policy change bracketing the event in time

## Normal vs Suspicious Pattern
**Normal:** A DBA runs a scheduled maintenance script against production at 2 AM with a linked change ticket; a help-desk tier-2 resets a password for a user who called in and logs the ticket number; a domain admin adds a service account to a group as part of a documented server build, visible in the change calendar.

**Suspicious:** An admin account accesses a mailbox, share, or system it has never touched in 12+ months of logs; a privilege grant or group-membership change with no corresponding ticket, made by the same person who then uses the new access within minutes; a help-desk account resetting the password of someone in a different department with no ticket; DCSync-pattern replication requests from an account that isn't a domain controller or a known backup/AD-sync tool (Azure AD Connect, backup software); an admin disabling Windows Defender/EDR or clearing Security logs (1102) on a host right before or after doing something else notable on it.

## Investigation Steps
1. Pull the raw event(s) — 4672/4662/4728/audit-log entry — and confirm exactly which privilege was exercised and against which object; don't work from the alert summary alone.
2. Check for a linked change ticket, approval, or standing authorization (job description, on-call runbook) covering this exact action — absence of a ticket is a strong signal but confirm it's actually required for this action type before treating silence as guilt.
3. Baseline the account's own historical access pattern for the last 90 days — is this object/resource genuinely new territory, or does the account touch it routinely and the alert is a threshold miscalibration?
4. Cross-reference PAM/vault checkout records if the environment uses one — was elevated access even checked out through the proper workflow at this time, or was it a standing/unrevoked permission?
5. Correlate with follow-on activity: did the privilege grant, mailbox delegation, or new account get *used* afterward, or was it created and left dormant (still worth flagging, lower urgency)?
6. Check for cover-tracks indicators in the same session or shortly after — 1102, 4719, EDR/AV disablement, deleted audit trails.
7. Interview the account owner through the proper channel (manager/HR present per policy — do not go direct without sign-off) once evidence is preserved, not before.
8. Document scope precisely: exact object(s) touched, exact privilege used, exact timestamps — HR/Legal will need this level of specificity, "accessed some files" won't hold up.

## True Positive Indicators
- No change ticket, approval, or job-function justification exists for the action taken
- Target resource has no operational relationship to the account's normal duties (HR data touched by a network admin, executive mailbox touched by a help-desk tier-1)
- Privilege was granted and then actively used, especially outside business hours or from an unusual source
- Audit-log clearing, policy changes, or EDR disablement bracket the privileged action in time
- Pattern repeats across multiple targets, suggesting reconnaissance (T1069/T1087) rather than a one-off mistake

## False Positive / Benign Positive Indicators
- Valid change ticket or documented on-call/runbook procedure covers the exact action
- Account is a legitimate service/sync tool (Azure AD Connect, backup software, SIEM collector) misclassified as a human admin — common source of DCSync false positives
- New hire in the admin role whose baseline simply hasn't been established yet
- Action was self-corrected within minutes (fat-fingered group add, immediately reverted) with no further use of the resulting access
- Resource owner confirms the access was requested and approved through a channel that didn't leave a ticket trail in the system SOC is watching (process gap, not misuse)

## Escalation Criteria
Escalate to Insider Threat/HR/Legal immediately when: the target of the access is another employee's personal data/mailbox with no business reason, the account holder denies or can't explain the action when asked through proper channels, or the activity coincides with a disciplinary case, PIP, or resignation. Escalate to IR immediately (parallel track, not instead of) if DCSync, DCShadow, or credential-dumping indicators are present — that pattern is indistinguishable from external compromise using a stolen privileged credential until proven otherwise, and containment can't wait on the HR timeline.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Preserve evidence first** — export relevant Security/audit logs, PAM session recordings, and mailbox audit trail before any account action tips off the subject. Approval: SOC lead + Legal.
- **Revoke the specific privilege/grant** (remove from group, revoke delegate permission, rotate the credential) rather than disabling the whole account, where the misuse is scoped and confirmed non-compromise. Approval: resource owner (AD team lead, cloud platform owner) + SOC lead.
- **Suspend the account entirely** — reserved for confirmed malicious intent or active risk of further damage. Approval: HR + Legal + CISO or designee.
- **Force PAM re-checkout / require dual control** on future elevated sessions for the account pending investigation close. Approval: SOC lead, notify PAM/IAM owner.
- SLA: for DCSync/DCShadow-class findings, containment decision within 2 hours regardless of time of day; for standard scope-of-access misuse, HR/Legal decision expected within 1 business day.

## Example Query
```kql
// Microsoft Sentinel — privilege grant with no linked change ticket, used within 15 minutes
SecurityEvent
| where EventID in (4728, 4732, 4756)
| project TimeGenerated, TargetAccount = TargetUserName, GrantedBy = SubjectUserName, GroupName = TargetSid
| join kind=leftouter (
    SecurityEvent | where EventID == 4672 | project TimeGenerated, SubjectUserName
  ) on $left.TargetAccount == $right.SubjectUserName
| where TimeGenerated1 between (TimeGenerated .. TimeGenerated + 15m)
| project TimeGenerated, GrantedBy, TargetAccount, GroupName, UsedAt = TimeGenerated1
```

## Closure Criteria
Close as **True Positive** (insider threat referred) once HR/Legal has taken ownership and the evidence package (raw logs, ticket-absence confirmation, PAM records) is handed off; SOC's part ends at detection and referral. Close as **Benign Positive** when the resource/data owner confirms a valid ticket or documented process covers the action. Close as **Insufficient Evidence** when the account owner can't be reached within SLA and no corroborating cover-tracks or scope-abuse indicator exists — reopen if the account triggers again within 90 days.

**Example case note:** *"Domain admin account svc-admin-mward (mapped to human owner M. Ward, Tier-3 infrastructure) added itself to the 'HR-FinanceShare-Admins' group at 2026-09-11 23:47 UTC (Event ID 4728, DC01), a group it had never held membership in over the prior 180 days of log history. No change ticket found in ServiceNow for this window. Access to \\fileserver03\HR\Compensation confirmed 6 minutes later (Event ID 4663). No corresponding request or approval located; M. Ward's manager not yet contacted pending HR/Legal sign-off. PAM vault shows no checkout event for this session — standing (non-vaulted) admin rights, flagged separately as an access-governance gap. Referred to HR/Legal with full log export; account privilege pending review, not yet suspended."*
