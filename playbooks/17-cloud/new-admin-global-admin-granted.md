# CLD-011: New Admin/Global-Admin Granted

**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)

## Business Risk

**[STAKEHOLDER]** - Every time someone is added to Global Administrator, `AdministratorAccess`, `roles/owner`, or an equivalent top-tier role, the blast radius of that identity's credential jumps from "one system" to "the whole tenant." Most tenants don't have a hard technical gate on this - if you can call `AttachUserPolicy` or `Add member to role`, the platform lets you do it, full stop. This playbook is not about catching someone *using* admin rights (that's covered separately) - it's about catching the moment the rights are handed out in the first place, because that's the cheapest point in the kill chain to stop an attacker: before they've done anything with the access, not after. A grant that goes unnoticed for even a few hours is effectively a standing backdoor.

## Severity / Priority Default

**High / P2** for any admin-tier role grant. Escalate to **Critical / P1** immediately if the grant is self-performed (grantor = grantee), unticketed, made to an account created within the prior 24-48 hours, or accompanied by any logging/MFA control change in the same session.

## MITRE ATT&CK Techniques

T1098 (Account Manipulation), T1098.003 (Additional Cloud Roles - the specific sub-technique for granting/attaching an admin-tier role or policy), T1098.001 (Additional Cloud Credentials - covers follow-on access-key/app-secret creation under the grantee), T1078.004 (Valid Accounts: Cloud Accounts), T1136 (Create Account), T1069 (Permission Groups Discovery), T1087 (Account Discovery), T1580 (Cloud Infrastructure Discovery), T1538 (Cloud Service Dashboard), T1562.001 (Impair Defenses: Disable or Modify Tools).

## Trigger / Detection Logic Summary

Fires on any control-plane event that assigns a top-tier administrative role or policy to a principal:

- **AWS:** CloudTrail `eventName` in `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, or `AddUserToGroup` where the policy ARN is `arn:aws:iam::aws:policy/AdministratorAccess` or an inline document contains `"Action":"*"` paired with `"Resource":"*"`.
- **Entra ID / M365:** `AuditLogs` `OperationName = "Add member to role"` where the target role is Global Administrator, Privileged Role Administrator, or Application Administrator with high-privilege app consent rights; also PIM `"Add member to role in PIM completed (permanent)"` events (permanent, not time-bound, assignments deserve extra scrutiny on their own).
- **GCP:** Admin Activity audit log `methodName = SetIamPolicy` where the added binding role is `roles/owner` or `roles/resourcemanager.organizationAdmin`.

**[ENGINEERING]** - Two correlation rules matter more than the raw grant event: (1) flag where `actor.id == target.id` (self-grant - a legitimate admin team almost never grants a role to itself in the same call it's using to grant others' roles), and (2) join the grant event against account-creation timestamps for the target principal - a grant landing within 24-48 hours of `CreateUser`/`Add user` for that same identity is a textbook create-then-elevate pattern (T1136 chained straight into T1098) and should score materially higher than a grant to a long-lived identity.

## Required Log Sources & Event Data

| Platform | Source | Key Event Identifiers |
|---|---|---|
| AWS | CloudTrail (management events) | `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `AddUserToGroup`, `CreateUser` (for age correlation) |
| Entra ID / M365 | Entra ID Audit logs, PIM audit history, Unified Audit Log | `Add member to role`, `Add eligible member to role`, `Add member to role completed (PIM activation)`, UAL `Add-RoleGroupMember` |
| GCP | Cloud Audit Logs (Admin Activity) | `SetIamPolicy` with `roles/owner` / `roles/resourcemanager.organizationAdmin` bindings, `google.iam.admin.v1.CreateServiceAccount` |
| Change/ITSM | Change management or PIM approval system | Ticket number, requestor, approver, business justification, expiry date |

## Key Fields to Inspect

**[ANALYST]**
- **Actor (grantor) identity** - `userIdentity.arn` / `initiatedBy.user.userPrincipalName` - is this a known IAM/identity-engineering team member, or an account with no history of making role changes?
- **Target (grantee) identity** - the account/role actually receiving the privilege. Confirm it's a real, active employee identity or an intended service principal, not a look-alike name (`admin-team` vs `admln-team`).
- **Role/policy scope** - is this a true top-tier grant (`AdministratorAccess`, Global Administrator, `roles/owner`) or a narrower role that only looks alarming in the alert title? Scope matters for triage priority.
- **Assignment type** - permanent/active assignment vs. PIM eligible-with-expiry vs. time-bound. Permanent grants to human accounts for "just in case" access are a recurring audit finding even when not malicious.
- **Target account age and recent activity** - `createdDateTime`, first sign-in timestamp, whether the account has any prior legitimate history.
- **Source IP/ASN and client** of the grant action itself - console UI performed by someone who normally works in the console vs. an unexplained CLI/API call from unfamiliar infrastructure.
- **Same-session or near-in-time events**: new access keys/app credentials (T1098.001), inbox rule creation (T1114.003 - relevant if the grantee is later used for mailbox access), Conditional Access or logging changes.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Grant tied to an approved joiner/mover ticket, executed by named IAM engineer from a known admin workstation | No ticket, or ticket number doesn't exist/doesn't match the grantee |
| PIM eligible assignment with defined expiry, activated only when needed with justification text | Permanent/active assignment with no expiry, or PIM eligibility skipped entirely in favor of direct active assignment |
| Grantor and grantee are different, identifiable people | Grantor and grantee are the same identity (self-escalation) |
| Grantee account has months/years of ordinary activity history | Grantee account created in the last 24-48 hours, or dormant for months and suddenly re-activated then elevated |
| Grant is a single isolated action in a normal admin's session | Grant follows a burst of `Account Discovery`/`Permission Groups Discovery`-style enumeration calls (`ListUsers`, `ListRoles`, `Get-MgDirectoryRole`) from the same session |

## Investigation Steps

1. Identify both actor and target from the raw event - confirm they resolve to real, distinct principals (watch for Unicode look-alikes and recently-renamed accounts).
2. Pull the actor's full session timeline (before and after the grant) from CloudTrail/Entra audit logs/GCP Admin Activity - look for discovery activity (`ListUsers`, `ListRoles`, `Get-MgDirectoryRole`, IAM policy enumeration) immediately preceding the grant, which suggests the actor was mapping the privilege model rather than executing a routine, pre-planned change. Pull a ±2 hour window around the grant timestamp as a default starting point (widen to ±24 hours if the actor's account shows little or no baseline admin activity to compare against). None of these platforms hand you a formal "session" object for this correlation - define it operationally as every event sharing the same actor identity (`userIdentity.arn` / `initiatedBy.user.userPrincipalName`) and the same source IP address within that window; for AWS specifically, also group by the same `userIdentity.accessKeyId`/STS session name where present, since that's a tighter grouping than IP alone if the actor is behind a shared NAT/VPN egress.
3. Validate against change management: does an open or recently-closed ticket exist naming this exact grantee and role, with an identifiable approver?
4. Check the grantee account's creation date, MFA enrollment status, and sign-in history - a brand-new or recently-dormant account receiving top-tier privilege is the single strongest indicator in this playbook.
5. Determine assignment durability: permanent/active vs. time-bound PIM eligible. Permanent grants outside the standard joiner process should be flagged for remediation even if the actor turns out to be legitimate.
6. Review activity immediately following the grant under the grantee's identity: new credentials/access keys, new app registrations with broad consent, mailbox delegation or forwarding rules, or any logging/Conditional Access changes.
7. Confirm whether the actor's own account shows signs of prior compromise in the hours before the grant (new sign-in location, MFA re-enrollment, other concurrently flagged alerts) - a legitimate-looking grant made from a takeover session is still a takeover.
8. If self-grant, missing ticket, or new-account-then-elevate pattern is confirmed, escalate immediately and check for a second/backup admin grant elsewhere in the tenant before declaring the incident contained - attackers who plant one persistence mechanism often plant two.

## True Positive Indicators

- Self-grant (actor and target are the same identity) with no corresponding emergency-access justification.
- No change ticket, or a ticket that doesn't name this grantee/role combination.
- Grant made to an account created or reactivated within the prior 24-48 hours.
- Discovery-style enumeration (`ListRoles`, `Get-MgDirectoryRole`, `iam.roles.list`) immediately preceding the grant from the same session.
- Post-grant activity includes new credentials, new OAuth app consent, mailbox rule creation, or logging/Conditional Access tampering.

## False Positive / Benign Positive Indicators

- Grant matches an approved joiner/mover/leaver ticket with a named, verifiable approver and business justification.
- PIM eligible activation with correct time-bound expiry and documented justification text, performed by an account with a legitimate history of similar activations.
- Migration or platform-engineering activity where a service principal was intentionally elevated as part of a documented infrastructure build, later confirmed and scoped down by the platform team.
- Scheduled internal access review re-confirming an existing grant (re-triggers the audit event without representing a new privilege).

## Escalation Criteria

Escalate to IR/CIRT immediately for any self-granted role, any grant with no matching ticket, or any grant to an account created within the prior 48 hours. Escalate as active compromise (not policy violation) if the grant is preceded by discovery activity or followed by credential/OAuth/logging changes under the same or grantee identity. Notify the tenant owner and IAM/security engineering lead within the hour for any confirmed unauthorized top-tier grant - this frequently overlaps with reportable-incident thresholds even before any data is touched.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Immediate revocation of the granted role/policy (Entra: remove role member and revoke refresh tokens; AWS: detach the policy and disable the access keys; GCP: remove the IAM binding) - SOC lead can execute for confirmed unauthorized grants under standing IR authorization.
- Suspend the grantee account (and the actor account, if evidence points to takeover) pending investigation - requires IAM/security engineering sign-off unless active misuse is in progress, in which case SOC lead can act under emergency authority with post-action notification.
- Convert any permanent/active admin assignment surfaced during the investigation (even benign ones) to time-bound PIM eligible - IAM engineering executes, tracked as a remediation ticket rather than an incident action.
- Full review and, if needed, reset of credentials for both actor and grantee identities - CISO or IAM platform owner approval required to close if the grant is confirmed malicious.

## Example Query (Splunk SPL - AWS CloudTrail)

```spl
index=cloudtrail eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy")
  requestParameters.policyArn="arn:aws:iam::aws:policy/AdministratorAccess"
| rex field=userIdentity.arn "\/(?<actorUser>[^\/]+)$"
| eval selfGrant=if(actorUser==requestParameters.userName, "true","false")
| join type=left requestParameters.userName
    [ search index=cloudtrail eventName="CreateUser"
      | eval acctCreated=eventTime
      | fields requestParameters.userName acctCreated ]
| eval acctAgeHrs=round((_time-strptime(acctCreated,"%Y-%m-%dT%H:%M:%SZ"))/3600,1)
| table _time, userIdentity.arn, requestParameters.userName, selfGrant, acctAgeHrs, sourceIPAddress
```

## Closure Criteria

Close only when: actor and grantee identities are both confirmed, a matching ticket or approved PIM activation is validated (or its absence is confirmed and escalated), grantee account age/history has been reviewed, and any post-grant activity has been checked line-by-line. Record disposition as **True Positive**, **Policy Violation** (unauthorized-but-internal - the grant was out of process but no external attacker was involved), **Benign Positive**, or **Insufficient Evidence** - a missing PIM justification field or an approver who's out of office and unreachable is a legitimate reason to close as Insufficient Evidence rather than force a verdict, provided the grant itself has been reverted pending their return.

**Example case note:**
"2026-09-15 09:02 UTC - AttachUserPolicy(AdministratorAccess) granted to iam-user jdoe-svc by iam-user jdoe-svc (self-grant) from 198.51.100.22, no matching change ticket. Target account created 2026-09-14 22:41 UTC, ~10 hours prior - create-then-elevate pattern. Session also shows ListUsers/ListRoles enumeration 4 minutes before the grant. Policy detached, access keys for jdoe-svc disabled, escalated to IR as confirmed unauthorized privilege escalation. IAM engineering lead notified 09:15 UTC; searching tenant for a second backdoor grant in progress."
