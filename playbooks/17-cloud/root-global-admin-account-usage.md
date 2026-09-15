# CLD-001: Root / Global-Admin Account Usage

**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)

## Business Risk

**[STAKEHOLDER]** - The root user (AWS), Global Administrator role (Entra ID / M365), and Organization Admin (GCP) sit above every other permission boundary in the tenant. Whoever holds one of these can create backdoor identities, disable logging, change billing destinations, or delete the entire estate - and in most tenants nothing technically stops them. Every use of this identity is a moment where a single compromised credential equals total loss of control. This playbook exists because "we'll notice if something goes wrong" is not a control; alerting on the use of the identity itself is the control.

## Severity / Priority Default

**Critical / P1** for any interactive root or Global Admin session outside a pre-approved change window. Downgrade only after analyst confirms it maps to an approved emergency-access ("break-glass") procedure.

## MITRE ATT&CK Techniques

T1078.004 (Valid Accounts: Cloud Accounts), T1098 (Account Manipulation), T1098.003 (Additional Cloud Roles - covers the persistence pattern of the root/GA session granting itself or another identity a further admin role during the session), T1098.001 (Additional Cloud Credentials), T1136 (Create Account), T1562.001 (Impair Defenses: Disable or Modify Tools), T1069 (Permission Groups Discovery), T1087 (Account Discovery), T1538 (Cloud Service Dashboard), T1580 (Cloud Infrastructure Discovery).

## Trigger / Detection Logic Summary

Fires on any authenticated action performed by:
- AWS: `userIdentity.type = "Root"` in CloudTrail, for anything other than the documented quarterly root-credential rotation/verification task.
- Entra ID / M365: sign-in or directory action where the signed-in user carries an **active** Global Administrator role assignment (not eligible/PIM-pending) - drawn from Entra ID sign-in logs joined to `AuditLogs`/directory role assignment data.
- GCP: IAM Policy Analyzer / Admin Activity audit log entries where the principal holds `roles/resourcemanager.organizationAdmin` or `roles/owner` at the org node.

Correlation logic should alert on **presence of the session**, not just on a "bad" action inside it - a Global Admin logging in from an unexpected ASN is itself the finding, before they've done anything else.

## Required Log Sources & Event Data

| Platform | Source | Key Event Identifiers |
|---|---|---|
| AWS | CloudTrail (management events, both console and API) | `userIdentity.type=Root`, `eventName` (ConsoleLogin, CreateUser, PutBucketPolicy, StopLogging, DeleteTrail, UpdateAccountPasswordPolicy) |
| Entra ID / M365 | Entra ID Sign-in logs, Entra ID Audit logs, Unified Audit Log (UAL) | `appDisplayName`, `Add member to role`, `Update user`, `Set-CASMailbox`, `New-InboxRule` (M365), UAL `Operations` field |
| GCP | Cloud Audit Logs (Admin Activity, Data Access if enabled) | `protoPayload.authenticationInfo.principalEmail`, `methodName` (SetIamPolicy, google.iam.admin.v1.CreateServiceAccountKey) |
| Identity provider / MFA | PIM activation logs, break-glass vault checkout logs | Correlate every root/GA session against an open, approved checkout ticket |

## Key Fields to Inspect

**[ANALYST]**
- `userIdentity.arn` / `userPrincipalName` - confirm it is literally the root/GA identity, not a same-named service account.
- `sourceIPAddress` / `ipAddress` and reverse-DNS/ASN - known corporate egress vs. residential ISP, VPS, or Tor exit.
- `userAgent` / client app - CLI tools (`aws-cli/`, `PowerShell`) used interactively where console-only access is expected is itself notable.
- `mfaAuthenticated` (CloudTrail `additionalEventData`), `authenticationMethod`/`authenticationRequirement` (Entra sign-in logs) - was step-up/phishing-resistant MFA actually enforced.
- `eventTime`/`createdDateTime` against the approved change-window ticket timestamps.
- Session duration and action count - a five-minute rotation check looks nothing like a 40-minute session touching IAM, billing, and logging config.
- Any subsequent `CreateUser`, `AttachUserPolicy`, `Add member to role` (Global Admin/Application Administrator), or new app registration with `AllPrincipals` consent - classic persistence-planting inside the privileged session.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Root/GA login tied to a change ticket, from known jump host or PAM bastion, MFA satisfied, short session, single well-defined action (e.g., quarterly root credential check, emergency Entra role recovery) | Login with no matching ticket, from unfamiliar geography/ASN, MFA absent or satisfied via a newly-registered method, long session touching multiple unrelated services |
| Break-glass account checked out via PAM, auto-checked-in after use, password rotated post-use | Break-glass account used without vault checkout, or checked out but never checked back in |
| Root MFA device unchanged for months | `DeleteVirtualMFADevice` / MFA re-enrollment immediately before or during the session |

## Investigation Steps

1. Confirm identity: verify `userIdentity`/`userPrincipalName` genuinely resolves to the root or Global Admin principal, not a look-alike account or a role name collision.
2. Pull the full session timeline from CloudTrail/Entra sign-in+audit logs/GCP Admin Activity logs for the entire login-to-logout window - do not stop at the alerting event.
3. Check for a matching, still-open change ticket or PAM checkout record with named approver and stated purpose.
4. Validate MFA: method type, enrollment date, and whether it was newly registered in the hours before use (a strong indicator of prior account takeover).
5. Enumerate every privileged action taken in the session: new principals created, policies attached, logging/monitoring disabled (`StopLogging`, `DeleteTrail`, Entra "Update conditional access policy" to disabled state), trust relationships or federation changes.
6. Check source infrastructure: IP reputation, ASN ownership, whether it matches the organization's documented egress ranges or known admin workstation pool.
7. Cross-check for concurrent or immediately-prior lower-privilege account activity from the same source (credential theft chains often escalate from a compromised standard account into privileged use).
8. If any persistence artifact is found, treat as active intrusion, not policy violation - move straight to escalation, don't wait for full timeline completion.

## True Positive Indicators

- No matching change ticket/PAM checkout for the session.
- MFA newly enrolled or bypassed (legacy auth, no MFA claim in the token).
- Session includes disabling of CloudTrail/Diagnostic Settings/Unified Audit Log, or deletion of the trail/workspace itself.
- New privileged principal, app registration with broad consent, or additional cloud credentials added mid-session.
- Source IP/ASN inconsistent with any prior legitimate use of that identity.

## False Positive / Benign Positive Indicators

- Confirmed scheduled root-credential verification or Global Admin PIM emergency activation with matching ticket and PAM checkout log.
- Break-glass drill explicitly scheduled by IAM/security engineering and communicated to SOC beforehand.
- Automated health-check script running under a service principal that was mis-tagged with the GA role during a migration (should still trigger a role-scoping remediation ticket even if benign).

## Escalation Criteria

Escalate to IR/CIRT immediately (do not wait for shift handover) if: no ticket exists, MFA was newly registered or absent, logging/audit trail was disabled, or any new privileged identity was created during the session. Notify tenant owner/CISO within the hour for any confirmed unauthorized root or Global Admin use - this is a board-notifiable event class in most breach-disclosure frameworks.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Immediate session revocation (Entra: revoke all refresh tokens for the account; AWS: rotate/deactivate root access keys and console password) - Tier 2 SOC lead can execute for confirmed unauthorized use without further approval, given standing IR authorization.
- Force MFA re-enrollment and credential rotation for the root/GA identity - IAM engineering executes, SOC lead authorizes.
- Suspend any newly-created principals or role assignments discovered in the session - requires cloud platform owner sign-off unless active data loss is in progress, in which case SOC lead can act under emergency authority and notify after.
- Re-enable/restore any disabled logging or conditional access policy immediately, then snapshot the tamper for evidence before restoration.
- Full root/GA credential reset plus review of all IAM/RBAC changes made in the session - CISO or cloud platform owner approval required to close.

## Example Query (Microsoft Sentinel - KQL)

```kql
// Sign-ins by principals who currently hold the Global Administrator role.
// Note: join on the role-assignment TARGET (the grantee), not on InitiatedBy
// (the grantor) - joining on InitiatedBy would surface sessions belonging to
// whoever *performed* a role grant, not sessions belonging to a GA holder.
let GaHolders = AuditLogs
    | where OperationName == "Add member to role"
    | where TargetResources has "Global Administrator"
    | mv-expand Target = TargetResources
    | extend GaUserId = tostring(Target.id)
    | distinct GaUserId;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| where UserId in (GaHolders)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, AuthenticationRequirement, Location
```

## Closure Criteria

Close only when: identity confirmed, ticket/PAM record validated (or confirmed absent and escalated), MFA method verified, full action list from the session reviewed line-by-line, and disposition recorded as **True Positive**, **Policy Violation** (unauthorized-but-internal use, no external attacker), **Benign Positive**, or **Insufficient Evidence** (log retention gap on the identity provider side, for example, is a legitimate reason to close as Insufficient Evidence rather than force a verdict).

**Example case note:**
"2026-09-15 03:14 UTC - GA role activation for svc-tenantadmin@example.com from 203.0.113.44 (unrecognized ASN, no PAM checkout, no ticket). MFA showed as newly registered SMS method 11 minutes prior. Session included AuditLogs entry disabling Conditional Access policy 'Require MFA for all users' and creation of app registration 'sync-tool' with Mail.ReadWrite and Directory.ReadWrite.All. Escalated to IR as confirmed compromise; refresh tokens revoked, CA policy restored, app registration disabled pending investigation. CISO notified 03:41 UTC."
