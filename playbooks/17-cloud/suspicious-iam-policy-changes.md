# Suspicious IAM Policy Changes

## Playbook ID & Name

**CLD-003 — Suspicious IAM Policy Changes (AWS / Azure / Entra ID / M365 / GCP)**

## Business Risk

**[STAKEHOLDER]** - Cloud IAM is the front door and the master key at the same time. An attacker who can quietly widen a policy, attach `AdministratorAccess` to a role, or add a rogue trust relationship doesn't need to keep breaking in - they just walk through the door they built for themselves. Left undetected, this is how a single phished developer credential turns into full account takeover, data exfiltration, or a ransom note on your S3 buckets. This playbook covers the moment someone (or something) touches a policy, role, or permission boundary and that change doesn't match who normally does that work.

## Severity/Priority Default

**High** for privilege-escalating changes (new admin-equivalent policy, wildcard `*:*` action, trust policy edit allowing external account). **Medium** for policy changes made by known automation/IaC pipelines outside their normal change window. Escalate to **Critical** if paired with new access key creation, MFA disablement, or CloudTrail/logging changes on the same account within the same session.

## MITRE ATT&CK Techniques

- T1098 Account Manipulation
- T1098.003 Additional Cloud Roles - the sub-technique for attaching/assigning a broader role or admin-managed policy to an identity, which is the core action this playbook detects
- T1098.001 Additional Cloud Credentials
- T1078.004 Valid Accounts: Cloud Accounts
- T1136 Create Account
- T1069 Permission Groups Discovery
- T1538 Cloud Service Dashboard

## Trigger / Detection Logic Summary

Alert fires when an identity/policy management API call creates, attaches, or modifies a permission set, role trust policy, or group membership, and one or more of the following is true: the actor is not on the approved list of IAM administrators or CI/CD service principals; the action grants a materially broader scope than the previous policy version (wildcard actions/resources, new admin-managed policy attachment); the action originates from an unfamiliar IP, ASN, or impossible-travel location relative to the actor's baseline; or the change occurs immediately after a new access key/app credential was issued for that same identity. Detection is deliberately keyed off the *combination* of "who," "what changed," and "from where" - any single factor alone produces too much noise in an active cloud environment.

## Required Log Sources & Event IDs

| Platform | Log Source | Key API Calls / Audit Events |
|---|---|---|
| AWS | CloudTrail (management events) | `PutUserPolicy`, `PutRolePolicy`, `AttachUserPolicy`, `AttachRolePolicy`, `CreatePolicy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`, `AddUserToGroup`, `CreateAccessKey`, `CreateUser` |
| Azure / Entra ID | Entra ID Audit Logs, Azure Activity Log | "Add member to role", "Add app role assignment to service principal", "Update application - Certificates and secrets management", "Add owner to application" |
| M365 | Unified Audit Log (Purview) | `Add-MailboxPermission`, `Add-RoleGroupMember`, `New-ManagementRoleAssignment` |
| GCP | Cloud Audit Logs (Admin Activity) | `SetIamPolicy`, `google.iam.admin.v1.CreateRole`, `google.iam.admin.v1.UpdateRole` |

Note: these are cloud control-plane audit events, not Windows/Sysmon Event IDs - this category has no numeric equivalents, so match on the API/operation name field.

## Key Fields to Inspect

**[ANALYST]**

- Actor identity: `userIdentity.arn` / `userIdentity.principalId` (AWS), `initiatedBy.user.userPrincipalName` (Entra ID), `actor.account.userKey` (GCP)
- Source IP / ASN and `userAgent` - CLI, console, SDK, or unfamiliar automation tool
- `requestParameters.policyDocument` (AWS) - diff old vs new policy JSON, look for `"Action": "*"`, `"Resource": "*"`, `iam:*`, `sts:AssumeRole` additions
- Target identity/role being modified - is it a break-glass, service, or privileged role?
- Session context: was this call made under a role assumed via `AssumeRole`/federated SSO, or a long-lived static access key?
- Time proximity to other sensitive events: `CreateAccessKey`, `DeleteTrail`, `StopLogging`, `UpdateTrail`, MFA deactivation
- Correlated sign-in event immediately before the change (auth method, MFA satisfied, device compliance state)

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Policy change made by known Terraform/CI service principal during deploy window | Same action from that service principal's credentials but from an unfamiliar IP/region |
| IAM admin adds a scoped, resource-specific policy | Newly created or rarely-used identity attaches `AdministratorAccess` or equivalent wildcard policy |
| Change ticket/change record exists in ITSM | No corresponding change ticket, or change made outside approved maintenance window |
| Role trust policy limited to known account IDs | Trust policy edited to add an external/unknown AWS account ID or `"Principal": "*"` |

## Investigation Steps

1. Pull the full CloudTrail/audit event for the change - capture `eventTime`, actor ARN/UPN, source IP, and the complete before/after policy document.
2. Identify the actor: human console user, CLI session, federated SSO role, or automation/service principal. Check whether that identity's typical behavior includes IAM writes at all.
3. Diff the policy document. Quantify the delta in privilege - specifically flag wildcard actions, `iam:PassRole`, `sts:AssumeRole` additions, and any change to a trust policy's `Principal` block.
4. Check the authentication event immediately preceding the change - MFA satisfied? Known device? Any recent password reset or MFA re-registration on that identity?
5. Search for related activity in the same session/time window: new access keys, new app secrets, disabled logging/CloudTrail, added forwarding rules, or new admin role assignments.
6. Validate against change management - is there an approved CR, ticket, or deployment pipeline run tied to this timestamp?
7. Check whether the modified role/policy has since been used - look for `AssumeRole`/sign-in activity using the newly granted privilege.
8. If the actor or IP is unfamiliar, pivot to identity provider logs (Entra ID sign-in logs, AWS SSO, Okta) to trace the authentication chain back to its origin.

## True Positive Indicators

- Privilege escalation from a low-privileged or newly-created identity to admin-equivalent access
- Trust policy modified to allow an external/unrecognized AWS account or add `"Principal": "*"`
- IAM change directly preceded by credential compromise indicators (impossible travel, new MFA device, password spray success)
- No matching change ticket and actor denies making the change during interview
- Change followed by use of the new privilege (e.g., data access, new resource creation, key exfiltration)

## False Positive / Benign Positive Indicators

- Change performed by verified IaC pipeline (Terraform/CloudFormation/Bicep) with matching commit/PR reference
- Actor confirmed as on-call IAM administrator performing scheduled least-privilege remediation
- Scope of change is a reduction in privilege (tightening, not widening) - typically benign/expected activity
- Duplicate alert from log replication/multi-region CloudTrail delivery of the same event

## Escalation Criteria

Escalate immediately to IR/on-call security lead if: privilege escalation to admin-equivalent is confirmed unauthorized, trust policy now includes an external principal, the acting identity shows signs of compromise (new MFA device, impossible travel), or the change is paired with credential creation and defensive-control tampering (logging/alerting disabled). Notify the cloud platform owner and application owner regardless of verdict when a privileged role/policy was touched.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority Required |
|---|---|
| Revert policy/trust document to last known-good version | SOC Tier 2 analyst, no approval needed if change is unauthorized and confirmed malicious |
| Disable/suspend the identity that made the change | Security lead approval; IAM/platform owner notified |
| Revoke active sessions and rotate access keys for affected identity | SOC Tier 2, immediate, notify account owner post-action |
| Quarantine role via explicit deny policy pending investigation | Security lead approval |
| Cross-account/organization-wide policy freeze | CISO or Cloud Platform Lead approval only |

SLA: privileged IAM changes must be triaged within 15 minutes of alert; confirmed unauthorized escalation reverted within 30 minutes.

## Example Query

```kql
// Entra ID / Azure AD - unexpected role/app role assignment
AuditLogs
| where OperationName in ("Add member to role", "Add app role assignment to service principal")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor !in~ (ApprovedIamAdmins)
| project TimeGenerated, OperationName, Actor, TargetResources, Result
```

## Closure Criteria

Close as **True Positive** (contained) once the policy is reverted, the compromised/unauthorized identity is suspended or rotated, and root cause (phished credential, leaked key, insider action) is documented. Close as **Benign Positive** when the change maps to an approved CR or verified IaC pipeline run. Close as **Insufficient Evidence** only after confirming log retention covered the full session and the actor could not be reached for validation within SLA.

**Example case note:** "CloudTrail shows `AttachRolePolicy` at 2026-09-14 03:12 UTC attaching AdministratorAccess to role `svc-reporting` from source IP 203.0.113.44 (unrecognized ASN, no prior activity for this identity). No matching CR in ServiceNow. Preceding sign-in shows MFA not satisfied - re-auth via legacy app password. Confirmed unauthorized; policy reverted 03:41 UTC, access keys rotated, identity owner (j.alvarez@example.com) notified, escalated to IR for credential compromise workstream."
