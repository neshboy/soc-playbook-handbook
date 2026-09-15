# CLD-009: Privilege Escalation via Role/Policy Chaining

**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)

## Business Risk

**[STAKEHOLDER]** - Most cloud breaches don't start with a stolen admin credential - they start with a low-privilege identity (a developer, a CI/CD service account, a forgotten Lambda execution role) that turns out to have just enough permission to grant itself more permission. Nobody designed this on purpose; it's the accumulated result of `iam:PassRole`, `AttachUserPolicy`, or an Azure custom role with a wildcard `Microsoft.Authorization/*` action that got approved eighteen months ago for "flexibility." The attacker doesn't need to steal an admin - they need to steal anyone who can *become* an admin in two or three hops. This playbook is about catching that pivot in progress, because by the time the resulting admin session does something obviously bad, the escalation itself is old news and the evidence trail is colder.

## Severity / Priority Default

**High / P2** on detection of a privilege-escalation-capable action chain in progress; **Critical / P1** the moment the chain completes into an actual privileged role/policy attachment or a new admin-capable principal exists.

## MITRE ATT&CK Techniques

T1078.004 (Valid Accounts: Cloud Accounts), T1098 (Account Manipulation), T1098.003 (Additional Cloud Roles - the sub-technique that covers the chain's end state, a principal granting itself or another identity a broader role/policy), T1098.001 (Additional Cloud Credentials), T1136 (Create Account), T1069 (Permission Groups Discovery), T1087 (Account Discovery), T1580 (Cloud Infrastructure Discovery), T1538 (Cloud Service Dashboard), T1552.005 (Unsecured Credentials: Cloud Instance Metadata API), T1562.001 (Impair Defenses: Disable or Modify Tools).

## Trigger / Detection Logic Summary

This is not one event - it's a *sequence* of individually-legal-looking actions performed by the same principal in a short window, where the end state is materially more privileged than the start state. Detection logic needs to catch two things:

1. **Known escalation primitives** - specific API calls/operations that are documented privilege-escalation vectors on their own (AWS: `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachUserPolicy`/`AttachRolePolicy`/`AttachGroupPolicy` where the target policy grants `*:*` or `iam:*`, `iam:PassRole` combined with a service that can execute code, `sts:AssumeRole` into a role with a broader trust policy than the caller's own; Entra ID: `Add member to role` targeting Global Administrator/Privileged Role Administrator/Application Administrator, adding an app registration owner then granting that app broad Graph consent; GCP: `SetIamPolicy` binding the caller (or a resource the caller controls) to `roles/owner`/`roles/editor` at a project or org node).
2. **Chain correlation** - the same `userIdentity`/principal performing a discovery action (list roles/policies), then a modification action (attach/create policy or role), then a privileged action using the newly granted permission, all within a tight time window (typically under 30 minutes for scripted/automated chains; manual chains can stretch over hours).

Alert on the *chain*, not the isolated step - `ListRolePolicies` alone is noise; `ListRolePolicies` → `AttachRolePolicy` (admin policy) → `AssumeRole` (that same role) by the same identity inside 10 minutes is the finding.

## Required Log Sources & Event IDs

| Platform | Source | Key Event Identifiers |
|---|---|---|
| AWS | CloudTrail (management events) | `eventName`: `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `CreateAccessKey`, `UpdateAssumeRolePolicy`, `AssumeRole`, `PassRole` (as a parameter on `CreateFunction`, `RunInstances`, `CreateLambdaFunction`) |
| AWS | IAM Access Analyzer / CIEM tooling | Findings for "unused permissions granting privilege escalation," policy-simulator flags |
| Entra ID / M365 | Entra ID Audit logs | `Add member to role`, `Add app role assignment to service principal`, `Add owner to application`, `Update application - Certificates and secrets management`, `Consent to application` |
| Entra ID | Entra ID Sign-in logs | Correlate the principal's authentication event that precedes the chain |
| GCP | Cloud Audit Logs (Admin Activity) | `methodName`: `SetIamPolicy`, `google.iam.admin.v1.CreateRole`, `google.iam.admin.v1.CreateServiceAccountKey`, `google.iam.admin.v1.UpdateRole` |
| Cross-platform | Instance metadata service logs (AWS IMDS, Azure IMDS, GCP metadata server) | Requests for temporary credentials from a workload that shouldn't be making IAM calls at all |

## Key Fields to Inspect

**[ANALYST]**
- `userIdentity.arn`/`principalId` (AWS), `initiatedBy.user.id`/`initiatedBy.app.appId` (Entra), `protoPayload.authenticationInfo.principalEmail` (GCP) - the *same* principal across every step of the suspected chain; escalations spanning multiple identities usually mean lateral movement first, escalation second.
- `eventTime`/`timestamp` deltas between discovery, modification, and privileged-use events - sub-minute gaps between `ListPolicies` and `AttachRolePolicy` strongly suggest scripted/automated tooling rather than a human clicking through console.
- Policy document content, not just the attach event - pull the actual JSON policy (AWS `GetPolicyVersion`, Entra role definition, GCP role permissions list) and check for `"Action": "*"`, `"Resource": "*"`, or an unusually broad Graph API permission (`RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`).
- `sourceIPAddress`/`callerIp` and whether it matches the IMDS/local-instance loopback range (`169.254.169.254` requests logged via VPC Flow Logs or a metadata-service audit sidecar) - workload identity abuse frequently starts with metadata-service credential theft before the escalation chain in CloudTrail even begins.
- `userAgent` - `aws-cli`, `Boto3`, custom Python/PowerShell User-Agent strings performing rapid sequential IAM calls vs. the AWS Console's browser UA doing the same slowly.
- For Entra: whether the role/app-role assignment was `isBuiltIn`/eligible-via-PIM vs. a direct, non-PIM, permanent assignment - permanent direct grants bypassing PIM approval are a strong signal.
- Whether the resulting privileged identity was then used immediately (within minutes) for a high-impact action - that closes the loop from "escalation" to "escalation with intent."

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| IAM/cloud engineer attaches a policy via approved IaC pipeline (Terraform/CloudFormation apply, logged as the CI/CD service principal with a matching change-ticket ID in commit history) | Same human/service identity performs discovery (`ListRoles`, `ListAttachedPolicies`), then attaches or creates a policy, then immediately assumes/uses the new privilege - no ticket, no pipeline |
| A developer's role is granted a *scoped* permission increase through a documented access-request workflow | A developer's own role/user is modified by that same developer (self-service privilege grant with no second approver) |
| `PassRole` used by a CI/CD pipeline to launch known, expected Lambda functions/EC2 instances | `PassRole` used to attach an execution role with broader permissions than the calling identity's own role - classic escalation via service impersonation |
| Entra app registration owner adds a certificate/secret as part of a scheduled credential rotation, logged with change record | New owner added to an app registration that already holds high-privilege Graph consent, followed by a new client secret generated minutes later |

## Investigation Steps

1. Identify the full principal identity involved (human user, service principal, IAM role, EC2 instance profile) and pull its baseline permission set *before* the suspected escalation - what could it legitimately do an hour earlier?
2. Reconstruct the timeline: list every API call/audit event by that principal in the window bracketing the alert (30 minutes before through 30 minutes after), sorted chronologically - look specifically for the discovery → modify → use pattern.
3. Retrieve the actual policy document or role definition that was created/attached/modified. Diff it against the principal's prior effective permissions to confirm a genuine privilege increase (some "policy changes" are lateral, not escalating - e.g., swapping one scoped policy for another of equal power).
4. Determine how the principal obtained the credentials used - was this a human MFA-backed session, a long-lived access key, a stolen IMDS-derived temporary credential, or a compromised CI/CD secret? Check `CreateAccessKey`/`GetSessionToken`/metadata-service request logs around the same time.
5. Check for a matching change ticket, IaC pipeline run, or documented access-request approval covering this exact permission change. Absence of a ticket is not automatically malicious (manual break-fix happens) but it removes the benign-by-default assumption.
6. Search for downstream use of the newly acquired privilege: new principals created, other users' permissions modified, data-plane access to sensitive storage/secrets, logging or monitoring changes (`StopLogging`, disabling a diagnostic setting, `DeleteTrail`).
7. Pivot on the source: IP/ASN, session token issuance point, and whether the same source touched any other identities in the tenant in the surrounding hours - escalation chains are frequently the second or third step after an initial low-privilege compromise.
8. If a workload identity (Lambda, EC2 instance role, GCP service account) is implicated, check whether the workload itself was compromised (unexpected code execution, SSRF into the metadata service) rather than the credential being stolen directly - this changes the containment target from "rotate a key" to "rebuild an instance/container."

## True Positive Indicators

- Discovery → modify → privileged-use sequence completed by the same principal with no corresponding change ticket or IaC pipeline run.
- Policy/role granted is disproportionate to the principal's job function (e.g., a read-only reporting service account attaches an administrator-equivalent policy to itself).
- Newly attached policy or role definition contains wildcard actions/resources (`"Action":"*"`, `Microsoft.Authorization/*/write`, `roles/owner`).
- Evidence the initiating credential was obtained via metadata-service abuse, a leaked access key, or a stolen session token rather than normal interactive login.
- The escalated identity is used within minutes to create additional persistence (new access key, new admin user, new app registration with broad consent) or to disable logging/audit controls.

## False Positive / Benign Positive Indicators

- Escalation-shaped sequence matches an approved IaC pipeline run with a valid commit/change-ticket reference and the CI/CD service principal identity, not a human.
- Legitimate emergency access-management activity (documented break-glass procedure, PIM emergency activation) with corresponding approval record.
- Access Analyzer/CIEM tooling itself performing simulation-only calls (`SimulatePrincipalPolicy`, policy-linting tools) that read policy documents but never attach/modify anything - confirm the event was a mutating call, not a read.
- Known, previously-reviewed automation (e.g., a secrets-rotation Lambda that legitimately needs `iam:PassRole` for a narrow set of target roles) - verify against the documented exception list before closing.

## Escalation Criteria

Escalate to IR/CIRT immediately if: the escalation chain completed (privileged role/policy actually attached, not just attempted), the resulting privileged identity was used for any data-plane access to sensitive resources, logging/audit controls were disabled as part of or after the chain, or the originating credential shows signs of compromise (metadata-service abuse, leaked key, anomalous source geography). Notify the platform/cloud owner within the hour for any confirmed successful escalation, even if no further malicious action occurred yet - the exposure window matters for scoping.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Immediately detach/remove the escalated policy or role assignment and revoke active sessions/tokens for the principal - Tier 2 SOC lead can execute for a confirmed unauthorized chain under standing IR authorization.
- Disable/deactivate the originating identity (IAM user, service principal, workload identity) pending investigation - requires resource/platform owner sign-off unless active misuse is ongoing, in which case SOC lead acts under emergency authority and notifies after.
- Rotate any credentials (access keys, client secrets, instance-profile-derived tokens) associated with the originating principal - IAM/cloud engineering executes, SOC lead authorizes.
- Quarantine or rebuild the underlying workload if the escalation originated from a compromised compute resource (instance, container, function) rather than direct credential theft - requires platform engineering coordination.
- Review and tighten the specific permission primitive that enabled the chain (remove wildcard actions, scope `iam:PassRole` to named roles, require PIM for the affected Entra role) - cloud security engineering owns the fix, CISO/platform owner approves the policy change, tracked to closure as a preventive action separate from the incident itself.

## Example Query (AWS CloudTrail via Athena/SIEM - SQL-style)

```sql
SELECT useridentity.arn, eventname, eventtime, sourceipaddress
FROM cloudtrail_logs
WHERE eventtime > now() - interval '1' hour
  AND eventname IN ('AttachUserPolicy','AttachRolePolicy','PutUserPolicy',
                     'CreatePolicyVersion','AssumeRole')
  AND useridentity.arn IN (
      SELECT useridentity.arn FROM cloudtrail_logs
      WHERE eventname IN ('ListRoles','ListAttachedUserPolicies','ListPolicies')
        AND eventtime > now() - interval '1' hour)
ORDER BY useridentity.arn, eventtime;
```

## Closure Criteria

Close only after: the full action chain is reconstructed and timestamped, the actual policy/role content granted is confirmed (not assumed from the event name alone), the originating credential's provenance is established, downstream use of the escalated privilege is checked, and disposition is recorded as **True Positive**, **Policy Violation** (internal, no malicious intent - route to IAM governance regardless), **Benign Positive** (validated IaC/pipeline activity), or **Insufficient Evidence** (common when CloudTrail data events aren't enabled or Entra audit retention has already rolled the earlier discovery events off before analysis started - note the specific telemetry gap rather than defaulting to Benign).

**Example case note:**
"2026-09-15 09:52 UTC - Service principal `svc-report-sync@example.com` (Entra ID) performed `Add app role assignment` granting itself `RoleManagement.ReadWrite.Directory` at 09:31, then used that grant to add itself as owner of app `int-billing-connector` (holding `Application.ReadWrite.All`) at 09:34, then generated a new client secret for that app at 09:37. No change ticket or PIM activation on record. Source IP 198.51.100.22 (non-corporate ASN, first seen for this identity). Escalated to IR as confirmed compromise of `svc-report-sync` credentials; role assignment and app ownership reverted, client secret revoked, credential for `svc-report-sync` rotated. Platform owner notified 10:05 UTC; preventive ticket opened to require PIM for `RoleManagement.ReadWrite.Directory` grants."
