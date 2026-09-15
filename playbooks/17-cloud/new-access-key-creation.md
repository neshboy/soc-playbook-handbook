# New Access Key Creation

**Playbook ID & Name:** CLD-002 — New Access Key / Programmatic Credential Creation (AWS IAM Access Key, Azure/Entra ID App & Service Principal Secret, GCP Service Account Key)

**[STAKEHOLDER]** - A long-lived credential just got created for a cloud identity. If that identity belongs to an attacker-controlled account, or the key was created *by* an attacker who already compromised a legitimate account, they now have durable, MFA-free access to your cloud environment that survives password resets and session revocation. This is one of the highest-value persistence mechanisms in cloud incidents - it's why "just reset the password" is never a complete remediation.

**Severity/Priority default:** Medium, auto-escalates to High if the key belongs to a privileged/admin identity, a break-glass account, or was created outside business hours from an unfamiliar location.

**MITRE ATT&CK Techniques:** T1098.001 (Additional Cloud Credentials) - primary; T1078.004 (Valid Accounts: Cloud Accounts); T1136 (Create Account) - when a new IAM user/service account is created immediately before the key; T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) - common precursor when the actor stole a session token via IMDS abuse before minting a durable key.

## Trigger / Detection Logic Summary

Fires on any successful API call that mints a new programmatic credential for an identity: AWS `CreateAccessKey`, Azure/Entra ID "Add service principal credentials" / "Add application password" (app registration client secret or certificate), or GCP `CreateServiceAccountKey`. The playbook is identity-and-context driven, not purely "event happened" - a key creation on a service account whose owning team requested it in the change ticket is expected operational noise; the same event on a dormant admin account at 03:00 from a new ASN is not.

**[ENGINEERING]** - Baseline this per-identity, not globally. Most environments have a small, stable population of principals that legitimately rotate keys on a schedule (CI/CD service accounts, Terraform runners, backup service principals). Anything outside that known population - or a known principal creating a *second or third concurrent* active key - should raise the correlation score.

## Required Log Sources & Event IDs

| Platform | Log Source | Event / Operation Name |
|---|---|---|
| AWS | CloudTrail (management events) | `eventName=CreateAccessKey`, `eventSource=iam.amazonaws.com` |
| AWS (context) | CloudTrail | `eventName=CreateUser`, `AttachUserPolicy`, `PutUserPolicy` |
| Azure / Entra ID | Entra ID Audit Logs (Microsoft Graph `directoryAudits`) | Activity: "Add service principal credentials", "Add application password" (Category: `ApplicationManagement`) |
| M365 | Unified Audit Log (Purview) / Entra ID Audit Log | Same app-registration secret events above (M365 auth chains through Entra ID app registrations) |
| GCP | Cloud Audit Logs - Admin Activity | `methodName=google.iam.admin.v1.CreateServiceAccountKey`, `serviceName=iam.googleapis.com` |
| All | IdP / SSO logs | Preceding authentication event for the actor who called the API |

Note the retention trap: AWS CloudTrail management events and Entra ID audit logs are often retained only 90 days by default before export to a SIEM or long-term S3/Log Analytics workspace - if this fires late (post-incident hunt), confirm the log actually still exists before assuming absence means innocence.

## Key Fields to Inspect

**[ANALYST]**

| Field | What to check |
|---|---|
| `userIdentity.arn` / `initiatedBy` (Entra) / `principalEmail` (GCP) | Who *called* the create operation - is it the same identity the key was created *for*, or a different (possibly compromised) admin? |
| `userIdentity.type` | `IAMUser`, `AssumedRole`, `Root` - root-account key creation is near-automatic escalation |
| `sourceIPAddress` / `callerIpAddress` | Known corporate egress, VPN range, CI/CD runner IP, or unfamiliar ASN/hosting provider |
| `userAgent` | AWS CLI, boto3, Terraform, or a raw `curl`/scripting agent nobody recognizes |
| `requestParameters.userName` (AWS) / `appId` (Entra) / `serviceAccountEmail` (GCP) | Which identity received the new credential - privileged role bindings attached to it? |
| `responseElements.accessKey.accessKeyId` | Track this key ID forward for first-use correlation |
| MFA / session context on the calling principal | Was the console/API session that created the key itself backed by MFA, or a long-lived unattended session? |
| Time-to-first-use | Gap between key creation and first authenticated API call using that key - near-zero gap from a new location is a strong signal |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| CI/CD service account rotates its own key on a documented schedule, same source IP range as always | Human admin account creates an access key for itself outside a change window |
| Key created by an automation role with a matching change ticket / IaC pipeline run ID | Key created by a role assumed minutes after a suspicious sign-in (impossible travel, new device) |
| One active key per service account (AWS best practice caps at 2 for rotation overlap) | Third or fourth concurrent active key appearing on an account that normally has one |
| Key creation followed by expected downstream calls consistent with the service's job | Key created, never used from the "normal" location, but used within minutes from a foreign IP/Tor exit/VPS |
| Entra ID app secret added by the app owner listed in the app registration's owner field | App secret added by an account with no relationship to the app, especially a guest account |

## Investigation Steps

1. Pull the raw event: confirm actor identity, target identity, source IP, user agent, and timestamp. Do not trust a dashboard summary - go to the raw CloudTrail/audit log record.
2. Establish whether the calling identity's own authentication was itself suspicious in the prior 30-60 minutes (failed MFA, new device, unusual geo, password spray hits against that account).
3. Check if the target identity is privileged - pull attached IAM policies/role bindings (AWS), app registration API permissions and admin consent status (Entra), or IAM roles bound to the service account (GCP).
4. Search for first-use of the new key/secret: which API calls, from where, how soon after creation. A key created then immediately used to call discovery APIs (`ListUsers`, `ListRoles`, `GetCallerIdentity`, `google.iam.admin.v1.ListServiceAccounts`) is a strong reconnaissance signal.
5. Check for a matching change record (ticket, Terraform plan/apply log, deployment pipeline run) - legitimate rotations almost always have paper trail; if the requesting team can't produce one within the SLA window, treat as unconfirmed.
6. Pivot on the source IP/ASN across the last 24-48 hours - is this the same actor behind other suspicious activity (console sign-ins, other IAM changes, S3 bucket enumeration)?
7. Check for related identity manipulation in the same session: new IAM users created, policies attached, MFA devices deregistered, or other principals' credentials touched - this scenario very often travels with T1136 and privilege escalation attempts.
8. If confirmed or suspected malicious, freeze the key's owning identity's other sessions (revoke STS tokens / refresh tokens) before deactivating the key itself, so the actor can't just re-mint another one first.

## True Positive Indicators

- Key created by an identity with no operational reason to manage credentials for the target account.
- Key/secret created immediately following a suspicious authentication event on the calling identity.
- Rapid first-use from infrastructure inconsistent with the service's normal footprint (VPS hosting range, anonymizing proxy).
- No corresponding change ticket, IaC run, or owner acknowledgment.
- Target identity is privileged and the key was created outside a documented rotation window.
- Multiple concurrent active keys appear where policy caps at one active + one overlap key.

## False Positive / Benign Positive Indicators

- Scheduled key rotation by a known automation pipeline (Terraform, Ansible, internal secrets-rotation Lambda) matching a documented cadence.
- Developer self-service key creation inside an approved sandbox/dev account with no production access, matching normal working hours and source IP.
- App registration secret renewal ahead of expiry, performed by the listed app owner, with admin consent status unchanged.
- Key created but never used within the observation window and owning team confirms it was pre-provisioning for a planned deployment.

## Escalation Criteria

Escalate to Incident Response if: the target identity is a break-glass/root/global-admin account; the key is used within the same session to touch other identities' credentials or IAM policies; source infrastructure matches known threat intel (Tor, bulletproof hosting, prior campaign IOC); or the calling identity's own sign-in was already flagged in an open case. Escalate to the cloud platform team (without full IR) when it's an unauthorized-but-likely-benign rotation from an unfamiliar internal team, for policy clarification.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Deactivate/delete the access key or app secret | SOC Tier 2 lead can act immediately if TP confirmed on a non-production identity; Cloud/IAM platform owner sign-off required for production or shared service accounts |
| Revoke active sessions/STS tokens for the owning identity | SOC Tier 2, no additional approval if identity is confirmed compromised |
| Disable the IAM user / service principal / service account entirely | Cloud platform owner or IAM team lead; notify application owner before disabling anything customer-facing |
| Force password/MFA reset on the calling human identity | IAM/Identity team, standard account-compromise SLA |
| Emergency root/global-admin credential rotation | Requires CISO or designated incident commander sign-off given blast radius |

Target SLA: acknowledge within 15 minutes for privileged-identity key creation alerts, contain within 1 hour once confirmed malicious.

## Example Query (Splunk SPL - AWS CloudTrail)

```spl
index=cloudtrail eventName=CreateAccessKey eventSource=iam.amazonaws.com
| eval callerIsTarget=if(userIdentity.arn LIKE "%".requestParameters.userName."%",1,0)
| where callerIsTarget=0 OR userIdentity.type="Root"
| stats count by userIdentity.arn, requestParameters.userName, sourceIPAddress, userAgent, _time
| sort - _time
```

## Closure Criteria

Close as **True Positive** once the key/secret is deactivated, owning identity's sessions revoked, and downstream use (if any) is fully scoped in the case timeline. Close as **Benign Positive** when a valid change ticket or IaC pipeline run is confirmed and matches actor, timing, and target identity. Close as **Insufficient Evidence** when CloudTrail/audit retention has already rolled off the source IP or user-agent detail needed to make a call, and no compensating log (VPC Flow Logs, IdP sign-in log) fills the gap - document what was missing so retention can be flagged to the platform team.

**Example case note:** *"CreateAccessKey on svc-billing-automation initiated by user arn:aws:iam::111122223333:user/j.torres, source IP 203.0.113.44 (unrecognized ASN, not corporate VPN range), no matching change ticket. j.torres's console sign-in 6 min prior flagged impossible-travel (last known location: Denver; sign-in from Bucharest). New key used once to call sts:GetCallerIdentity and iam:ListAttachedUserPolicies before deactivation. Classified True Positive - credential compromise, key deactivated, j.torres sessions revoked, password+MFA reset forced, escalated to IR for full account compromise workup."*
