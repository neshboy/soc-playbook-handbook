# Cloud Shell Abuse

## Playbook ID & Name
**CLD-016 — Cloud Shell Abuse (Azure Cloud Shell / AWS CloudShell / GCP Cloud Shell)**

## Business Risk

**[STAKEHOLDER]** - Cloud shells (Azure Cloud Shell, AWS CloudShell, GCP Cloud Shell) give an authenticated user a fully-featured Linux CLI running inside the provider's own network, pre-authenticated with that user's or a managed identity's permissions, and reachable from any browser with no client install. If an attacker gets a valid session — through a stolen token, a compromised admin account, or a phished Cloud Console login — they inherit a trusted execution environment that most egress and endpoint controls simply cannot see. This is one of the cheapest ways to turn "we caught a suspicious login" into "we're now missing storage account keys and three new service principals." The business impact is credential sprawl and data exposure, not ransomware-style noise, so it tends to get under-prioritized until the bill or the breach notification shows up.

## Severity / Priority Default
**High (P2)** on detection of cloud shell provisioning tied to any anomalous or risky sign-in. **Critical (P1)** if metadata/token theft, new credential creation, or storage/data-plane access is confirmed within the session.

## MITRE ATT&CK Techniques
- T1078.004 — Valid Accounts: Cloud Accounts (initial access enabling the shell session)
- T1059 / T1059.004 — Command and Scripting Interpreter / Unix Shell (execution inside the shell; AWS CloudShell and GCP Cloud Shell are Bash-only, and Azure Cloud Shell defaults to Bash with a PowerShell option — cite T1059.001 PowerShell instead when the session is confirmed running Azure Cloud Shell's PowerShell experience)
- T1105 — Ingress Tool Transfer (pulling tooling into the ephemeral shell VM)
- T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
- T1580 — Cloud Infrastructure Discovery
- T1530 — Data from Cloud Storage
- T1567 — Exfiltration Over Web Service
- T1098.001 — Additional Cloud Credentials
- T1572 — Protocol Tunneling
- T1090 — Proxy

## Trigger / Detection Logic Summary
Alert fires when a cloud shell provisioning or session-start event is correlated with any of: a risky/anomalous sign-in (impossible travel, unfamiliar ASN, anonymizer/Tor exit node), a sign-in outside the user's normal pattern for a privileged account, first-time cloud shell use by that identity, or cloud shell activity immediately followed by IMDS metadata calls, new access key/service principal creation, or storage/blob enumeration. Cloud shell provisioning itself is not inherently malicious — most tenants have legitimate daily use — so this playbook is triggered by the **combination** of shell launch plus a risk signal, not the launch alone.

## Required Log Sources & Event/Operation Names
| Platform | Log Source | Key Operations / Fields |
|---|---|---|
| Azure / Entra ID | Entra ID Sign-in logs | `AppDisplayName` = Azure CLI / Cloud Shell client, `ResourceDisplayName`, `RiskLevelDuringSignIn`, `ConditionalAccessStatus` |
| Azure | Azure Activity Log | `Microsoft.Portal/consoles/write` (shell provisioning), `Microsoft.Storage/storageAccounts/write` (first-run storage creation), `Microsoft.Authorization/roleAssignments/write` |
| Azure | Storage Account diagnostic logs | Reads/writes against the auto-created storage account (naming pattern `cs<suffix>`) and `.cloudconsole` file share |
| Azure | Microsoft Defender for Cloud / Defender for Identity alerts | Alerts tagged to cloud shell / CLI sign-in anomalies |
| AWS | CloudTrail | `CreateEnvironment`, `GetEnvironmentStatus`, `StartSession` (SSM-backed), `PutCredentials`, subsequent `GetSessionToken` / `AssumeRole` calls in the same session |
| GCP | Cloud Audit Logs | Service `cloudshell.googleapis.com`, method `google.cloud.shell.v1.CloudShellService.AuthorizeEnvironment` / `StartEnvironment` |
| All | Identity Provider / SSO logs | MFA satisfaction method, device compliance state, conditional access decision |

**Known blind spot:** none of these providers log the actual commands typed inside the shell by default. There is no shell history transcript shipped to SIEM unless the customer has separately configured session recording (e.g., piping shell activity to a logging endpoint, or AWS Session Manager logging for CloudShell-adjacent SSM sessions). Assume you are working from "session existed, here's what it touched afterward," not a command-by-command transcript, unless proven otherwise.

## Key Fields to Inspect

**[ANALYST]**
- Identity: UPN / IAM ARN / GCP principal email that launched the shell
- Source IP, ASN, and geolocation of the sign-in that preceded shell launch
- `AppDisplayName` / `ClientAppUsed` (Azure CLI, Cloud Shell, AWS console federated session)
- `RiskLevelDuringSignIn`, `RiskState`, Conditional Access policy result
- Time of provisioning vs. the user's historical baseline (first-time use is itself a signal)
- Storage account / file share access pattern immediately after shell start (Azure)
- Any call to `169.254.169.254` (IMDS) or the GCP/AWS metadata equivalents from within the session's subsequent API activity
- New IAM artifacts created in the following 15-30 minutes: access keys, service principals, app registrations, role assignments, additional email delegates
- Outbound destinations reachable from cloud shell egress (provider IP ranges), especially connections to storage/webhook/paste services

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Admin opens Cloud Shell mid-week from a known corporate IP/device, MFA satisfied, session under 20 minutes, runs routine `az`/`aws`/`gcloud` resource management commands | Shell launched seconds after a flagged risky sign-in, from an unfamiliar ASN, Tor/VPN exit, or a country the user has never signed in from |
| Shell used to redeploy a known pipeline, check resource health, rotate a known secret with change-ticket context | First-ever Cloud Shell use by an account that has never touched CLI tooling, especially a non-engineering account |
| Storage account (`cs*` share) access limited to the user's own profile/config files | Broad enumeration commands (`az resource list`, `aws s3 ls` across all buckets, `gcloud projects list --format=json`) run within minutes of session start |
| No new credential material created during the session | New access key, service principal, app registration secret, or mail delegate created mid-session |
| Session terminates normally, no unusual egress | Evidence of tunneling (SSH port-forward, `ngrok`-style relay) or the shell's trusted egress IP used to reach services that would otherwise be blocked from the attacker's real location |

## Investigation Steps
1. **Anchor on the triggering sign-in.** Pull the Entra ID / IAM sign-in event that immediately precedes the cloud shell provisioning event. Confirm risk level, IP/ASN, device compliance, and whether Conditional Access allowed or challenged it.
2. **Confirm the identity's baseline.** Check whether this account has used Cloud Shell/CLI tooling before. First-time use on a privileged or non-technical account is a strong signal on its own.
3. **Reconstruct the session window.** Correlate Activity Log / CloudTrail / Cloud Audit Log entries for the identity across the full session duration, not just the launch event — look for role assumptions, resource reads, and any write operations.
4. **Check for credential-related actions.** Search for new access keys, service principal creation (T1098.001), app registration secrets, or IMDS/metadata calls (T1552.005) issued by the same principal during or immediately after the session.
5. **Check for data access and staging.** Look for storage/blob/bucket list and get operations (T1530) inconsistent with the user's normal job function, and any subsequent outbound transfer to third-party web services (T1567).
6. **Check for tunneling or proxy use.** Review whether the shell's outbound connectivity was used to reach internal resources or external relay services that bypass normal egress controls (T1572, T1090) — this is more relevant when the tenant has Cloud Shell VNet integration enabled.
7. **Interview if warranted.** If the account belongs to a real person reachable during business hours, ask directly whether they opened a cloud shell session at the time in question before escalating — this resolves a large fraction of these alerts fast.
8. **Scope blast radius.** If compromise is confirmed, enumerate every resource, credential, and role touched by the session so remediation isn't limited to just the shell access itself.

## True Positive Indicators
- Cloud shell provisioning tied to a confirmed compromised credential or a sign-in the user denies performing
- New service principal / access key / app secret created within the session with no matching change ticket
- Metadata API calls followed by use of the retrieved token against unrelated resources
- Mass enumeration of storage, IAM, or resource inventory inconsistent with the account's role
- Outbound transfer of enumerated data to an external endpoint

## False Positive / Benign Positive Indicators
- Confirmed legitimate admin activity validated directly with the user, matching a change ticket or known maintenance window
- Risk score driven by a known corporate VPN egress IP that was recently reassigned or not yet allow-listed
- First-time Cloud Shell use explained by role change, onboarding, or a new automation pipeline adopting CLI tooling
- CI/CD service principal legitimately invoking Cloud Shell-adjacent APIs (verify against known pipeline identity, not a human UPN)

## Escalation Criteria
Escalate to IR immediately if: metadata/token theft is confirmed and reused elsewhere, new credentials were created that cannot be immediately accounted for, the session touched production data stores or secrets vaults, or the identity involved holds Global Admin / Owner / organization-level privilege. Escalate to the cloud platform team regardless of confirmed maliciousness if Cloud Shell's default configuration (no VNet restriction, no session logging) contributed to the blind spot — that's a control gap worth a ticket even on a benign closure.

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Who Can Approve |
|---|---|
| Revoke active session / refresh tokens for the identity | SOC on-call, immediate, no additional approval needed for a confirmed risky session |
| Force password reset + re-register MFA | SOC lead, immediate for suspected account compromise |
| Disable the specific access key / service principal created during the session | Cloud/IAM engineering lead, same-shift approval |
| Disable Cloud Shell for the account or at subscription/tenant level via Conditional Access or policy | Cloud platform owner — this has broad user impact, needs sign-off before tenant-wide rollout |
| Preserve/snapshot the Cloud Shell storage account (`.cloudconsole` share) before any deletion | SOC + Cloud engineering jointly, for forensic preservation |
| Rotate any secrets/keys the session had access to | Resource/data owner, escalated same-day |

## Example Query (Microsoft Sentinel / KQL)
```kql
SigninLogs
| where AppDisplayName in ("Azure CLI", "Microsoft Azure CLI", "Azure Portal")
| where ResultType == 0
| join kind=inner (
    AzureActivity
    | where OperationNameValue has "MICROSOFT.PORTAL/CONSOLES"
) on $left.UserId == $right.Caller
| where RiskLevelDuringSignIn != "none" or isnotempty(NetworkLocationDetails)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          OperationNameValue, RiskLevelDuringSignIn
```

## Closure Criteria
Close as **True Positive** once the session's actions are fully enumerated, any credentials created or exposed are rotated/revoked, and the initiating access path (stolen token, compromised account) is remediated. Close as **Benign Positive** once the user confirms the session was theirs and the risk signal that triggered the alert (new IP, first-time use) is explained. Close as **Expected Activity** instead when an approved change record already documents the session, and the risk signal is understood and, if needed, allow-listed. Close as **Insufficient Evidence** if command-level detail cannot be reconstructed and no downstream credential or data-access anomaly is found, but note the logging gap for follow-up.

**Example case note:**
> 2026-09-15 14:02 UTC — Alert triggered on Cloud Shell provisioning for user j.alvarez@example.com immediately following a sign-in flagged RiskLevelDuringSignIn=medium from an unrecognized ASN in Brazil (account normally signs in from 10.44.0.0/16 corporate range). No new credentials, role assignments, or storage access observed in Activity Log for the 25-minute session window. User confirmed via phone that they were traveling and used a hotel network; MFA was satisfied via Authenticator push. Closed as Benign Positive; recommended Conditional Access named-location update for travel scenario to reduce repeat noise.
