# New OAuth Application Registered/Consented

## Playbook ID & Name

**CLD-008 — New OAuth Application Registered/Consented (Entra ID / M365 / GCP / AWS)**

## Business Risk

**[STAKEHOLDER]** - Every time someone clicks "Accept" on an app permission prompt, they're potentially handing a third party a standing key to the tenant that doesn't expire when they change their password and often doesn't show up on an MFA prompt at all. This is the "illicit consent grant" problem: an attacker doesn't need your password if they can get you (or an admin) to authorize an app that can read your mail, your files, and your calendar on your behalf, indefinitely, via a refresh token. It's quiet, it's persistent, and it survives a normal password reset. This playbook covers the moment a new OAuth application is registered in the tenant and/or granted delegated or application permissions by a user or admin.

## Severity/Priority Default

**Medium** as the default for any new app consent by a standard user requesting non-trivial delegated scopes. **High** if the app requests mail, files, or directory-read scopes with `offline_access`, was consented to by a non-admin user, comes from an unverified publisher, or immediately follows a phishing click or suspicious sign-in. **Critical** if admin consent was granted tenant-wide for an unverified app, or if the app is later observed pulling mailbox/SharePoint data or creating a mail forwarding rule.

## MITRE ATT&CK Techniques

- T1550.001 Use Alternate Authentication Material: Application Access Token - the technique that most directly covers using the consented OAuth grant's access/refresh token to act as the user without their password
- T1098.001 Account Manipulation: Additional Cloud Credentials
- T1078.004 Valid Accounts: Cloud Accounts
- T1204 User Execution
- T1566.002 Phishing: Link
- T1114.003 Email Collection: Email Forwarding Rule
- T1567 Exfiltration Over Web Service
- T1530 Data from Cloud Storage

## Trigger / Detection Logic Summary

Alert fires on a new service principal/application object creation event combined with a consent grant event (`Add OAuth2PermissionGrant`, `Consent to application`) within the same session or a short correlation window, where any of the following is true: the requested scopes include high-privilege delegated permissions (`Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, `Sites.ReadWrite.All`, `Directory.ReadWrite.All`, `offline_access`); the consenting principal is a standard user rather than an admin (user consent, not admin consent); the application's publisher is unverified or the publisher domain doesn't match any known/approved vendor; the app is newly created in the tenant within the last 24 hours before consent; or the consent event is temporally close (same session, or within minutes) to a flagged sign-in (new device, unfamiliar ASN, or a prior phishing-link click logged by the email security gateway). Treat "app registered + consented within the same 10-minute window by the same actor" as a distinct high-signal pattern — it's the fingerprint of a self-service illicit consent attack rather than routine IT-approved integration work, which normally has days between registration/review and the actual consent grant.

## Required Log Sources & Event IDs

| Platform | Log Source | Key Operations / API Calls |
|---|---|---|
| Entra ID / M365 | Entra ID Audit Logs, Unified Audit Log (Purview) | `Add service principal`, `Add OAuth2PermissionGrant`, `Consent to application`, `Add app role assignment to service principal`, `Update application – Certificates and secrets management` |
| M365 (mailbox follow-on) | Unified Audit Log | `New-InboxRule`, `Set-Mailbox` (ForwardingSmtpAddress), `MailItemsAccessed` |
| GCP | Cloud Identity / Workspace Admin audit log | `AUTHORIZE_API_CLIENT_ACCESS`, third-party app OAuth token grant events |
| AWS | CloudTrail (if using IAM Identity Center / Cognito federated OAuth flows) | `CreateApplication`, `CreateOAuth2Client`, `AssumeRoleWithWebIdentity` |
| Email security / SEG | Gateway logs | Prior phishing-link click or consent-phishing URL delivery to the consenting user |

Note: OAuth consent activity has no numeric Windows/Sysmon Event ID equivalent — this is control-plane audit data, so correlation is done on the operation/activity name and object fields below, not an ID number.

## Key Fields to Inspect

**[ANALYST]**

- `AppId` / `AppDisplayName` and `ResourceDisplayName` (usually "Microsoft Graph" or "Office 365 Exchange Online")
- Requested `Scope` string on the `OAuth2PermissionGrant` — parse every delegated permission individually, don't eyeball it
- `ConsentType`: `AllPrincipals` (tenant-wide admin consent) vs a single user's consent
- `InitiatedBy.user.userPrincipalName` — who clicked Accept, and are they an admin role holder or a standard user
- Publisher verification status and publisher domain on the app registration object
- `ReplyUrls` / redirect URIs — do they point to a corporate domain, a generic cloud host, or something that looks like a credential-harvesting relay
- Whether the app is single-tenant or multi-tenant, and whether it was created in *this* tenant or is an external multi-tenant app being consented into it
- `CorrelationId` to tie the consent event to the sign-in session that preceded it
- Any `New-InboxRule` or mailbox forwarding change from the same user account in the following hours

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Known SaaS app (Salesforce, Zoom, DocuSign, Workday) consented via admin consent tied to a change ticket | Unfamiliar or generically-named app ("Document Viewer", "Office Update") consented by a single non-admin user |
| Requested scopes limited to `User.Read`, `offline_access` for basic sign-in | Scopes include `Mail.Read`, `Files.ReadWrite.All`, `Directory.ReadWrite.All` alongside `offline_access` |
| Publisher verified, domain matches vendor | Publisher unverified, or publisher domain unrelated to app's stated purpose |
| Days/weeks between app registration and production consent (review cycle) | App registered and consented within minutes by the same actor |
| Consent follows a planned integration rollout communicated to IT | Consent immediately follows a phishing-link click or an unfamiliar sign-in for that user |

## Investigation Steps

1. Pull the full audit event pair — `Add service principal`/app registration and the `Consent to application` / `Add OAuth2PermissionGrant` event — and record `AppId`, requesting/consenting UPN, timestamps, and exact scope string.
2. Decompose the scope string permission-by-permission. Flag any of `Mail.*`, `Files.ReadWrite.All`, `Sites.ReadWrite.All`, `Directory.ReadWrite.All`, or `offline_access` — these are the ones that enable durable mailbox/file access via refresh token.
3. Check publisher verification and app registration age/tenant of origin. An unverified publisher plus a brand-new multi-tenant app is the classic illicit-consent-grant signature. To actually pull these: in the Entra admin center, go to Enterprise Applications > [app] > Properties - the "Publisher verified" badge and publisher domain are shown there directly; via Graph API, `GET /servicePrincipals/{id}` returns `verifiedPublisher` and `appOwnerOrganizationId` (the latter is the tenant of origin for a multi-tenant app being consented into yours). For the reply URL/redirect URI, don't eyeball the domain for plausibility - run it through a URL/domain reputation tool (e.g., VirusTotal, urlscan.io) or your TIP's domain-lookup module; lookalike domains are built specifically to pass a glance.
4. Pull the sign-in event immediately preceding the consent for the consenting user — device, IP/ASN, MFA satisfaction, and whether the email gateway logged a consent-phishing link delivered/clicked around the same time.
5. Search mailbox audit logs for `New-InboxRule`, forwarding rule changes, or `MailItemsAccessed` spikes on the consenting user's mailbox in the hours after consent.
6. If application permissions (not just delegated) were granted, check what the app has actually done since — Graph API calls, SharePoint/OneDrive access, directory reads — via sign-in logs filtered on that `AppId`.
7. Interview the user: did they intend to install this app, do they recognize it, did they receive an email or pop-up prompting the consent.
8. Cross-check against the approved-application inventory/CASB (Defender for Cloud Apps, Cloud App Security) — is this app already known-good, known-bad, or genuinely new to the environment.

## True Positive Indicators

- High-privilege scopes (mail, files, directory) plus `offline_access`, granted by a non-admin user, from an unverified publisher
- Registration and consent occurring within minutes, by the same actor, for a never-before-seen app
- Consent immediately follows a logged phishing-link click or an anomalous sign-in for that user
- Follow-on activity from the app: mailbox forwarding rule creation, mass file download, or Graph API calls to enumerate users/mail after consent
- App reply URL or publisher domain resolves to infrastructure unrelated to any legitimate vendor

## False Positive / Benign Positive Indicators

- App matches an entry in the approved SaaS/vendor integration inventory with a corresponding change ticket
- Admin consent performed by IT during a documented rollout window for a verified publisher
- Scopes limited to basic profile/sign-in (`User.Read`, `openid`, `profile`) with no mail/file/directory access
- Internal developer test app registered and self-consented in a sandbox tenant, with no production data scopes
- Duplicate audit entries from Unified Audit Log replication/multi-region delivery of the same consent event

## Escalation Criteria

Escalate to Tier 2/IR immediately when high-privilege delegated or application permissions were granted by a non-admin user to an unverified-publisher app, especially when correlated with a phishing click or a flagged sign-in. Escalate to the IR lead and initiate breach-assessment/notification review if post-consent activity shows actual mailbox content access, a forwarding rule pointing to an external address, or SharePoint/OneDrive data pulled through the app's Graph token — this moves the case from "suspicious grant" to "confirmed data access" and may trigger regulatory notification depending on data classification.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority Required |
|---|---|
| Revoke the app's OAuth2PermissionGrant and disable the service principal (sign-in disabled) | SOC Tier 2, immediate, if app is confirmed unrecognized/malicious |
| Revoke all refresh tokens / active sessions for the consenting user | SOC Tier 2, immediate, notify user and manager post-action |
| Remove any inbox rule or forwarding address created after consent | SOC Tier 2, immediate |
| Force MFA re-registration and password reset for the affected user | Security lead approval |
| Disable user consent for applications tenant-wide (require admin consent workflow going forward) | Identity/IAM governance owner approval — business-impacting policy change |
| Notify data owner / initiate breach-assessment workflow if content access confirmed | CISO or Privacy/Legal, per incident severity |

SLA: high-privilege unverified-publisher consents triaged within 30 minutes of alert; confirmed malicious grants revoked within 1 hour of confirmation.

## Example Query

```kql
// Entra ID - non-admin consent to unverified app with high-risk scopes
AuditLogs
| where OperationName == "Consent to application"
| extend Scopes = tostring(TargetResources[0].modifiedProperties[0].newValue)
| extend ConsentGrantedBy = tostring(InitiatedBy.user.userPrincipalName)
| where Scopes has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All", "offline_access")
| where ConsentGrantedBy !in (AdminUpnList)
| project TimeGenerated, ConsentGrantedBy, Scopes, TargetResources
```

## Closure Criteria

Close as **True Positive** (contained) once the service principal is disabled, the permission grant is revoked, affected user sessions/tokens are invalidated, and root cause (phishing, coerced consent, curiosity click) is documented. Close as **Benign Positive** when the app maps to an approved vendor integration with matching change record. Close as **Insufficient Evidence** if the consenting user cannot be reached and no follow-on Graph/mailbox activity is observed within the retention window to confirm intent.

**Example case note:** "New multi-tenant app 'Quick PDF Helper' (AppId a1b2c3d4-...) registered and consented within 4 minutes by j.ferreira@example.com at 2026-09-12 14:22 UTC, requesting Mail.Read, Files.ReadWrite.All, offline_access from unverified publisher. Consent followed a link click on a phishing email flagged by SEG at 14:18 UTC. No forwarding rule found, but MailItemsAccessed shows a burst of 340 read events at 14:30 UTC. Service principal disabled and grant revoked 14:55 UTC, user tokens revoked, password reset forced, escalated to IR for mailbox-access impact assessment."
