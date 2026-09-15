# Credential Phishing (Email)

## Playbook ID & Name
**EML-007 — Credential Phishing (Email-Based Credential Harvesting)**

## Business Risk
**[STAKEHOLDER]** - A successful credential phish hands an attacker a working username and password (and, if the target org hasn't enforced phishing-resistant MFA, a live session token) without a single exploit or malware sample touching an endpoint. From there they can read mail, reset other passwords, redirect payments, or pivot into finance and payroll systems. This is the single most common entry vector the SOC deals with, and the cost of getting the response slow or wrong is measured in wire-fraud losses, not just analyst time.

## Severity/Priority default
**Medium** at first report (unconfirmed click, no sign-in correlation).
**High** if the click is confirmed and a subsequent sign-in from an unfamiliar ASN/device is observed within the click window.
**Critical** if the account is privileged (finance, payroll, help desk, IT admin, executive) or if post-compromise activity (inbox rule creation, delegate grant, MFA method registration) is already visible.

## MITRE ATT&CK Technique(s)
| ID | Technique | Where it applies here |
|---|---|---|
| T1566.002 | Phishing: Link | Primary delivery — link to credential harvesting page |
| T1566.001 | Phishing: Attachment | HTML/PDF attachment that redirects to or embeds a fake login form |
| T1204 | User Execution | User clicks the link and submits credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | Attacker authenticates to the cloud IdP with the stolen credential |
| T1078.002 | Valid Accounts: Domain Accounts | Credential also valid on-prem (password reuse against AD-synced account) |
| T1114.003 | Email Collection: Email Forwarding Rule | Post-compromise mailbox forwarding for continued visibility/BEC |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Attacker grants delegate access to persist |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Attacker registers a new MFA method / app password to survive a forced reset |

## Trigger / Detection Logic Summary
Any of the following opens a case:
- Secure Email Gateway (SEG) or M365 Defender/Safe Links verdict tags a delivered message as **credential phishing** / **spoof** / **malicious URL** after click-time re-scan.
- User submits a "Report Phishing" / "Report Message" add-in event, especially where the message body contains a login-form link.
- URL/web proxy or DNS logs show a user resolving or POSTing to a domain newly categorized as phishing, credential-harvesting, or typosquat of a known brand (Microsoft, Okta, Google, the org's own SSO portal).
- Correlation rule: a Safe Links/URL-click event for a flagged domain followed within a short window by an Entra ID sign-in from an ASN/country/device not previously associated with that user.

Most cases arrive as a user report, not an automated alert — the gateway missed it, and that's normal, not a control failure to relitigate every time.

## Required Log Sources & Key Audit Records
| Source | Record / Field of Interest | What it tells you |
|---|---|---|
| Secure Email Gateway / M365 Defender for Office 365 | Message trace, URL detonation verdict, Safe Links click log | Delivery path, sender infra, click timestamp, verdict |
| Entra ID (Azure AD) Sign-in logs | `UserLoggedIn`, `SignInLogs` (interactive + non-interactive) | IP, ASN, device, client app, conditional access result, MFA method used |
| M365 Unified Audit Log | `New-InboxRule`, `Set-InboxRule`, `Add-MailboxPermission`, `Set-Mailbox`, `UpdateInboxRules`, `Add-DelegatedPermission` | Post-compromise persistence and mailbox manipulation |
| MFA / Auth registration logs | `Add MFA method`, `Update user`, `Add app password` | New authenticator, phone, or app password added after the login |
| Web proxy / DNS logs | Destination domain, category, HTTP POST size to login form | Confirms the user actually reached and submitted to the harvesting page |
| Identity provider (Okta/Ping, if in use) | Login event, factor evaluation result | Same purpose as Entra sign-in logs for non-Microsoft shops |
| On-prem AD (only if password is shared/synced) | Authentication logs for the affected account | Confirms whether the phished credential is also valid internally |

## Key Fields to Inspect
**[ANALYST]**
- Sender: display name vs. actual SMTP address, return-path domain, SPF/DKIM/DMARC result (`pass`/`fail`/`softfail`/`none`).
- URL: full click-time URL (not just the display text), redirector chain length, final landing domain, TLS cert issuer/age (freshly issued certs on look-alike domains are common).
- Recipient behavior: click timestamp, user agent at click, whether the click came from a corporate egress IP or an unfamiliar one (attackers sometimes click their own tracking links).
- Sign-in correlation: IP/ASN, country, device ID (new vs. known), client app (legacy auth protocols like IMAP/POP with no MFA are a red flag), conditional access result (`success`, `failure`, `interrupted`).
- Post-auth artifacts: new inbox rules (especially ones that move/delete/forward mail matching finance-related keywords), new delegate/send-as grants, new registered MFA method.

## Normal vs Suspicious Pattern
| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Reported email | Marketing newsletter, legitimate password-expiry notice from actual IdP domain | Urgent tone, brand impersonation, mismatched sender domain, shortened/redirector link |
| Click | None, or click followed by no submission | Click followed by POST to the same domain (form submission) |
| Sign-in after click | No new sign-in, or sign-in from known device/location | New device, new country/ASN, legacy auth, conditional access "interrupted" then a later "success" from a different location |
| Inbox rules | None created, or admin-deployed rule with known name | User-created rule with generic name (`.`, `RSS`, `Update`) that moves mail to RSS Feeds/Archive or forwards externally |
| MFA registration | User re-registers their own known device after IT ticket | New method added with no corresponding help desk ticket, especially SMS to an unrecognized number |

## Investigation Steps
1. Pull the full message headers and Safe Links/URL click log for the reported message; confirm SPF/DKIM/DMARC results and the true sending infrastructure.
2. Resolve the landing URL through the SEG's detonation report or an isolated analysis VM — never browse to it directly from a corporate endpoint. Confirm whether it presents a credential-harvesting form and which brand it impersonates.
3. Check whether the user actually submitted credentials: proxy/DNS POST activity, or the SEG's own submission telemetry if available. A click alone is not proof of compromise.
4. Pivot to Entra ID / IdP sign-in logs for the affected UPN, filtered to a window starting at the click timestamp. Look for a sign-in from a new device/ASN, legacy auth, or a conditional-access anomaly.
5. Review the M365 Unified Audit Log for the account: new inbox rules, delegate grants, mailbox forwarding, mail flow rule changes, and MFA/security-info updates in the following 24-48 hours.
6. Check for lateral reuse — same subject line/sender infra hitting other mailboxes (bulk phishing campaign vs. targeted BEC against this one user).
7. If the credential is shared with on-prem AD (common in hybrid environments without separate passwords), check authentication activity against domain resources for the same account.
8. Document scope: one user, or a campaign. If a campaign, pull the full recipient list from the SEG and triage each recipient's click/submission status before closing the case.

## True Positive Indicators
- Confirmed form submission to a known or newly-categorized phishing domain.
- Sign-in success immediately following the click from an ASN/country/device never seen for that user before.
- New inbox rule or forwarding rule created shortly after the sign-in, particularly one filtering on terms like `invoice`, `wire`, `payroll`, or one that silently deletes replies.
- New MFA method or app password registered without a corresponding IT/help desk record.
- Multiple recipients across the org clicking the same campaign link within a short window.

## False Positive / Benign Positive Indicators
- Click occurred but the SEG's own detonation/redirect wrapper is what generated the "click" log entry (automated pre-fetch, not the human).
- Domain was miscategorized by the gateway and is a legitimate vendor portal — verify against the actual vendor's published domains before dismissing, don't just trust the user's assurance.
- Sign-in anomaly explained by legitimate travel, new corporate device rollout, or a VPN egress change — check the travel/device change ticket if one exists.
- Security awareness training simulated-phishing platform (KnowBe4, Proofpoint Security Awareness, etc.) — confirm against the simulation calendar before treating as real.

## Escalation Criteria
Escalate to IR/BEC-specific handling and notify management immediately when: the account is privileged or has finance/payroll access; a post-click sign-in success is confirmed; any inbox rule, delegate grant, or MFA registration change is found; or more than one user in the same business unit reports the same campaign. Escalate to legal/HR if the phishing lure itself contains sensitive internal information (suggests prior compromise or insider knowledge).

## Containment Options & Approval Authority
**[MANAGEMENT]**
| Action | Who can approve | Notes |
|---|---|---|
| Force password reset + revoke active sessions/tokens | Tier 2 analyst / IR lead, no separate approval needed once TP confirmed | Do this before anything else if sign-in success is confirmed |
| Remove malicious inbox rule / delegate grant (`Remove-InboxRule -Mailbox <UPN> -Identity "<RuleName>"`; delegate via `Remove-MailboxPermission`) | Tier 2 analyst | Log the exact rule content in the case before deleting it |
| Block sender domain/URL org-wide | SOC lead | Coordinate with messaging admin to avoid blocking a legitimate re-categorized domain |
| Disable account entirely | IR lead + manager of affected user (business impact) | Reserved for confirmed BEC/fraud risk, not routine phish clicks |
| Notify finance/payroll to hold pending payment changes | SOC lead escalates to Finance leadership directly, time-critical | Applies whenever a finance-adjacent mailbox is involved, don't wait for full investigation to close |
| Customer/partner notification (if their contacts were targeted from a compromised mailbox) | CISO / Legal | Standard breach-notification decision path, outside SOC authority |

## Example Query (Microsoft Sentinel / KQL)
```kql
EmailEvents
| where ThreatTypes has "Phish"
| join kind=inner (
    SigninLogs
    | where ResultType == "0"
) on $left.RecipientEmailAddress == $right.UserPrincipalName
| where TimeGenerated between (Timestamp .. Timestamp + 2h)
| project Timestamp, TimeGenerated, RecipientEmailAddress, SenderFromAddress, UrlCount, IPAddress, Location, AppDisplayName
```
*Note: `EmailEvents`' time column is `Timestamp`, not `TimeGenerated` (that name belongs to `SigninLogs`), and `SigninLogs.ResultType` is a string field ("0" = success), not an int — both are fixed above.*

## Closure Criteria
Close as **True Positive** once credential exposure is confirmed or ruled out (submission confirmed, sign-in checked), containment actions are logged, and any post-compromise artifacts (rules, delegates, MFA changes) are removed and verified gone. Close as **Benign Positive** when the click is confirmed automated/wrapper-generated with no submission. Close as **Insufficient Evidence** when message headers/click logs have expired out of retention before triage — note the gap, don't guess.

**Example case note:** *"User jsantos@northwind-analytics.example reported a message impersonating IT Service Desk with a link to secure-office365-login.example.net. Proxy logs confirm form POST at 09:14 UTC. Entra sign-in log shows successful auth at 09:16 UTC from ASN 64512 (previously unseen for this user), legacy IMAP client. New inbox rule 'RSS Feeds' found forwarding to external address, removed. Password reset and session revocation completed 09:41 UTC. Closed as True Positive — BEC precursor, Finance notified as precaution, no fraudulent transaction identified."*
