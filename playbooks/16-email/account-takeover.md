# Playbook: Account Takeover (Email / M365 / Entra ID)

## Playbook ID & Name
**EML-013 — Email Account Takeover (Cloud Mailbox Compromise)**

## Business Risk
**[STAKEHOLDER]** - A compromised mailbox gives an attacker read access to years of correspondence, the ability to impersonate the employee to customers and finance staff (invoice fraud, wire redirection), and a launchpad to pivot into other SaaS apps via SSO. The financial exposure isn't the login itself — it's what happens in the 24-72 hours after, when nobody's watching the mailbox rules.

## Severity/Priority Default
**High** at trigger (confirmed suspicious sign-in + mailbox rule change = **Critical**). VIP, finance, or HR mailboxes are auto-escalated one tier regardless of other signals.

## MITRE ATT&CK Techniques
- T1078.004 Valid Accounts: Cloud Accounts (primary — the takeover itself)
- T1110.001 / T1110.003 Brute Force: Password Guessing / Password Spraying (common initial access)
- T1566.001 / T1566.002 Phishing: Attachment / Link (credential harvest leading to ATO)
- T1114.003 Email Collection: Email Forwarding Rule (most common post-compromise action)
- T1098.002 Account Manipulation: Additional Email Delegate Permissions
- T1098.001 Additional Cloud Credentials (attacker registers own MFA method/app password)
- T1538 Cloud Service Dashboard (attacker browsing admin/self-service portals for recon)
- T1087 Account Discovery (GAL/directory enumeration after landing)
- T1090 Proxy (residential proxy / anonymizer use to defeat impossible-travel logic)

## Trigger / Detection Logic Summary
Fires on a correlation, not a single event: (1) an authentication anomaly on a mailbox — impossible travel, new country, new/unmanaged device, or a risky sign-in flagged by the identity provider's risk engine — **followed within a short window by** (2) a mailbox configuration change: new inbox rule, delegate/full-access grant, forwarding SMTP address added, or MFA/auth-method registration the user didn't request. Either signal alone is often benign; the combination is what should page someone.

## Required Log Sources & Event/Record Types
| Source | Record / Operation | Why |
|---|---|---|
| Entra ID Sign-in Logs | Interactive & non-interactive sign-ins, `RiskLevelDuringSignIn`, `RiskState`, `ConditionalAccessStatus` | Where, how, and under what risk score the session started |
| Entra ID Identity Protection | Risk detections (atypical travel, anonymized IP, leaked credentials) | Vendor-side ML scoring, corroborates raw sign-in data |
| M365 Unified Audit Log (UAL) | `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Set-Mailbox` (ForwardingSmtpAddress), `Add-MailboxPermission`, `MailboxLogin`, `MailItemsAccessed` | The actual mailbox-abuse actions |
| Entra ID Audit Log | `Register security info`, `Add MFA method`, `User registered security info` | Attacker planting persistence via their own MFA/app password |
| Conditional Access logs | Policy applied/not applied, legacy auth allowances | Explains why MFA didn't block the sign-in |
| Email security gateway / M365 Defender | Phishing verdicts on inbound mail near the sign-in time | Ties the ATO back to a delivery vector |

## Key Fields to Inspect
**[ANALYST]**
- `UserPrincipalName`, `IPAddress`, `Location` (city/country), `DeviceDetail.trustType`, `AppDisplayName`, `ClientAppUsed` (flag legacy protocols: IMAP4, POP3, MAPI over HTTP without modern auth)
- `RiskEventTypes` (`unfamiliarFeatures`, `anonymizedIPAddress`, `leakedCredentials`, `impossibleTravel`)
- UAL `Operation`, `Parameters` (look at the actual rule condition/action — e.g., `RedirectTo`, `ForwardTo`, `DeleteMessage`), `ClientIP`, `ResultStatus`
- `MailItemsAccessed` — `OperationCount`, `Folders` touched (Inbox vs. Sent Items vs. a specific finance thread — targeted access looks very different from a mail client sync sweep)
- Sign-in timestamp vs. mailbox rule creation timestamp — measure the gap in minutes, not hours

## Normal vs. Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Sign-in from known corporate egress IP or a previously-seen travel location, modern auth, device marked compliant/registered | Sign-in from unfamiliar ASN/country the user has never used, especially a known VPS/residential-proxy range |
| Inbox rules created by the user themselves, named sensibly ("Move newsletters"), visible in a change ticket or self-service | Inbox rule with a generic/blank name, action = forward externally or delete-after-forward, created outside business hours |
| MFA re-registration tied to a helpdesk ticket or new phone rollout | MFA method added seconds after a risky sign-in, from the same suspicious IP, with no helpdesk record |
| `MailItemsAccessed` volume consistent with normal client sync (hundreds of items, broad folder spread) | Narrow, targeted access to specific senders/subjects (e.g., searching "invoice," "wire," "W-2") shortly after login |

## Investigation Steps
1. Pull the full sign-in timeline for the account for the preceding 30 days — establish the user's normal IP/geo/device baseline before judging the flagged event as anomalous.
2. Correlate the flagged sign-in against Identity Protection risk detections and Conditional Access evaluation — was MFA satisfied, bypassed via legacy auth, or not required at all?
3. Query UAL for any `New-InboxRule`, `Set-Mailbox`, or `Add-MailboxPermission` operations in the 24 hours around the sign-in. Read the actual rule/permission parameters, not just the operation name.
4. Check `MailItemsAccessed` for targeted folder/keyword access suggesting the attacker was hunting specific correspondence (finance threads, password resets, HR data).
5. Check whether a new MFA method, app password, or OAuth app consent was registered on the account around the same window (T1098.001).
6. Trace back to the likely initial-access vector: search the mail gateway/Defender for a phishing message delivered to this user in the prior 1-14 days, and check for password-spraying patterns against this account or peers in the same department.
7. Determine blast radius — did the attacker use this mailbox to send phishing internally, request payment changes, or pivot into SSO-connected SaaS apps (check other app sign-ins under the same session token).
8. Interview the user (briefly, non-accusatory) — did they enter credentials somewhere recently, recieve an unexpected MFA prompt, or notice missing/rearranged email.

## True Positive Indicators
- Impossible travel or anonymizer-IP sign-in with a risk score, immediately followed by a hidden/forwarding inbox rule the user denies creating.
- Attacker-registered MFA method or app password from an unfamiliar IP.
- `MailItemsAccessed` shows targeted access to finance/HR content minutes after a risky login.
- Outbound phishing or BEC-style payment-redirect emails sent from the mailbox that the user did not author.

## False Positive / Benign Positive Indicators
- User genuinely traveling (calendar/expense report confirms), MFA satisfied cleanly, no mailbox rule or delegate changes follow.
- Corporate VPN egress change misidentified as a new country (check ASN ownership — many "impossible travel" alerts are just VPN exit-node churn).
- Inbox rule matches a known migration, mail-client re-sync, or an approved third-party marketing/CRM integration.
- Risk detection is a stale/duplicate Identity Protection alert re-surfaced by ingestion delay — verify against the live risk state, not just the historical detection.

## Escalation Criteria
Escalate to IR lead immediately if: mailbox belongs to finance, HR, legal, or an executive; an outbound payment-fraud or further-phishing email was sent; attacker registered persistent access (MFA method, OAuth app, mail forwarding to an external domain); or evidence of lateral movement into other SaaS apps via the same session.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- Immediate, analyst-authority: revoke active sign-in sessions/refresh tokens, force password reset, disable the mailbox forwarding rule/delegate grant. No approval needed — this is standard tier-1 ATO response.
- Requires IR lead sign-off: full account disable pending investigation if business-critical (finance/exec), and any customer/partner notification if outbound fraud emails were confirmed sent.
- Requires CISO/Legal sign-off: external breach notification if regulated data (PII, PHI, PCI) was accessed via the mailbox, per data-classification and incident-severity policy.
- SLA: containment actions on a confirmed critical ATO within 30 minutes of confirmation; full case closure within 5 business days.

## Example Query (Microsoft Sentinel — KQL)
```kql
SigninLogs
| where RiskLevelDuringSignIn in ("medium","high") and ResultType == "0" and IsInteractive == true
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, RiskEventTypes_v2
| join kind=inner (
    OfficeActivity
    | where Operation in ("New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission")
    | project RuleTime=TimeGenerated, UserId, Operation, Parameters, ClientIP
) on $left.UserPrincipalName == $right.UserId
| where RuleTime between (TimeGenerated .. TimeGenerated + 2h)
```

## Closure Criteria
Case closes when the initial access vector is identified (or documented as undetermined), all attacker-created persistence (rules, delegates, MFA methods, OAuth grants) is removed and verified, credentials are reset, and no further anomalous activity appears in a 72-hour monitoring window. Valid closures include True Positive, Benign Positive (legitimate travel/VPN), and Insufficient Evidence (user denies phishing entry, no artifact recovered, monitoring extended).

**Example case-note line:** *"Sign-in from AS-belonging-to-known-VPN-provider (Netherlands) initially flagged impossible travel; confirmed via expense report user was on approved remote-work travel. No inbox rule or delegate changes followed in 72h window. Closed as Benign Positive — user's Conditional Access location whitelist updated to reduce recurrence."*
