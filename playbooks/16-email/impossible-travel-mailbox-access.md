# Impossible Travel (Mailbox Access)

## Playbook ID & Name
**EML-012 — Impossible Travel (Mailbox Access)**
Category: Email | Applies to: Microsoft 365 / Exchange Online, Entra ID (Azure AD), Google Workspace equivalents

## Business Risk

**[STAKEHOLDER]** - This alert usually means a mailbox login happened from two places on earth that no human could physically travel between in the time observed - almost always a sign the account password (and possibly the session token) is in someone else's hands. Mailboxes are where password resets, wire transfer approvals, and privileged conversations live, so a compromised one is a direct path to fraud, data theft, or a second-stage compromise of other systems. This is one of the few alerts where minutes matter - decide fast whether it's a travelling exec on a bad VPN or an attacker reading the CFO's inbox.

## Severity/Priority Default

**High** at trigger. Escalates to **Critical** if the account has delegate access to a mailbox with financial approval authority, if a new inbox rule or delegate was created after the flagged sign-in, or if MFA was satisfied by a method the user doesn't recognize (indicating token theft rather than password guessing).

## MITRE ATT&CK Technique(s)

- **T1078.004** - Valid Accounts: Cloud Accounts (primary - the sign-in itself)
- **T1110** / **T1110.001** Password Guessing, **T1110.003** Password Spraying (common precursor)
- **T1098.001** - Account Manipulation: Additional Cloud Credentials (attacker registers new MFA method or app password for persistence)
- **T1098.002** - Account Manipulation: Additional Email Delegate Permissions (attacker grants themselves or another mailbox access)
- **T1114.003** - Email Collection: Email Forwarding Rule (silent exfiltration of future mail)
- **T1538** - Cloud Service Dashboard (attacker browsing the portal post-login to scope the environment)

## Trigger / Detection Logic Summary

Two (or more) successful authentications to the same mailbox/identity occur from IP addresses whose geolocated distance and elapsed time between logins make physical travel impossible - e.g., a login from Lagos, Nigeria at 09:02 UTC and another from Manchester, UK at 09:19 UTC, seventeen minutes apart, roughly 5,000 km. Native detections: Entra ID Identity Protection "Atypical travel" risk detection (`riskDetail = unlikelyTravel` / `riskEventType = unfamiliarFeatures`,`anomalousToken`), Microsoft 365 Defender/Sentinel geo-velocity analytics rule, or a custom SIEM rule joining consecutive successful sign-ins per user and flagging distance/time ratios above a plausible travel speed (commercial flight ~900 km/h, generous cutoff usually set at 1,000 km/h to avoid false positives near timezone/VPN edges).

This is a **derived** detection, not a raw log signature - it depends entirely on accurate IP geolocation, so treat the first output as a lead, not a verdict.

## Required Log Sources & Event IDs

| Source | Identifier / Operation | Notes |
|---|---|---|
| Entra ID Sign-in logs | `riskEventType = unfamiliarFeatures`, `riskDetail = unlikelyTravel`, `anomalousToken` | Interactive and non-interactive sign-ins both matter - token replay often shows up only in non-interactive logs |
| Microsoft 365 Unified Audit Log | `UserLoggedIn`, `MailboxLogin`, `MailItemsAccessed` | `MailboxLogin` confirms actual mailbox access, not just IdP auth success |
| Exchange Online Audit Log | `New-InboxRule`, `Set-InboxRule`, `Add-MailboxPermission`, `Set-Mailbox` (audit config) | Post-access persistence/collection actions |
| Entra ID Audit Log | `Add app password`, `Register security info`, `Update user` (MFA method changes) | Maps to T1098.001 |
| Conditional Access / Sign-in logs | `ConditionalAccessStatus`, `AuthenticationRequirement` | Confirms whether MFA was actually enforced/satisfied |
| Network/Proxy (if available) | Egress IP for the tenant's known VPN/proxy | To rule out corporate egress NAT masquerading as "new" location |

There are no Windows or Sysmon Event IDs relevant here - this is entirely IdP/mailbox audit telemetry.

## Key Fields to Inspect
**[ANALYST]**

- `UserPrincipalName` / `userId` - confirm the exact mailbox, not a look-alike alias
- `IPAddress`, `LocationDetails.city/countryOrRegion`, ASN/organization for the IP
- `ClientAppUsed` - legacy protocols (IMAP4, POP3, "Authenticated SMTP", "Other clients") bypass modern auth and MFA prompts; a sudden legacy-protocol login is a strong signal
- `AppDisplayName` - "Outlook Web Access," "Exchange Online PowerShell," or an unfamiliar first-party app being invoked (OAuth consent abuse)
- `AuthenticationRequirement` / `ConditionalAccessStatus` - was MFA actually satisfied, or was the sign-in outside CA scope (legacy auth, trusted network exclusion)?
- `CorrelationId` - ties the sign-in to any immediately following mailbox operations in the UAL
- `MailItemsAccessed` payload - folder accessed, `IsThrottled`, whether it was a sync (Outlook client indexing) or a targeted read
- Any new `InboxRule` condition/forwarding target created within minutes/hours of the flagged sign-in

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Sign-in from a new city that matches a known trip, calendar entry, or corporate VPN egress point | Sign-in from a country the user has no business reason to be in, with no travel booked |
| Time-and-distance gap that is tight but flight-plausible (e.g., 6 hours, 4,000 km) | Time-and-distance gap that is physically impossible (minutes apart, thousands of km) |
| MFA satisfied via the user's usual push/authenticator app | MFA satisfied via a newly registered method, or no MFA prompt at all (legacy protocol, token replay) |
| Access pattern consistent with normal mail use (read, occasional send) | Bulk `MailItemsAccessed`, mass folder enumeration, new forwarding rule pointing to an external domain |
| Same device fingerprint/browser as prior sessions | Unfamiliar OS/browser combo, or session token reused from a device never seen before (`anomalousToken`) |

## Investigation Steps

1. Pull all sign-in events for the affected UPN across the surrounding 24-72 hours; plot IP, city, ASN, client app, and CA status in time order - don't trust the single flagged pair, look at the whole session chain.
2. Geolocate both IPs independently (don't rely solely on the vendor's city label - ASN/WHOIS lookup catches VPN exit nodes and satellite/mobile carrier IP ranges that geolocate badly).
3. Check whether either IP matches a known corporate VPN, travel provider Wi-Fi, or a previously-seen benign range for this user (frequent flyers, remote contractors).
4. Query the Unified Audit Log for `MailboxLogin` and `MailItemsAccessed` tied to the same `CorrelationId`/session to confirm the mailbox was actually opened, not just an IdP token issued.
5. Search for `New-InboxRule`, `Add-MailboxPermission`, or MFA method registration events in the hour following the suspicious sign-in - this is the tell for an attacker settling in versus a one-off failed/odd login.
6. Contact the user directly through an out-of-band channel (phone, Teams from a known device, not email) to confirm or deny travel/VPN use.
7. If unconfirmed or unreachable, check for concurrent active sessions and force a token revocation while continuing the investigation.
8. Review any outbound mail sent during the suspicious window for BEC indicators (invoice fraud language, payment redirection, external forwarding of financial threads).

## True Positive Indicators

- User denies travel/VPN use and confirms they did not log in from the second location
- New inbox forwarding rule or delegate permission created within the suspicious session, especially forwarding to an external free-mail domain
- MFA satisfied via a method the user does not recognize, or `anomalousToken` risk detection fired alongside impossible travel
- Legacy authentication protocol used for the flagged sign-in on an account that normally uses modern auth
- Sign-in ASN maps to known bulletproof hosting, residential proxy, or Tor exit infrastructure

## False Positive / Benign Positive Indicators

- Confirmed business travel with calendar/travel-booking corroboration
- Corporate VPN/proxy egress change (e.g., failover between two regional VPN concentrators) - IP geolocation reflects the datacenter, not the user
- Mobile carrier IP reassignment causing rapid apparent location jumps (common with satellite internet, cruise ship Wi-Fi, some mobile carriers that route through distant gateways)
- Shared/service account used by an automated integration from a different region than the human owner's usual location
- Stale or inaccurate third-party geolocation database entry for a given ASN - verify against a second lookup source before concluding travel is impossible

## Escalation Criteria

Escalate to Tier 2/IR immediately if: the mailbox belongs to an executive, finance, HR, or IT admin role; a new forwarding rule or delegate was added; outbound mail with fraud indicators was sent; the user denies the second login; or the account shows access to other cloud services (SharePoint, OneDrive, Teams) beyond mail in the same session, suggesting broader tenant compromise rather than isolated mailbox access.

## Containment Options & Approval Authority
**[MANAGEMENT]**

| Action | Approval Needed | Notes |
|---|---|---|
| Revoke active sessions/refresh tokens | SOC Tier 2 lead | Immediate, low-impact; kicks out the attacker session |
| Force password reset | SOC Tier 2 lead | Pair with token revocation - reset alone doesn't kill an active session |
| Disable account temporarily | IT Ops / on-call manager | Use if user unreachable and risk is high; expect helpdesk friction |
| Remove newly added inbox rule/delegate | SOC Tier 2 (document before removing) | Preserve rule config as evidence prior to deletion |
| Notify affected counterparties (if BEC content sent) | IR lead + Legal/Comms | Required if fraudulent payment instructions went out |
| Block sign-in ASN/country at Conditional Access | IAM/Identity team, standard change if broad-scope | Watch for blocking legitimate remote staff in that region |

SLA target: initial triage within 15 minutes for High severity given the account-takeover risk; full containment decision within 1 hour.

## Example Query (Microsoft Sentinel - KQL)

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == 0
| summarize Countries = make_set(tostring(LocationDetails.countryOrRegion)),
            IPs = make_set(IPAddress), SignIns = count()
  by UserPrincipalName, bin(TimeGenerated, 15m)
| where array_length(Countries) > 1
```

## Closure Criteria

Close as **True Positive** once containment (session revocation, password reset, malicious rule/delegate removal) is confirmed and the user's identity is re-verified through an out-of-band channel. Close as **Benign Positive** when travel, VPN, or carrier routing is confirmed with corroborating evidence. Close as **Insufficient Evidence** if the user is unreachable after documented attempts, geolocation data is unreliable, and no follow-on malicious activity (rules, delegates, mail sent) is found - flag for a 24-hour recheck rather than a hard close.

**Example case note:** "Impossible travel flagged for j.osei@example.com - sign-ins from 41.203.x.x (Accra, GH) and 82.14.x.x (Manchester, UK) 14 min apart. User confirmed by phone he did not travel and had not used a VPN; new inbox rule forwarding to `finance-updates@extmailbox.example` found and removed. Sessions revoked, password reset enforced, MFA re-registered. Escalated to IR for BEC follow-up on finance thread. Closed as True Positive."
