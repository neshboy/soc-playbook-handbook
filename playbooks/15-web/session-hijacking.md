# Session Hijacking - Web/Cloud Session Token Theft and Replay

## Playbook ID & Name
**WEB-016** - Session Hijacking: Theft, Fixation, or Replay of a Valid Web/Cloud Application Session Token

## Business Risk
**[STAKEHOLDER]** - A session hijack means the attacker never needed a password at all - they took a live, already-authenticated session (a cookie, a bearer token, a SAML/OIDC session artifact) and are now acting as the real user inside the app, past MFA, past the login page entirely. On a customer portal this is account takeover and fraud; on M365/Entra or a SaaS admin console it's a full identity compromise that MFA resets alone won't fix, because the session itself - not the credential - is the thing that's stolen. Approval to force-terminate all active sessions for an app, or to revoke refresh tokens tenant-wide, sits with the Application Owner or Identity team lead; the SOC does not do a mass session-kill on a production system without that sign-off unless active data exfiltration or fraud is confirmed.

## Severity/Priority default
**High** by default the moment a session is confirmed reused from a second location/device inconsistent with the legitimate user. Escalates to **Critical** if the hijacked session belongs to a privileged/admin account, a finance/payroll system, or if the attacker has already performed a sensitive action (mailbox rule change, funds transfer, data export) inside the session.

## MITRE ATT&CK Technique(s)
- **T1539** - Steal Web Session Cookie (the theft mechanic: malware, JavaScript injection, or a malicious proxy pulls the session cookie/token out of browser storage, memory, or network traffic)
- **T1550.004** - Use Alternate Authentication Material: Web Session Cookie (the reuse mechanic: the attacker replays the stolen cookie/token to authenticate, bypassing the login and MFA challenge entirely)
- **T1078.004** - Valid Accounts: Cloud Accounts (the resulting access looks like a legitimate, already-trusted account session to the application)
- **T1566.002** - Phishing: Link (adversary-in-the-middle phishing kits and reverse-proxy phishing pages are the most common delivery mechanism for live session-cookie theft today)
- **T1114.003** - Email Collection: Email Forwarding Rule (common follow-on once a webmail/collab-suite session is hijacked - attacker plants a forwarding rule for silent, ongoing collection)
- **T1098.002** - Account Manipulation: Additional Email Delegate Permissions (alternate follow-on persistence inside the hijacked mailbox/session that survives a simple password reset)
- **T1090** - Proxy (attacker relays the replayed session through a proxy/VPS/residential-proxy pool to approximate the victim's normal geography and dodge naive geo-IP alerting)

## Trigger / Detection Logic Summary
Alert fires when the same session identifier (session cookie hash, refresh-token ID, SAML session index) is used from two materially different network/device fingerprints within a window shorter than plausible travel time ("impossible travel"), or when a session is observed continuing to make authenticated requests after the corresponding sign-in event shows a failed MFA challenge, a token issued to an unexpected client/app ID, or a device that never completed the original interactive login. A second path fires on IdP-native risk detections (Entra ID Identity Protection "anomalous token" / "unfamiliar sign-in properties", Okta "Suspicious Activity" session risk) correlated against WAF/CDN access logs showing the same session cookie value from a different source IP within minutes.

## Required Log Sources & Event Sources
| Source | What to pull |
|---|---|
| IdP / SSO (Entra ID Sign-in logs, Okta System Log) | Sign-in ID, session ID / token ID, source IP, device ID, browser/User-Agent, location, conditional access result, risk level, token issuance vs. token use timestamps |
| CASB / cloud app security (Defender for Cloud Apps, Netskope) | Session anomaly detections, impossible-travel flags, concurrent-session alerts by app |
| WAF / CDN / reverse proxy access logs | Session cookie value (hashed), source IP, `User-Agent`, TLS fingerprint (JA3/JA3S) if available, request path, timestamp |
| Application/session store logs | Session creation time, last-activity time, IP-at-creation vs. IP-at-last-use, concurrent active session count per account |
| EDR on the victim endpoint | Process reading the browser's cookie/session storage file, infostealer indicators, unexpected browser extension activity |
| Email/collab audit logs (Microsoft Purview Audit / Unified Audit Log, Google Workspace) | Mailbox rule creation, delegate permission grants, mail-forwarding changes, unusual mailbox access location |

*Note: this attack lives at the application/identity layer, not the host layer - there is no Windows Event ID or Sysmon ID specific to "a session cookie got replayed." Don't force one in. If the initial theft happened via malware on a managed endpoint, EDR process telemetry is your only host-side evidence, and it tells you *how* the token was stolen, not that it's being *used* elsewhere - that part only shows up in IdP/app logs.*

## Key Fields to Inspect

**[ANALYST]**
- Session/token ID (or its hash) - the single field that ties the IdP sign-in event to every subsequent app request; without it you're just guessing at correlation by time window.
- IP-at-issuance vs. IP-at-use, and ASN/geo for both - a token issued to a home ISP in Manchester and immediately used from a datacenter ASN in another country is the classic signature.
- User-Agent and device ID consistency across the session lifetime - a session that starts on Windows/Edge and continues on Linux/curl or a headless-browser UA mid-session did not "just switch laptops."
- Token issuance time vs. token type - refresh tokens and long-lived session cookies replayed hours or days after issuance, especially after the legitimate user's interactive session ended, are far more suspicious than a token used seconds after issuance.
- Conditional access / MFA satisfaction on the *original* sign-in that issued the token - if the original login satisfied MFA legitimately but the token later shows up on an unmanaged/non-compliant device, that's the token moving without the user.
- Any mailbox rule, delegate grant, or OAuth app consent created during the suspect session window - this is where hijacks turn into lasting access that outlives a password reset.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Same session ID used consistently from one IP range/device, or from the same corporate egress NAT/VPN pool across the day | Same session ID or refresh token used from two IPs on different continents/ASNs within a window shorter than realistic travel |
| Session naturally moves between home Wi-Fi and mobile carrier IP as the user changes networks - device/UA fingerprint stays constant | Session continues on a *different* device fingerprint or User-Agent than the one that completed the original interactive login |
| Legitimate app switching between corporate SSO session and a mobile app token, both tied to the same registered device | Token used by an unregistered/non-compliant device, or from a known VPS/hosting-provider IP with no prior history for that account |
| One active session per user, normal turnover on logout/re-login | Multiple concurrent active sessions for the same account across incompatible locations, or a session that persists after the user reports logging out |

## Investigation Steps
1. Identify the session/token ID from the triggering alert and pull every IdP sign-in and app-access event tied to that exact ID for the full session lifetime, not just the flagged event.
2. Build a timeline of IP, ASN, geo, device ID, and User-Agent for each use of that session ID - look for the discontinuity point where the fingerprint changes.
3. Check the *original* sign-in event that issued the session: was MFA satisfied, on what device, and does that match the user's known device inventory (Intune/Jamf/MDM record)?
4. Pull WAF/CDN access logs for the cookie/token value around the suspect window to confirm the app itself, not just the IdP, saw activity from the anomalous source.
5. Search email/collab audit logs for mailbox rule changes, delegate grants, OAuth app consents, or data exports created during the suspect session - these indicate the attacker did something with the access, not just tested it.
6. If an infostealer or endpoint compromise is suspected as the theft vector, pull EDR telemetry for the victim's endpoint around token-issuance time for browser-storage access or known stealer indicators.
7. Interview or message the user directly (out of band from the compromised app/mailbox) - confirm their actual location, device, and whether they recognize the activity; do not rely solely on log inference for a call this size.
8. Determine blast radius: what did the session have access to (SharePoint sites, downstream SSO-federated apps, admin consoles) and whether any of that access was actually exercised.

## True Positive Indicators
- Confirmed use of the same session/token ID from two geographically incompatible locations within an impossible-travel window.
- Token used from a device/UA fingerprint that never completed the original MFA-backed login.
- Mailbox forwarding rule, delegate permission, or new OAuth app consent created during the suspect session window that the user did not authorize.
- User confirms (via out-of-band contact) they did not perform the flagged activity and were not travelling or using the flagged device.
- EDR confirms an infostealer or malicious script accessed browser cookie/session storage on the victim endpoint shortly before the anomalous replay.

## False Positive / Benign Positive Indicators
- Legitimate VPN/corporate proxy egress change (user's traffic re-routes through a different regional egress node) - confirm against known corporate NAT/VPN IP ranges before treating an IP jump as impossible travel.
- Mobile carrier IP churn or CGNAT reassignment producing an apparent "new location" that's actually the same physical device - device ID and UA remain consistent, only the IP/geo-lookup changed.
- Authorized third-party integration (e.g., a scheduling assistant or email plugin) using a delegated token from a datacenter IP, which is expected behavior for that app category - check the app/client ID against an approved OAuth app inventory.
- Load balancer or CDN edge node changing the apparent source IP/geo mid-session due to routing, with no actual device/UA change - Benign Positive, verify against infrastructure documentation before closing.

## Escalation Criteria
Escalate to IR immediately if the hijacked session belongs to a privileged, finance, or executive account; if a mailbox forwarding rule, delegate grant, or OAuth consent was created during the suspect window; or if the session was used to access, download, or exfiltrate sensitive data. Escalate to the Identity/IAM team regardless of severity so token-issuance policy (session lifetime, conditional access, token binding) can be reviewed - a single confirmed hijack is a signal the control gap will be used again.

## Containment Options & Approval Authority

**[MANAGEMENT]** Revoking the single flagged session/refresh token can be performed by SOC/IR on-call immediately without further sign-off - this is the default first move and stops the specific hijack without disrupting the user's other legitimate sessions. Revoking *all* active sessions for the affected account (forcing full re-authentication everywhere) requires the account owner or their manager to be notified but can still be actioned by SOC/IR given confirmed compromise. Tenant-wide or application-wide session/refresh-token revocation (e.g., shortening session lifetime tenant-wide, invalidating all refresh tokens for an app) requires Identity team lead or Application Owner approval, logged with named approver and timestamp, given the user-disruption impact. Any change to conditional access policy or MFA enforcement as a permanent fix is tracked as an Identity/IAM engineering ticket, not closed purely at the SOC layer.

## Example Query (Microsoft Sentinel - KQL, Entra ID Sign-in Logs)
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| extend SessionId = tostring(AuthenticationDetails[0].sessionId)
| where isnotempty(SessionId)
| summarize DistinctIPs = dcount(IPAddress), IPs = make_set(IPAddress),
            Devices = make_set(DeviceDetail.deviceId), UserAgents = make_set(UserAgent),
            first_seen = min(TimeGenerated), last_seen = max(TimeGenerated)
            by SessionId, UserPrincipalName
| where DistinctIPs > 1
| sort by DistinctIPs desc
```

## Closure Criteria
Close when the affected session/token has been revoked, the theft vector (phishing kit, infostealer, unsecured stored token) is identified or explicitly logged as undetermined, any downstream persistence (mail rules, delegate grants, OAuth consents) created during the session has been removed, and the user has confirmed their account status out of band. Valid closures include True Positive (with revocation and cleanup), Benign Positive (IP/geo anomaly explained by VPN/CGNAT/CDN routing with consistent device fingerprint), or Insufficient Evidence (anomalous session flagged but token expired/was never reused before revocation, and no corroborating app-log or user confirmation was obtainable).

**Example case-note line:** "2026-09-15 09:47 UTC - Entra ID session for j.alvarez@example.com (session ID ending ...9f3c) issued from IP 203.0.113.22 (Leeds, UK, managed device WIN-JA-2201) at 08:12 UTC; same session ID observed making Exchange Online requests from IP 198.51.100.77 (Amsterdam datacenter ASN, unmanaged device) at 08:19 UTC - 7 minutes apart, not physically possible. Unified Audit Log shows an inbox forwarding rule created to an external address (billing-support@ex4mple-finance.net) at 08:20 UTC during the anomalous session. User confirmed via phone she was in the Leeds office all morning and did not create the rule. Session revoked, forwarding rule removed, password reset and MFA re-registration forced, IR opened for suspected AiTM phishing kit as delivery vector - EDR review of user's endpoint pending."
