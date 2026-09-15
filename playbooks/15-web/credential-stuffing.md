# Playbook: Credential Stuffing

## Playbook ID & Name

**WEB-008 — Credential Stuffing Detection and Response**

Category: Web Security. Applies to any internet-facing or SaaS authentication surface — customer web portal, webmail/Microsoft 365/Entra ID login, VPN or remote-access portal, mobile app API, partner extranet — protected by username-and-password auth (with or without MFA), where the attacker is running previously breached username/password pairs sourced from an unrelated third-party breach, not guessing passwords blind. This is the reused-credential-pair variant of automated login abuse; the low-and-slow single-password-against-many-accounts variant is covered separately under Password Spraying (Web-Facing). The two produce different log shapes and get confused constantly, so don't assume they're the same alert with a different name.

## Business Risk

**[STAKEHOLDER]** - Credential stuffing works because customers and employees reuse passwords across unrelated sites, so a breach at some other company you have no relationship with can hand an attacker a working login to yours. It doesn't need a vulnerability in your app at all — that's what makes it hard to argue away as "not our problem." A successful hit converts directly into account takeover: fraud on customer accounts, BEC on a mailbox, or a foothold into whatever that account has access to. Volume matters here more than sophistication — a botnet testing 500,000 credential pairs an hour against your login page will find the handful of your users who reused a password, purely on probability. The business decision that actually moves the needle is enforcing MFA and monitoring login velocity, not just detecting the noise after the fact.

## Severity / Priority Default

**Medium** at trigger for detected stuffing traffic with no confirmed successful authentication — this is closer to background internet weather than an active incident on most public login pages. Escalates to **High** the moment any authentication attempt in the flagged traffic returns a success. Escalates to **Critical** if a successful account has privileged access (admin console, finance system, executive mailbox), or if post-authentication activity shows signs of account takeover in progress (new mailbox rule, MFA method change, funds movement, data export).

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Pre-attack probing of the login endpoint — checking which usernames exist, what MFA is enforced, rate-limit thresholds |
| T1110.004 | Brute Force: Credential Stuffing | The specific sub-technique for this playbook — previously breached username/password pairs replayed against an unrelated login surface. Cite the parent T1110 alongside it if a reader is tracking at the umbrella level only |
| T1078.004 | Valid Accounts: Cloud Accounts | Successful stuffing hit against a SaaS/cloud identity provider (Entra ID, Okta, AWS, Workday) — attacker is now operating as a legitimate cloud account |
| T1078.002 | Valid Accounts: Domain Accounts | Successful hit where the web login is federated to on-prem AD/ADFS and the credential pair also works domain-side |
| T1531 | Account Access Removal | Attacker changes the password/MFA method post-takeover to lock the real owner out |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Common post-ATO move on a compromised mailbox — add a delegate for persistent silent access |
| T1114.003 | Email Collection: Email Forwarding Rule | Post-ATO BEC setup — auto-forward rule created to siphon mail without logging in again |

## Trigger / Detection Logic Summary

Alert fires on a spike in authentication attempts against a login endpoint characterized by a **high count of distinct usernames** from a given source (IP, subnet, ASN, or proxy/residential-proxy pool), each username typically attempted only once or twice — the inverse shape of password spraying, where one password is tried across many accounts. Correlate with: request cadence too regular to be human (bot timing), missing normal pre-login page-load traffic (direct POST to the auth endpoint with no prior GET), TLS/JA3 fingerprint or User-Agent anomalies, and a non-zero success rate against a firehose of failures. Bot-management/WAF platforms (Cloudflare Bot Management, Akamai Bot Manager, DataDome, PerimeterX/HUMAN) that already score requests should feed directly into this detection rather than being re-derived from raw logs where available.

## Required Log Sources & Event IDs

No Windows or Sysmon event IDs apply directly to this playbook — the primary detection surface is web/API authentication telemetry and cloud identity-provider sign-in logs, not the Windows Security event log. If the affected app federates to on-prem AD/ADFS, corresponding Windows logon events on the domain controller are relevant corroborating evidence, but no specific event ID for that path is confirmed in this book's reference set, so identify them by name (successful/failed logon) against your own environment's logging baseline rather than assuming a number.

| Source | What to pull |
|---|---|
| Identity provider sign-in logs (Entra ID `SigninLogs`, Okta System Log, Auth0, AWS Cognito) | Result code, source IP, ASN, device/browser fingerprint, MFA outcome, risk state/score |
| Application authentication log | Username attempted, success/failure, session ID issued, endpoint hit (`/login`, `/api/v1/auth`) |
| WAF / bot management logs | Bot score/verdict, JA3/TLS fingerprint, challenge (CAPTCHA) issue/solve/fail counts |
| Reverse proxy / CDN log | True source IP (if `X-Forwarded-For` trusted), request rate per IP/ASN, referer/missing-referer pattern |
| Rate-limit / account-lockout logs | Which accounts hit lockout thresholds, how many, over what window |
| Mailbox/audit log (post-ATO) | New forwarding rules, delegate additions, mailbox permission changes, sign-in location for the affected mailbox |
| Threat intel / IP reputation feed | Known credential-stuffing infrastructure, open proxy/residential proxy pool membership |

## Key Fields to Inspect [ANALYST]

- **UserPrincipalName / username attempted** — the core pivot; build attempts-per-username and distinct-usernames-per-source counts before concluding anything
- **ResultType / status code** — in Entra ID sign-in logs, `0` is success; any non-zero success-adjacent code (e.g., MFA satisfied via remembered device) deserves the same scrutiny as a clean success
- **IP address / ASN** — expect wide dispersion or a small number of proxy/VPN exit nodes cycling rapidly; a single static IP hammering one account is more consistent with targeted brute force than stuffing
- **Device/browser fingerprint & user agent** — identical or template-looking UA strings across thousands of "different" logins, or headless-browser markers, are a strong bot signal
- **MFA challenge result** — did the attempt actually get challenged, or did legacy/basic auth (IMAP, POP, older API surfaces) bypass MFA entirely? This is usually where stuffing succeeds even at MFA-enabled orgs
- **Time-between-attempts** — bot cadence is often suspiciously even (e.g., one request every 400ms ± jitter); humans are messier
- **Post-auth activity for any success** — mailbox rule creation, delegate grants, password/MFA method change, OAuth app consent, unusual download/export volume

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Login attempts per source IP roughly match expected customer/employee traffic for that IP's context (office NAT, ISP) | Hundreds to thousands of distinct usernames attempted from one IP, ASN, or proxy pool in a short window |
| Failure reasons vary naturally (typo, forgotten password, expired session) | Uniform "invalid credentials" failures with occasional success, no forgot-password or account-recovery activity mixed in |
| Request pattern includes normal page navigation before login POST | Direct POSTs to the auth endpoint with no preceding page load, missing/static referer |
| MFA challenge issued and satisfied through normal user interaction | MFA never challenged because a legacy/basic-auth path was used, or repeated MFA push attempts (fatigue pattern) |
| Login success followed by routine account activity | Login success from a new country/ASN immediately followed by mailbox rule, delegate, or credential change |

## Investigation Steps

1. Pull authentication log volume for the trigger window and build two counts by source IP/ASN: distinct usernames attempted, and attempts per username. Confirm the shape is "many usernames, low attempts each" before calling it stuffing rather than spraying or single-account brute force.
2. Isolate every attempt in that traffic that returned a success (or an MFA-satisfied-via-cache/remember-device result) — these accounts are the priority, everything else is noise to characterize, not chase individually.
3. For each successful account, pull its sign-in history for the preceding 30 days (default baseline window - shorten only if the account is newly created) and compare source IP/geolocation, device fingerprint, and time-of-day against that account's established baseline.
4. Check whether MFA is actually enforced for the app/account in question, and whether the successful sign-in came through a legacy or basic-auth path that bypasses it — this is the single most common reason stuffing converts to real account takeover.
5. Review post-authentication activity on each confirmed-successful account: new mail forwarding rules, delegate/permission changes, password or MFA method resets, OAuth app consents granted, abnormal data access or export volume.
6. Check IP reputation/ASN against threat intel and bot-management vendor scoring if available; confirm whether the same infrastructure is hitting other tenants/customers (relevant for multi-tenant SaaS) or is targeted specifically at your org.
7. Confirm whether rate-limiting, CAPTCHA, or lockout controls engaged as designed — if the attack volume seen in logs is far higher than what actually reached the app, controls likely worked; if not, that's a gap to flag regardless of outcome.
8. Scope total blast radius: list every account with a confirmed success, force password reset and session/token revocation for those accounts, and confirm the real account owner regained control where takeover occurred.

## True Positive Indicators

- Confirmed successful authentications embedded in a high-volume, many-distinct-username, low-attempts-per-username traffic pattern from proxy/botnet infrastructure
- Successful logins immediately followed by account-takeover behavior — mailbox rule, delegate grant, password/MFA change, session from an unfamiliar geography
- MFA bypassed via legacy/basic-auth protocol or satisfied through a stolen "remember this device" token rather than genuine step-up
- Traffic pattern and timing consistent with known stuffing tooling (scripted, evenly spaced requests, template user agents) rather than organic user behavior
- Same source infrastructure observed hitting other unrelated organizations' login endpoints (confirms commodity stuffing campaign, not org-specific targeting)

## False Positive / Benign Positive Indicators

- Traffic attributable to a corporate NAT, mobile carrier NAT, or VPN egress where many real employees/customers legitimately share one source IP
- Password manager auto-fill retry storms after a bulk password rotation (multiple saved-but-outdated credentials submitted in quick succession by legitimate users)
- Authorized penetration test or credential-stuffing resilience test running against the login endpoint — check the security testing calendar before escalating
- Health-check, monitoring, or QA automation repeatedly authenticating against a test account, misclassified as anomalous due to volume alone
- High distinct-username volume with zero successes and rate-limiting/CAPTCHA confirmed engaged — this is expected background noise for any public login page, close as Expected Activity rather than chasing it as an incident

## Escalation Criteria

Escalate to Incident Response immediately on any confirmed successful authentication from flagged stuffing traffic, regardless of account privilege — the volume of the surrounding noise doesn't change the urgency of a single real hit. Escalate as Critical if the account is privileged, holds financial authority, or shows post-ATO activity (mail rule, delegate grant, MFA change, data export). Escalate to the fraud team in parallel for customer-facing platforms where account takeover translates directly into financial loss.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| Rate-limit or CAPTCHA-challenge the login endpoint | Tier 2 (standing authority) | Fastest, lowest blast radius, usually already partially in place |
| Block source IP/ASN/proxy pool at edge/WAF | Tier 2, notify app owner | Watch for shared-NAT false-positive risk before blocking broad ranges |
| Force password reset + session revocation for confirmed-successful accounts | IAM/security lead sign-off | Standard, low-friction, do this fast once success is confirmed |
| Disable legacy/basic-auth protocols on the affected app | App owner + engineering lead | High-value fix but can break older client integrations — needs a comms plan |
| Enforce step-up/mandatory MFA org- or app-wide | Security leadership + product/engineering owner | Root-cause fix, tracked as a change, not a same-shift SOC action |
| Mass forced password reset across a customer base (breach-adjacent scenario) | Executive/Legal/Privacy sign-off | Customer-notification and support-volume implications, not purely a SOC call |

## Example Query (Microsoft Sentinel KQL)

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| summarize Attempts = count(),
            DistinctUsers = dcount(UserPrincipalName),
            Successes = countif(ResultType == "0")
      by IPAddress, AppDisplayName
| where DistinctUsers > 25 and Successes > 0
| extend SuccessRatePct = round(100.0 * Successes / Attempts, 2)
| sort by DistinctUsers desc
```

## Closure Criteria

Close as **True Positive** once every confirmed-successful account has had credentials reset, sessions revoked, and any post-ATO changes (mail rules, delegates, MFA methods) reverted, with the app owner and, where customer accounts are involved, the fraud team acknowledging the finding. Close as **Expected Activity** when the traffic shows the classic stuffing shape but zero successes and confirmed rate-limit/CAPTCHA engagement — this is normal internet background noise for a public login page and doesn't need an incident ticket per occurrence, just a trend note if volume is climbing. Close as **Insufficient Evidence** when the identity provider's sign-in logs don't retain enough history to confirm whether flagged attempts succeeded (common with short retention windows on lower SKU tenants) — flag the retention gap to the platform owner rather than guessing at the outcome.

**Example case note:**
`2026-09-15 09:47 UTC — Entra ID sign-in spike from ASN 39572 (known residential-proxy range): 1,840 distinct UPNs attempted against login.example.com over 35 min, avg 1.1 attempts/user, 3 successes. All 3 successful accounts (j.torres@example.com, l.chen@example.com, svc-reports@example.com) forced to password reset + session revoke within 20 min of detection. j.torres@example.com had a new inbox forwarding rule to an external address, removed; no evidence of further mailbox access after revoke. No MFA bypass observed on the other 2 — sign-in blocked at MFA challenge stage in audit trail despite valid password. Closing as True Positive (contained); recommending legacy IMAP auth (currently still enabled for svc-reports@example.com) be disabled, that account had no MFA enforced.`
