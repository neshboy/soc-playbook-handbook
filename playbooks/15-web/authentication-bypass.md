# WEB-015 — Authentication Bypass

## Business Risk

**[STAKEHOLDER]** - An authentication bypass means the login screen was never actually the barrier it looked like. Someone reached a protected page, API, or admin function without proving who they are — through a logic flaw, a tampered parameter, a forged token, or a backdoor credential left in the code. The blast radius is whatever sits behind that login: customer records, billing data, an admin console that can create accounts or change permissions. This is the alert category that turns into a breach notification if it's real, so triage speed matters more here than in almost any other web finding — the gap between "someone found the flaw" and "someone monetized it" can be minutes.

## Severity / Priority Default

- **Default:** High (P2) — authentication bypass attempts get elevated priority even before confirmation, because the cost of a slow triage is disproportionate to the cost of a fast one that turns out benign.
- **Critical (P1)** if the bypassed endpoint is an admin console, a payment/PII-handling function, or if any data access, account creation, or permission change is confirmed post-bypass.
- **Downgrade to Medium (P3)** only after confirming the request was blocked pre-authorization (WAF/app rejected it) with no successful response.

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1190 Exploit Public-Facing Application | Primary technique — the bypass itself is exploitation of a flaw in the app's authentication/authorization logic |
| T1595 Active Scanning | Frequently precedes discovery — parameter fuzzing, endpoint enumeration, forced-browsing probes against the login flow |
| T1552.001 Unsecured Credentials: Credentials In Files | Common bypass vector — hardcoded API keys, default admin creds, or backup/debug credentials left in client-side JS, config files, or exposed `.env`/`.git` paths |
| T1078.002 Valid Accounts: Domain Accounts | Post-bypass state if the flaw hands the attacker a session mapped to a real domain-backed identity |
| T1078.004 Valid Accounts: Cloud Accounts | Post-bypass state for SaaS/cloud-hosted apps where the bypass yields a session token treated as a legitimate cloud identity |
| T1098.001 Account Manipulation: Additional Cloud Credentials | Common follow-on once inside an admin panel — attacker adds an API key/service credential for persistence |
| T1136 Create Account | Common follow-on in admin/CMS bypasses — attacker creates a new account to avoid relying on the fragile bypass path |

## Trigger / Detection Logic Summary

**[ENGINEERING]** No single signature covers this category because "bypass" describes an outcome, not a payload. Build the rule around the *mismatch* between authorization state and response outcome rather than any one string match:

- A 2xx response on a URI tagged as authenticated/protected with **no** corresponding successful login or valid session-issuance event for that client in the preceding lookback window — default to the token/cookie's declared max lifetime (check the `exp` claim or session-timeout config) if it's known, otherwise use 24 hours as the floor (session ID, JWT `sub`/`jti`, or cookie value has no matching issuance record).
- A JWT/token presented with `alg: none`, a self-signed/unexpected `kid`, or a signature verification failure logged by the app/API gateway followed immediately by a 2xx on a protected resource.
- Parameter-tampering patterns on request bodies/query strings hitting auth-adjacent fields: `role=admin`, `is_admin=true`, `isAuthenticated=1`, `user_id=` sequences that don't match the session owner (classic IDOR — Insecure Direct Object Reference — turning into an auth bypass).
- WAF/app rule category specifically tagged "auth bypass," "broken authentication," or "forced browsing" firing on a request that received an allow/pass verdict rather than a block.

## Required Log Sources & Fields

| Source | What to pull |
|---|---|
| WAF / API gateway logs | Rule ID and verdict (allow/block), request URI, headers, JA3/TLS fingerprint, `X-Forwarded-For` |
| Web/app server access logs (IIS W3C, Apache/Nginx) | `cs-uri-stem`, `sc-status`, `cs-username`, response size, timestamp |
| Application authentication/audit log | Login success/failure events, session/token issuance records, `jti`/session ID, MFA satisfaction flag |
| IAM/SSO sign-in logs (Entra ID, Okta) | Result codes, correlation ID, session lifetime, conditional access decision |
| API gateway token-validation logs | Signature verification result, algorithm used, claims (`sub`, `aud`, `exp`, `role`) |

Note: if the app federates through an on-prem identity provider (e.g., AD FS), there may be a relevant Windows-side security or federation event trail — but no specific event ID for that chain is confirmed for this playbook, so describe it by name in the case notes rather than citing an ID you haven't verified against this environment's actual log schema.

## Key Fields to Inspect

**[ANALYST]**
- Session/token identifier lifecycle — was it ever legitimately issued, to whom, and does the claimed identity match the account whose data got accessed
- Sequence of requests immediately before the suspicious 2xx — is there a login POST, an OAuth redirect, an MFA challenge, or does the protected request appear cold with no auth handshake at all
- Response body size and structure on the flagged request compared to a known-good authenticated response — bypasses sometimes return a *different* rendering (error page reused as success, partial data) that a raw status-code check misses
- Parameter values in the request: role/permission fields, user/account ID fields, boolean auth flags
- Source IP/ASN and User-Agent continuity — does the same client that got the 2xx also appear anywhere in the legitimate login funnel
- Any subsequent account-management or data-access activity from the same session (new account created, credentials added, records exported)

## Normal vs. Suspicious Pattern

| Normal | Suspicious |
|---|---|
| 2xx on protected endpoint immediately preceded by a login POST/302 and valid session cookie set | 2xx on protected endpoint with no preceding login event for that session/token anywhere in logs |
| JWT signature verifies against the app's known signing key, `alg` matches expected (e.g., RS256) | `alg: none` accepted, or signature check absent/skipped, or `kid` points to an attacker-controlled key |
| `user_id`/`role` in request matches the authenticated session owner | Sequential ID enumeration across the endpoint, or role field flipped to an elevated value mid-session |
| WAF verdict on auth-bypass rule category is "block" | Same rule category logs "allow" or "detect only" and the request still returned 2xx |

## Investigation Steps

1. Pull the full raw HTTP transaction (request + response, including headers and body if captured) for the flagged event from WAF, gateway, and app logs — don't triage off the summary alert alone.
2. Trace the session/token backward: search the same 24-hour-minimum window (or the token's `exp`-derived lifetime, whichever is longer) for its issuance event. If none exists in that window, this is close to a confirmed bypass already; if one exists, check whether the issuing account matches who/what accessed the protected resource.
3. If a JWT/token is involved, decode it (offline, never paste live production tokens into third-party tools) and check `alg`, `kid`, `exp`, and claims against what the app's validation logic should be enforcing.
4. Check for parameter tampering: compare the request's role/permission/ID fields against the session owner's actual entitlements from the IAM system of record.
5. Look for repetition/enumeration immediately before the successful hit — forced-browsing tools and IDOR fuzzers typically leave a trail of 401/403/404 on adjacent URIs or sequential IDs right before the one that worked.
6. Check what happened *after* the bypass in the same session: data pulled, records viewed, account created (T1136), credentials/API keys added (T1098.001), permissions changed — this determines severity far more than the bypass mechanism itself.
7. Confirm whether the vulnerable endpoint/version is still live in production, and whether other tenants/customers share the same code path.
8. Check the authorized-testing calendar and any bug-bounty submission queue — a disclosed or in-scope pentest finding against this exact endpoint changes the disposition entirely.

## True Positive Indicators

- Protected/authenticated response returned with no corresponding valid login or token-issuance event anywhere in the chain.
- Token accepted despite failed or skipped signature verification, or with a self-signed/attacker-supplied key.
- Role or account-ID parameter successfully tampered to access data/functions outside the session owner's entitlements.
- Post-bypass account creation, credential addition, or permission change traceable to the same session.
- Vulnerability independently reproducible by the SOC/AppSec team against a non-production instance of the same code.

## False Positive / Benign Positive Indicators

- Legitimate OAuth/SSO redirect chain (302 → 302 → 200) misread as a bypass because the initial auth hop wasn't captured in the log source pulled.
- CDN or reverse-proxy cache serving a stale "logged in" page fragment to an unauthenticated client — a caching bug, not an auth bypass, but worth a bug ticket regardless.
- Authorized penetration test or bug-bounty researcher actively probing the auth flow (check the testing calendar before escalating).
- Internal service-to-service call using mTLS or a service account that legitimately bypasses the interactive login UI by design — confirm against the architecture diagram, don't assume malice from missing a "login event" that was never supposed to exist for that call path.
- Health-check/monitoring probe hitting an endpoint with a pre-provisioned long-lived token that looks anomalous only because it's rarely reviewed.

## Escalation Criteria

Escalate immediately to IR when: unauthorized access to production customer data, PII, or payment information is confirmed; an admin/privileged function was reached and used (account creation, permission grant, credential addition); the flaw is reproducible and still exploitable in production; or more than one account/tenant is affected. Regulatory notification review (Legal/Privacy) triggers automatically once confirmed data exposure is in scope.

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Who can approve |
|---|---|
| Revoke affected session(s)/token(s) | Tier 2 analyst, immediate, no further approval needed |
| Block source IP/ASN at WAF/edge | Tier 2 analyst, immediate |
| Disable the vulnerable endpoint/feature flag | App Owner + Engineering Manager sign-off (business-impacting) |
| Roll back a recent deployment identified as introducing the flaw | Engineering on-call + Change Advisory Board |
| Force reset of any account created or modified post-bypass | IAM owner approval, user/customer notification plan required |
| Customer/regulatory notification | Legal + Comms + CISO sign-off |

## Example Query (Splunk SPL)

```spl
index=app_auth OR index=waf earliest=-24h latest=now sourcetype IN ("app:access","gateway:token")
| eval has_valid_session=if(isnotnull(session_issued_ts) AND session_issued_ts<=_time, "yes","no")
| where status>=200 AND status<300 AND uri_tag="protected"
| where has_valid_session="no" OR jwt_sig_valid="false" OR jwt_alg="none"
| table _time, client_ip, uri, session_id, jwt_alg, jwt_sig_valid, status
| sort - _time
```

## Closure Criteria

Close as **True Positive** only after confirming the bypass mechanism, the scope of data/functions reached, and whether any persistence (account creation, credential addition) followed — engineering must confirm the flaw is patched or the endpoint disabled before closure. Close as **Benign Positive** when the flagged sequence resolves to a legitimate caching/redirect artifact or an authorized service-account call path, documented against the architecture reference. Close as **Insufficient Evidence** when session-issuance logs weren't retained long enough to confirm or rule out a preceding valid login — flag the retention/logging gap to engineering rather than guessing at a verdict either way.

**Example case note:** *"Session `sess_8f21c...` accessed `/api/v2/admin/users` (200 OK) on billing-portal.example.com with no matching login/session-issuance event in app_auth logs for the preceding 24h. Token `alg` field showed `none`, accepted by API gateway due to missing algorithm allowlist check (confirmed by AppSec repro on staging). Session origin 198.51.100.77 (VPS ASN AS64500) created one new account (`svc-support@example.com`) 40 seconds after the bypass. Session and new account disabled, token signing config patched (CHG-5502), endpoint taken offline for 25 minutes during fix deploy with App Owner approval. Closed as True Positive — confirmed unauthorized admin access, IR engaged for scope review."*
