# Playbook: API Abuse

## Playbook ID & Name

**WEB-013 — API Abuse Detection and Response (BOLA, Key Theft, Excessive Data Access, Rate-Limit Evasion)**

Category: Web Security. Applies to any first-party or partner-facing API surface — REST, GraphQL, gRPC-over-HTTP — fronted by an API gateway (AWS API Gateway, Azure APIM, Kong, Apigee, NGINX) or CDN. This playbook is scoped to abuse of the API *itself*: broken object-level authorization (IDOR-style access to other tenants' data), stolen/leaked API keys, mass automated data pulls, and quota/rate-limit evasion. Credential stuffing and password spraying against login endpoints are covered in their own playbooks in this folder — reference those when the abuse is purely at the authentication layer rather than post-auth API misuse.

## Business Risk

**[STAKEHOLDER]** - Modern breaches increasingly don't involve malware at all — they involve someone with a valid or stolen API key quietly pulling every customer record through an endpoint that was never rate-limited or scoped correctly. This is the "the app worked exactly as designed, and that's the problem" category of incident. A single leaked key or one broken authorization check on an object ID can expose the entire customer database without a single exploit, and because the traffic looks like normal API traffic, it can run for days or weeks before anyone notices the volume. Whether to throttle, revoke, or take an integration offline is frequently a joint call between SOC and the product/engineering team that owns the API, because containment can break a paying customer's integration.

## Severity / Priority Default

**Medium** at trigger — most API abuse alerts start as a volume or pattern anomaly that needs scoping before you know what's actually exposed. Escalates to **High** once a specific object-level authorization bypass (cross-tenant data access) is confirmed, or a leaked API key is confirmed active and in use from an unexpected source. Escalates to **Critical** when confirmed exfiltration involves regulated data (PII, payment data, health records) at scale, or the key/token belongs to a partner integration with broad backend access.

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Automated endpoint discovery/fuzzing against the API before a targeted abuse pattern starts (path brute-forcing, GraphQL introspection sweeps) |
| T1190 | Exploit Public-Facing Application | The core technique — abusing the API's own logic (BOLA, missing scope checks, unbounded queries) rather than injecting code |
| T1552.001 | Unsecured Credentials: Credentials In Files | API key/secret found hardcoded in a public repo, mobile app binary, or client-side JS bundle and then used from an unrelated source |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | SSRF-style abuse of an API endpoint that fetches a URL server-side, pivoted to hit `169.254.169.254` and harvest cloud role credentials |
| T1078.004 | Valid Accounts: Cloud Accounts | Stolen or leaked API key used as a legitimate credential — from the gateway's perspective, this is an "authorized" call |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Attacker with an initial foothold mints a *new* API key/secret on the compromised account to maintain access after the original key is rotated |
| T1530 | Data from Cloud Storage | API abuse used as the pull mechanism against a cloud storage-backed endpoint (e.g., a signed-URL or export API) |
| T1567 | Exfiltration Over Web Service | Bulk data pulled out through the API itself, which is also the exfil channel — no separate C2 needed |
| T1048 | Exfiltration Over Alternative Protocol | Data staged out via a non-HTTP channel (DNS, raw socket) when direct API response volume would trip alerting |
| T1090 | Proxy | Rotating residential/datacenter proxy pools used to spread request volume across many source IPs and evade per-IP rate limiting |

## Trigger / Detection Logic Summary

Alerts fire on one or more of: (1) a single authenticated identity (API key, OAuth client, JWT `sub`) requesting a sequential or high-cardinality range of object IDs it doesn't normally touch (BOLA/enumeration signature); (2) an API key used from a source IP/ASN/geo it has never been seen from, especially immediately after that key appeared in a public leak-detection feed or code-scanning alert; (3) request volume or unique-object count from one identity or one client IP exceeding a rolling baseline by a wide margin (z-score or simple multiple-of-median), independent of whether the gateway's rate limiter actually throttled it; (4) a spike in `429 Too Many Requests` followed by traffic resuming from a *different* source IP using the *same* key — classic rate-limit evasion via IP rotation; (5) GraphQL queries with abnormal nesting depth/field count consistent with introspection or a batched query designed to bypass per-field cost limits.

## Required Log Sources & Event IDs

No Windows or Sysmon event IDs apply — this is API gateway, WAF, and application-layer telemetry. If an API abuse case turns into confirmed key theft with follow-on cloud console access, pivot to your cloud provider's IAM/CloudTrail-equivalent logging (described by log source name only, since specific event IDs weren't confirmed for this write-up) rather than treating this playbook as covering that phase.

| Source | What to pull |
|---|---|
| API gateway logs (AWS API Gateway / Azure APIM / Kong / Apigee) | Request ID, route, method, auth principal (API key ID, OAuth client ID, JWT subject), status code, latency, response size, throttle/quota decision |
| WAF / CDN logs (Cloudflare, AWS WAF, Front Door) | Source IP, ASN, TLS fingerprint (JA3), rule matches, bot-score if available |
| Application/service log | Object IDs actually resolved server-side per request — the gateway log alone often can't tell you *which* customer record was returned |
| Auth service / IdP log | Token issuance, scope granted, token lifetime, key creation/rotation events, secondary-key creation on an existing client |
| Secrets-scanning / leak-detection feed (GitHub secret scanning, GitGuardian, internal DLP) | Confirmed leaked-key alerts — correlate the leak timestamp against first suspicious use |
| Cloud billing/usage export | Sudden cost spike on a metered API is sometimes the first signal, especially for partner-facing APIs billed per call |

## Key Fields to Inspect [ANALYST]

- **auth principal (API key ID / OAuth `client_id` / JWT `sub`)** — the actual identity making the call; never key your investigation off source IP alone, one key legitimately calls from many IPs (mobile clients, serverless functions, CDN egress)
- **object ID / resource path parameter** — is this identity requesting IDs that fall outside the range it owns or has previously touched? Sequential incrementing IDs (`/api/v2/orders/1001`, `1002`, `1003`...) from one token is the textbook BOLA/enumeration tell
- **scope / permission claims on the token** — does the granted scope actually match what's being requested? A read-only reporting key hitting a write or export endpoint is worth a hard look
- **X-RateLimit-Remaining / throttle decision** — repeated near-zero remaining followed by a source IP change on the *same* key is rate-limit evasion, not a retry bug
- **response size / row count per call** — a dashboard widget normally returns tens of rows; an export-shaped response returning tens of thousands from a UI-facing endpoint is abnormal
- **User-Agent and client SDK header** — legitimate SDKs self-report consistently (`okhttp/4.9`, `axios/1.4.0`); bare `python-requests` or `curl` hitting a partner-only endpoint that's normally called by a known SDK deserves scrutiny, though this is trivially spoofed and not sufficient alone
- **key creation timestamp vs. first use** — a key created seconds before its first high-volume call, or a *second* key minted on an account shortly after suspicious activity started, both point to T1098.001

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| One authenticated identity accesses object IDs it owns, in a pattern matching real user/session behavior | Same identity walks a sequential or randomized wide range of object IDs it has never touched before |
| Request volume per key tracks a stable daily/weekly baseline | Volume jumps 10x+ with no corresponding business event (marketing push, batch job, known integration change) |
| `429` responses are rare and self-resolve with backoff from the same source | `429` spikes followed immediately by continued traffic on the same key from a new IP/ASN |
| API key used consistently from a small, known set of egress IPs (app servers, known cloud region) | Key suddenly used from a residential proxy ASN, a Tor exit, or a country the integration has no business reason to call from |
| GraphQL queries have a stable shape matching the front-end's known queries | Deeply nested or introspection-style GraphQL queries (`__schema`, `__type`) from a production key, or batched queries stacking many object lookups in one call |
| Response payload sizes match expected page sizes (pagination in effect) | Full-table-shaped response sizes, or repeated pagination through every page of a resource in a tight loop |

## Investigation Steps

1. Identify the authenticated principal behind the alert (API key ID, OAuth client, JWT subject) — do not start from source IP, it's the least reliable anchor for API-layer identity.
2. Pull that principal's full request history across the gateway logs for the alerting window and baseline period (7-30 days back) — look at object IDs touched, endpoint diversity, and volume trend.
3. Check the auth/IdP log for when this key/token was created, its granted scope, its last rotation date, and whether a second credential was recently created on the same account (T1098.001 signature).
4. Cross-reference the key value (or a hash of it) against your secrets-scanning/leak-detection feed and any recent code-repo or CI log exposure — confirm whether this credential has appeared somewhere it shouldn't have.
5. For suspected BOLA, replay (in a safe, read-only, authorized test context) a handful of the flagged object IDs against the affected endpoint using the *legitimate* owner's session to confirm the authorization check is actually broken versus the requests being rejected server-side despite appearing in the gateway log.
6. Pull application-layer logs to confirm what was actually *returned*, not just requested — a 200 status code with an empty or access-denied body is a very different finding than a 200 with a full record.
7. Check for IP rotation against a stable key/token (ASN diversity, proxy/hosting-provider ASN flags) to distinguish rate-limit evasion from a single client behind a legitimately dynamic IP (mobile carrier NAT, CGNAT).
8. Scope blast radius: how many distinct objects/records were actually exposed, over what time window, and does that set overlap with regulated data categories.

## True Positive Indicators

- Confirmed authorization bypass — a token scoped to tenant A successfully retrieves tenant B's records, verified against application logs showing data actually returned
- API key confirmed present in a public leak (repo, paste site, mobile app decompile) with usage starting shortly after the leak timestamp from an unfamiliar source
- Sustained high-cardinality object enumeration by one identity with no legitimate business workflow to explain it
- Rate-limit evasion pattern: `429` responses followed by continued traffic on the same credential from rotating IPs/ASNs
- A new API key or secondary credential minted on an account immediately following anomalous activity, with no matching change ticket

## False Positive / Benign Positive Indicators

- Volume spike traced to a known batch job, data migration, or newly onboarded integration partner ramping up call volume — check the change calendar and partner onboarding tracker before escalating
- "Enumeration-looking" sequential requests actually generated by a legitimate paginated export feature the customer is entitled to use
- IP diversity on a single key explained by serverless/Lambda cold-start behavior or a mobile app on carrier-grade NAT, not proxy rotation — check ASN reputation, not just IP count
- GraphQL introspection queries from a known internal tooling client (API documentation generator, internal test harness) rather than an external actor
- Authorized penetration test or bug-bounty researcher probing object-level authorization with prior notice — cross-reference the pentest calendar

## Escalation Criteria

Escalate to Incident Response immediately if: a broken object-level authorization is confirmed to have returned another tenant's or customer's data (not just attempted); a leaked API key is confirmed active and used to pull data at volume; the exposed data set includes regulated categories (PII, cardholder data, health records) — this generally starts your breach-notification clock, so pin down the confirmed-access timestamp and record count precisely; or the compromised credential belongs to a partner/third-party integration with broader backend access than the abused endpoint alone suggests.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| Throttle/rate-limit a specific key or client ID at the gateway | Tier 2 (standing authority) | Fastest, minimal customer impact if scoped tightly |
| Revoke/rotate a specific API key | API/product owner + Tier 2 | Breaks the integration immediately — notify the owning team before or immediately after |
| Block source IP/ASN at WAF/CDN edge | Tier 2 | Low value alone if the key itself is compromised and portable to new IPs |
| Disable an endpoint or feature flag (e.g., an export function) | App/product owner + on-call engineering lead | Business-impact call, not purely SOC |
| Force account-wide credential rotation for a partner integration | IR lead + partner/account management sign-off | Reserved for confirmed compromise with broader account access, needs partner coordination |
| Suspend the third-party integration account entirely | IR lead + business owner (Sev-1 bridge) | Last resort — direct revenue/relationship impact, requires named sign-off above SOC |

## Example Query (KQL — Azure Monitor / API Management logs)

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| extend KeyId = tostring(parse_json(BackendRequestHeaders)["Ocp-Apim-Subscription-Key"])
| summarize DistinctObjects = dcount(Url), CallCount = count(),
            DistinctSourceIPs = dcount(CallerIpAddress),
            ThrottleHits = countif(ResponseCode == 429)
    by KeyId, bin(TimeGenerated, 1h)
| where DistinctObjects > 200 or (ThrottleHits > 20 and DistinctSourceIPs > 5)
| sort by CallCount desc
```

## Closure Criteria

Close as **True Positive** once the abused key is revoked or the authorization bug is patched/mitigated (gateway-level policy or code fix), the scope of exposed records is documented, and the app/product owner and, where regulated data is involved, privacy/legal have been notified. Close as **Expected Activity** when the volume or pattern is confirmed to match a known integration, migration, or authorized test. Close as **Benign Positive** when the pattern looked anomalous but resolves to legitimate, unplanned client behavior (e.g., a mobile client's normal serverless cold-start IP diversity) with no unauthorized access. Close as **Insufficient Evidence** when application-layer logs weren't retained long enough to confirm what was actually returned (gateway logs alone showing a 200 status don't prove data exposure) — flag the retention/logging gap for Engineering rather than letting the case lapse quietly.

**Example case note:**
`2026-09-15 09:47 UTC — API key nw_live_sk_4a1c (issued to partner Meridian Logistics, scope=orders:read) requested /api/v2/customers/{id} for 3,412 distinct sequential customer_id values over 40 minutes from src 198.51.100.22 (datacenter ASN, not Meridian's registered egress range). Application log confirms 3,109 requests returned full customer records (200, non-empty body). Key does not carry customers:read scope per IdP grant — authorization check on this endpoint confirmed missing tenant-scope enforcement. Key revoked 10:05 UTC, endpoint patched to enforce scope same day, Meridian account manager and privacy team notified 10:20 UTC. Closing as True Positive (contained); 3,109-record exposure logged for breach-assessment review.`
