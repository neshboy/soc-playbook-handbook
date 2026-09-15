# Playbook: Enumeration

## Playbook ID & Name

**WEB-014 — Enumeration (Reconnaissance Against Web Applications and APIs)**

Category: Web Security. Covers automated and manual reconnaissance against a web-facing application or API where the goal isn't exploitation yet — it's mapping what exists: hidden directories and files, valid usernames/emails, API object IDs, virtual hosts/subdomains, allowed HTTP methods, and undocumented parameters. This is the "casing the building" playbook. It rarely stands alone in an incident timeline; it's usually chapter one, with credential stuffing, path traversal, or exploitation of a discovered endpoint as chapter two.

## Business Risk

**[STAKEHOLDER]** - Enumeration by itself doesn't take anything or break anything, which is exactly why it gets under-prioritized. But every successful attack against a public-facing app starts with the attacker learning something they weren't supposed to know: that `/backup.zip` exists, that `finance-admin@example.com` is a valid account, that invoice IDs are sequential integers, that a staging vhost with weaker auth sits behind the same load balancer as production. The cost of enumeration isn't the scan itself, it's what it hands the attacker for the next step. Treating every enumeration alert as noise is how a SOC ends up finding out about the exposed `.env` file only after it's already been read.

## Severity / Priority Default

**Low** for a single scan burst that returns nothing but 403/404 and doesn't touch an authentication or account-lookup endpoint. **Medium** as the default for anything hitting login, registration, password-reset, or "forgot username" flows, since those carry a direct path to confirmed valid accounts. Escalates to **High** the moment any enumeration attempt returns a 200/302 against a sensitive path (backup archive, `.git`, admin panel, cloud storage listing) or produces a confirmed list of valid usernames/emails, and to **Critical** if that output is then used in a follow-on brute-force or credential-stuffing wave, or if a discovered path exposes credentials or PII directly.

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Core technique for this playbook — automated content discovery and fuzzing (dirbusting, API endpoint/parameter fuzzing, vhost enumeration) run against the target before an attacker decides where to focus |
| T1046 | Network Service Discovery | Frequently runs alongside or just before web enumeration when the actor is also mapping which ports/services sit behind the same IP or CDN edge — e.g. finding a staging instance on a non-standard port |
| T1087 | Account Discovery | Username/email enumeration specifically — via response differences on login, registration, password-reset, or account-lookup endpoints |
| T1580 | Cloud Infrastructure Discovery | Enumeration of cloud-hosted storage buckets, API Gateway stages, or serverless function URLs fronting the app (bucket-name guessing, exposed API routes, dashboard discovery) |
| T1190 | Exploit Public-Facing Application | The usual next step once enumeration surfaces something worth exploiting — flagged here as the handoff point, not because discovery itself is exploitation |
| T1110.001 / T1110.003 | Brute Force: Password Guessing / Password Spraying | Natural follow-on once username enumeration confirms a target list of valid accounts — correlate forward on the same source and on the harvested usernames |

## Trigger / Detection Logic Summary

Several distinct sub-patterns feed this playbook, and it's worth separating them at triage rather than treating "enumeration" as one alert type:

- **Directory/file discovery** — a single source generates a high volume of requests for unique URIs in a short window, dominated by 404/403 responses, with paths matching known wordlist entries (`/admin`, `/.env`, `/backup.zip`, `/wp-login.php`, `/.git/config`, `/server-status`, `/.well-known/`). Timing is often unnaturally even (bot-paced) or comes in dense bursts.
- **Username/account enumeration** — repeated login, registration, or password-reset requests from one source cycling through different usernames or emails, where the *response itself* leaks existence: different status code, different error message text, different response size, or a measurable response-time delta between "account exists" and "account does not exist" code paths.
- **API/object enumeration** — sequential or incrementing path/query values (`/api/v1/invoice/10042`, `10043`, `10044`...) walked far faster and further than any UI-driven session would generate, often with no session cookie or a shared service-account token.
- **Vhost/subdomain enumeration** — many distinct `Host` header values hitting the same origin IP in a tight window, or a DNS query burst against a wordlist of subdomain candidates.
- **HTTP verb/method enumeration** — the same URI probed repeatedly with different methods (GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH) to map what the server accepts, sometimes revealing an endpoint that only responds meaningfully to a method the frontend never uses.

**[ENGINEERING]** - Build the correlation rule as a per-source, time-bucketed aggregation rather than a single-event match — enumeration is defined by *pattern across many requests*, not by any one request looking malicious. Bucket in 1–5 minute windows, aggregate by source IP (or by session/API-key where auth is present), and alert on thresholds like distinct-URI count, 404-ratio, and request rate together — any single dimension alone produces too much noise from crawlers and monitoring tools.

## Required Log Sources & Event IDs

No Windows or Sysmon event IDs apply directly — enumeration against a web app is visible in web/WAF/API telemetry, not host telemetry, unless it later chains into a host-side action.

| Source | What to pull |
|---|---|
| WAF / CDN (Cloudflare, AWS WAF, Azure Front Door, Akamai, ModSecurity/OWASP CRS) | Matched rule category (scanner detection, bad-bot signature), action taken, request rate metrics, raw User-Agent |
| Web/app server access log (IIS W3C / Apache / Nginx combined) | `cs-uri-stem`, `cs-uri-query`, method, status code, `sc-bytes`, `time-taken`, `cs(User-Agent)`, `cs(Referer)`, `Host` header |
| API gateway log (Kong, Apigee, AWS API Gateway, Azure APIM) | Route/resource path, response code, latency, API key/client ID, rate-limit rejections |
| Application authentication log | Username/email submitted, result (exists/doesn't exist, valid/invalid), source IP, endpoint (login/register/reset) |
| DNS / passive DNS | Burst of NXDOMAIN or newly-resolved subdomains matching a wordlist pattern under the org's domain |
| Cloud storage access logs (S3 server access logs, Azure Storage logs) | Repeated `ListBucket`/`HeadObject` calls against sequential or wordlist-derived bucket/object names, especially unauthenticated attempts |

## Key Fields to Inspect [ANALYST]

- **Distinct URI/parameter count per source, per short time window** — the single strongest discriminator between a real user and a scanner; a human doesn't request 200 unique paths in ninety seconds
- **Status code ratio** — a session that's almost entirely 404/403 with an occasional 200 is discovery-shaped; flip that ratio and you're looking at something else (or a successful hit worth chasing immediately)
- **Response size and response-time deltas on auth-adjacent endpoints** — this is how username enumeration hides in plain sight; two requests with identical status codes but a consistent 40ms time difference or a 12-byte size difference between "valid" and "invalid" usernames is a textbook enumeration oracle
- **User-Agent** — literal tool signatures (`gobuster`, `ffuf`, `wfuzz`, `dirbuster`, `nikto`, `sqlmap`, `Nuclei`) are a gift when present, but don't rely on it; competent operators strip or spoof this
- **Host header vs. requested vhost** — many distinct Host values hitting one IP in a short window is vhost enumeration, not normal traffic
- **Sequential/incrementing values in path or query parameters** — flag numeric or predictable-pattern IDs walked outside any plausible UI navigation
- **Source IP / X-Forwarded-For, cross-checked against the authorized vulnerability-scan calendar** — do this before anything else; a huge share of these alerts trace straight back to an approved scan window

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| A handful of 404s per day from stale links, typos, or old bookmarks, spread across unrelated paths | Dozens to thousands of 404/403 responses to one source in minutes, against paths following a wordlist pattern |
| Login/reset attempts track roughly with real user volume and error rates stay flat across usernames | Response size/time/message varies measurably and consistently between valid and invalid usernames, and one source cycles through many candidate usernames |
| API object IDs requested match what a logged-in user's own session would plausibly reference | API path/query IDs walked sequentially far beyond what one account's data set should contain |
| One or two Host headers per origin IP, matching configured vhosts | Many distinct Host header values against a single IP in a tight window |
| Occasional OPTIONS/HEAD from legitimate tooling (health checks, CORS preflight) | The same URI hit with every HTTP verb in sequence, especially including TRACE/PATCH/PUT with no legitimate reason |

## Investigation Steps

1. Identify the source (IP, ASN, X-Forwarded-For chain) and check it against threat intel and, critically, the organization's authorized vulnerability-scan/pentest calendar before doing anything else — this single check resolves a large fraction of these alerts.
2. Pull the full session from WAF/proxy/API-gateway logs for the triggering time window: total request count, distinct URI/parameter count, status code distribution, and User-Agent consistency across the burst.
3. Classify which enumeration sub-type this is (directory/file, username, API object ID, vhost, verb) — the follow-up steps and impact differ meaningfully by type.
4. Check for any 200/302 (or, for auth endpoints, any status/size/timing pattern indicating a confirmed "account exists" result) inside the noise — this is the line between reconnaissance-with-no-yield and reconnaissance-that-worked.
5. If a sensitive path was actually returned (backup file, `.git`, admin panel, exposed storage bucket listing), pull the object and assess exactly what it discloses — treat any credential or key found in it as compromised immediately.
6. If usernames/emails were confirmed valid, check authentication logs on those specific accounts, going forward from the enumeration timestamp for several days — password spraying built on a harvested list often doesn't start immediately.
7. Check whether the WAF/rate-limit actually stopped the activity or just logged it — sustained volume after a block is deployed suggests the operator is adapting (rotating IPs, throttling to stay under the limit), which raises priority even without a confirmed hit.
8. Assess whether this is isolated or part of a broader pattern — same source hitting multiple applications, or multiple sources running an identical wordlist against the same app (distributed/low-and-slow enumeration to dodge per-IP thresholds).

## True Positive Indicators

- High-volume, high-distinct-URI request pattern from one source against wordlist-shaped paths, not matching any authorized scan
- Confirmed response differential (status, size, or timing) on an authentication/account-lookup endpoint across many submitted usernames from one source
- Sequential/incrementing object-ID access far outside a plausible single-user data footprint
- A discovery request returns a genuine hit — sensitive file, admin interface, exposed storage bucket, staging vhost with weaker controls
- Enumeration activity from a source that goes on to attempt login, credential stuffing, or exploitation against the same or a discovered endpoint

## False Positive / Benign Positive Indicators

- Confirmed authorized pentest or vulnerability scan against the change/scan calendar, with volume and pattern consistent with known scanning tooling
- Legitimate crawler/bot (Googlebot, Bingbot, uptime/monitoring services) generating 404s against removed or moved pages — check reverse DNS/ASN and declared User-Agent behavior against the vendor's published crawler ranges
- QA or automated test suite in a shared environment walking sequential test-data IDs as part of normal regression testing
- Browser link-prefetch or a misconfigured internal integration retrying the same set of endpoints repeatedly
- Shared corporate NAT/proxy inflating apparent request volume from a single source IP that's actually many real users

## Escalation Criteria

Escalate immediately if: any sensitive path or object is confirmed disclosed (not just probed); a confirmed list of valid usernames/emails exists and the source (or any source) begins authentication attempts against them; an exposed cloud storage bucket or API route with no auth control is found; the source IP/infrastructure matches known threat-actor tooling in threat intel; or enumeration activity continues, adapted, after a block/rate-limit is applied. Sustained, adaptive enumeration against authentication endpoints should be treated as the opening move of a credential-based intrusion, not a standalone low-severity finding.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| WAF rate-limit or rule tune for the specific pattern/source | Tier 2 (standing authority) | Fastest option; verify it won't rate-limit legitimate high-traffic clients (mobile app backends, partner integrations) |
| Block source IP/ASN at edge/CDN | Tier 2, notify app owner | Shared-NAT and CDN attribution risk — confirm the IP isn't a proxy pool before a broad block |
| Normalize login/reset/registration responses (equal status, size, timing regardless of account existence) | App/engineering owner, tracked as a change ticket | Root-cause fix for username enumeration — this is a code change, not a SOC action, but should be raised as a finding every time it's absent |
| Remove or restrict a discovered sensitive file/path (backup, `.git`, exposed config) | App owner + on-call engineering lead | Treat as urgent regardless of severity default — the file is disclosed the moment it's requested successfully |
| Fix cloud storage bucket/API route permissions | Cloud infrastructure owner + IR lead sign-off | Confirm no data was actually exfiltrated via prior successful list/get calls before closing |
| Force password reset / MFA enforcement on harvested valid accounts | IAM/identity owner + IR lead | Applies once username enumeration output is confirmed and there's any sign of follow-on targeting |

## Example Query (Splunk SPL)

```spl
index=web_access sourcetype=access_combined earliest=-15m
| bin _time span=5m
| stats count as requests, dc(uri_path) as unique_paths,
        count(eval(status=404)) as not_found, count(eval(status=200)) as found
        by src_ip, _time
| where requests > 150 AND unique_paths > 100 AND not_found > (found * 5)
| sort - requests
```

## Closure Criteria

Close as **True Positive** when enumeration is confirmed, blocked/rate-limited effectively, and any accidental disclosure (file, username list) has been remediated (file removed/secured, affected accounts flagged for reset) — or when it fed into a confirmed brute-force, credential-stuffing, or exploitation attempt, in which case hand off to that playbook's case rather than closing independently. Close as **Benign Positive** when traced to an authorized scan or known-good crawler/monitoring source. Close as **Insufficient Evidence** when source attribution is impossible (shared NAT, no X-Forwarded-For logged) and no hit or disclosure can be confirmed either way — flag the missing forwarded-IP logging as a gap rather than letting it lapse silently.

**Example case note:**
`2026-09-15 09:47 UTC — WAF and access-log correlation flagged src 192.0.2.183 against portal.example.com: 1,812 requests across 6 minutes, 1,340 unique URIs matching a common content-discovery wordlist (incl. /.env, /backup.zip, /wp-login.php, /.git/config), UA "Mozilla/5.0 (compatible; feroxbuster)". Status codes: 1,790x 403 (WAF block engaged after request #22), 22x 404, 0x 200. No entry on the authorized-scan calendar for this source or window; ASN resolves to a generic VPS hosting provider, no prior TI attribution. No corresponding auth-endpoint activity from the same source in the following 48 hours. Closing as True Positive (blocked, no disclosure). No containment action beyond existing WAF rule required; added source IP to 30-day watchlist given wordlist targeted our actual stack (Git, WordPress artifacts) rather than generic scanner defaults.`
