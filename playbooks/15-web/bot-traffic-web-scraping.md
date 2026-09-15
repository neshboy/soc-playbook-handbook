# WEB-017 — Bot Traffic / Web Scraping

## Business Risk

**[STAKEHOLDER]** - Not every bot is a security incident, and that's the first thing to get comfortable with. A lot of scraping is competitors pricing you out in real time, data brokers rebuilding your catalog for a comparison site, or AI training crawlers hoovering up your content — none of that is "breach," but it's still revenue leakage, content theft, and infrastructure cost you're paying for on someone else's behalf. The risk that does belong in a security queue is when scraping bots are really reconnaissance (mapping login pages, hidden endpoints, promo-code formats, or inventory/pricing APIs ahead of a fraud or abuse campaign), when bot volume degrades availability for real customers, or when the same infrastructure doing the scraping starts testing credentials or exploit payloads against what it found. The business decision is usually a cost/risk tradeoff: how much bot mitigation friction (CAPTCHAs, JS challenges, rate limits) is acceptable against real user experience and SEO-crawler needs.

## Severity / Priority Default

- **Default:** Low–Medium (P4/P3) — most scraping is nuisance-level and gets handled by rate limiting/WAF bot rules without SOC involvement.
- **Escalate to Medium (P3)** when scraping targets authenticated areas, non-public pricing/inventory APIs, or shows clear evasion (proxy rotation, header spoofing, session-cookie farming).
- **Escalate to High (P2)** when bot behavior pivots into credential testing, exploit probing against endpoints discovered by the crawl, or sustained volume causing availability degradation.

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1595 Active Scanning | Broad, low-and-slow crawling of the site/app to map structure, content, and endpoints |
| T1119 Automated Collection | The core behavior — scripted, repeated harvesting of pages, product data, listings, or user-generated content at a scale no human replicates |
| T1090 Proxy | Bot operators rotate through residential/datacenter proxy pools or open relays specifically to defeat IP-based rate limiting and blocklists |
| T1190 Exploit Public-Facing Application | Where scraping traffic transitions into probing discovered endpoints for injection, auth bypass, or logic flaws |
| T1110 Brute Force (.001/.003) | Handoff technique — same bot infrastructure pivots from content scraping to credential guessing (see PB-15.8/PB-15.9) |
| T1078.004 Valid Accounts: Cloud Accounts | Handoff technique — scraped or stuffed credentials get used to log into customer accounts for loyalty-point fraud, resale, or scalping |

## Trigger / Detection Logic Summary

**[ENGINEERING]** Alert on request patterns consistent with automation rather than human browsing: high request rate per session/IP against content-heavy URIs (product pages, listings, search), near-zero variance in inter-request timing, absence of expected supporting requests (no CSS/JS/image fetches, no favicon request), and/or systematic sequential traversal of numeric or predictable IDs (`/product/10432`, `/product/10433`, `/product/10434`...). Layer this with bot-signal sources: known datacenter/hosting ASN, missing or inconsistent TLS/JA3 fingerprint vs. claimed User-Agent, JS-challenge failure rate, and CAPTCHA solve-farm indicators (near-100% solve rate at inhuman speed is itself a signal). Tune thresholds separately for known-good crawlers (Googlebot, Bingbot) verified by reverse-DNS/IP-range confirmation — don't just trust the User-Agent string, it's the single most spoofed field in this entire playbook.

## Required Log Sources & Field References

| Source | What to pull |
|---|---|
| WAF / bot management (Cloudflare Bot Management, AWS WAF Bot Control, Akamai Bot Manager, F5 Distributed Cloud) | Bot score, `cs-uri-stem`, client IP, JA3/JA4 fingerprint, challenge outcome (JS/CAPTCHA pass/fail), rule action |
| CDN edge logs | Request rate per client IP/session, cache hit ratio (bots frequently hit uncached/dynamic paths deliberately), edge PoP/geography |
| Web/app server access logs (Nginx, Apache, IIS W3C) | `c-ip`, `cs(User-Agent)`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `time-taken`, `cs(Referer)` |
| API gateway logs | Per-key/per-token request rate, endpoint sequence, auth failures mixed into an otherwise-successful scraping session |
| Application-layer analytics / RUM | Absence of client-side JS execution telemetry (bots served server-rendered content skip this entirely) |
| Threat intel / proxy-reputation feeds | Match source IPs against known residential-proxy and scraping-as-a-service provider ranges |

## Key Fields to Inspect

**[ANALYST]**
- Requests-per-minute per source IP/session and its coefficient of variation — humans are bursty and irregular, scripts are metronomic
- User-Agent vs. TLS/JA3 fingerprint mismatch (claims to be Chrome on Windows, fingerprint says a Python `requests`/`curl`/headless-Chromium stack)
- Sequential or brute-force-style traversal of predictable resource IDs, or a request order that doesn't match how a real user would navigate (no referer chain, jumping straight to deep pages)
- Cookie/session churn — real users keep a session across a visit; scraper farms often mint a fresh session or rotate cookies every few requests to defeat session-based rate limiting
- Header completeness — missing `Accept-Language`, `Accept-Encoding`, or inconsistent header ordering vs. the claimed browser
- ASN and IP reputation — datacenter hosting, known VPN/proxy exit ranges, or a large IP pool that never repeats (classic residential-proxy botnet signature)
- Whether the scraped content maps to something monetizable (full catalog + pricing = competitor intel; user profile pages = data harvesting for phishing/fraud)

## Normal vs. Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Verified search-engine crawler (reverse-DNS confirms Googlebot/Bingbot), respects `robots.txt`, moderate steady crawl rate | Unverified bot claiming to be a search crawler UA but resolving to unrelated hosting ASN |
| Legitimate partner/API integration with an issued key, predictable rate within contract limits | High-volume unauthenticated scraping of the same catalog/listing endpoints, no key, sequential ID walk |
| Real user session: mixed page types, images/CSS/JS loaded, irregular timing, referer chain intact | Metronomic request timing, HTML-only fetches, no static asset requests, no referer, single-purpose URL pattern |
| Occasional CAPTCHA solve by a real frustrated user, low overall solve rate | Near-perfect, inhumanly fast CAPTCHA solve rate (solve-farm signature) across many sessions from one operator |

## Investigation Steps

1. Pull the full request history for the flagged IP/session/ASN over the detection window plus lookback — scraping campaigns often run in slow, distributed bursts across a large IP pool to stay under any single-IP threshold.
2. Cluster by behavior signature (timing variance, header set, JA3 fingerprint, URI pattern) rather than by IP alone — a well-run scraper farm rotates thousands of IPs but reuses the same client fingerprint and request logic.
3. Verify claimed-crawler identity via reverse-DNS/forward-confirm and published IP ranges (Google, Bing, etc.) before excluding traffic as benign.
4. Determine what was actually accessed — public catalog/marketing pages (low severity) vs. authenticated content, internal APIs, or endpoints that shouldn't be enumerable (higher severity, treat as reconnaissance).
5. Check whether the same source pool shows any authentication attempts, form submissions, or payloads beyond passive GET requests — this is the pivot point from "scraping" to an active-abuse or exploitation playbook.
6. Assess business impact: cache-bypass rate, origin load/latency contribution, and whether legitimate customer traffic showed increased error rates or slowness during the campaign window.
7. Cross-check current bot-mitigation rule effectiveness — was this traffic already being challenged/blocked (working as intended) or did it bypass existing controls (needs a rule/tuning change)?
8. Document the source infrastructure fingerprint (ASN ranges, JA3, UA set) for feeding into longer-term bot-management allow/deny lists.

## True Positive Indicators

- Confirmed non-human request cadence and header/fingerprint mismatch across a large, coordinated IP pool.
- Systematic traversal of the full catalog/dataset, well beyond what any single legitimate user session would touch.
- Evasion behavior present: session/cookie rotation, proxy rotation, CAPTCHA-farm solve pattern, User-Agent spoofing of a known crawler that fails reverse-DNS verification.
- Bot activity discovered non-public or unlinked endpoints (indicates prior undisclosed enumeration, not organic crawling).
- Measurable business impact — origin latency increase, cache-bypass cost spike, or inventory/pricing data reappearing on a competitor or reseller site shortly after the scrape.

## False Positive / Benign Positive Indicators

- Verified search-engine or SEO-tool crawler (Googlebot, Bingbot, Ahrefs, SEMrush) operating within `robots.txt` and reasonable rate.
- Legitimate monitoring/uptime service or internal synthetic-transaction testing hitting the same endpoints on a fixed schedule.
- A partner integration with a valid API key whose contracted rate limit was simply set too low for actual legitimate use — this is a config/business conversation, not an incident.
- AI-training or archival crawler (identifiable UA, e.g., `GPTBot`, `CCBot`) that is unwanted but not malicious — a policy decision (block via `robots.txt`/WAF rule) rather than a security escalation.
- Marketing/analytics pixel or headless-browser QA testing tool from an internal team not registered with SOC.

## Escalation Criteria

Escalate beyond Tier 1 when: scraping traffic pivots to credential submission or exploit-style payloads against discovered endpoints; the source pool begins targeting authenticated/customer-data endpoints rather than public content; sustained volume measurably degrades site availability or origin cost; or scraped data appears to be feeding a downstream fraud pattern (e.g., loyalty-program abuse, scalping bots checking out inventory faster than any human can).

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Who can approve |
|---|---|
| Apply/tighten WAF bot-management rule or rate limit on affected endpoints | Tier 2 analyst or web platform on-call, no further approval needed |
| Block specific IP ranges/ASNs at CDN/WAF edge | Tier 2 analyst, notify web platform team |
| Deploy JS challenge/CAPTCHA on previously ungated public endpoints | SOC lead + product/UX sign-off (affects real user experience) |
| Require authentication or API key on a previously open endpoint | Engineering + product owner approval — architectural change |
| Legal/cease-and-desist action against identified scraping operator | Legal team decision, SOC provides evidence package only |

## Example Query (Cloudflare/Elastic-style — Web Access Logs)

```sql
SELECT client_ip, ja3_fingerprint, user_agent,
       count(*) AS reqs,
       stddev(time_since_last_req) AS timing_variance
FROM edge_access_logs
WHERE uri_path LIKE '/product/%'
  AND ts > now() - INTERVAL '1 hour'
GROUP BY client_ip, ja3_fingerprint, user_agent
HAVING count(*) > 500 AND stddev(time_since_last_req) < 0.5
ORDER BY reqs DESC;
```

## Closure Criteria

Close as **True Positive** when automation is confirmed via behavioral/fingerprint evidence and mitigated at the edge, with impact (data exposure scope, cost, availability) documented. Close as **Benign Positive** when the traffic is a verified legitimate crawler, partner integration, or internal tool operating outside expected allow-lists but with no malicious intent — route to a config fix rather than an incident record. Close as **Expected Activity** for known and accepted SEO/AI-crawler traffic once policy on that crawler type is confirmed. Close as **Insufficient Evidence** when fingerprinting data (JA3, full header set) wasn't captured at the edge and User-Agent alone can't settle bot-vs-human — flag the logging gap to the platform team rather than guessing at a verdict.

**Example case note:** *"Detected 14,200 requests over 40 min against `/product/{id}` sequential IDs from a pool of 380 distinct IPs across 6 hosting ASNs (no residential overlap), shared JA3 fingerprint `771,4866-4867...` inconsistent with claimed Chrome/122 User-Agent. Zero static-asset requests, timing variance <0.3s across all sessions. No authentication attempts or payload injection observed — content-only scrape of public catalog pages. Cloudflare Bot Management rule tightened to challenge this fingerprint cluster; origin load returned to baseline within 10 min. Closed as True Positive (content scraping confirmed); no data beyond public catalog accessed, no further action required."*
