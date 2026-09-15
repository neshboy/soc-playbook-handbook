# Playbook: Admin Panel Scanning

## Playbook ID & Name

**WEB-010 — Admin Panel Scanning / Enumeration Detection and Response**

Category: Web Security. Applies to any internet-facing web property — corporate marketing site, customer portal, CMS-backed site, self-hosted webmail, hypervisor management console, network appliance UI — where an administrative or management interface exists at a predictable, guessable, or well-known URI path.

## Business Risk

**[STAKEHOLDER]** - This is reconnaissance, not compromise, so on its own it costs nothing. The risk is what it tells the attacker and how fast you notice: every hour a management console sits reachable from the open internet with a guessable path, no MFA, and default or weak credentials is an hour someone else could find it first. The real decision this playbook supports isn't "block this scanner" (there will be another one tomorrow), it's "should that admin interface be internet-facing at all" — and that's usually an infrastructure/app-owner call, not a SOC call, but the SOC is the one who notices the exposure exists.

## Severity / Priority Default

**Low** at initial trigger — this is background noise on any public-facing host and gets deprioritized against real incidents most shifts. Escalate to **Medium** if the scan discovers a live, reachable admin path (200/302 response) that wasn't previously known to be exposed. Escalate to **High** the moment scanning transitions into authentication attempts against a discovered panel, or the source correlates with known threat-actor infrastructure or an active campaign against your industry/CMS.

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | The core behavior this playbook detects — dictionary/wordlist-driven enumeration of admin/management paths |
| T1190 | Exploit Public-Facing Application | The objective the scan is usually feeding — successful discovery of an exposed, vulnerable, or default-configured panel is the setup step for exploitation |
| T1110 (.001 Password Guessing / .003 Password Spraying) | Brute Force | Common immediate follow-on once a login form is confirmed reachable |
| T1046 | Network Service Discovery | Where path enumeration is one part of a broader sweep across ports/services on the same host or subnet, not an isolated web-only probe |

## Trigger / Detection Logic Summary

Alert fires when WAF, reverse proxy, or CDN edge logs show a burst of requests against a defined list of known admin/management URI patterns (`/wp-admin`, `/wp-login.php`, `/administrator`, `/admin`, `/manager/html`, `/phpMyAdmin`, `/webmin`, `/cpanel`, `/.well-known/admin`, `/config.php.bak`, `/actuator`, `/console`, vendor-specific device UIs, etc.) from a single source IP, a small cluster of related IPs (same /24 or ASN), or a rotating pool sharing a fingerprint (identical User-Agent, JA3/JA3S hash, or request-timing signature) within a defined window — typically **10+ distinct admin-pattern paths from one source in under 5 minutes**, or a sustained low-and-slow variant of the same pattern spread over hours. Secondary trigger: an elevated ratio of 404/403 responses against the total request volume for a given source, correlated against a known scanner-path dictionary rather than random noise.

## Required Log Sources & Event IDs

No Windows or Sysmon event IDs apply — this activity lives entirely in web-tier telemetry. If a discovered panel is later authenticated against or exploited, pivot to the relevant identity or endpoint playbook for that follow-on stage; don't try to force this one to cover it.

| Source | What to pull |
|---|---|
| WAF (AWS WAF / Azure WAF / Cloudflare / F5 ASM / ModSecurity) | Rule matches for path-traversal/known-CMS/admin-signature rule groups, action taken (block/log/count), matched URI, source IP, rule ID |
| Web server access log (IIS W3C / Apache combined / Nginx) | Full `cs-uri-stem`, HTTP method, `sc-status`, bytes returned, User-Agent, referer, timestamp |
| Reverse proxy / load balancer / CDN edge log | True client IP (when `X-Forwarded-For` is trustworthy), Host header/vhost, TLS SNI, edge PoP/geo |
| IDS/IPS (Suricata/Snort) | HTTP-layer signature hits for known scanner tools (Nikto, dirb, gobuster, ffuf default UA/behavior signatures) |
| Threat intel feed | Reputation lookup on source IP — known scanner infra, TOR exit node, bulletproof hosting ASN |
| Change/pentest calendar | Not a log source, but essential — cross-reference before escalating |

## Key Fields to Inspect [ANALYST]

- **cs-uri-stem** — the actual paths requested; sort and look for dictionary-style sequencing (alphabetical wordlist order is a strong automation tell)
- **sc-status distribution per source** — a source generating 40 requests with 38×404 and 2×200/302 just told you exactly which two paths are real
- **cs(User-Agent)** — scanner defaults (`Nikto`, `gobuster/3.x`, `python-requests`, `Go-http-client`, `curl/`, blank UA) are common but trivially spoofed; treat as corroborating, not conclusive
- **Request rate per source, per minute** — human browsing a site doesn't request 15 distinct admin-style paths in 8 seconds
- **Referer header** — normal navigation to an admin login page has a referer from the site's own nav or a bookmark; scanners typically send none
- **Host header / vhost targeted** — check whether multiple vhosts/tenants on the same infrastructure were scanned with an identical wordlist (campaign against the hosting platform, not just one customer)
- **Source ASN / hosting provider vs. residential** — datacenter/VPS ranges with no prior legitimate history in your logs weigh toward malicious
- **JA3/JA3S fingerprint (if captured)** — ties rotating source IPs back to the same scanning tool/infrastructure

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| One or two requests to a known admin login path from a corporate/VPN IP range, business hours | Dozens of distinct admin-pattern paths requested from one source within seconds to minutes |
| Referer present, browser-realistic UA, follows normal page-load sequence (CSS/JS/images alongside the HTML) | No referer, no accompanying static asset requests, just raw path probes |
| Requests target paths that actually exist on this specific site | Requests target paths for CMSs/platforms this site doesn't even run (e.g., `/wp-login.php` hitting a .NET app) |
| Source IP has prior legitimate history (known staff, known scanner subnet) | Source IP is a fresh VPS/hosting-provider address never seen before, or a TOR exit node |
| Single vhost targeted, consistent with a known user's workflow | Same wordlist fired at every vhost on a shared platform in sequence |

## Investigation Steps

1. Pull the raw request list for the triggering source IP(s) across the full detection window — confirm actual path diversity, method, status codes, not just the alert's summarized count.
2. Check the response-code breakdown: any 200/301/302 mixed in with the 404/403 noise tells you a real path was found — that's the single most important fact to establish first.
3. Fingerprint the source: IP reputation, ASN/hosting provider, geolocation, and whether it has any prior legitimate history in this environment (internal vuln scanner subnet, known pentest vendor range).
4. Check the change/pentest calendar and vulnerability-management schedule before doing anything else — Qualys/Nessus/Tenable/Burp scanning from an unlisted IP is a very common source of this alert.
5. If a real path was discovered, check whether activity progressed past enumeration — any subsequent POST requests to a login form, any authentication attempts (feeds the brute-force playbook), or any exploitation attempt against a version-specific CVE for that panel.
6. Check breadth: was this single-vhost or did the same wordlist/signature hit multiple tenants/vhosts on shared infrastructure — the latter means this is a platform-wide event, not a one-customer issue, and needs broader notification.
7. Confirm current WAF/IPS disposition — was traffic blocked, rate-limited, or passed straight through to origin? Passed-through traffic against a real discovered path is the urgent case.
8. Regardless of verdict, record whether the admin panel *should* be internet-reachable at all. A benign-positive scanning alert against a panel that has no business being public is still a finding — route it to the asset owner separately from this alert's closure.

## True Positive Indicators

- Dictionary/sequential path pattern consistent with known scanning tools (dirbuster/gobuster/ffuf/Nikto wordlists)
- Elevated 404/403 rate from a single source or fingerprint-linked cluster, well above baseline for that host
- Non-browser or known-scanner User-Agent, or a UA that's blank/generic when paired with abnormal request timing
- At least one real admin path confirmed reachable (200/301/302), especially if it wasn't previously documented in the asset inventory
- Follow-on POST requests to a discovered login form, or a pivot into credential brute forcing
- Source IP/ASN matches threat intel as known scanner infrastructure, TOR, or a campaign already tracked against your CMS/platform

## False Positive / Benign Positive Indicators

- Authorized internal or third-party vulnerability scan (Qualys, Nessus, Tenable, Burp) from a documented scanner subnet — confirm against the scan calendar
- Legitimate security researcher or bug-bounty participant operating within program scope (check against your bug bounty platform's active-tester IP disclosures if available)
- Search engine or uptime-monitoring crawler (Googlebot, Pingdom, UptimeRobot) that happened to request a disallowed path listed in `robots.txt` — verify UA and reverse-DNS against the vendor's published ranges
- Browser link-prefetch or security-extension "check this site" feature generating a handful of probe requests, not a full wordlist sweep
- Duplicate alerts from the same request replayed by a load balancer health check — correlate by transaction ID before counting multiple sources

## Escalation Criteria

Escalate immediately if a real, previously undocumented admin panel is confirmed reachable from the internet with weak/default credentials or no MFA; if enumeration transitions into successful authentication or active brute forcing; if the source correlates with tracked threat-actor infrastructure or an active campaign against your specific CMS/appliance version; or if the same wordlist signature hit multiple customer tenants on shared/SaaS infrastructure, which changes this from a single-alert item into a platform-wide notification.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| Rate-limit or short-term block source IP/ASN at WAF/edge | Tier 1 (standing authority) | Fastest response, minimal blast radius, expect the next scanner within hours |
| Add/tune WAF rule for the specific admin-path signature | Tier 2 | Reduces alert volume for repeat noise from the same pattern |
| Restrict discovered admin panel to VPN/allow-listed IPs only | App/infrastructure owner + security engineering sign-off | The actual fix for most findings from this playbook |
| Force MFA / step-up auth on the admin login | App owner + security engineering | Required if panel must stay reachable for legitimate remote admin use |
| Take the panel off the public internet entirely | Change management + infrastructure owner approval | Highest-value fix; can affect legitimate remote admin workflows, so needs a change ticket, not a same-shift call |
| Rotate credentials on the discovered panel | Asset/app owner, notify IR lead if default/weak creds were in use | Do this regardless of whether an intrusion is confirmed if creds were ever default |

## Example Query (Splunk SPL)

```spl
index=waf OR index=web_access
| regex cs_uri_stem="(?i)(wp-admin|wp-login\.php|administrator|phpmyadmin|webmin|cpanel|actuator|console|manager/html)"
| stats count, dc(cs_uri_stem) as distinct_paths, values(sc_status) as statuses,
        earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, cs_host
| where distinct_paths >= 10 AND (last_seen - first_seen) < 300
| sort - distinct_paths
```

## Closure Criteria

Close as **True Positive** when a real admin path was discovered by the source and the finding has been routed to the asset owner, even if no exploitation followed — the exposure itself is the deliverable, not just the scan. Close as **Benign Positive** when the source is a confirmed authorized scanner, researcher, or monitoring service. Close as **Expected Activity** when the traffic matches a scheduled, pre-notified pentest engagement. Close as **Insufficient Evidence** when the source IP/fingerprint can't be attributed and no real path was confirmed discovered either way — don't force a verdict just to close the ticket.

**Example case note:**
`2026-09-15 09:47 UTC — WAF logged 34 requests from src 198.51.100.77 (hosting-provider ASN, no prior history) against admin-path wordlist on host portal.example.com over 96 seconds. 32x404, 2x200 on /wp-login.php and /wp-admin/admin-ajax.php — site does not run WordPress, so these are false-path noise, but confirms the source is running an automated scanner (UA: python-requests/2.31). No POST/auth attempts followed in the subsequent 30 minutes. Not on pentest calendar. Blocked src_ip at WAF edge for 24h. Closing as True Positive (reconnaissance confirmed, blocked at edge); no real exposure found on this host; no further action required.`
