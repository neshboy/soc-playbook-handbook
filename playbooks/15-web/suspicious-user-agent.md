# WEB-018 — Suspicious User-Agent

**Category:** Web Security
**Playbook ID:** WEB-018

## Business Risk

**[STAKEHOLDER]** - Attackers and automated scanners regularly probe our public-facing web apps and APIs before ever touching a login prompt, and the client identifying itself in that traffic (its User-Agent string) is one of the cheapest, earliest tells we get. Missing this signal means we find out about a compromise attempt from the exploitation stage instead of the reconnaissance stage — the difference between a blocked scan and a data breach headline.

## Severity / Priority Default

**Medium** on initial trigger (reconnaissance-grade signal). Auto-escalates to **High** if the same suspicious UA is associated with a successful authentication, a 2xx response on a sensitive endpoint, or an embedded exploit payload (e.g., JNDI/LDAP string, SQL injection fragment) inside the header itself.

## MITRE ATT&CK Mapping

| Technique | Relevance |
|---|---|
| T1595 Active Scanning | Bulk scanners (Nikto, Nuclei, ZGrab, masscan-derived HTTP probes) announce themselves via default library/tool UAs. |
| T1046 Network Service Discovery | Internal or post-compromise enumeration against internal web/API services carrying non-browser UAs. |
| T1190 Exploit Public-Facing Application | Exploit payloads (SQLi, JNDI/log4j-style strings, command injection) delivered inside the UA header against a vulnerable app. |
| T1105 Ingress Tool Transfer | curl/wget/PowerShell UAs pulling second-stage payloads from the target or from staging infrastructure. |
| T1071 Application Layer Protocol | C2 frameworks using HTTP(S) with static or malformed UA strings for beaconing. |
| T1090 Proxy | Traffic relayed through Tor exit nodes or open proxies, often paired with generic/stripped UAs. |
| T1552.005 Unsecured Credentials: Cloud Instance Metadata API | Suspicious UA (usually curl/python) hitting `169.254.169.254` metadata paths from inside a web app or container. |

## Trigger / Detection Logic Summary

Alert fires when web/proxy/WAF telemetry shows a request (or a burst of requests) where the User-Agent string matches a known scanner/tool/library signature, is empty, is malformed, contains obvious payload characters, or is internally inconsistent with the TLS fingerprint and HTTP client-hint headers presented by the same session. Correlation rules typically layer this with request rate, target path sensitivity (`/admin`, `/.env`, `/wp-login.php`, `/actuator`, cloud metadata paths) and response code to cut noise before an analyst ever sees it.

## Required Log Sources & Event IDs

| Source | Field of interest |
|---|---|
| Web server logs (IIS W3C, Apache/Nginx access log) | `cs(User-Agent)`, `c-ip`, `cs-uri-stem`, `sc-status` |
| WAF / reverse proxy (e.g., Cloudflare, F5, Azure App Gateway, Akamai) | UA, matched rule ID, action (block/allow/challenge) |
| CDN edge logs | UA, ASN, edge PoP, cache status |
| Forward proxy (Zscaler, Squid, Blue Coat) | UA (outbound, useful for T1105/T1552.005 from inside) |
| Entra ID Sign-in logs | `userAgent` field on sign-in event, `deviceDetail` |
| Okta System Log | `client.userAgent.rawUserAgent` |
| Sysmon Event ID 1 (Process Creation) | command line of `curl.exe`, `powershell.exe -UseBasicParsing`, `wget` where the process is later correlated to outbound web hits |

> Note: Windows Security Event IDs (4624/4625) do **not** carry the UA field natively — UA is a web/application-layer artifact, not part of the Windows logon event schema. Don't waste time searching Security logs for it directly; correlate by timestamp/source IP against the web log instead.

## Key Fields to Inspect

**[ANALYST]**
- `User-Agent` (full raw string, not truncated — truncation hides the payload half the time)
- Source IP, ASN, geolocation, and whether the IP is a known cloud/hosting range (AWS, Hetzner, DigitalOcean, Alibaba) vs residential/corporate
- TLS `JA3`/`JA3S` fingerprint vs claimed browser/OS in UA
- `Sec-CH-UA`, `Sec-CH-UA-Platform` client hints (modern Chromium browsers send these; scripted clients usually don't, or send inconsistent values)
- HTTP method, requested URI/path, query string content
- Response status code and response size
- `Referer` and `Accept-Language` presence/consistency
- Request cadence per source IP/session (single hit vs. sequential enumeration)
- Cookie/session token present and whether it later authenticates successfully

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36` matching a Chromium JA3 fingerprint | `python-requests/2.31.0`, `curl/7.68.0`, `Go-http-client/1.1`, `libwww-perl/6.67` hitting login or admin paths from an unrecognized ASN |
| Verified `Googlebot/2.1` with matching reverse DNS on `googlebot.com` | UA claims `Googlebot` but source IP doesn't resolve/reverse-resolve to Google's published ranges (spoofed crawler) |
| Known internal scanner (Qualys, Nessus, Tenable.io) hitting during its documented maintenance window from its documented egress IP | Same scanner signature (`Mozilla/5.0 (compatible; Nessus)` or Nikto default string) from an IP with no scan record |
| Empty UA from a known health-check load balancer probe on `/healthz` | Empty or single-character UA hitting `/wp-login.php`, `/.env`, `/actuator/env`, or the cloud metadata path |
| Stable UA across a session's requests | UA that rotates per request from the same session cookie/IP (automation trying to evade UA-based blocklists) |
| Plain browser UA string | UA string containing `${jndi:ldap://...}`, `' OR 1=1--`, `../../../etc/passwd`, or shell metacharacters — the header itself is the attack payload |

## Investigation Steps

1. Pull the full raw log line(s), not the SIEM's summarized alert — you need every header, not just the UA field, to judge intent.
2. Baseline the source IP: ASN, known hosting/VPN/Tor exit-node status, and whether it appears on the approved internal-scanner or synthetic-monitoring allow-list.
3. Compare the UA against the TLS JA3/JA3S fingerprint and any `Sec-CH-UA` client hints in the same request — a mismatch (claims Chrome, fingerprints as curl/OpenSSL) is a strong evasion signal.
4. Check request cadence and target breadth: one-off curiosity hit vs. sequential path enumeration or parameter fuzzing across many URIs in a short window.
5. Inspect the UA string character-by-character for embedded payloads (SQLi, JNDI, path traversal, command injection) — copy it out of the log viewer into a plain text editor first so nothing gets HTML-decoded or hidden.
6. Check the response: status code, response size, and whether the app returned anything sensitive (200 with a body) versus a WAF block/challenge/403/404.
7. If the request carried a session cookie or credentials, pivot to Entra ID/Okta sign-in logs for the same identity around that timestamp — look for impossible travel or an anomalous UA succeeding where the legitimate user's normal browser UA usually appears.
8. Cross-check the source IP/timeframe against any scheduled internal vulnerability-scan or pentest window before treating this as external hostile activity — this single check kills a large share of false escalations.

## True Positive Indicators

- Known malicious scanner/exploit-tool UA signature hitting a sensitive path from an unrecognized external IP with no scan record.
- UA string contains a matched exploit payload (WAF/IDS signature hit) and the backend returned a 200 rather than a block.
- UA associated with known offensive frameworks (default Cobalt Strike or Metasploit HTTP client strings) beaconing on a regular interval.
- UA rotates per request from the same session/cookie — active evasion, not organic browser behavior.
- Scanning-grade UA later followed by a successful authentication from the same IP.

## False Positive / Benign Positive Indicators

- Confirmed internal vulnerability scanner (Qualys, Nessus, Tenable) inside its documented schedule and egress range — Benign Positive, add to allow-list if not already there.
- Legitimate uptime/synthetic monitoring (Pingdom, UptimeRobot, Datadog Synthetics) with a generic UA hitting a health-check endpoint only.
- Verified search-engine crawler confirmed via reverse DNS against the vendor's published ranges.
- Internal integration or QA/load-testing tool (JMeter, Locust, a homegrown script) using a default library UA — expected activity, but flag to the owning team to set a descriptive UA so it stops generating noise.
- Log retention or ingestion delay means the UA field is missing/blank on an otherwise ordinary request — Insufficient Evidence, not automatically suspicious.

## Escalation Criteria

Escalate to Tier 2 / IR if: an exploit payload embedded in the UA header returned a 200 on a sensitive endpoint; the UA maps to a known C2 framework signature; a scanning-grade UA transitions into a successful login or file upload; or scanning traffic with a hostile-tool UA originates from an **internal** IP not on the approved scanner list (possible internal compromise or unauthorized/rogue pentest activity).

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Push a WAF rule blocking the specific UA signature/regex — pre-approved for Web/App Security Engineering when the UA maps to a known-bad scanner or exploit tool, no change ticket required (documented in the standing WAF runbook).
- Rate-limit or geo/ASN-block the source at the CDN/WAF edge — requires Web Ops sign-off if it risks customer-facing false blocks during business hours.
- Temporarily take an exposed endpoint offline — requires Change Management + application owner approval given the availability impact; reserved for confirmed/suspected RCE.
- Force session/token revocation for any identity whose session was touched by the suspicious UA — Identity/IAM team executes, Security Operations Manager approves outside business-hours change windows.
- SLA: Tier 1 triage within 30 minutes for High severity (payload confirmed), 4 hours for Medium; weekly review of the scanner allow-list owned by Detection Engineering.

## Example Query (Splunk SPL)

```spl
index=web sourcetype=access_combined
| eval ua=lower(useragent)
| where match(ua, "curl|python-requests|nikto|sqlmap|go-http-client|masscan|nuclei")
   OR len(useragent)=0
   OR match(useragent, "jndi:|union select|\.\./\.\./")
| stats count min(_time) as first max(_time) as last values(cs_uri_stem) as paths by src_ip, useragent
| where count > 3 OR match(useragent, "jndi:|union select")
```

## Closure Criteria

Close as **Benign Positive** when the UA maps to a documented internal scanner/monitoring tool within its approved window (add IP/UA to allow-list). Close as **Insufficient Evidence** when the UA field is missing due to a logging gap and no other corroborating signal exists. Close as **True Positive** when a hostile scanner/exploit UA was blocked with no successful response and no downstream authentication. Escalate and keep open as an active incident when exploitation succeeded.

**Example case-note line:** *"UA `Mozilla/5.0 (compatible; Nessus)` from 203.0.113.44 hit /actuator/env three times over 90s, WAF returned 403 each time, IP not on scanner allow-list and no scan ticket on file — treating as external recon, blocked at edge, no auth success observed. Closing as True Positive — blocked, no downstream compromise; recommending ASN 203.0.113.0/24 added to watchlist."*
