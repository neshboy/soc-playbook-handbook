# Playbook: SQL Injection

## Playbook ID & Name

**WEB-001 — SQL Injection Detection and Response**

Category: Web Security. Applies to internet-facing and internal web applications backed by a relational database (MSSQL, MySQL/MariaDB, PostgreSQL, Oracle) where user-supplied input reaches a query string — form fields, URL parameters, HTTP headers (User-Agent, X-Forwarded-For, Referer), JSON/XML bodies, or REST path segments.

## Business Risk

**[STAKEHOLDER]** - A successful SQL injection can expose the entire contents of a database in one request — customer records, payment data, credentials, session tokens — and in the worst case allows an attacker to run operating-system commands on the database server itself. It's one of the few web attack classes that can go from "someone found a bug" to "we have a breach notification obligation" inside a single afternoon. Fixing the underlying code is a developer decision; blocking traffic at the WAF is an on-call SOC decision and should not wait for a change window.

## Severity / Priority Default

**High** at trigger (any confirmed injection attempt against a production app with an auth or payment surface). Escalates to **Critical** on any evidence of successful data extraction, `xp_cmdshell`/`sp_configure` abuse, or out-of-band exfiltration. Downgrade to **Medium** only after analyst confirms the request was blocked pre-execution by WAF/parameterization with no downstream anomaly.

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Automated fuzzing/scanner traffic probing parameters before a targeted attempt |
| T1190 | Exploit Public-Facing Application | The injection itself — primary technique for this playbook |
| T1059.001 / T1059.003 | Command and Scripting Interpreter (PowerShell / Windows Command Shell) | Follow-on OS command execution via `xp_cmdshell`, `EXEC`, or stacked queries on MSSQL |
| T1552.001 | Unsecured Credentials: Credentials In Files | Injected query pulls connection strings, config files, or `web.config` contents via `LOAD_FILE`/`OPENROWSET` |
| T1071.004 | Application Layer Protocol: DNS | Out-of-band/blind SQLi using DNS lookups to exfiltrate data (`xp_dirtree`, `UTL_HTTP`, `dns_lookup`) |
| T1048 | Exfiltration Over Alternative Protocol | Data pushed out via DNS or non-web protocol when direct response-body extraction is blocked |

## Trigger / Detection Logic Summary

Alert fires when WAF, reverse proxy, or application-layer logging flags a request containing SQL metacharacter patterns (`' OR 1=1`, `UNION SELECT`, `; DROP`, `SLEEP(`, `WAITFOR DELAY`, encoded variants) **and** either (a) the request was not blocked, or (b) the same source repeats pattern variations against the same parameter within a 15-minute rolling window (classic time-based/blind SQLi fuzzing) — widen to a 24-hour window before ruling out repetition if the source is behind a rotating proxy pool. Correlate with abnormal database response size, response-time variance (boolean/time-based blind SQLi signature), or unexpected outbound DNS/HTTP from the DB tier.

## Required Log Sources & Event IDs

No Windows or Sysmon event IDs apply directly to this playbook's primary detection surface — SQLi is observed in web/WAF/DB telemetry, not the Windows event log, unless a follow-on OS command executes on the host. If it does, pull Sysmon Event ID 1 (Process Create) or Windows Security Event ID 4688 (Process Creation, if Audit Process Creation is enabled) from the DB or app host and correlate by timestamp and parent process.

| Source | What to pull |
|---|---|
| WAF (Azure WAF / AWS WAF / ModSecurity / Cloudflare) | Rule match logs, action (block/log/count), matched pattern, transaction ID |
| Web server access log (IIS W3C / Apache / Nginx) | Full request URI, query string, method, status code, bytes sent, User-Agent, referer |
| Application log | Framework-level exception traces (SQL syntax errors leaking to app log are a strong signal) |
| Database audit log | Query text, executing account, source host, rows returned, error codes (native SQL Server Audit, MySQL general/audit log, PostgreSQL `log_statement`) |
| Reverse proxy / CDN log | Upstream vs. edge request correlation, geo/ASN of source IP |
| DNS logs (recursive resolver) | High-entropy or high-frequency subdomains to attacker-controlled domain — out-of-band SQLi signature |

## Key Fields to Inspect

**[ANALYST]**
- **cs-uri-query / request.body** — raw payload; decode URL/hex/Unicode encoding before dismissing as benign
- **sc-status** — 500s clustered around one parameter strongly suggest the app is choking on injected syntax
- **time-taken / response latency** — spikes correlating with `SLEEP()`/`WAITFOR DELAY` payloads are the fingerprint of time-based blind SQLi
- **c-ip / X-Forwarded-For** — check for NAT/proxy pooling before attributing many requests to one "attacker"
- **cs(User-Agent)** — scanner tooling (sqlmap, Havij, jSQL) often leaves a distinctive or blank UA; don't rely on this alone, it's trivially spoofed
- **DB audit: executing account** — is this the app's low-privilege service account or something with `sysadmin`/`db_owner`? A service account suddenly running `sp_configure` or `xp_cmdshell` is a hard escalation trigger
- **rows_returned / bytes_returned** — a login form query normally returns 0 or 1 row; a UNION-based injection often returns many, or an unusually wide column set

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Parameter contains expected data type/length (numeric ID, short alphanumeric) | Parameter contains quotes, `--`, `/*`, `UNION`, `OR 1=1`, hex-encoded strings |
| DB query response time consistent (±50ms) across requests | Response time scales with an injected delay value across successive requests |
| App-layer errors are rare and varied | Repeated identical SQL syntax error against the same parameter from the same source |
| Service account only ever runs the queries the app was built to run | Service account executes ad hoc `SELECT`, `xp_cmdshell`, or schema enumeration (`information_schema`) |
| DNS from DB tier limited to patching/update endpoints | DB host resolving attacker-controlled domains with encoded subdomain labels |

## Investigation Steps

**Default lookback:** pull the preceding 24 hours for the source IP/ASN and the affected parameter across the steps below. If step 8 shows a sustained multi-endpoint campaign, extend to 7 days to establish true first-seen and confirm whether this is a new actor or a recurring one.

1. Pull the full raw request (headers + body) for the triggering event from WAF or proxy logs — confirm the actual payload, not just the truncated alert summary.
2. Decode any URL/Base64/hex/Unicode encoding in the parameter value to see the real injected string.
3. Check WAF disposition: was it blocked, logged-only, or did it pass through to the origin? This determines urgency immediately.
4. Pivot to the web server/application log for the same transaction ID or timestamp+source IP to see the HTTP status code and response size returned to the client.
5. Pull database audit log entries for the affected account/session around the same timestamp — confirm whether the malformed query actually executed against the DB engine or was rejected by the app/ORM layer (parameterized queries usually neutralize this at the driver level).
6. If query execution is confirmed, determine what was returned — row count, column names, any evidence of `UNION SELECT` against sensitive tables (`users`, `payments`, `sessions`).
7. Check for follow-on indicators: new outbound DNS to unfamiliar domains, `xp_cmdshell`/`sp_configure` calls, new local accounts on the DB host, or unexpected process creation on the database server.
8. Determine attacker scope: single parameter probed once (likely scanner noise) vs. multi-parameter, multi-endpoint campaign from the same source/ASN (targeted).

## True Positive Indicators

- Injected SQL syntax confirmed present in the raw request and echoed/executed in DB audit log
- Application returned data inconsistent with the expected query shape (extra columns, unexpected row counts)
- Time-based response delay directly correlates with injected `SLEEP`/`WAITFOR` values across a sequence of requests
- Evidence of schema enumeration (`information_schema.tables`, `sys.tables`) or privilege escalation attempts (`xp_cmdshell`, `sp_addsrvrolemember`)
- Outbound DNS/HTTP to attacker infrastructure immediately following query execution (exfiltration channel)

## False Positive / Benign Positive Indicators

- WAF rule matched a legitimate value containing SQL-like syntax (e.g., a user typing `O'Brien` or a search query containing the literal word "select")
- Security scanner or pentest engagement running against the app with prior authorization — check the change/pentest calendar before escalating
- Parameterized query/ORM confirmed the input was bound as data, not concatenated into SQL — request reached the DB layer safely despite tripping the pattern match
- Duplicate WAF alerts from a single request replayed by a load balancer health check or retry logic — correlate transaction IDs before counting as multiple attempts

## Escalation Criteria

Escalate to Incident Response immediately if: the payload executed (not just logged) against a production database; any evidence of data exfiltration (unusual outbound volume, DNS exfil pattern, large response bodies to attacker IP); privileged DB commands were run; or the affected table includes regulated data (PII, cardholder data, health records) — this typically triggers your breach-notification clock, so document the confirmed-execution timestamp precisely.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| WAF rule tune/block for specific pattern or source IP | SOC Tier 2 (standing authority) | Fastest, lowest blast radius |
| Block source IP/ASN at edge/CDN | SOC Tier 2, notify app owner | Watch for shared-NAT/CDN false-positive risk |
| Disable affected endpoint or feature flag | App owner + on-call engineering lead | Business-impact call, not purely SOC |
| Rotate DB service account credentials | DBA team + IR lead sign-off | Required if account confirmed misused |
| Isolate database host from network | IR lead + infrastructure owner (Sev-1 bridge) | Reserved for confirmed active exploitation with exfil in progress |
| Force full application redeploy with parameterized queries | Engineering management, tracked as a JIRA/change ticket, not a same-shift SOC action | Root-cause fix, always follows containment, never replaces it |

## Example Query (Splunk SPL)

```spl
index=waf OR index=web_access earliest=-24h latest=now
| eval decoded_uri=urldecode(cs_uri_query)
| regex decoded_uri="(?i)(union\s+select|or\s+1=1|sleep\(|waitfor\s+delay|information_schema|xp_cmdshell|--\s|/\*)"
| stats count, values(cs_uri_query) as payloads, values(sc_status) as statuses,
        earliest(_time) as first_seen, latest(_time) as last_seen by src_ip, cs_uri_stem
| where count > 3
| sort - count
```

## Closure Criteria

Close as **True Positive** once the malicious payload's execution path is confirmed blocked (WAF rule, code fix, or credential rotation deployed), no evidence of successful data extraction exists in DB audit logs, and the app owner has acknowledged the finding. Close as **Benign Positive** when the pattern match is confirmed to be legitimate user input safely parameterized. Close as **Insufficient Evidence** when DB audit logging wasn't enabled for the relevant window and execution status can't be confirmed either way — flag this as a logging-gap finding for Engineering, don't just let it lapse silently.

**Example case note:**
`2026-09-15 14:22 UTC — WAF alert on src 203.0.113.44 against /account/search?name= parameter, payload decoded to "' UNION SELECT username,password FROM users--". WAF action=block confirmed, request never reached origin. DB audit log shows no corresponding query from app service account in the 5-min window. No outbound anomalies from DB host. Closing as Benign Positive — blocked at edge, no execution; recommending WAF rule set stay in blocking mode for this endpoint, no code change required at this time.`
