# RFI — Remote File Inclusion Exploitation

## Playbook ID & Name
`WEB-006` — Remote File Inclusion (RFI) Exploitation Attempt / Success

## Business Risk
**[STAKEHOLDER]** - An RFI flaw lets an attacker force one of our own web applications to fetch and run code from a server they control, which usually means a webshell on our infrastructure inside minutes, not a slow burn — this is a full compromise path, not a "low severity input validation issue," and it decides whether the next call is a patch ticket or an incident bridge.

## Severity / Priority Default
| Condition | Priority |
|---|---|
| Payload blocked by WAF/edge control, no origin response | Medium (P3) |
| Payload reached origin, ambiguous/error response (404/500) | High (P2) |
| Origin returned 200 with attacker content, or outbound connection confirmed from server | Critical (P1) |

Default queue priority on open: **High**. RFI has a short window between "attempt" and "webshell on disk" compared to most web findings, so this one doesn't sit in queue overnight waiting for triage.

## MITRE ATT&CK Techniques
- **T1190** — Exploit Public-Facing Application (primary technique — the inclusion vulnerability itself is the entry vector)
- **T1105** — Ingress Tool Transfer (the "remote" part of RFI — attacker-hosted stager/webshell being pulled in)
- **T1059.001 / T1059.003** — Command and Scripting Interpreter (PowerShell / Windows Command Shell — post-inclusion execution if the included code shells out)
- **T1027** — Obfuscated Files or Information (base64/encoded wrapper payloads, double URL-encoding, null-byte tricks)
- **T1071.004** — Application Layer Protocol: DNS (out-of-band inclusion confirmation or beacon via attacker-controlled DNS)
- **T1595** — Active Scanning (precursor fuzzing that usually shows up in the days/hours before a working RFI payload lands)

## Trigger / Detection Logic Summary
Alert fires when an HTTP request parameter that a vulnerable script hands to a file-inclusion function contains a full URI scheme (`http://`, `https://`, `ftp://`) or a language-specific stream wrapper (`php://input`, `php://filter`, `data://text/plain;base64,`, `expect://`) instead of the plain filename or numeric ID the parameter normally holds. Detection sits at three layers: WAF/edge signature match on the request, web-server error log entries showing a failed or successful `fopen`/`include`/`require` against an external host, and — where host telemetry exists — the web server worker process spawning a shell or writing new files under the web root shortly after the request.

## Required Log Sources
This scenario lives almost entirely at the HTTP layer, so the WAF/access/error logs below are the primary evidence — but if host telemetry exists for the follow-on execution, it has a real ID: Sysmon Event ID 1 (Process Create) or Windows Security Event ID 4688 (Process Creation, if Audit Process Creation is enabled). Pull:

- WAF / reverse-proxy logs (ModSecurity, Azure WAF, AWS WAF, Cloudflare, F5 ASM) — request line, matched rule, action taken
- Web server access logs (Apache, Nginx, IIS) — full request URI including query string, response code, response size
- Web server error logs — the actual `fopen()`/`include()` failure or warning line, which often names the attacker's URL verbatim
- Outbound proxy / firewall / NetFlow logs from the web server's subnet — confirms whether the box actually reached out to attacker infrastructure
- DNS logs — lookups to attacker-registered domains, useful when the payload uses a domain instead of a raw IP
- Host EDR / Sysmon telemetry — Sysmon Event ID 1 / Windows Event ID 4688 for process creation from the web worker (`w3wp.exe`, `php-cgi.exe`, `httpd`, nginx worker), and Sysmon Event ID 3 (Network Connect) for any new outbound connection initiated by that worker process

## Key Fields to Inspect
**[ANALYST]**
- `request_uri` / query string parameter name and value (e.g., `?page=`, `?file=`, `?template=`, `?module=`, `?lang=`)
- Scheme prefix or wrapper string inside the parameter value
- `http_method`, `status_code`, `bytes_out` (a large `bytes_out` on a normally tiny "page not found" response is a tell)
- `user_agent` — scanner signatures, curl/python-requests defaults, or a legitimate browser UA reused across hundreds of requests (spoofed to blend in)
- `src_ip`, ASN, geolocation, and whether that IP has prior recon hits (T1595) against this same app in the preceding 24–72 hours
- Referrer header (usually empty/absent on automated fuzzing, present on manual browser-driven testing)
- Web server error log line text — this frequently contains the attacker's full staging URL, which is your fastest pivot
- Outbound connection destination and port from the web server host, and any files written to the web root with an unexpected timestamp

## Normal vs Suspicious Pattern
**Normal:** the parameter takes a short relative filename or a small integer/enum matching an internal allow-list — `?page=contact`, `?template=2` — and the app's logic maps that value to a fixed set of local files server-side.

**Suspicious:** the parameter value is, or contains, a fully qualified URL or stream wrapper; the same source IP is trying the parameter with dozens of variant encodings in a short burst (classic fuzzing behavior); the request includes path traversal (`../../../`) combined with a wrapper; or the web server error log references a hostname that isn't ours.

## Investigation Steps
1. Pull the raw request from WAF and origin access logs — confirm the exact parameter, payload, and whether the WAF blocked it or passed it through to the origin.
2. Check the corresponding origin response code and size. A 200 with unexpected size/content on a script that should have returned a template page is the strongest single signal.
3. Grep the web server error log around that timestamp for `fopen`/`include`/`require`/`allow_url_include` warnings — these often name the attacker's staging domain outright.
4. Confirm whether the language runtime is actually exploitable in this config (for PHP specifically: is `allow_url_fopen`/`allow_url_include` enabled on this host?). Check the CMDB/config baseline rather than guessing.
5. Pivot on `src_ip` — reputation lookup, ASN, and search the prior 72 hours of WAF/access logs for scanning activity from the same source (T1595) that likely preceded the working payload.
6. Check outbound connection and DNS logs from the web server host for traffic to the domain/IP referenced in the payload (T1105) — this tells you attempt vs. successful fetch.
7. If host telemetry exists, check for a process spawned by the web worker running a shell interpreter (T1059.001/.003), and scan the web root for newly created or recently modified files (webshell drop).
8. Determine blast radius — if this app runs behind a load balancer across multiple nodes sharing the same vulnerable code path, every node is presumptively exposed until proven otherwise.

## True Positive Indicators
- Parameter value confirmed as a full external URL or language stream wrapper, and origin returned 200 with attacker-supplied content
- Web server outbound connection or DNS lookup to the exact host named in the payload, timed to the request
- New file dropped in or below the web root immediately following the request
- Error log explicitly shows a failed/successful stream open against a non-owned domain

## False Positive / Benign Positive Indicators
- Authorized pentest or vulnerability scan traffic (check the change calendar / scan schedule before escalating)
- App genuinely stores full URLs as a legitimate field (e.g., a CMS "external thumbnail URL" feature) and the WAF pattern-matched on shape alone with no actual inclusion vulnerability behind it — analyst needs to validate the sink actually performs a file-inclusion call before assuming intent
- Payload rejected by WAF, no origin log entry at all, no outbound connection — close as Benign Positive, not True Positive, once the WAF-block disposition is confirmed for that transaction ID

## Escalation Criteria
Escalate immediately to IR Lead / Tier 3 when: origin returned 200 with attacker-controlled content, an outbound connection to attacker infrastructure is confirmed, a webshell file is found on disk, or the affected system touches customer data, payment processing, or sits in a production trust zone. Don't sit on a confirmed 200 waiting for a "second opinion" — the window between inclusion and webshell persistence is short.

## Containment Options & Approval Authority
**[MANAGEMENT]**
| Action | Approval |
|---|---|
| Block source IP/ASN at WAF or edge | Tier 1/2 analyst, standing authority |
| Virtual-patch the vulnerable parameter/endpoint at WAF | App owner + SecEng sign-off |
| Disable `allow_url_include`/equivalent runtime setting | Change record, App owner approval |
| Isolate host from network (confirmed webshell) | IR Lead approval |
| Full incident declaration, customer notification review | Incident Commander / CISO |

## Example Query (Splunk SPL)
```spl
index=web sourcetype=access_combined
| rex field=_raw "(?<param_val>(?:https?|ftp|php|data|expect)://\S+)"
| where isnotnull(param_val)
| stats count min(_time) as first_seen max(_time) as last_seen
    values(uri_path) as endpoints values(status) as codes
    by src_ip param_val
| where count > 0
| sort -count
```

## Closure Criteria
Close as **True Positive** once the vulnerable endpoint is virtual-patched or the code fix is deployed, outbound C2 traffic (if any) has stopped, and any dropped files are removed and hashed for the case record. Close as **Benign Positive** when the pattern match is confirmed to hit a non-vulnerable sink. Close as **Insufficient Evidence** when logs don't retain far back enough to confirm origin response or outbound behavior — don't force a verdict the telemetry can't support.

**Example case note:** *"WAF alert on `?template=` param containing `http://198.51.100.44/shell.txt` against app03.example.com. Origin access log shows 404 (script does not call remote fetch — local include only), no corresponding error log entry, no outbound connection from app03 in the 15-minute window. Closed as Benign Positive — attempt only, WAF blocked at edge before reaching origin; recommend endpoint still be added to virtual-patch allow-list given repeat fuzzing from same /24 over past week."*
