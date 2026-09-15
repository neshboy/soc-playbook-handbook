# Playbook: Path Traversal

## Playbook ID & Name

**WEB-004 — Path Traversal (Directory Traversal) Detection and Response**

Category: Web Security. Applies to any component that takes user-supplied input and uses it, directly or after light manipulation, to build a filesystem path — static file handlers, document/report download endpoints, image resizers, template/theme loaders, log viewers, backup/export utilities, and file-upload processing that unzips or renames files server-side.

## Business Risk

**[STAKEHOLDER]** - Path traversal lets an attacker step outside the folder a web application is supposed to be confined to and read (sometimes write) arbitrary files on the server — configuration files with database passwords, SSH private keys, source code, `/etc/passwd`, cloud instance credentials cached on disk. There's rarely a "partial" version of this: either the traversal is blocked and nothing happens, or it works and the attacker can pull whatever file they ask for, one request at a time, with no exploit chain required beyond a URL. It also frequently shows up as the quiet first step before a much louder incident — reading a config file today, using the leaked credential to log in tomorrow.

## Severity / Priority Default

**Medium** at trigger for a single blocked or low-value-target attempt (e.g., probing `../../../../etc/passwd` against a static asset handler that 404s cleanly). Escalates to **High** on confirmed successful read of any file outside the intended directory, and to **Critical** if the file read contains credentials, private keys, connection strings, or source code with hardcoded secrets, or if traversal is combined with file upload/write capability (path traversal on write is effectively arbitrary file write — a very short path to remote code execution on most stacks).

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Automated fuzzers/scanners (dotdotpwn, wfuzz, Burp Intruder, generic vuln scanners) probing every parameter for traversal sequences before a targeted attempt |
| T1190 | Exploit Public-Facing Application | The traversal itself — primary technique for this playbook; the vulnerable parameter is the exploited surface |
| T1552.001 | Unsecured Credentials: Credentials In Files | The typical objective once traversal succeeds — reading `.env`, `web.config`, `wp-config.php`, `id_rsa`, `.git/config`, cloud SDK credential files, etc. |

## Trigger / Detection Logic Summary

Alert fires when a request's URI path or a parameter value (commonly named `file=`, `path=`, `doc=`, `page=`, `template=`, `download=`, `img=`, `dir=`) contains directory-traversal sequences — literal `../` or `..\`, their URL-encoded (`%2e%2e%2f`, `%2e%2e%5c`), double-encoded (`%252e%252e%252f`), Unicode/overlong-UTF8 (`%c0%ae%c0%ae%2f`), or null-byte-terminated (`%00`) variants — **or** the value resolves to an absolute path (`/etc/passwd`, `C:\Windows\win.ini`, `file://`, `php://filter/`) or a UNC path (`\\attacker\share\`). Correlate with the HTTP response: a `200 OK` with a response body/size that doesn't match the requested resource's expected content type (e.g., a request for a `.jpg` returning text that looks like a passwd file or an INI file) is the strongest confirmation signal available directly in web logs, without needing host-side telemetry.

## Required Log Sources & Event IDs

No Windows or Sysmon event IDs apply directly to the traversal itself — that part is visible in web/WAF telemetry first. If the traversal is used to stage a follow-on payload (e.g., a zip-slip write that lands an executable, or a read that yields a credential later used to log in), pull endpoint/EDR process-creation telemetry for the web server host: Sysmon Event ID 1 (Process Create) or Windows Security Event ID 4688 (Process Creation, if Audit Process Creation is enabled), plus Sysmon Event ID 11 (FileCreate) for the file-write side, correlated by timestamp against the traversal request.

| Source | What to pull |
|---|---|
| WAF / CDN (Cloudflare, AWS WAF, Akamai, ModSecurity/OWASP CRS) | Rule match logs, action (block/log/count), matched category (LFI/path-traversal rule group), transaction ID, raw matched payload |
| Web server access log (IIS W3C / Apache / Nginx) | `cs-uri-stem`, `cs-uri-query`, method, status code, `sc-bytes`, `cs(User-Agent)`, `cs(Referer)`, `time-taken` |
| Application log | Framework-level file-not-found or permission-denied exceptions with the resolved (post-concatenation) path — extremely useful when the app logs the *actual* path it tried to open |
| EDR / host telemetry on the web server | Process-creation and file-read/write events by the web worker process, if traversal chains into RCE or file drop |
| Cloud storage access logs (S3 server access logs, Azure Storage logs) | If a proxy/gateway maps traversal-style paths onto object storage keys — traversal against a signed-URL proxy is a common variant |
| File integrity monitoring | Unexpected reads of sensitive files (`/etc/shadow`, `web.config`, `.env`) outside normal admin/backup process activity |

## Key Fields to Inspect

**[ANALYST]**
- **cs-uri-query / parameter value, fully decoded** — decode URL encoding, then decode again for double-encoding, before deciding a value is benign. A single decode pass is the single most common analyst mistake on this playbook.
- **sc-status paired with sc-bytes** — a `200` with a response size matching a known file (e.g., `/etc/passwd` on a typical Linux box is a few hundred bytes to a couple KB, `win.ini` is small and starts with `[fonts]` or `[extensions]`) is near-conclusive; a `403`/`404`/`400` from WAF or app-layer validation means it was blocked
- **Content-Type of the response vs. Content-Type expected for the requested resource extension** — a `.png` request returning `text/plain` is a red flag independent of the payload itself
- **Requested parameter name and its normal value shape** — is this parameter normally a numeric ID or a fixed enum of filenames (`invoice.pdf`, `report.pdf`)? Any deviation into path-shaped input is itself suspicious even before you see `../`
- **Depth and target of the traversal** — `../../etc/passwd` targeting a well-known OS file reads as generic scanner noise; a payload targeting the app's own known directory structure (e.g., `../../../config/database.yml`) suggests the attacker has done recon or has source-code knowledge
- **c-ip / X-Forwarded-With** — check for shared NAT/corporate proxy pooling before attributing volume to a single actor; also check against the vulnerability-scan calendar
- **Application log's resolved/canonicalized path** — if the app logs what path it actually tried to `open()`, this tells you definitively what the traversal resolved to after any `..` normalization, independent of what was in the raw URL

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Parameter value is a filename from a fixed, expected set (`report_q3.pdf`) or a simple numeric/UUID ID | Parameter contains `../`, `..\`, encoded equivalents, null bytes, or an absolute path |
| Response status/size consistent with the requested known-good file | `200 OK` with response body/size inconsistent with the requested file's expected type or size |
| Requests stay within the application's document root the whole session | Requested path, once decoded/normalized, resolves outside the intended base directory |
| A handful of 404s from typos or stale links, spread across normal file names | Repeated 400/403/404 against the *same* parameter with systematically varying traversal depth (`../`, `../../`, `../../../`) — textbook fuzzing |
| File download feature only ever serves files it generated/owns | File download feature asked to serve `web.config`, `.env`, `id_rsa`, or other files it has no legitimate reason to reference |

## Investigation Steps

1. Pull the full raw request for the triggering event from WAF/proxy logs and fully decode the parameter value — check for single, double, and Unicode/overlong-UTF8 encoding before concluding what the actual payload is.
2. Determine WAF/gateway disposition: blocked, logged-only, or passed through to the origin. This alone usually settles urgency for a single-shot event.
3. Pivot to web server access logs for the same transaction ID, timestamp, and source IP; check the returned status code and, critically, the response size and content-type against what the requested resource *should* have returned.
4. If the app has its own logging, check for the canonicalized/resolved path it actually attempted to open — this removes ambiguity about what the traversal string decoded to after `..` normalization.
5. If a `200 OK` with an unexpected body is confirmed, work out exactly what was disclosed — a generic OS file (moderate concern, scanner-shaped) vs. an app config file, credential file, or source file (high concern, targeted).
6. Check whether any credential or secret exposed in the disclosed file has since been used — pivot to authentication logs for that specific credential, service account, or API key across the following days, not just hours; attackers often sit on a leaked credential before using it.
7. Check for write-capable variants (file upload endpoints that accept a traversal-crafted filename, "zip slip" during archive extraction) — a write-capable path traversal is functionally a file-drop primitive and should be escalated regardless of what was actually dropped so far.
8. Assess scope: single parameter, single request (likely scanner noise) vs. multiple endpoints/parameters, increasing depth, or a shift from OS files to app-specific files from the same source — that progression is the signature of a human operator, not an automated scanner.

## True Positive Indicators

- Decoded request contains a traversal sequence or absolute/UNC path, and the response status/size/content-type confirms a file outside the intended directory was actually returned
- Application log shows a resolved path outside the configured document root or base directory
- Disclosed file contains credentials, private keys, connection strings, or source code — followed by any authentication activity using that material
- Traversal depth or target filename escalates across a short session from generic OS files to application-specific config/source paths
- File-upload or archive-extraction feature accepts a crafted filename/path that writes outside the intended upload directory (zip slip pattern)

## False Positive / Benign Positive Indicators

- Scanner or authorized pentest traffic confirmed against the pentest/vuln-scan calendar, with consistent systematic depth-incrementing pattern and no actual disclosure (all blocked or 404)
- A legitimate filename or path segment coincidentally contains a double-dot pattern (rare, but version strings or certain internationalized filenames can trip naive regex matches) — confirm by checking the actual resolved path, not just the raw string match
- WAF blocked the request pre-execution and application logs show no corresponding file-open attempt at all
- Load balancer or CDN health-check/retry replaying the same request multiple times, inflating count without representing multiple distinct attempts — correlate transaction IDs before treating as a burst

## Escalation Criteria

Escalate to Incident Response immediately if: any file outside the intended directory was confirmed disclosed (not just attempted) on a production system; the disclosed content includes credentials, keys, or secrets of any kind; a write-capable traversal (zip slip, upload path manipulation) is confirmed; or the exposed file relates to regulated data or a system in scope for a compliance obligation. Treat "attacker read our `web.config`" with the same urgency as a credential-dumping alert on an endpoint — the next step for the attacker is almost always "use what we just read."

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| WAF rule tune/block for the specific parameter or pattern | SOC Tier 2 (standing authority) | Fastest, lowest blast radius; verify it doesn't break legitimate filename parameters |
| Block source IP/ASN at edge/CDN | SOC Tier 2, notify app owner | Watch for shared-NAT/CDN false-positive risk |
| Disable the affected download/file-handler endpoint | App owner + on-call engineering lead | Business-impact call if the endpoint is customer-facing |
| Rotate any credential or key confirmed exposed in a disclosed file | Credential/DBA/IAM owner + IR lead sign-off | Non-negotiable once exposure is confirmed — treat the file's contents as compromised the moment it left the server |
| Force redeploy with path canonicalization / allow-list validation | Engineering management, tracked as a change ticket | Root-cause fix — validate against a fixed allow-list of filenames/IDs, never just strip `../` |
| Isolate the web server host from the network | IR lead + infrastructure owner (Sev-1 bridge) | Reserved for confirmed write-capable exploitation with evidence of a dropped payload |

## Example Query (Splunk SPL)

```spl
index=waf OR index=web_access
| eval decoded=urldecode(urldecode(cs_uri_query))
| regex decoded="(?i)(\.\.[\\/]|%2e%2e|%c0%ae|/etc/passwd|win\.ini|\.\./config|php://|file://)"
| stats count, values(cs_uri_stem) as endpoints, values(sc_status) as statuses,
        values(sc_bytes) as sizes, earliest(_time) as first_seen, latest(_time) as last_seen
        by src_ip, cs_uri_query
| where count > 1 OR match(statuses, "200")
| sort - count
```

## Closure Criteria

Close as **True Positive** once disclosure is confirmed, any exposed credential is rotated, the vulnerable parameter has allow-list validation or a WAF block deployed, and the app owner has acknowledged the finding — the case note should state that containment is complete. Close as **Benign Positive** when the pattern match traces to authorized scanning/pentest activity with no actual disclosure. Close as **Insufficient Evidence** when the application doesn't log the resolved path and web-server logs alone can't confirm whether the traversal actually escaped the document root — flag the missing resolved-path logging as a gap for Engineering rather than letting the finding lapse.

**Example case note:**
`2026-09-15 16:05 UTC — WAF alert on src 198.51.100.77 against /reports/download?file= parameter, payload decoded to "../../../../etc/passwd". WAF action=block confirmed, sc-status=403, no corresponding file-open attempt in app log. Same source also probed /reports/download?file=..%2f..%2fconfig%2fdatabase.yml (also blocked) three minutes later, consistent with automated fuzzing rather than a targeted operator. No entry for this source on the authorized-scan calendar. Closing as True Positive — blocked pre-execution, no disclosure; recommending file= parameter move to allow-list validation against known report IDs rather than raw filename input.`
