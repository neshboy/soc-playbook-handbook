# LFI - Local File Inclusion

## Playbook ID & Name

**WEB-005** - Local File Inclusion (LFI) Exploitation Attempt

Companion to `04-path-traversal.md` (the underlying primitive) and `06-rfi.md` (the remote-fetch variant). This playbook covers cases where the vulnerable application pulls in and executes/renders a **file already present on the local filesystem** - via a manipulated file path, include/require call, or file-wrapper - as opposed to fetching attacker-hosted content over the network.

## Business Risk

**[STAKEHOLDER]** - A successful LFI can expose application source code, configuration secrets (database credentials, API keys, session signing keys) and, in the worst case, be chained into full remote code execution on the web server - turning a "just reading a file" bug into a server takeover. It matters because the blast radius isn't limited to one user's data; it's the app's own crown jewels.

## Severity/Priority Default

**High** for confirmed file disclosure of sensitive content (credentials, source code, `/etc/passwd`, SSH keys). **Critical** if there is any evidence of the read primitive being chained into code execution (log poisoning, wrapper-based execution, session-file inclusion). **Medium** for a single blocked/failed attempt with no successful response.

## MITRE ATT&CK Techniques

- **T1190** - Exploit Public-Facing Application (primary technique; LFI is a sub-class of this)
- **T1552.001** - Unsecured Credentials: Credentials In Files (the typical objective - config files, `.env`, `wp-config.php`, `web.config`, private keys)
- **T1059.001 / T1059.003** - Command and Scripting Interpreter: PowerShell / Windows Command Shell (when LFI is chained into execution via wrapper abuse or poisoned log/session files)
- **T1027** - Obfuscated Files or Information (encoded/double-encoded traversal sequences and wrapper payloads used to bypass filters)

## Trigger / Detection Logic Summary

Alert fires on HTTP requests where a parameter value that is normally a filename, template name, language code, or page identifier instead contains directory-traversal sequences, absolute paths, null bytes, or PHP/Java stream-wrapper prefixes, targeting a request that results in a 200 response with a body inconsistent with the expected page (source code fragments, `root:x:0:0`, INI-file syntax, base64 blobs, or a 500 error revealing a stack trace with local paths).

## Required Log Sources & Event IDs

There are no standardized numeric "Event IDs" for this category - detection relies on HTTP-layer fields, not Windows/Sysmon IDs. Sources:

- **WAF logs** (ModSecurity, AWS WAF, Cloudflare, Azure App Gateway) - rule hits for LFI/path-traversal signature categories (vendor-specific rule IDs, e.g., ModSecurity CRM `93xxx` file-inclusion group - check your own ruleset mapping, don't assume the number above is universal)
- **Web/app server access & error logs** (Apache, Nginx, IIS W3C, PHP-FPM/application error log)
- **Application-layer audit log**, if the app logs which template/file it actually resolved and loaded
- **Host EDR/process-creation telemetry on the web server** - relevant only if execution is suspected; look for the web server or PHP-FPM worker process spawning a shell or interpreter, evidenced by parent-child process lineage and command-line content (no specific numeric ID cited here since none is confirmed for this environment)

## Key Fields to Inspect

**[ANALYST]**

| Field | Why it matters |
|---|---|
| Request URI / query string (decoded) | Look for `../`, `..%2f`, `%00`, `....//`, absolute paths (`/etc/passwd`, `C:\Windows\win.ini`) |
| Parameter name | `page=`, `template=`, `file=`, `lang=`, `module=`, `include=` are classic LFI-prone params |
| Stream-wrapper prefixes | `php://filter/convert.base64-encode/resource=`, `php://input`, `php://filter/read=`, `data://text/plain;base64,`, `zip://`, `phar://`, `expect://` |
| HTTP response status + body size | 200 with abnormal body size/content for that endpoint; 500 with a leaked stack trace containing local file paths |
| Response body content (if captured) | `root:`, `[boot loader]`, `-----BEGIN`, PHP tags in an otherwise HTML response, base64 that decodes to source code |
| User-Agent / Referer header | Log-poisoning attempts inject PHP/code payloads into these headers so a later LFI request includes the access log |
| Session cookie / session file references | Session-poisoning chains write attacker content into a session file, then include it via a path-traversal parameter |
| Source IP, X-Forwarded-For | Attribution - remember the origin log usually shows your LB/CDN, not the real client, unless XFF is trusted and logged |
| Timing between requests | Fuzzing tools submit dozens of traversal-depth/encoding variants in seconds - burst pattern is itself a signal |

## Normal vs Suspicious Pattern

**Normal:** `file` or `page` parameters carrying an application-controlled value from a fixed allowlist (`?page=about`, `?lang=en`), or no user-controllable file parameter at all. Static asset requests for genuinely existing files.

**Suspicious:** Same parameter carrying `../../../etc/passwd`, `..\..\..\windows\win.ini`, encoded variants (`%2e%2e%2f`, `%252e%252e%252f`), null-byte terminators, or a wrapper prefix that has no legitimate reason to appear in that parameter. Also suspicious: the parameter value pointing at the app's *own* log file, session storage path, or upload directory - a strong signal of a poisoning-then-include chain rather than simple disclosure.

## Investigation Steps

1. Pull the full raw request (URI, headers, body) and URL-decode it fully - decode iteratively, some payloads are double- or triple-encoded specifically to survive a naive single-decode filter.
2. Identify the target parameter and compare against the application's documented valid values for that endpoint (source code review or developer confirmation if unclear).
3. Check the HTTP response code and body. If body was captured by the WAF/proxy, inspect for `/etc/passwd`-style content, INI syntax, PHP source, base64 blobs, or leaked stack traces with local file paths.
4. Search web/app logs across the preceding and following 15-30 minutes from the same source IP/session for a reconnaissance pattern - sequential traversal-depth increments, parameter fuzzing, or automated scanner user-agents (sqlmap, dotdotpwn, custom fuzzers).
5. If a stream wrapper or log-poisoning indicator is present, pivot to host EDR on the web server: has the web server/PHP-FPM process spawned an unexpected child process, written a new file to the webroot, or made an outbound connection shortly after the suspect request?
6. Cross-check the source IP/ASN against known scanner ranges, your own vulnerability-scanning schedule, and threat intel feeds for LFI-associated infrastructure.
7. If file content disclosure is confirmed, determine exactly what was exposed (grep for credential patterns, key headers, connection strings) and scope which systems those credentials touch - this drives whether it becomes a credential-rotation event, not just a web alert.
8. Document the full request chain (recon → traversal test → wrapper/poisoning attempt → confirmed read) in the case timeline, noting encoding used at each stage.

## True Positive Indicators

- Response body confirmed to contain contents of a known sensitive local file (`/etc/passwd`, `.env`, `web.config`, private key material, application source with embedded secrets)
- Successful retrieval via a stream wrapper designed to bypass filtering (`php://filter/convert.base64-encode`) followed by a decodable payload in the response
- Evidence of log or session-file poisoning followed by a request that includes that same file, correlating with new process execution on the host
- Escalating traversal-depth/encoding attempts from the same source that eventually return a 200 with anomalous content, after a series of 403/404s

## False Positive / Benign Positive Indicators

- Authorized penetration test or vulnerability scan against the same endpoint, matching the scheduled testing window
- WAF blocked the request outright (403/406) with no evidence of a subsequent successful bypass
- Legitimate file parameter value that merely contains characters resembling traversal (e.g., a filename with literal dots) but resolves within the intended directory and returns expected content
- Static analysis/crawler bot (documented, allowlisted) probing common file paths as part of routine content discovery, not actual exploitation
- Response captured as 200 but body is a generic error page rather than actual file content - the traversal attempt failed even though the status code looks "successful"

## Escalation Criteria

Escalate immediately to Incident Response if: sensitive credential material is confirmed disclosed, there's any host-level evidence of code execution following the LFI request, or the exposed file grants access to systems beyond the web tier (database creds, cloud provider keys, internal API tokens). Escalate to the application owner regardless of exploit success if a previously unknown LFI-capable parameter is discovered - it needs a code fix, not just a blocked IP.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| WAF virtual patch (block/rewrite rule on the vulnerable parameter) | SOC Lead / Web App Security Engineer | Fastest containment, buys time for code fix |
| Block source IP/ASN at edge or CDN | Tier 2 analyst, standing authority | Low-risk, temporary; expect IP churn from cloud-hosted scanners |
| Rotate exposed credentials (DB, API keys, signing keys) | System/App Owner, expedited via IR | Mandatory once disclosure is confirmed, regardless of exploitation depth |
| Take affected endpoint offline / feature-flag disable | Application Owner + IR Lead | Only for active exploitation with confirmed execution risk |
| Emergency code deploy (sanitize file parameter, allowlist) | Engineering Lead, expedited change process | The actual fix; containment above is a bridge to this |

## Example Query (Splunk SPL)

```spl
index=web_proxy sourcetype=access_combined
| rex field=uri_query "(?i)(?<traversal>(\.\.%2f|\.\.\/|%2e%2e|php:\/\/|data:\/\/|zip:\/\/|phar:\/\/|\x00))"
| where isnotnull(traversal)
| stats count min(_time) as first max(_time) as last values(uri_path) as paths
        by src_ip, http_user_agent
| where count > 3
```

## Closure Criteria

Close as **True Positive** once the vulnerable parameter is patched or virtually patched, exposed credentials (if any) are rotated, and host telemetry confirms no follow-on execution. Close as **Benign Positive** when the traffic matches an authorized scan/pentest window. Close as **Insufficient Evidence** when WAF blocked the payload pre-response and no downstream log confirms any successful read - don't assume malicious intent from a single blocked probe with no corroborating pattern.

**Example case-note line:** *"2026-09-15 14:22 UTC - `?template=` param on portal.example.com confirmed vulnerable to LFI; response returned base64 of app config via php://filter wrapper, decoded to reveal DB connection string for db01.internal.example.com. WAF virtual patch applied 14:41 UTC, DB credential rotation requested from App Owner (ticket APP-4471), no evidence of follow-on process execution on web01. Closed True Positive (contained)."*
