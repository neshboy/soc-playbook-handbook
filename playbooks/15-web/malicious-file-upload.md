# Malicious File Upload

## Playbook ID & Name
`WEB-011` — Malicious File Upload via Web Application Upload Function

## Business Risk
**[STAKEHOLDER]** - Any feature that lets a customer or employee upload a file — a profile photo, an invoice attachment, a support-ticket screenshot — is also a feature that lets an attacker place their own code on our server if the upload isn't validated properly. Once that file lands somewhere the web server will execute it, the attacker doesn't need a second vulnerability; they have a foothold, and from there it's credential theft, lateral movement, or a launch pad into the rest of the environment. This is the "one careless `<input type=file>`" scenario, and it's a recurring finding in bug bounty and pentest reports for a reason.

## Severity / Priority Default
| Condition | Priority |
|---|---|
| Upload blocked by WAF/upload-handler validation, file never written to disk | Low–Medium (P4/P3) |
| File written to disk but content-type/extension mismatch only, no execution evidence | Medium (P3) |
| File written to a web-servable path and subsequently requested/executed, or matches known webshell signature | Critical (P1) |

Default queue priority on open: **High**. The gap between "file landed on the server" and "file is running as a webshell" can be a single follow-up HTTP GET, so this doesn't get parked behind lower-severity tickets.

## MITRE ATT&CK Techniques
- **T1190** — Exploit Public-Facing Application (the upload validation flaw itself is the entry vector)
- **T1105** — Ingress Tool Transfer (the upload *is* the delivery mechanism for the attacker's tool/webshell)
- **T1059.001 / T1059.003** — Command and Scripting Interpreter (PowerShell / Windows Command Shell — commands executed once the uploaded script is reachable and run)
- **T1027** — Obfuscated Files or Information (base64-wrapped payloads inside image/PDF wrappers, split webshell strings, encoded eval blocks)
- **T1071.001** — Application Layer Protocol: Web Protocols (webshell-to-attacker or attacker-to-webshell traffic riding over ordinary HTTP/HTTPS, indistinguishable from normal app traffic without content inspection)
- **T1505.003** — Server Software Component: Web Shell (the uploaded file itself, once it's a working, callable backdoor left in a web-accessible path — this is the specific sub-technique for a persistent web shell, distinct from the initial upload/delivery step covered by T1190/T1105 above)
- **T1053.005 / T1543.003** — Scheduled Task / Windows Service (common next step once a webshell has command execution and the attacker wants persistence beyond the web root)

## Trigger / Detection Logic Summary
Alert fires on one or a combination of: (1) an uploaded file's declared `Content-Type` header disagrees with its actual magic-byte signature (e.g., declared `image/jpeg`, magic bytes match a PE or script), (2) the filename carries a double extension (`invoice.pdf.php`), a null byte (`shell.php%00.jpg`), or an executable extension disguised via case/encoding (`shell.PhP`, `shell.pHp5`), (3) the upload-handler writes the file into a directory the web server will execute scripts from rather than a storage-only path, or (4) — the strongest signal — a file uploaded via POST to the upload endpoint is requested again shortly after via GET against a path under the web root and returns a 200 with unexpected content-length for what should be a static asset.

## Required Log Sources
No Windows/Sysmon Event IDs are asserted here — none were supplied for this scenario and I'm not attaching numbers I can't verify against your build. Pull:

- Web server access logs (IIS, Apache, Nginx) — the POST to the upload endpoint and any subsequent GET of the stored file path, status codes, response sizes
- WAF / reverse-proxy logs — matched upload-inspection rules (file-type restriction, magic-byte checks), action taken
- Application upload-handler logs, if the app logs this itself — original filename, computed hash, storage path, declared vs. detected content-type, uploading user/session ID
- Antivirus/EDR on the file-storage host or web server — file-write events, hash reputation hits, and quarantine actions if AV scans uploads on write
- Host EDR / Sysmon telemetry (described by name, not ID) — process creation from the web server worker process (`w3wp.exe`, `php-fpm`, `httpd`, nginx worker) spawning a shell interpreter, and any outbound connection initiated by that worker shortly after
- Cloud storage logs, if the upload target is S3/Azure Blob/GCS — `PutObject`/blob-create events, bucket/container ACL and public-access changes, and any Lambda/Function trigger that processes the object afterward

## Key Fields to Inspect
**[ANALYST]**
- Original filename and stored filename/path — watch for double extensions, null bytes, path traversal sequences (`../`), and mismatched case tricks
- Declared `Content-Type` vs. detected file type from magic bytes (first few bytes of the file — `MZ` for a PE, `<?php` or `#!/bin/` for scripts, `GIF89a`/`\xFF\xD8\xFF` for genuine images)
- File hash (SHA256) — check against VT/internal sandbox and any known webshell hash sets before assuming novelty
- Storage path — is it under a directory the web server is configured to execute (`/uploads/`, `/images/` mapped as executable) or a genuinely non-executable storage tier (blob storage, CDN-only path)?
- Uploading account/session, source IP, and whether that account has a normal history of using this upload feature
- Any subsequent HTTP request for the exact stored path, its response code, and response size versus the original uploaded file size
- Process spawned by the web worker (parent-child chain), and outbound connections from that host in the minutes following the request

## Normal vs Suspicious Pattern
**Normal:** file extension matches declared content-type matches actual magic bytes; file lands in a storage-only path (object storage, a directory with execute permissions stripped, or served only through a controlled download handler that never lets the browser execute it directly); file size and type are within the app's documented limits (e.g., avatar uploads capped at 2 MB, JPEG/PNG only).

**Suspicious:** extension/content-type/magic-byte mismatch in any combination; filename contains a double extension or encoding trick; the file is written into or later moved into a web-servable path; the exact upload path is requested again via GET within seconds to minutes of the POST (an attacker confirming their webshell landed); the response to that GET is a 200 rather than the "not viewable, download only" behavior a legitimate media file would get.

## Investigation Steps
1. Pull the raw upload request from the web/WAF logs — confirm the uploading account, source IP, declared filename, declared content-type, and whether the WAF's upload-inspection rule fired or passed it through.
2. Retrieve the file from storage or quarantine (do not execute it), compute its SHA256, and check it against VirusTotal/internal sandbox and any known webshell signature set (China Chopper, ASPX/PHP one-liner shells, etc. — check by behavior/pattern, not by an ID this book doesn't supply).
3. Inspect the file's actual magic bytes and, if it's a text-based script type, review the content directly in a sandboxed viewer — look for `eval()`, `base64_decode()`, `system()`/`exec()`/`Invoke-Expression` calls, or heavily obfuscated single-line payloads (T1027).
4. Confirm the storage path and whether it sits under a web-servable, script-executable directory. Check the app/server config (CMDB or IaC source, not a guess) for whether that path can actually be reached and executed via HTTP.
5. Search access logs for any GET request to the exact stored filename/path following the upload — a hit here with a 200 response is your strongest single indicator of a working webshell (T1190 and T1105 confirmed for the delivery stage; T1505.003 for the webshell itself once it's confirmed callable).
6. If host telemetry exists, pivot to the web server host: check for a process spawned by the web worker running `cmd.exe`/`powershell.exe` or an equivalent shell (T1059.001/.003), and any outbound connection opened by that process shortly after the GET.
7. Check for follow-on persistence — new scheduled tasks (T1053.005) or services (T1543.003) created around the same timeframe, which would indicate the attacker used shell access to entrench beyond the web root.
8. Determine scope — search the same upload endpoint across the full log retention window for other suspicious uploads from the same account/IP/UA, and check whether the same vulnerable upload-handler code path exists on other app instances or environments (staging, other regions) behind the same codebase.

## True Positive Indicators
- Content-type/extension/magic-byte mismatch confirmed, and the file was written to a web-servable, script-executable path
- Subsequent GET to the exact stored path returned 200 with script-execution behavior (not a static file download)
- File content or hash matches known webshell patterns, or contains obfuscated `eval`/`exec`/`Invoke-Expression`-style code
- Process spawned by the web server worker following the request, and/or outbound connection to attacker infrastructure

## False Positive / Benign Positive Indicators
- Genuine media file with a benign extension quirk (e.g., a camera-exported `.jpeg.JPG` from a mobile OS) — verify magic bytes actually match the declared type before treating it as an attack
- Upload rejected by WAF/handler validation, file never persisted, no origin log entry showing it reached executable storage — close as Benign Positive, not True Positive
- Authorized pentest or vulnerability scan traffic against the upload endpoint (check the scan calendar before escalating — this endpoint gets hit constantly by automated scanners probing for exactly this flaw)
- Legitimate app feature that stores executable-looking files intentionally in a sandboxed, non-executable context (e.g., a CI/CD platform storing user-submitted build scripts in isolated blob storage with no execution path) — analyst needs to validate the storage path is genuinely non-executable before assuming intent

## Escalation Criteria
Escalate immediately to IR Lead / Tier 3 when: the uploaded file is confirmed reachable and executable (GET returned 200 with script behavior), a process was spawned by the web worker following the request, any outbound connection to non-owned infrastructure is observed, or the affected application handles customer data, payment processing, or sits in a production trust zone. Don't wait on sandbox results if the webshell is already confirmed live — contain first, finish the malware analysis in parallel.

## Containment Options & Approval Authority
**[MANAGEMENT]**
| Action | Approval |
|---|---|
| Block source IP/ASN at WAF or edge | Tier 1/Tier 2 analyst, standing authority |
| Quarantine/delete the uploaded file, disable public read on the storage path | App owner + Tier 2 analyst |
| Virtual-patch the upload endpoint (enforce strict MIME/magic-byte validation at WAF) | App owner + SecEng sign-off |
| Disable the upload feature entirely pending a code fix | App owner approval, change record |
| Isolate host from network (confirmed webshell with process execution) | IR Lead approval |
| Full incident declaration, customer notification review | Incident Commander / CISO |

## Example Query (Splunk SPL)
```spl
index=web sourcetype=access_combined method=POST uri_path="*/upload*"
| rex field=_raw "filename=\"(?<upload_fname>[^\"]+)\""
| eval double_ext=if(match(upload_fname, "\.\w+\.(php|asp|aspx|jsp|phtml)$"), 1, 0)
| where double_ext=1
| stats count min(_time) as first_seen values(uri_path) as endpoint by src_ip upload_fname
| sort -count
```

## Closure Criteria
Close as **True Positive** once the file is confirmed removed from any executable path, the endpoint is virtual-patched or code-fixed, any spawned process/outbound connection has been terminated, and the file hash is logged for the case record and threat-intel sharing. Close as **Benign Positive** when the mismatch resolves to a legitimate file-format quirk with no execution path. Close as **Insufficient Evidence** when the file itself is unrecoverable (already deleted/rotated out of retention) and access logs alone can't confirm whether it was ever requested — don't force a True Positive verdict the evidence can't carry.

**Example case note:** *"Upload to portal.example.com/api/v1/documents/upload from account jsmith@example.com, src_ip 203.0.113.77, filename `invoice.pdf.php`, declared content-type image/jpeg, magic bytes confirm PHP script (`<?php` header). File was written to /wwwroot/uploads/ (script-executable path). Access log shows GET to the same path 40 seconds later, response 200, 1.2KB body — consistent with webshell check-in. EDR on WEB03 shows php-cgi.exe spawning cmd.exe at matching timestamp, followed by outbound connection to 198.51.100.212:443. File quarantined, host isolated pending forensic imaging, IR Lead notified. Escalated to Critical/P1."*
