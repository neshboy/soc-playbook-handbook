# Web Shell Detection

## Playbook ID & Name
**WEB-007 — Web Shell Detection & Response**
Category: Web Security

## Business Risk

**[STAKEHOLDER]** - A web shell is a small script an attacker drops on an internet-facing server that turns it into a permanent, interactive backdoor. It usually runs with the same account the web application already uses, so it doesn't need a second exploit or stolen credentials to keep working. Once it's live, the attacker doesn't need to re-exploit anything - they just browse to the file. This is one of the highest-value detections a SOC runs because it typically catches the intrusion at the beachhead stage, before it turns into data theft, ransomware staging, or a foothold used to move into the internal network. A missed web shell on a customer-facing app is the kind of finding that ends up in a breach notification letter.

## Severity / Priority Default

High / P2 by default. Escalate to Critical / P1 immediately if the host is internet-facing, holds customer data, sits in a PCI/regulated zone, or if outbound command-and-control traffic or lateral movement is already confirmed.

## MITRE ATT&CK Techniques

| ID | Technique | Role in this scenario |
|---|---|---|
| T1505.003 | Server Software Component: Web Shell | The artifact itself - the malicious script backdooring the web server for persistent access; this is the primary technique this playbook exists to catch |
| T1190 | Exploit Public-Facing Application | Initial access - the vulnerability (file upload flaw, deserialization bug, vulnerable plugin, unpatched CMS) that let the attacker place the shell |
| T1105 | Ingress Tool Transfer | Attacker uses the shell to pull down secondary tools, larger shells, or scanners |
| T1059.001 / T1059.003 | PowerShell / Windows Command Shell | Commands executed *through* the shell on the underlying OS |
| T1027 | Obfuscated Files or Information | Base64/rot13/gzip-wrapped shell code, dynamically eval'd strings |
| T1543.003 / T1053.005 / T1547.001 | Windows Service / Scheduled Task / Registry Run Keys | Persistence the attacker installs once shell access confirms they have a foothold |
| T1071.004 / T1572 / T1090 | DNS / Protocol Tunneling / Proxy | C2 channel out of the shell, often DNS-based to survive egress filtering |
| T1046 / T1087 | Network Service Discovery / Account Discovery | Recon commands run through the shell after initial access |
| T1218.005 / T1218.010 / T1218.011 | Mshta / Regsvr32 / Rundll32 | LOLBins invoked from the shell to launch a secondary payload while evading AV |
| T1562.001 | Disable or Modify Tools | Attacker uses shell-level access to kill AV/EDR or clear logs |

Note: the artifact itself maps directly to T1505.003 above. Everything the attacker *does* with the shell once it's placed is mapped to the remaining IDs in this table.

## Trigger / Detection Logic Summary

Web shells rarely announce themselves - they announce themselves through what happens *around* them. The reliable trigger isn't "found a suspicious .aspx file," it's a behavioral chain: (1) the web server process writes a new script file into a web-accessible directory it doesn't normally write to, (2) that file is then requested over HTTP shortly after, and (3) the HTTP worker process (`w3wp.exe`, `httpd`, `php-fpm`, `nginx` worker) spawns a child process it should never spawn - a command interpreter, a discovery utility, or a LOLBin. Any one of those three alone is often noisy or ambiguous. All three lining up in sequence, on the same host, within a short window, is a strong signal — "shortly after" is commonly minutes, but treat up to several hours between file-write and first request as still in-chain (attackers routinely stage a shell and come back later); don't rule out the correlation just because the two timestamps aren't adjacent.

## Required Log Sources

- Web server access and error logs (IIS, Apache, Nginx) - request-level detail, not just aggregate counts
- File integrity monitoring / EDR file-create telemetry on web root and upload directories
- Process creation telemetry from EDR, or host-level process auditing where EDR isn't deployed - looking specifically for the web server worker process as a *parent*
- Network/proxy egress logs and DNS query logs for the host
- WAF logs (if a WAF sits in front of the app)
- Backup/version-control diff of the web root, where available, for retroactive "when did this file first appear" questions

Where Windows host telemetry is in scope, the process-creation signal is Sysmon Event ID 1 (Process Create) or Windows Security Event ID 4688 (Process Creation, if Audit Process Creation is enabled); the network-connection signal is Sysmon Event ID 3 (Network Connect). Neither is a Web Security-layer log by itself — they only become relevant once the web/WAF evidence below points at a specific host and timestamp.

## Key Fields to Inspect

**[ANALYST]**

| Field | Source | What you're looking for |
|---|---|---|
| `cs-uri-stem` | Web log | Request path to an unfamiliar script, especially in `/uploads/`, `/images/`, `/tmp/`, `/cache/` |
| `cs-method` | Web log | POST requests to a script with no legitimate form behind it |
| `sc-status` | Web log | 200 on a file nobody deployed through the release pipeline |
| `cs(User-Agent)` | Web log | Missing, generic (`curl`, `python-requests`), or scanner-style UA on requests to the file |
| `c-ip` | Web log | Source IP - check reputation, ASN, prior WAF blocks |
| `time-taken` | Web log | Long response times when the shell is shelling out to run commands |
| Parent process | EDR/process log | `w3wp.exe`, `httpd`, `nginx`, `php-fpm` spawning `cmd.exe`, `powershell.exe`, `bash`, `whoami`, `net.exe` |
| Command line | EDR/process log | Encoded/obfuscated arguments, `certutil`, `curl`, discovery commands |
| File metadata | FIM/EDR | File creation time vs. last known-good deployment timestamp; file owner = web service account |
| DNS queries | DNS logs | High-entropy subdomains, unusually frequent TXT/NULL queries from the web tier |

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| File writes in web root | Only during deployment pipeline runs, owned by deploy service account | Ad-hoc write by the web server's own runtime identity, outside a deployment window |
| Web server process children | None, or known helper processes (e.g., PHP-FPM workers, report generators) | `cmd.exe`, `powershell.exe`, `sh`, `bash`, `whoami`, `net.exe`, `nslookup` |
| Requests to new files | Match release notes / change ticket | Unfamiliar filename, single-character or generic name (`cache_update.aspx`, `x.php`, `1.jsp`), no corresponding deploy |
| Outbound connections from web tier | To known app dependencies, payment gateway, monitoring | To unfamiliar public IPs, especially over non-standard ports or via DNS tunneling |
| Request volume to the file | N/A - shouldn't exist | Recurring low-volume hits from a small set of source IPs, often at odd hours |

## Investigation Steps

**Default lookback:** start with 30 days of web access and file-create/EDR history when hunting for first-seen — a dormant shell can sit unused for weeks before an attacker returns to it, so a 24-hour window will make an old shell look like it appeared out of nowhere. Once first-seen is established, narrow subsequent steps (process creation, outbound traffic, persistence) to the window starting at that timestamp.

1. Pull the web access log entries for the suspicious file - full request history, not just the alerting hit. Establish first-seen timestamp for the file and cross-reference against deployment/change records.
2. Pull file system metadata (creation time, owner, permissions) and compare owner against the actual account used for legitimate deployments. Web service account owning a script file is a strong tell.
3. Check process creation telemetry on the host for any process where the parent is the web server worker process. Capture full command lines, not truncated ones - obfuscated shells often base64 or reverse a payload before execution.
4. Retrieve the file content (or a hash, at minimum, if content can't be safely pulled) and run it against sandbox/AV/YARA tooling. Don't execute it locally out of curiosity.
5. Review outbound network and DNS activity from the host for the period after the file first appeared - look for beaconing intervals, DNS tunneling patterns, or connections to newly-registered domains.
6. Check for persistence artifacts installed after the shell's first appearance - new scheduled tasks, services, or run-key entries on the host.
7. Scope laterally: has this source IP or file hash touched any other host in the environment? Check other web-facing systems for the same filename pattern or upload path.
8. Identify the root-cause vulnerability (the T1190 entry point) - vulnerable plugin, unpatched CMS, insecure file upload validation - so it gets patched, not just the shell removed.

## True Positive Indicators

- Unfamiliar script file in a web-writable directory, owned by the web service account, not tied to any deployment record
- Web server worker process spawning a command interpreter or discovery utility
- Obfuscated/encoded content inside the file (base64 blobs, `eval()` on decoded strings, single-letter variable names typical of shell generators)
- Outbound connections or DNS queries from the web tier to infrastructure with no legitimate business relationship
- Recurring low-and-slow HTTP requests to the file from a small, consistent set of source IPs

## False Positive / Benign Positive Indicators

- Legitimate debug, diagnostic, or admin utility page left in place by developers (ugly, but not malicious - still needs remediation as a hardening gap)
- File matches a scheduled deployment or a known internal tool (report generator, health-check endpoint) that happens to accept parameters
- Backup or staging file (`.bak`, `.old`, copy-of-`index.php`) picked up by a generic "unexpected extension in webroot" rule with no execution behavior behind it
- Authorized penetration test or red team engagement - verify against the current testing calendar before treating as an incident
- WAF/scanner false block on a legitimate file due to an overly broad signature match, with no corresponding process execution or file-write anomaly

## Escalation Criteria

Escalate to IR/Critical if: process execution is confirmed from the web server context, any outbound C2-style traffic is observed, the host has touched a database or internal segment reachable from the web tier, or the same artifact/hash appears on more than one host. Escalate to the application owner and patch/vuln management regardless of outcome, since the entry vulnerability needs fixing whether or not this particular shell turns out active.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Isolate host from network (keep running for forensics) | SOC shift lead | Preferred first move over shutdown - preserves memory/process state |
| Quarantine/remove the shell file | Application owner + SOC lead | Don't delete before hashing and copying to evidence storage |
| Block source IP(s) at WAF/firewall | SOC analyst (pre-approved for confirmed malicious IPs) | Low-risk, reversible, do this early |
| Full host rebuild from known-good image | Application/Infra owner, IR manager | Required if persistence or root/admin compromise confirmed |
| Public disclosure / customer notification | CISO, Legal | Only after scoping confirms data exposure |
| Emergency patch of the root-cause vulnerability | Application owner, Change Management (expedited) | Track as the actual fix - shell removal alone is not closure |

## Example Query (Splunk SPL)

```spl
index=edr_process earliest=-30d latest=now (parent_process_name IN ("w3wp.exe","httpd","nginx","php-fpm"))
  process_name IN ("cmd.exe","powershell.exe","sh","bash","whoami.exe","net.exe","nslookup.exe")
| stats count min(_time) as first_seen max(_time) as last_seen
  by host, parent_process_name, process_name, command_line, user
| where count > 0
```

## Closure Criteria

Close as **True Positive** only once: the shell file is removed/quarantined and hashed, the entry vulnerability (T1190 vector) is identified and patched or mitigated, no persistence artifacts remain on the host, and outbound C2 activity (if any) has stopped and been blocked at the perimeter. Close as **Benign Positive** if the file is confirmed to be a legitimate internal tool with no execution anomaly, and flag it to the app owner for hardening. Close as **Insufficient Evidence** if the file was removed by hosting cleanup or log retention expired before content/process data could be retrieved - document what was and wasn't checked.

**Example case note:**
"WEB01 (10.20.5.15) - file `cache_update.aspx` found in `C:\inetpub\wwwroot\uploads\`, owned by IIS_APPPOOL service account, first seen 2026-09-12 03:14 UTC, no matching deploy ticket. Confirmed `w3wp.exe` spawning `cmd.exe` with base64-encoded argument at 03:16 UTC. Outbound connection to 203.0.113.44:443 (no known business relationship) at 03:17 UTC, four times over following 48h. Root cause: unrestricted file upload in third-party image-resize plugin (unpatched since 2026-06). File quarantined and hashed, host rebuilt from known-good image 2026-09-13, plugin patched 2026-09-13. Closed as True Positive — contained, root cause patched."
