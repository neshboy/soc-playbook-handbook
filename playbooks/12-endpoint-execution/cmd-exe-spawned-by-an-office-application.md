# cmd.exe Spawned by an Office Application

## Playbook ID & Name

**EP-005 — cmd.exe Spawned by an Office Application**
Category: Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - This is one of the highest-confidence early-warning signs of a phishing document detonating on a workstation. Office applications don't legitimately need to launch a command shell in the vast majority of business environments, so when it happens the likely story is a user opened an attachment, enabled macros (or triggered a DDE/OLE exploit), and the document just handed an attacker a foothold on that machine. Left unaddressed, this is the opening move that leads to credential theft, ransomware staging, or a foothold used for lateral movement across the network. Business impact scales fast if the host is a domain-joined workstation with cached admin credentials or VPN access.

## Severity/Priority Default

**High** on first detection. Auto-escalate to **Critical** if the spawned cmd.exe chains into PowerShell, reaches out to the internet, or the host belongs to a privileged user (finance, IT admin, executive).

## MITRE ATT&CK Techniques

- T1204 User Execution (typically .001/.002 style attachment or link interaction — described here by name since only the parent technique ID is confirmed for this data set)
- T1059.003 Command and Scripting Interpreter: Windows Command Shell
- T1059.001 Command and Scripting Interpreter: PowerShell (when cmd.exe chains into powershell.exe)
- T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32) — common next hop after the cmd.exe stage
- T1105 Ingress Tool Transfer
- T1027 Obfuscated Files or Information (heavily obfuscated command lines, environment-variable string splitting, `cmd /c set` tricks)

## Trigger / Detection Logic Summary

Alert on any process creation event where the parent image is an Office application (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `msaccess.exe`, `mspub.exe`, `onenote.exe`) and the child image is `cmd.exe`. This is a near-zero-baseline pattern in most fleets — legitimate macro-driven shell-outs exist (a handful of legacy mail-merge or print-automation macros), but they're rare enough that most SOCs run this as close to a "detect and triage every single hit" rule rather than a tuned-threshold correlation.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Primary telemetry — full command line, parent command line, hashes, integrity level |
| Sysmon | 3 (Network Connection) | Did cmd.exe or its child reach out to the internet |
| Sysmon | 22 (DNS Event) | Resolves domains queried by the shell/child process |
| Sysmon | 11 (FileCreate) | Dropped payloads (staged binaries, scripts, LNKs) |
| Windows Security | 4688 (Process Creation) | Backup/cross-check if Sysmon unavailable — needs command-line auditing enabled to be useful |
| Windows Security | 4689 (Process Exited) | Confirms short-lived vs persistent child processes |

## Key Fields to Inspect

**[ANALYST]**

- **ParentImage / Creator Process Name** — confirm it's genuinely the Office binary path (`C:\Program Files\Microsoft Office\...`), not a masquerade
- **ParentCommandLine** — Office apps rarely have unusual switches; check for anything pointing at a specific document path with odd flags
- **Image / New Process Name** — `cmd.exe`, verify it's from `System32` or `SysWOW64`, not a renamed binary dropped elsewhere
- **CommandLine** — this is the whole ballgame. Look for `/c`, `/k`, piped commands, `powershell -enc`, `certutil -urlcache`, `bitsadmin`, base64 blobs, string concatenation with `set` and `%var%` tricks
- **CurrentDirectory** — often a Temp path, Downloads, or an INetCache location tied to the document's extraction
- **User / IntegrityLevel** — is this the interactively logged-on user, and is the token elevated
- **Hashes (SHA256/IMPHASH)** if configured — for any dropped or chained binary
- **ParentProcessGuid / ProcessGuid** — to build the full process-lineage chain in the SIEM

## Normal vs Suspicious Pattern

| Normal (rare, but exists) | Suspicious |
|---|---|
| A known, documented internal macro (e.g., a mail-merge tool calling `cmd /c copy` to a mapped drive) running on a small, consistent set of hosts at predictable times | First-ever occurrence on a host, or occurring right after a document was opened from an email attachment or a Downloads/Temp path |
| Command line is short, static, matches an approved script inventory | Long, obfuscated, base64-encoded, or heavily escaped command line |
| No outbound network activity from the spawned process | cmd.exe or a child process resolving a freshly-registered or non-business domain, or connecting to a raw IP on an unusual port |
| Child process exits quickly with no further spawning | cmd.exe spawns powershell.exe, mshta.exe, rundll32.exe, or regsvr32.exe as a further hop |
| User is a known power-user for that document/macro type | User has no history of macro-driven documents, or the mailbox shows the document arrived from an external sender minutes earlier |

## Investigation Steps

1. Pull the full Sysmon Event ID 1 record for the cmd.exe process — capture ParentCommandLine, CommandLine, User, ProcessGuid, and timestamps.
2. Identify the source document: check Outlook/mail gateway logs or the file path in ParentCommandLine/CurrentDirectory to find the originating attachment or downloaded file, and pull it (or its hash) for sandboxing if still available.
3. Walk the full process tree forward from cmd.exe (Sysmon 1, chained by ParentProcessGuid) — did it spawn PowerShell, mshta, rundll32, regsvr32, or a renamed binary? Capture every hop's command line.
4. Check Sysmon Event ID 3/22 for any network connections or DNS lookups tied to the process tree — resolve destination IPs/domains against threat intel and check for beaconing patterns (regular interval callbacks).
5. Check Sysmon Event ID 11 for files dropped in Temp, AppData, ProgramData, or the user's profile around the same timestamp — these are common staging locations for second-stage payloads.
6. Check whether Office macro settings, Protected View, or Mark-of-the-Web (Sysmon 15, FileCreateStreamHash) were bypassed or disabled to allow the document to execute in the first place.
7. Check the user's recent authentication history (4624/4634/4672) for anything indicating the session was already compromised or elevated before this event, and confirm whether the account holds any privileged group membership.
8. Determine blast radius — has this same document hash, sender, or C2 indicator been seen on any other host in the environment (search across the fleet, not just this endpoint).

## True Positive Indicators

- ParentCommandLine references a document opened directly from an email attachment, a browser download folder, or an external share, opened minutes before the cmd.exe spawn
- CommandLine is obfuscated, base64-encoded, or contains `powershell -enc`, `-w hidden`, `-nop`, `IEX`, `certutil -urlcache -split -f`, or similar download/execute idioms
- Process chain continues past cmd.exe into a scripting engine or LOLBin, and/or reaches out to a non-business domain or raw IP
- A file is dropped into Temp/AppData immediately after and then itself executed
- Document metadata or the mail gateway shows the sender was external/spoofed and the subject line follows known phishing lure patterns (invoice, HR, shipping notice)

## False Positive / Benign Positive Indicators

- A documented, change-controlled internal macro tool that is on the approved-script inventory and runs from consistent internal document templates
- CommandLine matches a known legacy print/merge/export utility with static, non-obfuscated arguments
- No network activity, no further process chaining, process exits cleanly within seconds
- The same exact command line and hash have a long, unremarkable history across many hosts in this environment (check baseline before assuming benign — a long history doesn't rule out a business-approved but risky legacy tool)

## Escalation Criteria

Escalate immediately to Incident Response / Tier 2 if any of the following are true: the chain reaches PowerShell or another LOLBin; there's a confirmed external network connection to a non-reputable domain; the affected user holds privileged or executive access; the same document hash appears on more than one host; or a dropped file's hash matches known malware family indicators in threat intel. Do not wait for certainty before isolating — this technique's entire value to an attacker is speed, and Insufficient Evidence at hour one can become a confirmed True Positive by hour two if you sit on it.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Endpoint network isolation (EDR quarantine) | SOC Tier 2 analyst, no additional approval needed for confirmed suspicious chains | Reversible, low business disruption for a single workstation |
| Disable user account / force password reset | Shift lead or IR manager | Coordinate with IT ops to avoid locking out a legitimate but compromised user mid-task |
| Block sender domain / attachment hash at email gateway | SOC Tier 2, notify email security owner | Prevents re-delivery to other mailboxes |
| Full incident declaration and IR playbook activation | IR Manager / CISO delegate | Required once lateral movement or privileged account involvement is confirmed |
| Fleet-wide hash/IOC block via EDR | SOC Tier 2, informational notice to IT ops | Low-risk, high-value once IOC is confirmed malicious |

SLA target: triage start within 15 minutes of alert for High severity, containment decision within 30 minutes if any TP indicator is present. Weekly review of false-positive volume against the approved-macro inventory to keep the rule from becoming noise.

## Example Query

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe",
    "outlook.exe","msaccess.exe","mspub.exe","onenote.exe")
| where FileName =~ "cmd.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

*(Equivalent logic applies against Sysmon Event ID 1 in Splunk/Sentinel — filter on `ParentImage` for the Office binaries and `Image` = `cmd.exe`, projecting `CommandLine` and `ParentCommandLine`.)*

## Closure Criteria

Close as **True Positive - Contained** only once the full process chain, dropped artifacts, and any C2 indicators are documented and remediation (isolation, credential reset, IOC block) is complete. Close as **Benign Positive** only when the command line and parent document map to a documented, approved internal macro on file with change management — reference the ticket number in the case note. Close as **Insufficient Evidence** if the host was reimaged, logs rotated past retention, or the document is unrecoverable before analysis completed — do not default to Benign Positive just because evidence ran out.

**Example case note:**
> 2026-09-15 14:22 UTC — WKS-FIN-042 (user j.alvarez), winword.exe spawned cmd.exe /c powershell -enc <base64> two minutes after opening "Invoice_88214.docm" received from external sender billing@example-supplier-co.com. Chain confirmed reaching update-cdn-delivery[.]net over 443; file dropped to %TEMP%\svchost_upd.exe (SHA256 matches known loader family per TI feed). Host isolated via EDR at 14:29, account disabled, IR declared per EP-005 escalation criteria. Closed as True Positive - Contained, handed to IR-2026-0341.
