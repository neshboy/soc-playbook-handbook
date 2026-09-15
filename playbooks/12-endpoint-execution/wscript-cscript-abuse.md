# EP-012 — WScript/CScript Abuse (Windows Script Host Execution)

**Category:** Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - `wscript.exe` and `cscript.exe` are the two faces of Windows Script Host - a component that ships on every Windows build and has done since Windows 98. It runs VBScript and JScript, and it's still the delivery engine behind a huge share of commodity phishing: the ".vbs disguised as an invoice" or ".js hidden inside a zipped attachment" that a user double-clicks without a second thought. Because the interpreter itself is signed by Microsoft, a lot of allowlisting and legacy antivirus controls simply don't look at it twice - the actual malicious logic lives in a plain-text or lightly obfuscated script file, not in a binary AV can fingerprint. When this pattern lands, the realistic outcomes range from a single infected workstation to a full ransomware precursor if the script is a downloader for a second-stage loader. The business question a stakeholder actually cares about is simple: did the script just show a fake error box and die, or did it phone home and fetch something else? Those two outcomes look almost identical in the first five seconds of telemetry.

## Severity / Priority Default

**Medium** on initial trigger for a script running from a user-writable path with no immediate follow-on activity. Escalate to **High** the moment any of the following is present: outbound network activity from the script host process, a child process spawn (especially `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`), or a persistence artifact written to disk/registry. Don't default this to Low just because wscript.exe "isn't malware" - the interpreter is never the payload, the script content is, and you won't know what that content does until you've read it.

## MITRE ATT&CK Techniques

- **T1059.005 / T1059.007** - Command and Scripting Interpreter: Visual Basic / JavaScript (VBScript and JScript are the two languages Windows Script Host runs, and both have their own current ATT&CK sub-technique - cite the one that matches the actual file extension/content rather than the bare parent T1059)
- **T1204** - User Execution (the near-universal delivery pattern: user opens an attachment or extracts an archive and double-clicks the script)
- **T1566.001** - Phishing: Attachment (most common initial-access vector feeding this playbook)
- **T1105** - Ingress Tool Transfer (where the script's sole job is to pull a second-stage payload)
- **T1027** - Obfuscated Files or Information (`Chr()`/`Execute()` chains, string concatenation, base64 blobs embedded in the script body)
- Follow-on techniques to watch for once execution is confirmed: **T1547.001** (Registry Run Keys, if the script installs its own persistence) and **T1053.005** (Scheduled Task, same purpose via a different mechanism).

## Trigger / Detection Logic Summary

Alert on `wscript.exe` or `cscript.exe` process creation where any of the following hold: (1) the parent process is an Office application (`outlook.exe`, `winword.exe`, `excel.exe`, `powerpnt.exe`), a browser, `mshta.exe`, or an archive utility - i.e., something that just handed the user a file rather than an admin tool that launches scripts on a schedule; (2) the script path resolves to `%TEMP%`, `%APPDATA%`, `Downloads`, or another user-writable location rather than a version-controlled internal share; (3) the command line references a `.vbs`, `.vbe`, `.js`, `.jse`, or `.wsf` file with a random/GUID-like filename; or (4) the process, within its short lifetime, opens a network connection or spawns a child process. None of these alone is a hard verdict - a help-desk macro that calls `cscript.exe` against a script in `%TEMP%` during a legitimate software push looks similar on paper. The detection value is in the combination, same as everywhere else in this category.

## Required Log Sources & Event IDs

| Source | Event ID | Why |
|---|---|---|
| Sysmon | 1 (Process Creation) | Full command line for wscript.exe/cscript.exe, parent chain, hashes, integrity level - the anchor event |
| Sysmon | 11 (FileCreate) | Confirms how the script arrived (attachment save, browser download, archive extraction) and catches any dropped second-stage payload |
| Sysmon | 3 (Network Connection) | Confirms the script phoned home, attributed to wscript.exe/cscript.exe by PID/GUID |
| Sysmon | 22 (DNSEvent) | Resolves the domain the script queried, tied to the same process |
| Sysmon | 12/13 (RegistryEvent) | Catches persistence written via Run keys as a follow-on action |
| Windows Security | 4688 | Fallback where Sysmon isn't deployed; command line only populated if CLI auditing is enabled via GPO |
| Windows Security | 4698 | Scheduled task creation if the script establishes persistence that way - Task Content XML shows the action |
| System log | 7045 | Service installed, if the script's follow-on payload installs itself as a service |
| Microsoft-Windows-PowerShell/Operational | 4104 | Script block text if the WSH script pivots into an encoded PowerShell child process |

Command-line auditing gaps bite hard here specifically because the script filename is often the only clue you get from a bare 4688 record - if the command line field comes back empty, you're guessing at the script's purpose from the file path alone.

## Key Fields to Inspect

**[ANALYST]**
- `CommandLine` (Sysmon 1 / 4688) - the full path and filename of the `.vbs`/`.js`/`.wsf` being executed, plus any arguments the script itself takes
- `ParentImage` / `ParentCommandLine` - Outlook or a browser handing off to WSH is a different story than a signed deployment agent doing it on a schedule
- `CurrentDirectory` - working directory often confirms where the script was extracted or saved, useful when the command line uses a relative path
- `Hashes` (Sysmon 1) - hash the script file itself where possible; the interpreter's own hash rarely changes since it's a stock Microsoft binary
- `IntegrityLevel` - medium (user) is typical; anything running elevated changes your containment urgency
- Sysmon 11 `TargetFilename` - where the script landed before execution, and whether a second file (the actual payload) got dropped afterward
- Sysmon 3/22 `DestinationIp`, `DestinationPort`, `QueryName` scoped to the wscript.exe/cscript.exe PID - don't assume the network event belongs to the script host just because the timestamps are close, confirm the PID/ProcessGuid match
- Script content itself, recovered from disk, EDR quarantine, or the original attachment - `WScript.Shell`, `CreateObject`, `Chr()` chains, and hardcoded URLs or IPs are the giveaways

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| `cscript.exe \\corp\netlogon\scripts\login.vbs` fired at every interactive logon, same hash for months | `wscript.exe //E:vbscript C:\Users\j.reyes\AppData\Local\Temp\Invoice_88231.vbs` fired once, right after an email attachment was opened |
| SCCM/Intune/vendor installer calling `wscript.exe` against a packaged script in `Program Files` | Script path is a random GUID-like filename inside `Downloads` or an extracted zip in `Temp` |
| Script content is plain, readable VBScript matching a known internal tool | Script body is a wall of `Chr()` calls, string concatenation, or a single base64 blob decoded with `Execute()` |
| No network activity, or activity limited to a documented internal endpoint | Outbound connection to a bare IP, newly-registered domain, or a URL shortener within seconds of launch |
| Parent process is a scheduled task, RMM agent, or software deployment tool | Parent process is `outlook.exe`, `winword.exe`, a browser, or `explorer.exe` immediately after an archive was opened |
| Process exits cleanly with no children | Script spawns `powershell.exe -enc`, `cmd.exe /c`, `mshta.exe`, or `regsvr32.exe` as a child |

## Investigation Steps

1. Pull the full Sysmon 1 record for the `wscript.exe`/`cscript.exe` process: `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `Hashes`.
2. Establish delivery vector - trace the parent chain and correlate with Sysmon 11 for the script file's arrival (mail attachment save path, browser download folder, archive extraction). If it came through email, pull the message from the mail gateway/EDR for the sender, subject, and attachment hash.
3. Recover and read the script content wherever you can get a copy - quarantine, disk (if not yet deleted), or the original attachment. Identify what it actually does: does it call `Shell.Run`, `CreateObject("WScript.Shell")`, build a URL string, or invoke `Execute()` on decoded content?
4. Check Sysmon 3/22 for the same PID/ProcessGuid for outbound connections or DNS queries within the process lifetime. Flag bare IPs, newly-seen domains, and non-standard ports.
5. Check for child processes under the same ParentProcessGuid - `powershell.exe`, `cmd.exe`, `regsvr32.exe`, `rundll32.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe` spawned from a script host is a strong signal the script succeeded past stage one.
6. Check for persistence - Sysmon 12/13 Run key writes, 4698 scheduled task creation, or 4697/7045 service installs referencing the script or a dropped payload in the action/`ImagePath`.
7. Hunt across the environment for the same script hash, filename pattern, or destination domain on other endpoints in the same time window - commodity phishing rarely hits just one mailbox.
8. Validate against change records or known internal tooling (SCCM packages, login scripts, vendor installers) before committing to a verdict - a surprising number of legacy line-of-business tools still ship VBScript glue code.

## True Positive Indicators

- Script executes from a user-writable path (`Temp`, `Downloads`, extracted archive) immediately after an email attachment or download
- Script content is obfuscated (`Chr()` chains, concatenation, single-line base64 decoded via `Execute()`/`Eval()`)
- Outbound connection to a bare IP, newly-registered domain, or paste-site/URL-shortener within seconds of launch
- Spawns a child LOLBin or interpreter (`powershell.exe`, `cmd.exe`, `mshta.exe`) that continues the chain
- Writes a Run key, scheduled task, or service referencing itself or a dropped payload
- Script hash or destination domain matches known threat intel, or the same IOC appears on multiple hosts

## False Positive / Benign Positive Indicators

- `cscript.exe`/`wscript.exe` invoking a stable, version-controlled script from a domain logon path or `Program Files`, same hash observed over an extended period
- Parent process is SCCM, Intune, a vendor installer, or another documented deployment agent, running during a known change window
- Script content is plain-text, readable, and matches a known internal automation tool (print management, ERP integration, legacy line-of-business glue code)
- No network activity, no child process, no persistence artifact - script ran, did something local and benign, exited
- Security or IT tooling itself uses WSH for a legitimate helper action - check your own software inventory before escalating

## Escalation Criteria

Escalate to Tier 2/IR immediately if: the script established outbound contact with an IOC matching threat intel, a child process continued the chain into credential access or further payload staging, persistence was written successfully, the affected account holds elevated privileges (4672 alongside the originating logon), or the same script hash/domain has appeared on more than one host. A "blocked at the proxy" outbound attempt still confirms the script executed with malicious intent - don't downgrade severity just because the network leg failed.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Kill the wscript.exe/cscript.exe process and any spawned children - Tier 1/2 analyst, no separate approval needed, log the action in the case.
- Single-endpoint EDR network isolation - Tier 2 analyst can execute unilaterally under standard SOC authority; notify on-call IR lead within 15 minutes for anything beyond a single workstation.
- Block destination domain/IP at proxy/firewall - Tier 2 can push immediately at high IOC confidence; otherwise route to the network team with a 30-minute SLA target for confirmed malicious indicators.
- Restrict WSH execution via GPO/AppLocker/WDAC (disable `wscript.exe`/`cscript.exe` for standard users, or block `.vbs`/`.js`/`.wsf` execution from user-writable paths) - this is a change-managed action requiring IT operations manager sign-off; it has a real chance of breaking legacy line-of-business tooling, so it doesn't get pushed org-wide on a single incident without a review.
- Remove persistence artifacts (Run key, scheduled task, service) - Tier 2/3 with a documented change ticket before deletion, capture the artifact first.
- Disable the user account if the entry vector suggests credential exposure - requires IR lead or manager approval, coordinate with the account owner's manager given the disruption.

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once outbound network activity, a child-process spawn, or a persistence write escalates the case to High.

## Example Query (Microsoft Sentinel / KQL, Defender for Endpoint schema)

```kql
DeviceProcessEvents
| where FileName in~ ("wscript.exe", "cscript.exe")
| where InitiatingProcessFileName in~ ("outlook.exe","winword.exe","excel.exe","powerpnt.exe")
    or ProcessCommandLine has_any (@"\AppData\", @"\Temp\", @"\Downloads\")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the script's purpose, source, and any follow-on activity are confirmed malicious and contained (host isolated/remediated, hash and destination IOC pushed to blocklist, ticket includes full script content or a summary of its de-obfuscated logic). Close as **Benign Positive** when the process matches a documented internal tool, deployment agent, or logon script with a verifiable change record. Close as **Expected Activity** for recurring, baselined internal automation once it's been reviewed and added to the allowlist. Close as **Insufficient Evidence** if the script file was deleted before recovery and no EDR quarantine copy exists - don't force a verdict on a payload you never actually read, but do log the recovery gap so quarantine/retention settings get revisited.

**Example case note:** *"wscript.exe on WKSTN-0512 (user j.reyes) launched `C:\Users\j.reyes\AppData\Local\Temp\Invoice_88231.vbs`, parent process OUTLOOK.EXE, three minutes after attachment delivery per mail gateway log MSG-33920. Recovered script (EDR quarantine copy) used `Chr()`-chain obfuscation resolving to a `WScript.Shell` call building an `Invoke-WebRequest` command. Sysmon 3 confirms outbound to 185.x.x.x:443 within four seconds of launch; Sysmon 22 shows domain first-seen in environment with no business relationship. No child process observed - EDR blocked the PowerShell spawn attempt. Host isolated 14:07 UTC, hash and IP pushed to blocklist, phishing sender added to mail gateway block list. Verdict: True Positive, T1566.001/T1204/T1059.005/T1027/T1105."*
