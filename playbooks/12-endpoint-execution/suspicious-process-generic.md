# Suspicious Process (Generic)

**Category:** Endpoint – Execution & LOLBins
**Playbook ID:** EP-002

This is the catch-all playbook for the alert that fires when a process launches that *shouldn't reasonably be launching from where it launched, by what launched it, or with the arguments it was given*, but doesn't yet match a named, higher-fidelity playbook (no ransomware note yet, no LSASS handle, no C2 beacon confirmed). Most analysts will see far more of these than any other execution alert, because the underlying detection logic is deliberately broad — it's built around living-off-the-land binaries (LOLBins) and abnormal parent/child relationships rather than a single IOC. Treat it as a triage funnel, not a verdict.

## Business Risk

**[STAKEHOLDER]** - Attackers increasingly avoid dropping custom malware and instead abuse binaries already trusted and signed by Microsoft (`rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe`) to download, decode, or execute their actual payload. This detection is the net that catches that behaviour early — often at the initial-access or staging step, before ransomware deployment or credential theft — so the business impact of a missed detection here is "we catch it at a much more expensive stage later, if at all."

## Severity / Priority Default

**Medium**, auto-escalating to **High** when the process chain includes a network connection to a non-corporate destination, a script-interpreter with encoded content, or a server/DC asset as the source host.

## MITRE ATT&CK Techniques

- T1204 User Execution
- T1059.001 Command and Scripting Interpreter: PowerShell
- T1059.003 Command and Scripting Interpreter: Windows Command Shell
- T1218.005 System Binary Proxy Execution: Mshta
- T1218.010 System Binary Proxy Execution: Regsvr32
- T1218.011 System Binary Proxy Execution: Rundll32
- T1027 Obfuscated Files or Information
- T1105 Ingress Tool Transfer
- T1053.005 Scheduled Task/Job (common follow-on for persistence)

## Trigger / Detection Logic Summary

Fires on Sysmon/EDR process-creation telemetry when a process matching a defined LOLBin watchlist (`rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe`, `wscript.exe`, `cscript.exe`, `bitsadmin.exe`, `msiexec.exe`, `powershell.exe`) is launched with **any one** of the following:

- A parent process that is an Office application (`winword.exe`, `excel.exe`, `outlook.exe`), a browser, or `explorer.exe` combined with a suspicious grandparent.
- A command line referencing a URL, an IP literal, `-enc`/`-EncodedCommand`, `-w hidden`, `-nop`, Base64-looking blobs, or `/i:http` (regsvr32 remote scriptlet pattern).
- Execution from a user-writable path: `%TEMP%`, `%APPDATA%`, `\Downloads\`, `\Public\`, or a ProgramData subfolder that isn't a known application install.
- A hash with zero or very low AV-engine detections but no prior local execution history (first-seen binary on this host/fleet in the last N days).

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Primary signal — full command line, parent command line, hashes, integrity level |
| Windows Security | 4688 (New Process) | Corroboration where Sysmon isn't deployed; command line only if auditing enabled |
| Windows Security | 4689 (Process Exited) | Runtime duration, exit code |
| Sysmon | 3 (Network Connection) | Follow-on: did the LOLBin phone out? |
| Sysmon | 11 (FileCreate) | Follow-on: did it drop a payload? |
| Sysmon | 22 (DNSEvent) | Follow-on: resolved domain tied to the exact process |
| Microsoft-Windows-PowerShell/Operational | 4104 (script block), 4103 (module logging) | If interpreter is PowerShell — 4104 carries the de-obfuscated script block, 4103 corroborates which cmdlets/modules actually ran |
| Security | 4698 / 7045 / 4697 | If the LOLBin's next action is persistence (scheduled task or service) |

## Key Fields to Inspect

**[ANALYST]**

- `Image` / New Process Name and full path (case matters — `C:\Windows\System32\rundll32.exe` vs a copy sitting in `\Users\jsmith\AppData\Local\Temp\`)
- `CommandLine` — the whole string, not just the binary name
- `ParentImage` / `ParentCommandLine` — this is usually where the story is
- `ProcessGuid` / `ParentProcessGuid` — for chaining forward and backward reliably across dedup/re-ingest
- `Hashes` (SHA256 preferred) — pivot in EDR/VT
- `IntegrityLevel` — Medium is normal user context; High/System from a browser-spawned chain is a red flag
- `User` and `LogonId` — service account vs interactive human
- `CurrentDirectory` — working directory the process was launched from

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Parent of `rundll32.exe` | `explorer.exe`, `svchost.exe` (COM-launched), installer processes | `winword.exe`, `wscript.exe`, `powershell.exe`, `cmd.exe` spawned by a browser |
| Command line | Local DLL path with a known exported function, e.g. `rundll32.exe shell32.dll,Control_RunDLL` | URL, encoded blob, `javascript:` or `about:blank#mhtml:` argument to `mshta.exe` |
| Execution path | `System32`, `SysWOW64`, vendor Program Files folder | `%TEMP%`, `%APPDATA%\Roaming`, `\Downloads\` |
| Frequency | Recurring, same hash, seen fleet-wide over weeks | First-seen hash on the host/fleet, single occurrence tied to a phishing click |
| Network follow-up | None, or to known update/CDN endpoints | Outbound to a raw IP, a newly registered domain, or over an unusual port |

## Investigation Steps

1. Pull the full Sysmon Event ID 1 record for the alerting process — command line, parent command line, hashes, integrity level, ProcessGuid.
2. Walk the process tree up to the root (usually `explorer.exe`, a browser, or an Office app) and down to any children the LOLBin spawned. Don't stop at one hop — LOLBin chains are frequently three or four processes deep.
3. Check Sysmon Event ID 3/22 for any network connection or DNS query attributed to the exact `ProcessGuid` in the alert window (+/- 5 minutes to cover clock drift and log ingestion delay).
4. If the interpreter is PowerShell, pull the matching 4104 script block — de-obfuscate mentally or with CyberChef if it's Base64/gzip; don't rely on the alert summary alone.
5. Check Sysmon Event ID 11 for files written by the process or its children in the same window — this is where the actual payload usually lands.
6. Hash-lookup the binary (if non-native) against VirusTotal / internal threat intel and check first-seen-in-environment via your EDR's file prevalence feature.
7. Confirm user context: was this an interactive session (correlate Logon ID back to a 4624/4648) or a scheduled/service execution nobody was sitting at the keyboard for?
8. If persistence indicators appear (4698 scheduled task, 7045/4697 service, or a Run-key registry write), pivot to the relevant persistence playbook rather than closing this one in isolation.

## True Positive Indicators

- LOLBin spawned directly or indirectly by an Office app or script host, with an encoded/URL-bearing command line.
- Binary executing from a user-writable path with no corresponding legitimate install.
- Confirmed network callout to a domain/IP with no business justification, immediately following process launch.
- Hash matches known-bad or is flagging on multiple AV engines after the fact.
- Chain terminates in a dropped executable, DLL, or script under `%TEMP%`/`%APPDATA%`.

## False Positive / Benign Positive Indicators

- Legitimate software installer using `msiexec.exe` or `regsvr32.exe` as part of a signed, expected deployment (check against your CMDB/patch calendar).
- Internal admin tooling or RMM agent that legitimately shells out to `rundll32.exe`/`wscript.exe` for a known function — should already be allow-listed, if not, feed it back to detection engineering.
- IT-run script (SCCM/Intune/GPO logon script) using `cscript.exe`/`wscript.exe` against a known internal share path.
- Developer or power-user running a personal automation script with benign encoded PowerShell (still worth a quiet word, not an incident).

## Escalation Criteria

Escalate to Tier 2 / IR when: the process chain includes a confirmed external network connection to an uncategorized or newly-observed domain, when the source host is a server or domain controller rather than a standard endpoint, when script-block content decodes to a known offensive-tooling pattern (download-and-execute, in-memory loader), or when the same hash/command-line pattern appears on more than one host within the escalation window — that's no longer "suspicious process," that's a spreading incident.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority |
|---|---|
| EDR-isolate the single endpoint pending investigation | Tier 1/2 analyst, no additional approval, reversible |
| Kill the process tree via EDR live-response | Tier 2 analyst |
| Block hash/domain at EDR and proxy/firewall | Tier 2 analyst, notify detection engineering for rule tuning |
| Disable the user account (if credential misuse suspected) | IR lead approval, coordinate with IAM/HR if user-facing |
| Isolate a server/DC-class asset | IR lead + infrastructure owner sign-off (production impact) |

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once the chain escalates to High (external network hop, encoded interpreter, or server/DC source host).

## Example Query (KQL – Microsoft Defender / Sentinel)

```kql
DeviceProcessEvents
| where FileName in~ ("rundll32.exe","regsvr32.exe","mshta.exe","certutil.exe","wscript.exe","cscript.exe")
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","cmd.exe","powershell.exe")
| where ProcessCommandLine has_any ("http://","https://","-enc","-EncodedCommand","/i:http")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the host is isolated/remediated, the artifact is blocked fleet-wide, and no further callout activity is observed for 24 hours. Close as **Benign Positive** once the parent application, path, and command line are confirmed against a known-good software inventory or change record. Close as **Insufficient Evidence** when command-line auditing was disabled on the source host, Sysmon wasn't deployed there, or the process had already exited and no file/network telemetry survived retention — don't force a verdict the evidence doesn't support, note the telemetry gap explicitly so detection engineering can fix coverage.

**Example case note:**
> 2026-09-15 14:02 UTC — `mshta.exe` (PID 5412) spawned by `winword.exe` on host `WKS-FIN-014` (user `l.ortiz`), command line referenced `http://update-cdn-check[.]com/a.hta`. Sysmon ID 3 confirmed outbound to 185.x.x.x:443 within 4s of launch, no file drop observed (ID 11 clean). Hash first-seen in environment, 0/70 on submission but domain registered 6 days prior. Host isolated via EDR, hash+domain blocked, user's mailbox searched for the delivery message (macro-enabled attachment found, phishing playbook opened). Closed here as True Positive, handed to PB-EMAIL-PHISH-002 for the delivery-vector side.
