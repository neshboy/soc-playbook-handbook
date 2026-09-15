# EP-007: Suspicious rundll32 Usage

**Category:** Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - rundll32.exe is a signed Microsoft binary present on every Windows host, which is exactly why attackers use it: it lets malicious code run under a trusted process name and slip past application allow-listing and naive AV signatures. Left unchecked, this is a common first-stage execution point for phishing payloads and commodity loaders, and it's frequently the pivot into credential theft or ransomware staging. Getting this detection tuned well is a cheap, high-leverage control - it rarely requires new tooling, just disciplined baselining of what "normal" rundll32 looks like in your environment.

## Severity / Priority Default

**Medium** on initial trigger. Escalates to **High** when paired with network beaconing, an unsigned dropped DLL, or a child process chain (rundll32 spawning cmd.exe/powershell.exe).

## MITRE ATT&CK Techniques

- **T1218.011** - System Binary Proxy Execution: Rundll32 (primary)
- **T1204** - User Execution (phishing lure triggers the chain)
- **T1566.001 / T1566.002** - Phishing: Attachment / Link (common delivery vector)
- **T1027** - Obfuscated Files or Information (encoded/obfuscated command-line arguments)
- **T1105** - Ingress Tool Transfer (rundll32 pulling a second-stage payload)
- **T1059.001** - Command and Scripting Interpreter: PowerShell (frequent downstream chain)
- **T1055** - Process Injection (rundll32 hosting a malicious DLL that then injects into another process, or rundll32 itself being used as the injected-into target) - this is a follow-on/branch technique, confirmed via Sysmon 8/10 below, not something the base trigger logic detects on its own

## Trigger / Detection Logic Summary

Alert fires on process creation for `rundll32.exe` where one or more of the following hold: the referenced DLL path is outside `%SystemRoot%\System32` or `%SystemRoot%\SysWOW64`; the command line contains the `javascript:` pseudo-protocol; the export function name doesn't match a maintained allow-list of known-legitimate calls (e.g. `Control_RunDLL`, `PrintUIEntry`); the parent process is a browser, Office application, `wscript.exe`, `cscript.exe`, or `mshta.exe`; or the process initiates an outbound network connection or DNS query within a short window of launch. Don't run this as a single monolithic rule - split "unusual path/parent" (higher fidelity) from "network activity post-launch" (needs correlation) or you'll bury analysts in noise from legitimate installer routines.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Full command line, parent process/command line, hashes, integrity level |
| Sysmon | 3 (Network Connection) | Outbound connections attributed to the rundll32.exe PID |
| Sysmon | 7 (Image Loaded) | DLL side-loading / unsigned or unusual module loads into the process |
| Sysmon | 8 (CreateRemoteThread) | rundll32.exe creating a remote thread in another process, or another process creating one inside rundll32.exe - the actual evidence behind the T1055 mapping |
| Sysmon | 10 (ProcessAccess) | Handle opens between rundll32.exe and a sensitive target (e.g. `lsass.exe`) - same purpose as 8, catches injection techniques that don't use CreateRemoteThread |
| Sysmon | 11 (FileCreate) | Correlate the DLL's drop event if it landed via download/attachment |
| Sysmon | 22 (DNSEvent) | DNS resolution tied directly to the rundll32.exe process |
| Windows Security | 4688 | Fallback process creation record where Sysmon isn't deployed (command line only if auditing enabled) |
| Windows Security | 4689 | Process exit/exit status, useful for short-lived loader behaviour |

## Key Fields to Inspect

**[ANALYST]**
- `Image` / `New Process Name` - confirm it's actually `rundll32.exe`, not a renamed binary masquerading as it (check the hash and signature, not just the filename)
- `CommandLine` - the DLL path and export function called; this is the single most important field in this whole investigation
- `ParentImage` / `ParentCommandLine` - who launched it and how (double-click from Explorer vs. spawned from a macro)
- `Hashes` (SHA256) on both `rundll32.exe` and the target DLL - pivot to VirusTotal/internal TI
- `IntegrityLevel` - medium is typical for user-invoked calls; high/system warrants a closer look
- `CurrentDirectory` - working directory outside expected system paths is a tell
- Sysmon 3/22 `DestinationIp`, `DestinationPort`, `QueryName` tied to the same `ProcessGuid`

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| DLL path | `C:\Windows\System32\shell32.dll`, `printui.dll` | `C:\Users\<user>\AppData\Local\Temp\upd8r.dll`, `C:\ProgramData\*.dll` |
| Export called | `Control_RunDLL`, `PrintUIEntry`, known vendor entry points | Unnamed/obscure export, `javascript:` protocol handler abuse |
| Parent process | `explorer.exe`, `services.exe`, signed installer | `WINWORD.EXE`, `EXCEL.EXE`, `mshta.exe`, browser process |
| Signature on DLL | Microsoft or known vendor, valid chain | Unsigned, self-signed, or signature check fails |
| Network activity | None, or expected update-check traffic from known vendor process | Connection to newly registered domain or raw IP within seconds of launch |
| Child processes | None | `cmd.exe`, `powershell.exe`, another `rundll32.exe` instance |

## Investigation Steps

1. Pull the full Sysmon Event ID 1 record for the `rundll32.exe` process: command line, parent image/command line, hashes, integrity level, and working directory.
2. Check the DLL path and export function against your environment's allow-list of known-legitimate rundll32 invocations (printing, Control Panel applets, vendor installer/update routines). If it's on the list and nothing else looks off, this is likely a benign positive - don't over-investigate a printui.dll call.
3. Trace parent-child lineage. `explorer.exe` as parent with an interactive logon nearby (4624) reads very differently than `WINWORD.EXE` or a browser process as parent, which points at a phishing or drive-by chain.
4. Pivot on the process's Sysmon 3 network connections and Sysmon 22 DNS queries. Any external IP/domain contacted within roughly 60 seconds of process launch is worth reputation-checking immediately - don't assume it's noise just because the DLL name sounds legitimate.
5. Check Sysmon 7 for images loaded into the rundll32.exe process - unsigned or unusual DLLs loaded from user-writable paths are a strong signal of side-loading.
6. Look for child processes spawned from rundll32.exe (Sysmon 1 with `ParentImage=rundll32.exe`). A `cmd.exe /c` or `powershell.exe -enc` child is close to a confirmed finding on its own.
7. Check Sysmon 8 (CreateRemoteThread) and Sysmon 10 (ProcessAccess) for rundll32.exe either opening a handle to / creating a thread in another process, or being the target of one from an unrelated process - this is the actual evidence behind the T1055 process-injection mapping, not something to assume from the LOLBin name alone.
8. Correlate host/account context: is this a shared kiosk, a VIP endpoint, a server? Check whether the same command line or DLL hash appears on other hosts - a single hash across multiple endpoints usually means a phishing campaign, not an isolated incident.
9. If indicators support malicious intent, preserve the DLL sample and relevant Sysmon/EDR telemetry before remediation, then move to containment.

## True Positive Indicators

- Command line uses the `javascript:` pseudo-protocol to invoke script execution via a DLL such as an mshtml/url handler
- DLL loaded from `%TEMP%`, `%AppData%`, `%ProgramData%`, or a similarly user-writable path, and unsigned
- Hash of the DLL matches a known loader/malware family in threat intel
- Parent process is an Office application, `mshta.exe`, or a browser, consistent with a phishing execution chain
- Outbound connection or DNS lookup to a newly registered domain or bare IP address immediately following launch
- Child process spawned from rundll32.exe (command shell, PowerShell, another LOLBin)

## False Positive / Benign Positive Indicators

- Export call matches a well-documented Control Panel applet (`shell32.dll,Control_RunDLL desk.cpl`) or printing routine (`printui.dll,PrintUIEntry`)
- DLL is Microsoft-signed or signed by a recognized vendor and resides in `System32`/`SysWOW64` or the vendor's Program Files directory
- Parent process is a known, signed installer or Group Policy client-side extension performing a routine software update/config task
- No associated network activity and no child processes
- Activity matches a documented, recurring pattern already reviewed and baselined for this host/application

## Escalation Criteria

Escalate to Tier 2/IR when: confirmed outbound beaconing to an untrusted destination is observed alongside an unsigned DLL; the same command line or hash appears on more than one host; the affected asset is a server, domain controller, or VIP endpoint; process access to `lsass.exe` is observed nearby (hand off to the credential-dumping playbook); or EDR/AV independently flags the same PID/hash.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Kill the offending process and quarantine the DLL - Tier 2 analyst authority, no separate approval needed once TP is confirmed
- Isolate a standard user workstation via EDR network isolation - Tier 2 analyst may action directly under delegated authority
- Isolate a server, domain controller, or VIP asset - requires IR Lead (or on-call manager) sign-off before isolation, given business-continuity impact
- Block the associated hash, domain, and IP at proxy/firewall/EDR - SOC Engineering actions on Tier 2 request, logged in the ticket
- Disable the associated user account (if credential compromise suspected) - routed to IAM/Helpdesk with IR Lead approval
- Preserve the sample and relevant telemetry (Sysmon export, EDR timeline) before any remediation that would destroy evidence

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once network beaconing, an unsigned dropped DLL, or a child-process chain escalates the case to High.

## Example Query (Splunk SPL)

```spl
index=sysmon EventCode=1 Image="*\\rundll32.exe"
| where NOT (like(CommandLine, "%shell32.dll,Control_RunDLL%")
             OR like(CommandLine, "%printui.dll,PrintUIEntry%"))
| eval flag=if(match(CommandLine, "(?i)javascript:")
               OR match(CommandLine, "(?i)\\\\(temp|appdata|programdata)\\\\"),
               "high","review")
| table _time, Computer, User, ParentImage, ParentCommandLine, CommandLine, Hashes, flag
```

## Closure Criteria

Close as **True Positive** once the DLL is confirmed unsigned/malicious via hash reputation or sandboxing, the delivery chain (phishing, drive-by, etc.) is identified, and containment is verified complete on all affected hosts. Close as **Benign Positive** or **Expected Activity** when the export call, DLL signature, and path all match documented legitimate use and no network or child-process anomalies exist. Close as **Insufficient Evidence** when command-line auditing wasn't enabled and Sysmon coverage is missing, leaving no way to confirm the DLL/export invoked.

**Example case note:**
> 2026-09-15 14:32 UTC - HOST-FIN-042 (finance workstation, user jdoe) - `rundll32.exe C:\Users\jdoe\AppData\Local\Temp\upd8r.dll,Run` observed, parent `WINWORD.EXE` following the open of macro-enabled attachment `Invoice_3391.docm`. DLL unsigned, SHA256 matched a known loader family in TI (34/70 vendors). Sysmon 3 showed outbound connection to 203.0.113.24:443 approx. 12 seconds post-launch, DNS query for `statica-cdn.example.net` (Sysmon 22) immediately prior. No child processes observed before EDR isolation. Classified True Positive - phishing-delivered loader via rundll32 (T1218.011/T1566.001). Host isolated (Tier 2 authority, standard workstation), hash and domain blocked org-wide, user account credentials rotated as precaution. Escalated to IR for delivery-chain review across mail gateway logs.
