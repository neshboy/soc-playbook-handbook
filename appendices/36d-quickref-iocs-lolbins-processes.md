# Appendix 36D: Quick Reference - IOC Types, LOLBins, Persistence Locations & Process Lineage

This one lives next to 36A on the wall. It's the "is this normal" cheat sheet - what an indicator actually is, which built-in Windows binaries get abused for living-off-the-land activity, where persistence likes to hide, what a clean process tree looks like, and which parent-child pairings should make you sit up. None of this replaces the detection logic in the main chapters; it's the fast-lookup layer for triage under time pressure.

## Common Indicator of Compromise (IOC) Types

Not every IOC is the same shape, and mixing them up costs time in a ticket. This table is the taxonomy.

| IOC Type | Example | Typical Source | Notes |
|----------|---------|-----------------|-------|
| IPv4 address | `203.0.113.44` | Firewall, proxy, NetFlow, C2 sandbox report | Check for private-range false hits (10.x, 172.16-31.x, 192.168.x) before treating as external |
| Domain name | `update-service.example.net` | DNS logs, proxy logs, sandbox detonation | Newly registered domains and high-entropy subdomains deserve extra scrutiny |
| URL | `hxxp://example.com/payload.php?id=1` | Email gateway, proxy, EDR network events | Defanged notation (`hxxp`, `[.]`) is a reporting convention, not a detection value - normalize before matching |
| File hash (MD5/SHA1/SHA256) | `d41d8cd98f00b204e9800998ecf8427e` | AV/EDR alert, VirusTotal, malware sandbox | Prefer SHA256; MD5/SHA1 still show up in older feeds and legacy tooling |
| File path | `C:\Users\Public\svchost.exe` | EDR process telemetry, Sysmon Event ID 1 | Wrong-location legitimate-sounding filenames are a strong signal on their own |
| Email address / sender | `billing@examp1e-corp.com` | Email gateway headers, phishing report | Lookalike domains (0/O, 1/l substitution) are the giveaway - read it character by character |
| Registry key/value | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` | Sysmon Event ID 13, EDR registry telemetry | Value data (the command it runs) matters as much as the key path |
| Mutex name | `Global\MtxSvcHostUpd` | Sandbox/malware analysis report | Useful for hunting across an environment but rarely useful alone for blocking |
| User agent string | `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36` | Proxy/web logs | Outdated or malformed UA strings on modern OS builds are a mild anomaly signal |
| Certificate hash/thumbprint | `SHA1: 3B:1E:...` | Code-signing telemetry, EDR | Stolen or living-off-trust certs are increasingly common in signed malware |
| CVE / vulnerability ID | `CVE-2024-XXXXX` | Vulnerability scanner, threat intel bulletin | Not an IOC of compromise by itself - it's context for why an exploit attempt might target a host |
| ASN / network range | `AS64500` | Threat intel enrichment, GeoIP/ASN lookup | Useful for pivoting on hosting infrastructure reused across campaigns |

**[ANALYST]** - When an IOC lands in a ticket from a feed or intel report, don't just search-and-close on a single match. A single hash hit against an old signed installer, or a single IP hit against a shared CDN range, is not the same confidence level as a domain match tied to a known C2 pattern plus outbound beacon timing. Pull context before writing the verdict.

## Common LOLBins (Living-Off-the-Land Binaries)

These are legitimate, signed Windows binaries that get repurposed by attackers to download, execute, or move data while blending into normal admin noise. Presence of the binary is never itself the alert - the *argument set* and *parent process* are what turn this into a detection.

| Binary | Legitimate Use | Common Abuse | Watch For |
|--------|-----------------|--------------|-----------|
| `powershell.exe` / `pwsh.exe` | Admin scripting, automation, module management | Download-and-execute, in-memory payloads, obfuscated commands | `-enc`, `-EncodedCommand`, `-nop`, `-w hidden`, `IEX (New-Object Net.WebClient)` patterns |
| `certutil.exe` | Certificate/CRL management | File download (`-urlcache`), base64 decode/encode of payloads | `-urlcache -f`, `-decode`, `-decodehex` outside of PKI admin context |
| `mshta.exe` | Runs HTML Application (.hta) files | Executes remote/local script payloads, sandbox evasion | Any invocation with a URL argument or spawned from Office/browser |
| `regsvr32.exe` | Registers/unregisters DLL and ActiveX controls | "Squiblydoo" - remote script execution via `/i:` scriptlet | `/i:http`, `/s /u /i:` combinations, no local DLL argument |
| `rundll32.exe` | Executes exported functions from DLLs | Loads malicious DLL, proxy-executes shellcode | Unusual DLL paths (Temp, AppData, Public), unexplained export names |
| `wmic.exe` | System/WMI administration | Remote process creation, recon, persistence via WMI event subscriptions | `process call create`, `/node:` against remote hosts from a workstation |
| `bitsadmin.exe` | Background Intelligent Transfer for Windows Update etc. | Stealthy file download/upload via BITS jobs | `/transfer`, `/create` with an external URL |
| `msiexec.exe` | Installs Windows Installer packages | Executes remote .msi payloads bypassing some app-control rules | `/i` with an `http`/`https` source, unsigned or unknown package |
| `csc.exe` / `cvtres.exe` | .NET/C# compilation toolchain | On-the-fly compilation of malicious code from a dropped .cs file | Invocation from a user Temp directory rather than dev tooling |
| `installutil.exe` | .NET installer utility for Windows services | Executes arbitrary .NET assemblies, bypasses some allow-listing | Run against a binary with no real installer intent |
| `wscript.exe` / `cscript.exe` | Runs VBScript/JScript (.vbs/.js) | Executes malicious scripts dropped by macros or email attachments | Script path in Temp/Downloads/AppData, spawned from Office |
| `schtasks.exe` | Creates/manages scheduled tasks | Persistence mechanism, delayed execution | `/create` with a Temp/AppData binary path or a suspicious trigger |
| `net.exe` / `net1.exe` | Local/domain user and share management | Recon (`net group`, `net user`), lateral prep | High-frequency use across many hosts in a short window |
| `curl.exe` / `certoc.exe` | Native file transfer (Win10+), cert operations | Payload download, C2 fetch | External destination, unusual scheduling, chained to execution |
| `msbuild.exe` | Builds .NET projects from a build tool file | Executes inline task code embedded in a project XML file | Run from a non-dev host, project file in Temp/user profile |
| `odbcconf.exe` | ODBC driver configuration | Loads/executes an attacker DLL via a response file | `/a {REGSVR ...}` action against an unexpected DLL |

**[ENGINEERING]** - LOLBin detections need parent-process and argument context baked into the logic, or the false-positive rate will bury the queue. A `certutil.exe -decode` with no `-urlcache` and launched by a PKI management tool is routine; the same binary launched by `WINWORD.EXE` with a `-urlcache -f http` argument set is not. Build the rule around the combination, not the binary name alone.

## Common Windows Persistence Locations

Where attackers plant something to survive reboot, logoff, or an initial cleanup attempt.

| Location | Mechanism | Relevant Telemetry |
|----------|-----------|---------------------|
| `HKCU\...\Run` / `HKLM\...\Run` | Registry Run key launches program at logon | Sysmon Event ID 13 (registry value set) |
| `HKCU\...\RunOnce` / `HKLM\...\RunOnce` | Same as Run but self-deletes after one execution | Sysmon Event ID 13 |
| Startup folder (`...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) | Shortcut/script dropped for per-user auto-launch at logon | File creation events, Sysmon Event ID 11 |
| Scheduled Tasks (`schtasks`/Task Scheduler) | Task with a time, logon, or event-based trigger runs a command | Windows Event ID 4698 (created), 4702 (updated), Sysmon Event ID 1 for the eventual execution |
| Windows Services (`services.msc` / SCM) | New or modified service launches a binary at boot with SYSTEM-level context | Windows Event ID 4697 (Security log), 7045 (System log) |
| WMI Event Subscriptions | Filter + consumer pair triggers a command on a system event | WMI-Activity operational log, Sysmon Event ID 19/20/21 where configured |
| DLL search-order hijack (app directory or PATH) | Malicious DLL placed where a legitimate app loads it by name before the real one | Sysmon Event ID 7 (image load), unexpected DLL path relative to the loading EXE |
| COM hijacking (`HKCU\...\Classes\CLSID\{...}\InprocServer32`) | Overwritten CLSID entry points to attacker DLL instead of the legitimate one | Sysmon Event ID 13 on the CLSID registry path |
| Image File Execution Options (IFEO) Debugger key | `Debugger` value hijacks launch of a target executable (classically Utilman/sethc for RDP tricks) | Sysmon Event ID 13 on the IFEO key |
| Winlogon Shell/Userinit keys | Replaces or appends to the shell/logon script launched at interactive logon | Sysmon Event ID 13 |
| AppInit_DLLs / LSA extensions | DLL forced to load into every process using User32, or into LSASS | Sysmon Event ID 7/13 depending on mechanism, high-severity if LSASS-adjacent |
| Browser extensions | Malicious/rogue extension retained across restarts, harvests session/cookies | Browser extension inventory, EDR browser-telemetry modules where available |
| Office Add-ins / Startup templates | Add-in or template auto-loads with Office and can run macro code | File creation in Office startup paths, macro execution telemetry |

**[STAKEHOLDER]** - Persistence mechanisms are why "we removed the malware" and "the incident is closed" are not the same sentence. A single missed Run key or scheduled task means the attacker walks back in on the next reboot cycle. Closure sign-off should require a persistence sweep, not just malware removal, and that sweep is a documented step owned by the IR lead - not an assumption.

## Common Windows Processes and Normal Parentage

Baseline lineage for everyday Windows processes. Anything that deviates from this on a given host is worth a second look, not an automatic verdict.

| Process | Normal Parent | Normal Behavior |
|---------|----------------|-------------------|
| `smss.exe` | `System` (PID 4) | Session manager, spawns `csrss.exe`/`wininit.exe`, then exits per session |
| `csrss.exe` | `smss.exe` (transient, then orphaned under `System`) | Client/server runtime, no children expected in normal operation |
| `wininit.exe` | `smss.exe` | Spawns `services.exe` and `lsass.exe` at boot |
| `services.exe` | `wininit.exe` | Service Control Manager - parent to legitimate service host processes |
| `svchost.exe` | `services.exe` | Hosts DLL-based Windows services; multiple instances are normal, each with a distinct `-k` group argument |
| `lsass.exe` | `wininit.exe` | Local Security Authority - handles auth/token operations, should have essentially no child processes |
| `winlogon.exe` | `smss.exe` | Handles interactive logon (Secure Attention Sequence, lock screen), spawns `userinit.exe` at logon |
| `userinit.exe` | `winlogon.exe` | Runs logon scripts, launches the user shell (`explorer.exe`), then exits |
| `explorer.exe` | `userinit.exe` | User shell - normal parent for user-launched applications (browsers, Office, utilities) |
| `taskhostw.exe` | `svchost.exe` | Hosts DLL-based scheduled task actions |
| `RuntimeBroker.exe` | `svchost.exe` | Brokers permission checks for UWP/Store apps |
| `dllhost.exe` | `svchost.exe` (via COM/DCOM activation) | Hosts COM surrogate objects |
| `spoolsv.exe` | `services.exe` | Print spooler service |
| `WINWORD.EXE` / `EXCEL.EXE` / `POWERPNT.EXE` | `explorer.exe` | Office apps launched by the user from the shell or a file association |
| `outlook.exe` | `explorer.exe` | Email client launched by the user |
| `powershell.exe` | `explorer.exe` (interactive) or a scripting/automation parent (`taskeng.exe`, `wsmprovhost.exe`, an RMM agent) | Admin or automation scripting - parent context determines whether it's routine |
| `cmd.exe` | `explorer.exe` (interactive) or the application that legitimately shells out | Command interpreter - context-dependent, but should trace to a plausible user or automation action |

**[ANALYST]** - `lsass.exe` having zero expected children is one of the highest-value baseline facts in this whole appendix. Any process spawned by `lsass.exe`, or any process opening a handle to it for reading/dumping memory, deserves immediate escalation regardless of what else is going on in the ticket queue that day.

## Suspicious Parent-Child Process Combinations

This is the list to keep in your head during triage. None of these are automatically confirmed-malicious on their own - macros legitimately shell out to PowerShell in some business workflows, and admins do run `cmd.exe` under `services.exe` occasionally for troubleshooting - but every row here should raise the priority of the ticket and trigger a closer look at command-line arguments, file paths, and network activity before closing it as benign.

| Parent Process | Child Process | Why It's Suspicious |
|----------------|-----------------|------------------------|
| `WINWORD.EXE` / `EXCEL.EXE` / `POWERPNT.EXE` | `powershell.exe` | Classic macro-triggered payload delivery - Office documents don't normally need to spawn a scripting engine |
| `WINWORD.EXE` / `EXCEL.EXE` | `cmd.exe` | Macro shelling out to the command interpreter, often chained into a download-and-execute sequence |
| `outlook.exe` | `cmd.exe` / `powershell.exe` | Email client spawning a shell almost always traces back to a malicious attachment or embedded object, not normal mail handling |
| `services.exe` | Any non-service-host binary (not `svchost.exe`/known service EXE) | Service Control Manager launching something outside its normal child set suggests a hijacked or maliciously registered service |
| `lsass.exe` | Any child process at all | LSASS should have no children in normal operation - treat as high-severity regardless of what the child is |
| `spoolsv.exe` | `cmd.exe` / `powershell.exe` / unexpected EXE | Print spooler exploitation (privilege escalation via spooler vulnerabilities has a long history) |
| `mmc.exe` | `powershell.exe` (unexpected context) | Management console spawning a scripting shell outside of an admin's deliberate action |
| `svchost.exe` | `powershell.exe` / `cmd.exe` with no plausible service context | Service host spawning a shell is occasionally legitimate (some scheduled/service scripts) but common in fileless persistence via a hijacked service |
| `java.exe` / `w3wp.exe` (web app pools) | `cmd.exe` / `powershell.exe` | Web application or app-server process spawning a shell is a strong web-shell / RCE indicator |
| `mshta.exe` | `powershell.exe` | Chained LOLBin execution - HTA-triggered script payload, common in phishing kill chains |
| `rundll32.exe` | `powershell.exe` / network-connected child | DLL host spawning a scripting engine is inconsistent with normal DLL export execution |
| `explorer.exe` | `powershell.exe -enc ...` (encoded command) | Even under a normal parent, an encoded/obfuscated command line at launch is a red flag worth pulling the full command line for |
| Any Office app | `mshta.exe` / `regsvr32.exe` / `certutil.exe` | Office documents invoking LOLBins directly is a strong macro-abuse signal |
| `AcroRd32.exe` / `Acrobat.exe` | `cmd.exe` / `powershell.exe` | PDF reader spawning a shell suggests exploitation of a reader vulnerability or embedded action |
| `taskeng.exe` / `svchost.exe` (Task Scheduler context) | Binary in `Temp`, `AppData`, or `Public` paths | Scheduled task persistence executing from a non-standard, user-writable location |

**[ENGINEERING]** - When building correlation logic off this table, match on `(ParentImage, Image)` pairs from Sysmon Event ID 1 or your EDR's equivalent process-creation telemetry, then layer a second condition on command-line content and destination path before firing a high-severity alert. A bare parent-child match without argument context will generate volume the team stops trusting within a week.

**[MANAGEMENT]** - These five tables are the kind of content that should be reviewed on a fixed cadence (quarterly is reasonable) against current threat intel and any environment-specific baseline changes - a new RMM tool, a new line-of-business app that legitimately spawns `cmd.exe`, or a LOLBin technique that's fallen out of active use. Ownership for the review sits with detection engineering; sign-off on any baseline change belongs with the SOC lead, since it directly affects what gets suppressed versus escalated.
