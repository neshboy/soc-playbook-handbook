# Execution Stage — Ransomware Master Playbook Deep-Dive

## What "Execution" Actually Looks Like on the Wire

By the time you're looking at execution-stage telemetry, initial access already happened — phishing attachment opened, RDP brute-forced, VPN appliance exploited, whatever. What you're chasing now is the moment the actual encryptor (or the loader that fetches it) runs on a host. This is usually the first point where a SOC gets a *loud* signal, because ransomware operators don't care about being quiet at this stage the way an APT does during recon. They care about coverage and speed. That changes the alert profile: expect volume, expect noise, expect the encryptor to hit dozens of hosts within minutes once it starts.

Most modern ransomware crews (whether it's an affiliate running a RaaS build or an IAB handing off to a human operator) don't drop the final payload directly during initial access. There's almost always a loader or dropper stage first — a small stub whose only job is T1105 Ingress Tool Transfer of the real payload, followed by execution via T1204 User Execution or a scheduled/service-based trigger.

## LOLBins and Proxy Execution

This is where T1218 System Binary Proxy Execution earns its keep in almost every case you'll work.

| LOLBin | ATT&CK ID | Typical use in this stage | What to look for |
|---|---|---|---|
| mshta.exe | T1218.005 | Executes HTA payload that stages loader or decodes embedded script | mshta.exe spawning cmd.exe/powershell.exe as child |
| regsvr32.exe | T1218.010 | "Squiblydoo"-style execution of a scriptlet, sometimes over SMB/WebDAV | regsvr32 /s /n /u /i:<url> scrobj.dll pattern |
| rundll32.exe | T1218.011 | Loads a malicious DLL export directly — very common for the actual encryptor DLL | rundll32.exe with an unusual export name, or loading a DLL from %TEMP%, %APPDATA%, or a UNC path |

Sysmon Event ID 1 (Process Creation) is your primary evidence source here — it captures full command line and parent command line unconditionally, unlike Windows 4688 where command-line auditing has to be explicitly enabled. Pull parent-child chains: `explorer.exe → mshta.exe → powershell.exe → rundll32.exe` is a textbook execution chain, and each hop should be individually suspicious-looking (unsigned binary, unusual working directory, or a UNC-path image name).

**[ANALYST]** - Don't stop at the first LOLBin hit. In active cases the loader frequently daisy-chains two or three of these before the actual encryptor binary or DLL touches disk. Pull the full process tree for the host, not just the alerting node, and check Sysmon Event ID 11 (FileCreate) in the minutes before and after for dropped executables/DLLs in %TEMP%, %ProgramData%, or a mapped admin share.

## PowerShell and Script Execution Patterns

PowerShell shows up constantly, either as the loader stage or as the delivery mechanism for the actual encryption logic (some families run almost entirely in-memory via a PowerShell reflective loader). T1059.001 Command and Scripting Interpreter: PowerShell is the technique; T1027 Obfuscated Files or Information is nearly always layered on top — base64 blobs, `-EncodedCommand`, string concatenation to evade static signatures, `IEX (New-Object Net.WebClient).DownloadString(...)` patterns.

Windows Event ID 4104 (script block logging) is the one log that consistently defeats this obfuscation, because it records the de-obfuscated block after PowerShell's own engine expands it. Event ID 4103 (module logging) gives you pipeline execution and parameter detail alongside it. If 4104 isn't enabled in your environment, flag this now — it's one of the highest-value gaps to close before the next incident, not during it.

T1059.003 Windows Command Shell shows up too, usually for simpler tasks — deleting shadow copies, disabling recovery, or invoking `net`/`wmic` commands from a batch script dropped alongside the loader.

## Persistence and Impairment Riding Alongside Execution

Execution rarely happens in isolation. In the same window you'll typically see:

- T1543.003 Create or Modify System Process: Windows Service, and T1053.005 Scheduled Task/Job, used to make the encryptor re-run or to fan it out — check Windows Event ID 4697/7045 for service installs and 4698 for task creation, and pull Task Content XML for the actual command.
- T1547.001 Boot or Logon Autostart Execution: Registry Run Keys as a lighter-weight persistence option — Sysmon Event ID 13 (RegistryEvent value set) on Run/RunOnce keys.
- T1562.001 Impair Defenses: Disable or Modify Tools — killing or unhooking EDR/AV before the encryptor runs. This is frequently the loudest EDR alert of the whole stage, because most EDR agents self-alert loudly on tamper attempts against their own service or driver.
- T1055 Process Injection — some loaders inject the encryption routine into a legitimate process (explorer.exe, svchost.exe) rather than running it as its own image. Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) are the evidence trail; a non-security process suddenly getting a handle opened into it with unusual access rights is the tell.
- Early T1490 Inhibit System Recovery activity (vssadmin/wmic shadow copy deletion, bcdedit recovery changes) sometimes starts before mass T1486 Data Encrypted for Impact begins — if you catch this, you are still in a containment window, not a cleanup one.

**[ENGINEERING]** - Build correlation logic around the chain, not single events: LOLBin child-of-Office/browser process → 4104 script block containing `DownloadString`/`EncodedCommand` → new service or scheduled task within N minutes on the same host → shadow-copy deletion command. Any three of these firing on one host in a short window should page, not queue.

**[STAKEHOLDER]** - This is the stage where "we got an EDR alert" turns into "we might have an active encryption event." The business decision that matters here is speed of isolation authority — does the on-call analyst have pre-approved authority to isolate a host the instant this chain appears, or does that require a call-out? That approval question needs to be settled before an incident, not during one.
