# EP-019 Registry Run Key Persistence

## Playbook ID & Name

**EP-019 - Registry Run Key / RunOnce Persistence**
Category: Endpoint - Persistence & Impact
Maps to detection content covering `HKLM\...\Run`, `HKCU\...\Run`, `RunOnce`, `RunServices`, and the corresponding Load/Winlogon Shell substitution variants.

## Business Risk

**[STAKEHOLDER]** - A Run key entry means malicious code is configured to restart automatically every time a user logs on or the machine boots - the attacker doesn't need to keep a live connection open, and a simple reboot or antivirus quarantine of the dropped file won't remove the underlying re-infection mechanism. Left unresolved, this is how a single phishing click on a laptop turns into a persistent foothold that survives patch Tuesday reboots, password resets, and even a full AV clean, until someone finds and deletes the registry value itself.

## Severity / Priority Default

**High** on servers, domain controllers, or any host tagged as a privileged-access workstation. **Medium-High** on standard end-user endpoints, with automatic upgrade to High if the payload path resolves to a temp/download directory, a LOLBin is invoked, or the same registry value/hash correlates across more than one host.

## MITRE ATT&CK Technique(s)

- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (primary)
- **T1059.001 / T1059.003** - PowerShell or cmd.exe frequently used to write the value or as the payload itself
- **T1027** - Obfuscated Files or Information, where the Run key command line contains encoded PowerShell (`-enc`, `-EncodedCommand`) or string-splitting tricks
- **T1218.011 / T1218.010** - Rundll32 or Regsvr32 referenced as the Run key's target binary (LOLBin proxy execution)
- **T1105** - Ingress Tool Transfer, where the file the Run key points to was recently downloaded

## Trigger / Detection Logic Summary

Alert fires on a registry value **create** or **modify** event under any of the known autostart locations, where the value data (the command that will execute) matches one or more suspicion heuristics: points outside `Program Files` / `Windows`, references a script interpreter or LOLBin, contains encoded/obfuscated content, or was written by a process that itself has no legitimate reason to touch autorun keys (browsers, Office apps, archive utilities, `mshta.exe`). Sysmon event ID 13 (RegistryEvent - value set) against the Run key paths is the primary trigger; event ID 12 catches key creation for less common variants (e.g., a new custom Run subkey). A secondary, lower-confidence trigger on legacy environments without Sysmon uses 4657 registry auditing if explicitly enabled (rare - most estates rely on Sysmon for this).

**Canonical registry paths in scope:**

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit values)
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager (BootExecute)
```

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 13 | RegistryEvent (Value Set) - the value data written to the Run key, and the writing process |
| Sysmon | 12 | RegistryEvent (Create/Delete) - new Run subkey creation, or attacker cleanup/deletion afterward |
| Sysmon | 1 | Process Creation - identifies the process that wrote the key (parent chain, command line, hashes) |
| Sysmon | 11 | FileCreate - correlates the dropped payload file the Run value points to, with timestamp |
| Windows Security | 4688 | Corroborating process creation if Sysmon isn't deployed on that host (command line only if audited) |
| Windows Security | 4624/4634 | Establishes the logon session context for interactive vs. remote-triggered writes |
| PowerShell Operational | 4104 | Script block content if the write was performed via PowerShell (`Set-ItemProperty`, `reg add`) |

## Key Fields to Inspect

**[ANALYST]**

- **TargetObject** (Sysmon 13) - the full registry key\value path, e.g. `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDriveSync`
- **Details** (Sysmon 13) - the value data, i.e. the actual command line that will run at logon
- **Image / ParentImage** (Sysmon 1/13) - which process wrote the value, and what spawned that process
- **CommandLine** (Sysmon 1) - full command line of the writing process (watch for `reg add`, `powershell -c Set-ItemProperty`, or direct API calls from a dropped .exe)
- **User** - the account context the write occurred under (SYSTEM writes to HKLM are far more significant than a user writing to their own HKCU)
- **Hashes** (Sysmon 1/11) - SHA256 of the target binary/script the Run value points to, for reputation lookup
- **UtcTime** - correlate the registry write timestamp against the file creation timestamp of the referenced payload; a value pointing to a file created seconds earlier is a strong TP signal

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Value name matches a known vendor product ("OneDrive", "Dropbox", "Zoom", "Adobe Updater") and points into `C:\Program Files\...` with a signed binary | Value points into `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, or `C:\ProgramData\` with a random or misspelled name |
| Written during software install by an MSI/installer process (`msiexec.exe`, vendor setup .exe) with a valid signature | Written by `powershell.exe`, `wscript.exe`, `mshta.exe`, `cmd.exe`, or an Office child process shortly after a phishing attachment execution |
| Value data is a short, direct path to an .exe with no arguments | Value data includes `-enc`, `-w hidden`, `-nop`, base64 blobs, or chains through `rundll32.exe`/`regsvr32.exe` |
| Consistent across the fleet via GPO/SCCM software deployment | Appears on one or two hosts only, no matching change-control ticket |
| Value name is descriptive and matches the installed product name | Value name is a single random string, GUID-like, or deliberately mimics a legitimate name with a typo ("OneDrvie", "Sytem32Update") |

## Investigation Steps

1. Pull the full **Sysmon 13** event: capture `TargetObject`, `Details`, `Image`, `ParentImage`, and `UtcTime`. Confirm whether this key path is one that's legitimately managed on this host (check asset/software inventory).
2. Pivot on the writing process's hash and command line. Check EDR/AV verdict and run the hash against your threat intel platform or VirusTotal. If the writing process is `powershell.exe`, pull the matching **4104** script block for the exact command used.
3. Resolve the target of the Run value - does the referenced file/script actually exist on disk? Pull **Sysmon 11 (FileCreate)** for that path to get its creation timestamp, and compare against the registry write time. A near-simultaneous drop-then-persist pattern is a strong indicator this isn't legitimate software install behavior.
4. Trace the process lineage backward using **Sysmon 1** parent chain. Does it terminate in a browser, `outlook.exe`/`winword.exe`, an archive extractor, or a removable media path? This tells you the likely initial access vector (phishing, drive-by, USB).
5. Check for related persistence mechanisms on the same host in the same time window - scheduled tasks (4698), new services (7045/4697), and additional Run key writes. Attackers frequently lay down two or three autostart mechanisms as redundancy.
6. Determine scope: query EDR/SIEM across the fleet for the same registry value name, same file hash, or same payload path on other endpoints. Default lookback 7 days; extend to 30 days once confirmed True Positive. A single value name recurring across ten hosts within an hour points to a mass-deployment tool (GPO push, worm-like spreader, or an already-compromised admin account), not an isolated infection.
7. If the box is a server or has elevated/domain-admin logons in its recent 4624/4672 history, treat this as a higher-severity case regardless of the malware verdict - persistence on a privileged asset changes the blast radius calculation.
8. Capture the full command line, target binary hash, and registry path in the case notes before remediation - this is your evidence set if the case needs to go to IR/legal or gets reopened later.

## True Positive Indicators

- Value data references a binary/script in a user-writable, non-standard path (`%TEMP%`, `%APPDATA%\Roaming`, `C:\Users\Public\Downloads`)
- Writing process is an unsigned or recently-dropped executable, or a scripting engine invoked with obfuscation flags
- Payload file hash has known-bad reputation or zero prior prevalence in the environment
- Registry write occurs within seconds/minutes of a phishing attachment execution, macro run, or suspicious download (Sysmon 22/3 correlation)
- Value name deliberately mimics a legitimate product but with a subtle typo, or is a random string with no descriptive intent
- Same value/hash appears on multiple hosts with no corresponding software deployment record

## False Positive / Benign Positive Indicators

- Legitimate software installer (signed, known vendor) writing its own updater/tray-icon entry as part of normal setup - cross-check against a recent 4688/Sysmon 1 install event for that product
- IT-managed software (VPN client, EDR agent itself, printer utility, collaboration tool) adding itself via GPO or SCCM baseline - confirm against your approved software baseline
- User-installed but legitimate freeware/utility that happens to add a Run entry (common with some accessibility tools, clipboard managers) - Benign Positive if hash/vendor check out clean and there's no malicious payload behavior
- Duplicate alert from the same legitimate install triggering both HKLM and WOW6432Node writes for a 32-bit component on 64-bit Windows - expected and not two separate incidents

## Escalation Criteria

Escalate to Tier 2 / IR immediately if: the target host is a domain controller, privileged-access workstation, or has recent admin-equivalent logons (4672); the same artifact is confirmed on more than one host; the payload hash matches known ransomware precursor or known APT tooling in threat intel; or the writing process chain shows evidence of credential access, lateral movement tooling staging, or C2 beaconing (Sysmon 3/22) alongside the persistence write. A single isolated adware-style Run key on a non-privileged kiosk machine with a benign-reputation hash generally does not need IR escalation - handle at Tier 1/2 with standard remediation.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority | Notes |
|---|---|---|
| Isolate host via EDR network containment | Tier 1 analyst, no approval needed if TP confidence high | Standard for confirmed malicious Run key with active payload |
| Delete/quarantine registry value and referenced file | Tier 1/2 analyst | Document exact key path and value data removed before deletion, in case rollback is needed |
| Domain-wide hunt/remediation sweep (same value/hash across fleet) | SOC Lead sign-off | Coordinate with IT Ops before mass remote remediation to avoid breaking legitimate deployments matched by weak heuristics |
| Disable/reset credentials for the account under which the write occurred | IR Lead approval | Only if evidence suggests credential compromise rather than local-only infection |
| Full forensic image before remediation | IR Lead, required for servers/DCs or suspected targeted intrusion | Skip for routine commodity-malware cases on standard endpoints |

Standard SLA: Tier 1 triage and initial verdict within 30 minutes of alert; full investigation and containment decision within 4 hours for standard endpoints, 1 hour for privileged/server assets.

## Example Query (Sysmon via KQL / Microsoft Sentinel style)

**[ENGINEERING]**

```kql
SysmonEvent
| where EventID == 13
| where TargetObject has_any (
    @"CurrentVersion\Run", @"CurrentVersion\RunOnce")
| where Details has_any ("powershell", "cmd.exe", "wscript", "mshta",
    "rundll32", "regsvr32", "AppData", "Temp", "-enc", "-EncodedCommand")
| project TimeGenerated, Computer, Image, ParentImage, TargetObject, Details, User
| order by TimeGenerated desc
```

## Closure Criteria

Close as **True Positive - Remediated** once the malicious registry value and referenced payload file are removed, host has passed a post-remediation EDR scan clean, and no re-creation of the value is observed for at least one full logon/reboot cycle. Close as **Benign Positive** when the writing process and payload are confirmed as legitimate vendor software matched against the approved baseline. Close as **Insufficient Evidence** when the referenced file no longer exists on disk, no EDR telemetry captured the writing process's command line, and no matching activity is found on peer hosts - note the gap for the retention/coverage backlog rather than guessing at intent.

**Example case note:** *"Sysmon 13 on WKSTN-0221 showed HKCU Run value 'AdobeARMHelper' pointing to C:\Users\jcole\AppData\Roaming\upd.exe, written by powershell.exe (parent: WINWORD.EXE) 4 minutes after a macro-enabled attachment was opened per Outlook logs. Hash of upd.exe matched a known loader family, zero prior prevalence in environment. Confirmed on 1 additional host (WKSTN-0347, same value name, same hash) - both isolated via EDR, value and file removed, local admin password rotated. Escalated to IR for scope confirmation across fileshare access from WKSTN-0221 during the dwell window. Closed as True Positive - Remediated, IR case #4471 opened for lateral scope check."*
