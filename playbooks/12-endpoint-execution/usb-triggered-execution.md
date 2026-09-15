# EP-015 — USB-Triggered Execution

**Category:** Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - Someone plugs in a USB drive - their own, a "found" one from the parking lot, a vendor's firmware stick, a conference freebie - and a file on it runs. This bypasses every control built around email and web traffic: no attachment scanner, no proxy category block, no sandboxing of a download. It's also one of the few vectors that can jump an air-gapped or segmented network, which is exactly why it's a favorite for targeting OT/ICS environments and why "USB drop" is still a live red-team and real-world tactic in 2026. The business exposure isn't just malware on one laptop - it's malware that walked past every perimeter control you paid for, carried in someone's pocket.

## Severity / Priority Default

**Medium** on initial trigger (execution off removable media, unconfirmed intent). Escalate to **High** immediately if the executed process spawns a LOLBin or PowerShell, writes persistence, or the host sits in a restricted/OT/air-gapped segment where USB use is supposed to be controlled or prohibited entirely - in those environments, treat any unapproved execution from removable media as High regardless of payload verdict, because the exposure is the access path itself, not just the file.

## MITRE ATT&CK Techniques

- **T1091** - Replication Through Removable Media (the vector itself - a file staged on removable media that executes when the drive is inserted/opened; this is the technique the whole playbook is named for, and it's also the ID ATT&CK uses for exactly the air-gapped/OT exposure argument made above)
- **T1204** - User Execution (primary - someone double-clicks the file)
- **T1059.001 / T1059.003** - Command and Scripting Interpreter: PowerShell / Windows Command Shell (common follow-on)
- **T1218.005 / T1218.010 / T1218.011** - System Binary Proxy Execution: Mshta / Regsvr32 / Rundll32 (common LOLBin handoff)
- **T1027** - Obfuscated Files or Information (icon/extension masquerade, encoded payloads)
- **T1105** - Ingress Tool Transfer (second-stage payload pulled after initial execution)
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys (persistence set post-execution)

## Trigger / Detection Logic Summary

Alert on process creation where the executable's path resolves to a drive letter outside your environment's standard fixed-volume baseline (commonly `D:` and above, tuned per fleet since some builds legitimately use `D:` for recovery partitions or a second internal disk), **and** the parent process is `explorer.exe` (the user double-clicked it from the drive's window) or there is no parent chain consistent with a mapped network share or ISO mount. Strengthen the signal by correlating a Sysmon FileCreate on the same volume/serial number in the moments before execution - a file that was just written and immediately run looks very different from a document the user has had on a personal drive for months.

A second, complementary trigger: any LOLBin (`mshta.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`, `regsvr32.exe`) or `powershell.exe` whose `ParentImage` is `explorer.exe` and whose `ParentCommandLine` or working directory references a non-system drive letter. This catches the common pattern where the visible double-click is an `.lnk` or masquerading icon, and the actual payload execution is one hop downstream.

One honest gap worth flagging in the ticket every time: there is no Windows Security Event ID in this book's reference set for "USB device inserted" (PnP/device-install events live outside that set). This playbook works entirely off process and file telemetry as a proxy for the insertion event - it tells you something ran from removable media, not the exact moment the device was plugged in. If you need device-serial-level attribution, that comes from EDR device-control telemetry or asset inventory, not from the IDs listed here.

## Required Log Sources & Event IDs

| Source | Event ID | Why |
|---|---|---|
| Sysmon | 1 (Process Creation) | Anchor event - `Image`/`CommandLine` on removable volume, `ParentImage`, hashes, integrity level |
| Sysmon | 11 (FileCreate) | Confirms the file was freshly written to the drive (dropper behavior) vs. long-resident |
| Sysmon | 7 (Image Loaded) | Catches DLL sideload if `rundll32`/`regsvr32` loads a library straight off the USB path |
| Sysmon | 12/13/14 (Registry) | Persistence via Run key set immediately after execution |
| Sysmon | 3 (Network Connection) | Outbound callout tied to the executed process's PID |
| Sysmon | 22 (DNS Event) | Domain resolution attributed to the same PID - first-seen/rare domain check |
| Windows Security | 4688 | Fallback if Sysmon isn't deployed; command line only present if CLI auditing is on |
| Windows Security | 4689 | Confirms a short-lived dropper exited after handing off to a persistent child |
| Windows Security | 4624 | Logon Type 2 (interactive, console) ties the execution to a physical presence, not a remote session |
| Microsoft-Windows-PowerShell/Operational | 4104 (script block), 4103 (module logging) | 4104 carries the decoded script content if the chain hands off to PowerShell; 4103 corroborates which modules/cmdlets ran |

## Key Fields to Inspect

**[ANALYST]**
- `Image` / `CommandLine` (Sysmon 1) - full path including drive letter and volume; note any icon-masquerade filenames (`Invoice.pdf.exe`, `Photos .lnk`, double extensions, trailing spaces)
- `ParentImage` / `ParentCommandLine` - is `explorer.exe` the parent (user click) or is this a second-hop LOLBin spawned by the first payload?
- `Hashes` - hash the executed file, check EDR/internal reputation and threat intel before assuming intent
- `IntegrityLevel` - medium (standard user) is typical; high/system warrants an immediate look at how it got elevated
- `TargetFilename` and `CreationUtcTime` (Sysmon 11) - drive letter, volume serial if your EDR surfaces it, and the delta between file creation and process start
- `User`/logon session from the correlated 4624 - confirm interactive console logon, not RDP/remote, since this is a physical-media scenario
- Sysmon 3 `DestinationIp`/`DestinationPort` and Sysmon 22 `QueryName` - any outbound activity in the seconds/minutes after execution
- Sysmon 12/13/14 `TargetObject` - Run key or similar autostart location written post-execution

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| User opens a `.docx`/`.xlsx` from a personal USB stick, no process spawn beyond the associated Office app | `.exe`/`.scr`/`.lnk` on the drive spawns `mshta.exe`, `wscript.exe`, or `powershell.exe` seconds after being clicked |
| IT technician runs a signed vendor imaging/firmware tool from a labeled, asset-tagged USB drive | Filename uses a document/folder icon on an executable, or a double extension (`Report.pdf.exe`) |
| File on the drive has existed for weeks (personal photos, resume, presentation) | File was written to the drive moments before execution - looks like an autorun-style dropper rather than user content |
| No registry or network activity follows opening the file | Registry Run key write or outbound connection to a rare/newly-registered domain within seconds of execution |
| Drive is asset-inventoried as company-issued (BitLocker To Go, encrypted) | Drive is unlabeled, "found," brought in by a visitor, or the user can't explain where it came from |

## Investigation Steps

1. Pull the Sysmon 1 record for the process: exact `Image` path and drive letter, `CommandLine`, `ParentImage`/`ParentCommandLine`, `User`, `IntegrityLevel`, `Hashes`.
2. Confirm the drive letter is actually removable media, not a mapped network share, mounted ISO, or a legitimate second internal partition on that host - check EDR device info or asset records before treating every non-`C:` path as a USB stick.
3. Correlate Sysmon 11 FileCreate on the same volume in the minutes prior - was this file just dropped (bootstrap/dropper pattern) or has it existed on the drive for a while (ordinary user content)?
4. Check the filename for masquerade patterns (icon mismatch, double extension, right-to-left override characters, trailing whitespace before the real extension) and hash the file against internal EDR reputation and external threat intel.
5. Trace the process tree for follow-on children - did it launch a LOLBin or PowerShell? If PowerShell is involved, pull 4104 to see the actual (de-obfuscated) script content rather than trusting the visible command line.
6. Check Sysmon 12/13/14 for a Run key write and Sysmon 3/22 for outbound network activity tied to the same PID in the following minutes - this tells you whether the chain progressed past initial execution.
7. Correlate the 4624 logon session (Logon Type 2, interactive) to confirm a physical, console-based insertion and identify the exact user; talk to them directly - where did the drive come from, is it personal/company-issued/borrowed/found?
8. Check whether the same file hash, filename, or (if your EDR captures it) USB device serial number has shown up on other hosts - USB drop campaigns and autorun-style worm spread both present as multi-host recurrence over a short window.

## True Positive Indicators

- LOLBin or PowerShell spawned directly from a removable-media path, with an obfuscated or encoded command line
- Icon/extension masquerade on the executed file, or a file that was written to the drive only seconds before it ran
- Registry Run key (or similar autostart) write immediately following execution
- Outbound connection or DNS query to a rare/newly-seen domain shortly after the process launches
- File hash matches a known malware family or threat-intel indicator
- User confirms the drive was unlabeled, found, or from an untrusted source, or can't account for its origin

## False Positive / Benign Positive Indicators

- Company-issued, encrypted (BitLocker To Go) drive with a signed, known-good installer or firmware/diagnostic tool
- IT/AV/EDR technician using approved deployment or imaging media, consistent with a change ticket
- File has a long residency on the drive and is clearly personal content (documents, photos, presentations) with no child-process anomalies
- No registry or network activity follows the execution, and the hash comes back clean across EDR and threat intel
- Drive is inventoried in asset management as a company-issued peripheral tied to that user's role

## Escalation Criteria

Escalate to Tier 2/IR immediately if any persistence artifact is written, a LOLBin/PowerShell chain executes beyond the initial click, the hash matches known threat intel, the same indicator appears on more than one host, or the host sits in a restricted/OT/air-gapped segment - in that last case escalate on the execution event alone, before payload analysis is even complete, because unauthorized USB execution in that kind of environment is itself the policy violation. Also escalate if the user cannot account for the drive's origin (found, unlabeled, given by an unknown party) even if the file itself analyzes as benign - that's a physical-security and awareness issue worth its own track regardless of malware verdict.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Kill the process tree and quarantine the file via EDR - Tier 1/2 analyst, no separate approval, log the action in the case.
- EDR network isolation of the endpoint - Tier 2 can execute unilaterally under standard SOC authority, notify on-call IR lead within 15 minutes.
- Physically retrieve and preserve the USB device for forensics (write-blocked imaging) - requires manager or security lead approval, maintain chain-of-custody documentation from the point of seizure.
- Remove persistence (Run key, scheduled task, service) - Tier 2/3, change-managed action, documented before deletion.
- Org-wide USB mass-storage restriction via GPO or EDR device control - this is a policy decision, not a per-incident action; route to IT/security leadership and change management, not executed ad hoc off a single ticket.
- Disable the user's ability to use USB ports pending investigation - team lead approval, coordinate with the user's manager given the workflow impact.

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once the case escalates to High (LOLBin/PowerShell handoff, persistence write, or a restricted/OT/air-gapped host).

## Example Query (Microsoft Sentinel / KQL, Defender for Endpoint schema)

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "explorer.exe"
| where FolderPath matches regex @"^[D-Z]:\\"
| where FileName has_any ("mshta.exe","wscript.exe","cscript.exe","rundll32.exe",
                           "regsvr32.exe","powershell.exe")
      or FolderPath matches regex @"\.(exe|scr|lnk|hta)$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the executed file, any follow-on LOLBin/PowerShell activity, and persistence/network behavior are confirmed malicious, the host is contained, and the device is either recovered for forensics or its hash/indicators are documented and blocked. Close as **Benign Positive** when the drive is confirmed company-issued/inventoried and the file matches a known-good installer or ordinary user content with no anomalous child processes. Close as **Insufficient Evidence** if the drive was already removed before triage, no FileCreate/process telemetry survived retention, or command-line auditing wasn't enabled - don't force a verdict past what the evidence supports, and log the telemetry gap as a follow-up item so device-control or Sysmon coverage gets reviewed.

**Example case note:** *"WKS-FIN-014 (user r.dawson) - Sysmon 1 shows `E:\Scan_Invoice_0847.pdf.exe` executed with parent `explorer.exe`, IntegrityLevel Medium. Sysmon 11 shows the file was created on the E: volume 40 seconds before execution - not pre-existing content. Process spawned `mshta.exe` with an obfuscated command line referencing `hxxp://cdn-assets-update.example.net/x.hta`. Sysmon 3/22 confirm outbound to that domain, first-seen in environment, no business relationship. Registry Run key write blocked by EDR before persistence completed. User states the drive was handed to her at a vendor conference booth two days prior, not company-issued. Host isolated 14:07 UTC, file hash and domain submitted to blocklist, drive retained for forensic imaging under chain-of-custody log CoC-2291. Verdict: True Positive, T1091/T1204/T1218.005/T1105."*
