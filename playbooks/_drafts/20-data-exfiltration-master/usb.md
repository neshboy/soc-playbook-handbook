# Exfiltration via USB Removable Media

USB doesn't get the attention DNS tunneling or cloud-upload exfil gets in threat intel writeups, but it's still the channel that shows up in a large chunk of insider-threat and departing-employee cases. No egress traffic to alert on, no proxy log, no firewall hit. If your detection stack is entirely network-centric, USB exfil is invisible to you by design. This section covers what to pull once USB is a live hypothesis for how data left the building - the goal is evidence that either confirms a device was the vector or lets you rule it out and move to the next channel in the master playbook's elimination sequence.

## Telemetry sources — building the evidence chain

| Artifact | Location | What it tells you |
|---|---|---|
| Device install history | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` and `\USB` | Every mass-storage device ever enumerated on the host, with vendor/product/serial in the subkey name. Survives reboots; doesn't survive a full registry wipe. |
| Drive letter / volume mapping | `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`, `MountedDevices` | Which drive letter a given device serial got assigned, and when - needed to tie a device to file-copy activity on that letter. |
| First/last connect timestamps | `EMDMgmt` registry key under `CurrentControlSet\Control` | Volume serial number plus first-seen/last-seen timestamps for removable volumes - one of the few places you get a clean "when" without deep forensics. |
| Device install log | `setupapi.dev.log` (Windows\INF) | Driver install sequence for the device, useful for pinning an exact insertion timestamp when registry timestamps are ambiguous. |
| Device Manager events | Microsoft-Windows-DriverFrameworks-UserMode/Operational log | Named device arrival/removal entries - not in the Security-log ID set covered by this playbook, but still a legitimate corroborating source. |
| Process activity | Security 4688 | `explorer.exe`, `cmd.exe`, `robocopy.exe`, `xcopy.exe` launched with a command line referencing a removable drive letter (e.g. `E:\`, `F:\`). Requires command-line auditing enabled - confirm this before assuming absence of evidence means absence of activity. |
| Scripted copy operations | 4103 / 4104 | `Copy-Item`, `Move-Item`, or raw `.NET` file APIs targeting a removable volume, captured in PowerShell module and script-block logging. Watch for base64 or compressed payload staging just before the copy. |
| Anti-forensics | 1102 | Security log cleared shortly after a device connect/disconnect window - high-signal pairing, check Subject against who was logged on at 4624/4672 level. |

## Device and file-level indicators

**[ANALYST]** - What normal looks like: known corporate-imaged USB drives (asset-tagged, previously seen on this host or others in the fleet), insertion during business hours, copy volume consistent with the user's role. What's suspicious: a device serial never seen anywhere else in the environment, insertion right after access to a sensitive file share, a burst of file-open/file-copy activity with near-identical last-accessed timestamps across dozens or hundreds of files (classic sign of a bulk copy tool or drag-and-drop of an entire folder), file extensions changed just before the copy (`.docx` renamed to `.tmp` or `.dat`), or archive creation (`.zip`, `.7z`, `.rar`) staged in a temp directory moments before the device shows a write. Pull $MFT/$LogFile or USN Journal entries if you have EDR or forensic tooling that surfaces them - timestamps there are far more reliable than anything in Explorer's "recent files" jump lists, which the user can clear.

**[ENGINEERING]** - Correlation logic for a SIEM without dedicated device-control telemetry: join EMDMgmt/USBSTOR-derived device-connect timestamps (pushed from an EDR device-inventory feed if you have one) against a time-boxed window of 4688 events where `New Process Name` is a known file-copy binary and `Command Line` contains a drive letter outside the C:\ range. Where PowerShell logging is enabled, add 4104 matches for `Copy-Item`, `[System.IO.File]::Copy`, or `Compress-Archive` in the same window. Score higher when the device serial is new to the asset inventory and the file volume/size exceeds a role-based baseline.

## Anti-forensics behavior

Sophisticated insiders clear the Security log (1102) after the fact, but registry-based USB artifacts and setupapi logs usually survive that - correlate 1102's Subject against logon activity (4624/4634/4647) in the surrounding window to establish who had hands on keyboard when the log was cleared, independent of what got deleted from Security.

## Channel elimination logic

**[STAKEHOLDER]** - USB exfil bypasses network monitoring entirely, which is exactly why it matters to prove or disprove early: if the DLP and proxy logs show nothing, that's not evidence of "no exfiltration," it may mean the wrong channel was checked. Confirming or ruling out USB narrows the remaining investigation and avoids burning time chasing a network trail that doesn't exist.

**[MANAGEMENT]** - Device-control policy (block, read-only, or allow-with-encryption for removable media) should be owned jointly by IT security and endpoint engineering, reviewed at least quarterly against business exception requests. Track mean-time-to-detect for unauthorized device connects as a KPI, and require that any exception (e.g., a contractor issued a USB drive) be logged in the asset system, not just approved verbally - otherwise every legitimate device shows up as an anomaly during the next investigation.

## MITRE ATT&CK mapping

| Behavior | Technique |
|---|---|
| Copying data to a removable device to move it out of the network - described here by name only; no listed technique ID in this playbook's reference set covers physical-medium exfiltration | Exfiltration Over Physical Medium (USB) - name only, ID not confirmed for this draft |
| Renaming/changing extensions or compressing files before the copy to blend in or shrink footprint | T1027 Obfuscated Files or Information |
| Bulk gathering of files from shares/local disk into a staging folder ahead of the copy | T1119 Automated Collection |

## Worked example

Helpdesk ticket at Meridian Analytics flags that former employee `d.osei` connected an unrecognized USB device (`VID_0951&PID_1666`, serial `9C8A2B01`) to host `MRD-FIN-042` at 17:42 on their last working day, per the EMDMgmt registry key pulled during offboarding forensics. 4688 events in the same window show `robocopy.exe` launched from `explorer.exe` with a command line copying `\\mrd-fs01\Finance\Q3_Forecast` to `E:\`. No 1102 event follows, and the device serial has never appeared on any other host in the fleet inventory. That combination - novel device, privileged-share source path, matching timestamp window, no other channel showing corresponding egress - is enough to escalate as confirmed USB exfiltration rather than close as Insufficient Evidence.
