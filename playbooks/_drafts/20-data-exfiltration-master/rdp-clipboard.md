# RDP Clipboard/File Transfer Exfiltration: Telemetry and Indicators

RDP is the channel analysts most often forget to check because it "isn't a file transfer protocol" — except it absolutely is, once clipboard redirection (`cliprdr`) or drive redirection (`rdpdr`) is enabled on the session. An attacker with valid creds and an open 3389 path can drag a folder from a domain file server straight onto their own laptop through a mapped `\\tsclient\` drive, or copy-paste a chunk of a database export through the clipboard, and none of it looks like "exfil" to a bandwidth-based control. Maps to **T1021.001 (Remote Services: RDP)** for the access itself, **T1048 (Exfiltration Over Alternative Protocol)** for the transfer riding inside the RDP virtual channel rather than a file-sharing or web protocol, and **T1078.002 (Valid Accounts: Domain Accounts)** when the session rides on stolen or legitimately-issued domain creds rather than an exploit.

## Telemetry Reality Check

**[ANALYST]** - Set expectations early: the Windows Security log has no event that records clipboard *content*, and no event that records bytes moved over a redirected drive. RDP exfil detection in the native logs is almost entirely inferential — you're stitching together session timing, process activity, and file-path artifacts, not reading a "5.2 MB copied" line item. If someone asks "how much data left," the honest answer usually starts with "the Security log won't tell you that directly."

## Core Event Sequence for an RDP Session

| Event | What it confirms | RDP-specific detail |
|---|---|---|
| 4624 (Logon Type **10** = RemoteInteractive) | Interactive RDP session established | Source Network Address = originating client IP, Workstation Name = client hostname as reported by the client (spoofable), Logon ID ties the whole session together |
| 4648 | Explicit alternate credentials used to open the connection (e.g., `mstsc.exe /admin` with a stored credential, or a `runas` wrapper) | Target Server field should match the RDP host; useful when the RDP client isn't using the caller's own token |
| 4672 | Session token carries admin-equivalent privileges | Fires alongside 4624 — an RDP session onto a file server or DC with 4672 attached is a higher-stakes finding than a standard user session |
| 4688 | Process creation inside the session | Look for `rdpclip.exe` (the clipboard-redirection helper — expected on both ends of a redirected session), `mstsc.exe` (outbound client on the *source* host), and Explorer/`cmd.exe`/`powershell.exe` launched with `\\tsclient\` paths in the Command Line field |
| 4689 | Process exit | Pairs with 4688 to bound how long a copy-adjacent process ran |
| 4634 / 4647 | Session teardown | 4647 (user-initiated logoff) vs 4634 (session torn down another way) — a 4647 immediately after a burst of `\\tsclient\` file activity is a classic "grab and disconnect" pattern |
| 1102 | Audit log cleared | Check if it precedes or follows a suspect RDP session — a self-inflicted 1102 right after a large redirected-drive copy is a strong anti-forensics signal |
| 4103 / 4104 | PowerShell module/script block logging | Captures `Copy-Item`, `robocopy`, or `Compress-Archive` commands referencing `\\tsclient\` paths if the attacker scripted the transfer instead of dragging files in Explorer |

## The Two Sub-Channels That Matter

**Clipboard redirection (cliprdr).** When enabled (Group Policy: "Do not allow Clipboard redirection" set to Disabled, or the registry value `fDisableClip` under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` left at 0), text and file data copied on either end of the session becomes available on the other. There's no native event for a clipboard paste. Your best native-log proxy is `rdpclip.exe` appearing in 4688 process-creation events near the time window of interest, correlated with the 4624/4634 session bounds — presence of the process just tells you redirection is *active*, not what moved through it. This is a gap you close with EDR clipboard-monitoring telemetry or DLP agents, not the Security log.

**Drive/file redirection (rdpdr).** When client drive mapping is enabled (`fDisableCdm` = 0, or "Do not allow drive redirection" GPO set to Disabled), the client's local drives appear on the *server* side as `\\tsclient\<drive-letter>` — e.g., `\\tsclient\C\Users\jsmith\Downloads`. This is the higher-value artifact: it shows up in file paths inside 4688 command lines, in 4104 script block text, and in any endpoint file-activity telemetry your EDR captures independent of Windows auditing. A `robocopy \\fileserver\finance\reports C:\` run *from inside* an RDP session onto a redirected client drive is functionally identical to plugging in a USB drive — same intent, different transport.

## Registry and Forensic Artifacts Worth Pulling

- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDisableClip` and `fDisableCdm` — confirm whether redirection was policy-enabled at the time, and check for recent tampering if a normally-locked-down host suddenly allowed it.
- `HKCU\Software\Microsoft\Terminal Server Client\Servers` on the *source* host — MRU list of RDP targets the user's client has connected to; useful for establishing intent/frequency even though it's not a Security-log event.
- Cached `.rdp` connection files (often on the Desktop or in Documents) — check for `drivestoredirect:s:` and `redirectclipboard:i:1` settings explicitly configured rather than left at default.

## Worked Example

Analyst `jsmith`'s workstation `FIN-WKS12` shows a 4624 (Logon Type 10) onto `FILESVR03` at 22:14, sourced from `FIN-WKS12`'s IP. Three minutes later, 4688 on `FILESVR03` shows `explorer.exe` and then `robocopy.exe` with command line `robocopy \\tsclient\C\ D:\Finance\Q3_Exports\ /E`, followed by a 4647 logoff at 22:24. Ten minutes of session, one redirected-drive copy operation, deliberate logoff — worth pulling `FIN-WKS12`'s own endpoint telemetry next to see what left that machine afterward (upload, USB, personal cloud sync), because the RDP hop itself was the *staging* move, not necessarily the final exfil leg.

## Detection Logic

**[ENGINEERING]**

```
// Pseudocode — correlate RDP session with redirected-drive command-line activity
SecurityEvent
| where EventID == 4624 and LogonType == 10
| project SessionHost = Computer, SourceIP = IpAddress, LogonId, LogonTime = TimeGenerated
| join kind=inner (
    SecurityEvent
    | where EventID == 4688 and CommandLine has @"\\tsclient\"
    | project SessionHost = Computer, LogonId, ProcName = NewProcessName, CommandLine, ExecTime = TimeGenerated
  ) on SessionHost, LogonId
| where ExecTime between (LogonTime .. LogonTime + 30m)
| project SessionHost, SourceIP, ProcName, CommandLine, LogonTime, ExecTime
```

Tune the join window per environment — 30 minutes catches most interactive drag-and-drop or scripted-copy behavior without pulling in unrelated activity from long-lived sessions left open overnight.

## Confirming or Ruling Out RDP as the Channel

**[ANALYST]** - Before you commit to "RDP was the exfil path" in the master playbook's channel-narrowing step, verify: (1) redirection was actually enabled at session time — a session with `fDisableCdm`/`fDisableClip` both set and no `rdpclip.exe`/`\\tsclient\` artifacts can't have moved data this way, full stop; (2) the timing lines up — a 4624/4647 pair with no file-path activity in between is a normal admin session, not exfil; (3) volume plausibility — a two-minute session isn't moving a 40 GB database dump over an interactive drive-redirect copy, so cross-check against network throughput if you have NetFlow on that segment. A lot of RDP-adjacent findings resolve as Benign Positive (helpdesk doing legitimate remote support with drive redirection on) or Insufficient Evidence (redirection policy state at the time can't be reconstructed, or the source workstation's own telemetry has already rolled off retention).

**[MANAGEMENT]** - Ownership of the clipboard/drive-redirection GPO settings sits with endpoint engineering; any exception request (a business unit that "needs" drive redirection on jump hosts) should route through a documented risk acceptance, not a silent GPO change. Review redirection policy exceptions and 4672-tagged privileged RDP sessions on tier-0 assets on a quarterly cadence, and treat command-line auditing (needed to populate the 4688 Command Line field at all) as a detection prerequisite, not an optional extra — without it this entire channel goes dark.

A confirmed RDP redirected-drive or clipboard finding should narrow the master playbook's channel list hard — if `\\tsclient\` paths and a matching 4624/4647 session bound are present, prioritize the source workstation's own endpoint telemetry as the next hop, since the RDP session itself is frequently a staging move rather than the final egress point.
