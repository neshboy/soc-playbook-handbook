# Category: Endpoint - Execution & LOLBins

Every playbook in this folder covers the same moment in an intrusion: something ran. Not "something connected outbound" or "something touched a credential" - a process started, and either the process itself is the problem (a flagged malicious binary) or the process is a perfectly legitimate Windows or Office component being used to do something it wasn't really meant to do. That second pattern - Living Off the Land Binaries, LOLBins - is the reason this category exists as its own block rather than being folded into generic malware handling. `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `wscript.exe`/`cscript.exe` are all signed, all present on a stock build, and all capable of executing attacker code without ever dropping a second unsigned file for AV to catch. Attackers use them precisely because a hash-based or file-reputation control has nothing to alert on.

The common thread across every playbook here is process creation as the primary evidence type, and a parent/child relationship as the primary signal. A `rundll32.exe` alert on its own is close to meaningless - `rundll32.exe` spawned by `explorer.exe` loading a legitimate control panel DLL happens constantly. The same binary spawned by `WINWORD.EXE`, with an unusual command line, three seconds after a user opened an emailed invoice, is a different story entirely. Nearly every playbook in this category is really an exercise in reading the process tree and the command line together, then deciding whether the *combination* is normal for that host and that user.

**[ANALYST]** - Expect to spend most of your time in the parent-child chain and the command line, not the alert itself. Ask what spawned this process, what that spawned in turn, and whether the account and host have done this before. A one-off is more interesting than a pattern that's run daily for six months.

## Log sources and tooling that matter most

- **Sysmon Event ID 1 (Process Creation)** is the backbone of this entire category - it gives you full command line, parent command line, integrity level, and (if configured) hashes, none of which you can reliably get from Windows Security auditing alone.
- **Windows Event ID 4688** is the fallback where Sysmon isn't deployed, but command-line auditing has to be explicitly enabled via GPO (`Include command line in process creation events`) or the field comes back empty - a common gap that quietly kills an investigation before it starts.
- **Event ID 4104 (PowerShell Script Block Logging)** and **4103 (Module Logging)** are non-negotiable for anything involving PowerShell - without them, an encoded or obfuscated command line in 4688/Sysmon 1 is often the *only* thing you have, and it may not decode cleanly by hand.
- **Sysmon Event ID 3 (Network Connection)** and **22 (DNSEvent)** tie a LOLBin back to whatever it phoned home to - critical for download cradles and `certutil`/`bitsadmin` abuse.
- **Sysmon Event ID 11 (FileCreate)** catches the payload actually landing on disk after the LOLBin fetches or decodes it.
- **Event ID 7045** (System log, service install) matters where execution is being used to establish persistence rather than just run once.
- EDR process-tree visualization and AMSI telemetry (where the vendor exposes it) usually beats piecing the story together from raw logs alone, when it's available.

## Friction specific to this category

This is one of the noisiest categories in the whole book, and the noise is structural, not accidental. Legitimate software installers, GPO logon scripts, and RMM tooling use the exact same binaries attackers do - `regsvr32` registering a real COM component, `mshta` running a vendor's help viewer, `certutil` decoding a base64 cert bundle for an internal PKI job. Command-line auditing gaps and PowerShell logging left disabled (it's not on by default) routinely leave analysts working from a bare process name with no argument to reason about. Encoding and obfuscation - base64, string concatenation, `-EncodedCommand`, char-code building - make plain-text searching brittle, and a script block that decodes cleanly in a lab can still throw analysts off in a live queue at 2am. Renamed binaries, unsigned tools with a signed-sounding name, and allowlisted install paths abused for staging all show up here too. Don't assume a clean-looking parent process means a clean chain - validate the whole tree before closing anything as Benign Positive.

## Playbooks in this category

| # | Playbook | File | Primary reference technique(s) |
|---|----------|------|----------------------------------|
| 1 | Malware Detection (Generic AV/EDR Alert) | `malware-detection-generic-av-edr-alert.md` | Varies by verdict - execution vector often T1204 |
| 2 | Suspicious Process (Generic) | `suspicious-process-generic.md` | T1059 Command and Scripting Interpreter |
| 3 | Encoded/Obfuscated PowerShell | `encoded-obfuscated-powershell.md` | T1059.001, T1027 |
| 4 | PowerShell Download Cradle | `powershell-download-cradle.md` | T1059.001, T1105 |
| 5 | cmd.exe Spawned by an Office Application | `cmd-exe-spawned-by-an-office-application.md` | T1204, T1059.003 |
| 6 | PowerShell Spawned by an Office Application | `powershell-spawned-by-an-office-application.md` | T1204, T1059.001 |
| 7 | Suspicious rundll32 Usage | `suspicious-rundll32-usage.md` | T1218.011 |
| 8 | regsvr32 Abuse | `regsvr32-abuse.md` | T1218.010 |
| 9 | mshta Abuse | `mshta-abuse.md` | T1218.005 |
| 10 | certutil Abuse (Download/Decode) | `certutil-abuse-download-decode.md` | T1218, T1105, T1027 |
| 11 | bitsadmin Abuse | `bitsadmin-abuse.md` | T1105, T1197 |
| 12 | wscript/cscript Abuse | `wscript-cscript-abuse.md` | T1059, T1027, T1204 |
| 13 | Unknown/Unrecognised Executable Execution | `unknown-unrecognised-executable-execution.md` | Varies - T1204, T1105 |
| 14 | Unsigned Binary Execution | `unsigned-binary-execution.md` | Varies - T1204, T1105 |
| 15 | USB-Triggered Execution | `usb-triggered-execution.md` | T1204 |
| 16 | Remote Administration Tool Abuse | `remote-administration-tool-abuse.md` | Remote access/RMM tool misuse - not separately ID'd in this book's reference set |

**[MANAGEMENT]** - This category tends to generate a disproportionate share of tuning requests and exception approvals, because so many entries overlap with legitimate IT and RMM activity. Track false-positive rate per playbook separately from true-positive rate; a playbook that's 95% Benign Positive isn't necessarily broken, but it's a strong candidate for an allowlist review at the next detection engineering cadence.
