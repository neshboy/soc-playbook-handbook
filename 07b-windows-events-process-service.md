# Windows Event IDs: Process & Service Lifecycle Events

This cluster covers the events that tell you *something started running, kept running, or was scheduled to run*: process creation and exit, service installation, and the full scheduled-task lifecycle. Individually most of these are noisy. Together they're one of the highest-value correlation sets in Windows, because persistence and execution both eventually touch one of these mechanisms — you can obfuscate a payload, but you can't avoid creating a process or registering a way to run again later.

IDs covered: **4688, 4689** (process create/exit — Security log), **4697** (service installed — Security log) and **7045** (service installed — System log), and **4698–4702** (scheduled task created/deleted/enabled/disabled/updated — Security log, Task Scheduler operational events).

---

## 4688 — A New Process Has Been Created

**What it means:** A process was launched on the host. This is the single most heavily-relied-on event in Windows endpoint investigation, and also the one most SOCs under-collect — command-line auditing is off by default, which turns a gold-mine event into a shell of itself.

**Where it appears:** Security log, via Audit Process Creation. Command-line capture requires the separate "Include command line in process creation events" policy — without it, this event tells you *what* ran but not *how*.

**Important fields:**

| Field | Notes |
|---|---|
| New Process Name | Full path of the executable launched |
| New Process ID | PID (hex), unique per boot cycle, reused over time |
| Creator Process Name / Creator Process ID | The parent — this is what makes 4688 correlatable into process trees |
| Process Command Line | Only populated if command-line auditing is enabled |
| Subject: Account Name / Domain / Logon ID | Who launched it, tied back to the 4624 that started the session |
| Token Elevation Type | Whether it ran elevated |

**What normal looks like:** `explorer.exe` spawning `outlook.exe`, `chrome.exe`, `teams.exe`. Scheduled jobs spawning `powershell.exe` with a known, repeatable command line at a known time. `services.exe` spawning `svchost.exe` instances. Software update agents spawning `msiexec.exe`.

**What suspicious looks like:** `winword.exe` or `excel.exe` as the parent of `cmd.exe`, `powershell.exe`, `wscript.exe`, or `mshta.exe` — classic macro-dropper chain. `svchost.exe` spawning `cmd.exe` (svchost should not be spawning shells under normal conditions). Command lines with `-enc`, `-EncodedCommand`, `-nop`, `-w hidden`, `IEX(`, base64 blobs, or `certutil -urlcache -decode`. Processes launched from `%TEMP%`, `%APPDATA%`, or user-writable paths with names mimicking system binaries (`svhost.exe`, `scvhost.exe`).

**[ANALYST]** - Don't chase 4688 in isolation. Pull the process tree: parent, grandparent, and children in the surrounding few minutes on that host. A `powershell.exe` with an encoded command line is a lead, not a verdict — check what it actually decodes to and what it touched before deciding severity.

**Related IDs / correlate with:** 4689 (did it exit clean or get killed), 4697/7045 (did the process go on to install a service), 4698 (did it register a scheduled task), 4624/4672 (session and privilege level that launched it), 4103/4104 (PowerShell pipeline and script-block detail if the process is `powershell.exe`) — plus DNS/proxy logs for anything the process reached out to, and the account's normal working hours and host set as a baseline.

**Common false positives:** Legitimate admin tooling (RMM agents, backup software, patch management) that looks like a LOLBin chain because it genuinely calls `cmd.exe` or `powershell.exe` as part of normal operation. Software packagers that route through `mshta.exe` for install wizards. Security tools themselves spawning `powershell.exe` to run scans.

**Example investigation narrative:** An alert fires on `WKSTN-FIN22` for `powershell.exe` with an encoded command line, parent `winword.exe`. The prior 4688 shows Word was opened by `svc_billing@northwindtraders.example.com` about ninety seconds earlier, matching an attachment opened from Outlook. Decoding the command line reveals a download-and-execute against a domain not seen elsewhere in the environment — a macro downloader, not benign tooling. That call hinges entirely on the command line being captured; without it, this ticket dies at "PowerShell ran, can't tell why."

**Example KQL query (Microsoft Sentinel / SecurityEvent table):**

```kql
SecurityEvent
| where EventID == 4688
| where Process has_any ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| where ParentProcessName has_any ("winword.exe", "excel.exe", "outlook.exe")
| project TimeGenerated, Computer, Account, ParentProcessName, Process, CommandLine
| order by TimeGenerated desc
```

---

## 4689 — A Process Has Exited

**What it means:** The counterpart to 4688 — tells you a process terminated, and how (exit status). Underused, mostly because most SOCs don't bother correlating it, but it has real value for confirming process lifetime and detecting abnormally short-lived processes (a common trait of "run once and delete" tooling).

**Where it appears:** Security log, same audit subcategory as 4688 (Audit Process Termination must also be enabled — it's a separate switch from process creation auditing and is frequently missed).

**Important fields:** Process Name, Process ID, Exit Status (a Win32 status code — `0x0` is clean exit).

**What normal looks like:** Matching Process ID to a corresponding 4688, with a lifetime consistent with what the tool normally does (a backup agent running for twenty minutes, a script running for two seconds).

**What suspicious looks like:** A process that starts and exits in well under a second repeatedly (a dropper that unpacks a payload and exits immediately), or an exit status indicating it was forcibly terminated shortly after launch (could mean AV caught it, could mean the attacker's tooling self-cleans).

**Related IDs / correlate with:** 4688 (the matching start event — always pair by Process ID and host, remembering PIDs recycle across reboots) for full lifetime, 4697/7045/4698 if the short-lived process is the one that dropped a service or task before exiting, and file system / EDR telemetry for what it wrote to disk, since 4689 by itself carries almost no context.

**Common false positives:** Legitimate short-lived utility processes (`ipconfig.exe`, `whoami.exe`, `net.exe`) that are supposed to run and exit in milliseconds as part of normal scripts and login processing.

**Example investigation narrative:** In the Word-macro case above, 4689 for the encoded `powershell.exe` process shows exit status `0x0` about four seconds after launch — consistent with a stager that downloads a second-stage payload and exits cleanly rather than an interactive session. That window becomes the pivot point for scoping what else touched disk on `WKSTN-FIN22`.

**Example SPL query (Splunk):**

```spl
index=wineventlog EventCode=4689
| eval exit_hex=tostring('Exit Status')
| where exit_hex != "0x0"
| stats count by Computer, Process_Name, Exit Status
| sort -count
```

---

## Service Installation: 4697 (Security log) and 7045 (System log)

**What they mean:** Both fire when a new service is registered with the Service Control Manager — 4697 is the Security-log audit event (requires the Audit Security System Extension subcategory enabled), 7045 is the System-log event and is on by default with no extra configuration. In practice, 7045 is the one you can rely on being present when 4697 wasn't turned on — genuinely one of the best "free" detection sources in a default Windows build.

**Where they appear:** 4697 in Security log; 7045 in System log, Source: Service Control Manager.

**Important fields (both events cover the same install, slightly different field names):**

| Field (4697) | Field (7045) | Notes |
|---|---|---|
| Service Name | Service Name | The internal service name, not always the display name |
| Service File Name | Image Path | The actual binary/command the service runs — check this closely |
| Service Type | Service Type | Kernel driver vs. own-process vs. shared-process |
| Service Start Type | Start Type | Auto, Manual, Disabled — attacker services are frequently set to Demand/Manual to avoid a reboot triggering early detection |
| Service Account | Account | Often LocalSystem for malicious services (max privilege) |
| Subject (Account Name, Logon ID) | — (7045 doesn't carry a Subject field the same way) | 4697 tells you who installed it; pair with 4688 for the same info if 4697 isn't enabled |

**[STAKEHOLDER]** - New services are one of the classic ways an attacker gets code to run with the highest available privilege and to survive a reboot. This isn't theoretical - service creation shows up constantly in ransomware precursor activity and in tooling like PsExec-style remote execution. Treat unexpected service installs on servers, especially domain controllers and file servers, as immediate-attention items.

**What normal looks like:** Software installers, Windows Update components, approved endpoint agents (EDR, patch management, backup) registering services during a known change window, with Image Path pointing to `Program Files` and a legitimate vendor path.

**What suspicious looks like:** Image Path pointing to `C:\Windows\Temp`, `C:\Users\Public`, or `%APPDATA%`, or containing `cmd.exe /c`, `powershell.exe -enc`, or a remote UNC path. Service names that are random-looking or closely mimic legitimate ones (`WindowsUpdatee`, `Ntfsvc`). LocalSystem account where the service has no business needing that access. Installation on a server outside any recorded change ticket.

**Related IDs / correlate with:** 4688/4689 for the process that performed the install (the parent of the registration call is usually the installer or the attacker's shell), 4624/4672 for the session and privilege that did it, 1102 if an attacker cleared logs before or after (a common pairing in intrusions that use service creation for lateral movement, since tools like PsExec-style utilities create a service, run, then remove it) — plus binary hash/reputation from EDR telemetry if available, and whether the service was later started versus just registered and left dormant.

**Common false positives:** Legitimate software deployment tools (SCCM, Intune, RMM platforms) that install and immediately remove short-lived services as part of push-install mechanics — these show up as a burst of 7045 events with generic-looking service names and should be baselined per tool, not treated as one-off anomalies every time.

**Example investigation narrative:** 7045 fires on `SRV-FILE01` for a service named `UpdateHelperSvc` with Image Path `C:\Windows\Temp\svcupd.exe`. No change ticket exists for this server this week. Pivoting to 4688 around the same timestamp shows the install was performed under `svc_backup`, an account whose normal job is scheduled overnight backups — but this install happened at 14:32 on a weekday. Right account, wrong time and wrong activity: that mismatch is what turns a routine ticket into an escalation, since it points to the backup account's credentials being used interactively by someone else.

**Example KQL query (System log via Sentinel):**

```kql
Event
| where Source == "Service Control Manager" and EventID == 7045
| extend ServiceName = tostring(EventData.ServiceName),
         ImagePath   = tostring(EventData.ImagePath),
         StartType   = tostring(EventData.StartType)
| where ImagePath has_any ("\\Temp\\", "\\AppData\\", "\\Users\\Public\\")
   or ImagePath has_any ("cmd.exe", "powershell.exe")
| project TimeGenerated, Computer, ServiceName, ImagePath, StartType
```

---

## Scheduled Task Lifecycle: 4698, 4699, 4700, 4701, 4702

**What they mean:** These five cover the full lifecycle of a scheduled task registered with Task Scheduler: 4698 created, 4699 deleted, 4700 enabled, 4701 disabled, 4702 updated. Scheduled tasks are the other pillar of Windows persistence alongside services, and they're arguably more attractive to attackers because they can be configured to run under a specific user context without needing a service binary that has to conform to the Service Control Manager's expectations.

**Where it appears:** Security log, requires Audit Other Object Access Events. The Task Scheduler operational log also records related run/registration activity and is worth having as a secondary source, though it's outside this cluster's ID list.

**Important fields (shared shape across all five):**

| Field | Notes |
|---|---|
| Task Name | Full path, e.g. `\Microsoft\Windows\Update\SilentCleanup` vs a suspicious `\update_check` sitting at the root |
| Task Content | Full XML of the task definition — this is where the actual command/action lives, including triggers, run-as context, and arguments |
| Subject (Account Name, Domain, Logon ID) | Who made the change |

**What normal looks like:** 4698 events tied to software installers (backup agents, update mechanisms) registering tasks under well-known paths like `\Microsoft\Windows\...`, running as SYSTEM or a service account, with triggers matching documented schedules (daily maintenance windows, patch cycles). 4702 updates coinciding with a version upgrade of the software that owns the task. 4699 deletions during an uninstall.

**What suspicious looks like:** Task Content XML referencing `powershell.exe`, `cmd.exe`, `rundll32.exe`, or `regsvr32.exe` with encoded or obfuscated arguments. Tasks sitting at the root of the task tree rather than a vendor subfolder, with generic names (`Update`, `Sync`, `svchelper`). Triggers set to fire at logon or on a short repeating interval — a common way to survive reboots and keep re-establishing a callback. A 4701 (disable) followed shortly by a 4699 (delete) on a task nobody remembers creating, a pattern seen when an attacker cleans up after themselves. 4702 updates that swap the action to a different binary while keeping the task name and schedule the same — hiding a payload change inside what looks like routine maintenance.

**[ENGINEERING]** - When alerting on these events, parse the Task Content XML rather than string-matching the raw event — the `<Command>`, `<Arguments>`, and `<UserId>` elements inside the `<Actions>` and `<Principals>` blocks are where the real signal is, and the surrounding XML boilerplate is identical across almost every task.

**Related IDs / correlate with:** 4688/4689 for the process that made the Task Scheduler API call (usually `schtasks.exe`, `powershell.exe`, or `taskeng.exe` as parent), 4624/4672 for the session and privilege level of whoever registered it, 4103/4104 if the registering command came through a PowerShell cmdlet like `Register-ScheduledTask`, and 1102 for anti-forensic cleanup around the same window. Critically, also check what the task actually *does* when it fires — that shows up later as its own 4688 event referencing the same task-runner parent.

**Common false positives:** Group Policy-pushed maintenance tasks that re-register on every policy refresh, showing up as repeated 4698/4702 pairs for the same task name — this is normal GPO behavior and should be baselined, not alerted on every cycle. Software update agents that legitimately update their own scheduled tasks (4702) with every version bump.

**Example investigation narrative:** 4698 fires for a new task named `\GoogleUpdateTaskMachineCore2` on `SRV-APP03` — deliberately close to the legitimate `GoogleUpdateTaskMachineCore`, a naming trick meant to blend in on a quick scan. Task Content shows the action is `powershell.exe` with a `-WindowStyle Hidden -Command` argument pointing to a script on a network share, triggered every four hours. The Subject is a helpdesk account with no business creating tasks on an application server. Correlating 4688 shortly before shows that same account's session ran a `psexec`-style remote command from `WKSTN-IT07` — the real pivot point, since the task was the persistence mechanism, not the entry point.

**Example KQL query (covering the whole lifecycle, Sentinel):**

```kql
SecurityEvent
| where EventID in (4698, 4699, 4700, 4701, 4702)
| extend Action = case(
    EventID == 4698, "Created",
    EventID == 4699, "Deleted",
    EventID == 4700, "Enabled",
    EventID == 4701, "Disabled",
    "Updated")
| where TaskName !startswith @"\Microsoft\Windows\"
| project TimeGenerated, Computer, Account, Action, TaskName, TaskContent
| order by TimeGenerated desc
```

---

## Cross-Cluster Correlation Cheat Sheet

| If you see... | Pull these next | Why |
|---|---|---|
| 4688, encoded/obfuscated command line | 4103, 4104, 4689, child 4688s | Confirm what the script did and for how long |
| 4697/7045 outside a change window | 4688/4689 installer process, 4624/4672 session | Identify who, and what account context, did the install |
| 4698 with non-standard Task Name/path | 4688 registering process, 4103/4104 if PowerShell-driven | Establish intent and initial access |
| 4701 then 4699 on an unfamiliar task | 1102, 4688 same window | Check for cleanup behavior consistent with covering tracks |
| Any of the above on a domain controller | 4768/4769/4771/4776, 4720–4738 | DC service/task creation frequently pairs with credential or group tampering |

**[MANAGEMENT]** - Command-line auditing for 4688, Audit Security System Extension for 4697, and Audit Other Object Access Events for scheduled tasks (4698-4702) are all cheap to enable and routinely missing in environments that "have logging" but never validated coverage. Make re-verifying these subcategories a standing item in the logging-coverage review, not a one-time deployment task — GPO drift and off-baseline server builds are the usual way this regresses. Ownership sits with the team managing GPO/audit baselines; SOC engineering should run a monthly sample check for 4688 command-line population and 4697/4698 presence, flagging any host group reverted to disabled.

Insufficient Evidence is a legitimate close reason here, particularly for 4689 exit-status anomalies and one-off 4702 updates with no surrounding context — not every odd artifact resolves to a clean verdict, and that's fine as long as the reasoning is documented.
