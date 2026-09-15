# Sysmon Event ID Reference Cluster: File, Registry, Pipe & DNS Events

Native Windows auditing gets you a decent skeleton — logons, process creation, account changes — but it was never designed as a forensic instrumentation layer. Turn on every applicable audit subcategory in Group Policy and you still won't get a SHA256 of the binary that just ran, you won't see which process actually wrote a file to disk, and you get nothing meaningful about DNS resolution tied to a process. Windows Security auditing answers "who logged on and what process started." It does not answer "what did that process touch, what did it write, what did it ask the network to resolve, and did it use a named pipe to talk to another process on this box." That's the gap Sysmon was built to close, and this cluster covers the part of Sysmon that watches the filesystem, the registry, named pipes, and DNS — the four places attackers have to touch sooner or later, whether they're dropping a payload, setting up persistence, or beaconing out.

A quick framing note before the IDs: none of these events exist as native Windows Security log equivalents in the way process and logon auditing do. Where a native ID is genuinely complementary, it's called out. Where there isn't one, that's said plainly rather than papered over — this is exactly the kind of telemetry gap analysts inherit and then have to explain to auditors who assume "Windows logs everything."

## File Events: 11, 15, 23

### Event ID 11 — FileCreate

Fires when a file is created or overwritten, with the responsible process attached. This is the single most useful Sysmon event for catching dropped payloads, staged exfil archives, and ransomware note deployment, because it ties a concrete file path directly to the process that wrote it — something no native event does.

| Field | Description |
|---|---|
| UtcTime | Timestamp of creation |
| ProcessGuid / ProcessId | Sysmon-internal and OS PID of the writing process |
| Image | Full path of the process that created the file |
| TargetFilename | Full path of the file created |
| CreationUtcTime | File's creation timestamp (useful for timestomping detection when compared to UtcTime) |
| User | Account context of the process |

**Normal vs suspicious:**
Every install, every autosave, every browser cache write generates FileCreate — this is high-volume by default, so most builds filter it to interesting directories (`Downloads`, `AppData\Roaming`, `Startup` folders, `Temp`, web server upload directories) rather than ingesting the firehose.

Normal: `winword.exe` writing `~$report.docx` to a user's Documents folder. Suspicious: `powershell.exe` writing `C:\Users\jsmith\AppData\Local\Temp\update.exe`, or a mass wave of FileCreate events under `C:\Users\*\Documents` all writing files with a `.locked` or ransom-note-style extension within a few seconds of each other from the same process — that pattern is the ransomware encryption sweep, and it's one of the highest-value uses of this event.

**[STAKEHOLDER]** - The mass-rename pattern described above (many files under user directories getting a new extension within seconds, from one process) is the earliest machine-detectable moment in a ransomware event — earlier than the ransom note, earlier than any help-desk call. A SOC that can act on this signal in near-real-time is the difference between isolating one host and re-imaging a file server; the decision on isolation authority for this trigger should be pre-agreed with the client, not worked out live during the incident.

**[ANALYST]** - When you get a FileCreate hit on a suspicious drop, don't stop at the filename. Pull the ProcessGuid and pivot to Sysmon Event ID 1 for that GUID to get the full command line and parent chain — FileCreate tells you *what* landed, Process Creation tells you *how* it got there.

**Native gap filled:** Complements 4688. Process creation auditing tells you a process ran; it says nothing about what that process wrote to disk. There's no native Security-log event for generic file writes — the closest native mechanism is object access auditing on specific file SACLs, which most environments never enable because of noise and per-object configuration overhead.

### Event ID 15 — FileCreateStreamHash

Fires when a file is created with an alternate data stream (ADS), and Sysmon hashes the resulting stream. The everyday, entirely benign source of this event is Windows itself tagging downloaded files with the `Zone.Identifier` ADS — that's the mechanism behind Mark-of-the-Web, which is what triggers the "Keep/Open anyway" security prompt on downloaded Office files and executables.

| Field | Description |
|---|---|
| Image | Process that created the stream |
| TargetFilename | File path, including stream name (e.g. `report.xlsx:Zone.Identifier`) |
| Hash | Hash(es) of the stream contents |
| Contents | First bytes of the stream, if configured |

**Normal vs suspicious:** Normal is `chrome.exe` or Outlook writing a `Zone.Identifier` stream on every downloaded file — this is expected background noise and should be tuned rather than alerted on wholesale. Suspicious is a process writing an ADS that *isn't* the standard Zone.Identifier tag — attackers occasionally stash payloads or staged data inside alternate data streams on legitimate-looking files specifically to hide them from casual directory listings, since `dir` doesn't show ADS by default. A non-browser, non-mail-client process writing a stream on an executable in a Temp directory is worth a look.

**[ANALYST]** - The Zone.Identifier content itself is worth reading, not just the fact it exists. It usually contains the source URL the file was downloaded from — that's a free pivot to a possibly malicious download source, sitting right there in the stream contents.

**Native gap filled:** No native equivalent at all. Windows Security auditing has no concept of alternate data streams; this is Sysmon-exclusive visibility into a mechanism attackers have used for both defense evasion (MOTW) and simple concealment.

### Event ID 23 — FileDelete

Fires on file deletion, and — depending on configuration — Sysmon can archive a copy of the deleted file before it goes, which is genuinely useful for after-the-fact forensic recovery of something an attacker tried to destroy.

| Field | Description |
|---|---|
| Image | Deleting process |
| TargetFilename | Path of the deleted file |
| Hashes | Hash of the file at time of deletion (if archiving/hashing enabled) |
| IsExecutable | Flag for whether the deleted file was a PE |
| Archived | Whether Sysmon retained a copy |

**Normal vs suspicious:** Installers cleaning up their own temp files, log rotation, browser cache eviction — all normal and all noisy, so like FileCreate this one is usually scoped to interesting paths. Suspicious is the flip side of the Event ID 11 ransomware pattern: a burst of deletions immediately following a burst of "encrypted" file creations in the same directories, which is the tell-tale of ransomware deleting originals after encrypting a copy. Also watch for a process deleting its own dropped tooling (`certutil.exe`, `psexec.exe`, custom binaries) shortly after use, or deletion of Sysmon's own log-adjacent artifacts, prefetch files, or shadow copy related files — classic anti-forensics cleanup.

**[ANALYST]** - Correlate FileDelete against Event ID 11 for the same TargetFilename over a short window. A file created and deleted within seconds by the same process, especially something in Temp or Downloads with an executable extension, is the signature of "drop, run, self-delete" behavior.

**Native gap filled:** Complements 1102 in spirit — both are anti-forensics indicators — but they cover different terrain. 1102 is specifically the Security audit log being cleared. FileDelete covers file-based cleanup (tools, staging directories, ransom artifacts) that 1102 says nothing about. There's no native file-deletion audit event in the reference set here.

## Registry Events: 12, 13, 14

Registry persistence is one of the oldest tricks in the book — Run keys, RunOnce, service configuration, IFEO debugger hijacks — and native Windows auditing gives you essentially nothing here without enabling registry object access auditing on specific keys, which is rarely done because of the configuration burden and volume. Sysmon's three registry event IDs split registry activity into create/delete, value-set, and rename, which is more granular than most SOCs actually need but useful once you know which one you're looking at.

### Event ID 12 — RegistryEvent (Object create and delete)

Fires when a registry key is created or deleted.

### Event ID 13 — RegistryEvent (Value set)

Fires when a value under a key is set or modified. This is the one that matters most operationally, because Run-key persistence is a value-set operation, not a key creation.

### Event ID 14 — RegistryEvent (Key and value rename)

Fires on rename operations — less common in normal usage, occasionally used to evade simple string-match detections on a known-bad key name.

| Field (all three) | Description |
|---|---|
| EventType | CreateKey / DeleteKey / SetValue / RenameKey |
| Image | Process performing the operation |
| TargetObject | Full registry path |
| Details | New value data (for SetValue, Event ID 13) |
| NewName | New key/value name after the operation (for rename, Event ID 14) |
| User | Account context |

**Normal vs suspicious:**
Software installs constantly write to the registry — this is unavoidable background noise, and most Sysmon configs scope registry monitoring to a specific, well-known set of persistence-relevant hives: `\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `Winlogon\Shell`, `Winlogon\Userinit`, `Image File Execution Options`, service `Start` values under `\SYSTEM\CurrentControlSet\Services`, and scheduled-task-adjacent keys.

Normal: an approved software package writing its own uninstall string under `Uninstall` at install time. Suspicious: a value set under `...\Run` pointing to a script interpreter with an encoded argument —

```text
TargetObject: HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync
Details: C:\Windows\System32\wscript.exe //B "C:\Users\jsmith\AppData\Roaming\sync.vbs"
Image: C:\Windows\System32\reg.exe
```

`reg.exe` setting a Run value from a script that isn't Explorer or an MSI installer process is a pattern worth escalating on its own — legitimate software rarely installs its persistence via a manually invoked `reg add`.

**[ANALYST]** - Always check the parent chain of the process writing the registry value (pivot to Event ID 1). `reg.exe add` launched from `cmd.exe` launched from a macro-enabled Office document is a materially different story than the same `reg.exe` call from an MSI installer under SYSTEM.

**[ENGINEERING]** - Scope registry monitoring in the Sysmon config with explicit `TargetObject` includes on the known persistence hives rather than logging everything — unscoped registry monitoring is one of the fastest ways to blow through EPS budgets and SIEM ingestion costs for very little analytic return.

**Native gap filled:** No comparable native event exists in the reference set for general registry value changes. The nearest native artifacts are indirect — 7045 (System log) and 4697 (Security log) both fire when a *service* is installed, which does correspond to a registry write under the Services key, but that only covers the service-creation case, not Run keys, IFEO, or Winlogon persistence. For everything outside service installation, Sysmon 12/13/14 is the only visibility available short of enabling per-key SACL auditing.

## Pipe Events: 17, 18

Named pipes are an interprocess communication mechanism, and they're used constantly by entirely legitimate Windows components (print spooler, RPC, various services talking to each other locally). They're also a favorite mechanism for post-exploitation frameworks and lateral movement tooling, because named pipes can tunnel command-and-control traffic or facilitate process interaction without going near the network stack in a way that's obviously visible.

### Event ID 17 — PipeEvent (Pipe Created)
### Event ID 18 — PipeEvent (Pipe Connected)

| Field | Description |
|---|---|
| Image | Process creating/connecting to the pipe |
| PipeName | Name of the pipe |
| ProcessId | PID of the process |

**Normal vs suspicious:** Windows itself creates and uses a large number of pipes with predictable, boring names (`\PIPE\srvsvc`, `\PIPE\lsass`, `\PIPE\wkssvc`, spooler-related pipes). Suspicious is a pipe name matching a known tooling default or a randomized-looking name created by an unexpected process — several well-known post-exploitation and C2 frameworks use recognizable default pipe naming conventions, and a security-conscious build maintains a watchlist of those names. Also suspicious: `svchost.exe` or another system process connecting to a pipe created moments earlier by an unrelated user-context process — that pattern shows up in some lateral movement and named-pipe-based command execution tooling.

**[ANALYST]** - PipeName alone is rarely conclusive — plenty of legitimate software (Docker Desktop, backup agents, remote management tools) creates non-standard-looking pipe names too. Treat a pipe match as a lead to correlate against process lineage and network activity around the same timestamp, not a standalone verdict.

**Native gap filled:** None. There is no native Windows Security auditing event for named pipe creation or connection in the reference set — this is Sysmon-exclusive territory, and one of the better arguments for running it even on hosts where log volume is a constant fight.

## DNS Event: 22

### Event ID 22 — DNSEvent

Fires on a DNS query, with the requesting process attached — the piece native logging is missing almost everywhere it matters for beacon detection.

| Field | Description |
|---|---|
| QueryName | The domain queried |
| QueryStatus | Result code of the resolution |
| QueryResults | Resolved IP(s), if any |
| Image | Process that issued the query |
| ProcessId | PID of the querying process |
| ProcessGuid | Stable process identifier — pivot on this, not ProcessId, when correlating into Event ID 3 |

**Normal vs suspicious:** The overwhelming majority of this event is browsers, update services, telemetry endpoints, and CDN lookups — high volume, usually filtered to exclude known-noisy processes and allow-listed domains in mature builds. Suspicious is a query for a domain with a short registration age, a DGA-looking name, or a query issued by a process that has no legitimate reason to be doing DNS resolution at all — `rundll32.exe` or `mshta.exe` resolving `a8x2ndkq.example.com` is a very different signal than `chrome.exe` resolving `cdn.example.com`.

```text
Image: C:\Windows\System32\rundll32.exe
QueryName: kq7z9x-update.example.net
QueryStatus: 0
QueryResults: 203.0.113.44
```

**[ANALYST]** - QueryStatus non-zero (NXDOMAIN, etc.) repeated rapidly from the same process against sequentially different domain names is a classic DGA-beacon pattern — the malware is cycling through a domain generation algorithm until one resolves. A single failed lookup means nothing; a rapid-fire pattern of dozens means quite a lot.

**[ENGINEERING]** - Correlate QueryName against Sysmon Event ID 3 (Network Connection) for the same ProcessGuid within a short window — a resolved domain followed immediately by an outbound connection to the resolved IP, from a process with no business making network calls, is a strong pairing for beacon detection logic.

**Native gap filled:** There is no Windows Security log event for DNS queries in the reference set for this book. Some environments enable a separate DNS client operational log outside the Security channel, but even where that's turned on it typically lacks the process attribution that makes Sysmon 22 valuable — tying the specific querying process to the specific domain is the whole point, and native tooling generally can't do it without Sysmon or an EDR agent filling that role.

## Closing Note for This Cluster

None of these nine events are individually damning. A single FileCreate, a single registry SetValue, a single pipe connection, a single DNS query — on their own, almost all of them are Insufficient Evidence at best. The value shows up in correlation: FileCreate plus FileDelete on the same path within seconds, a Run-key SetValue from a script host with no matching change ticket, a named pipe connection immediately preceded by a suspicious process spawn, a DGA-shaped DNS query followed by an outbound connection to the resolved address. Build detections that chain these together rather than alerting on any one in isolation — that's where this telemetry earns the ingestion cost.
