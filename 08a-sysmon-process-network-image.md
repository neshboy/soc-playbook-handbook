# Sysmon — Process, Network & Image Events (Event IDs 1, 3, 6, 7, 8, 10)

Native Windows Security auditing gets you a decent skeleton — a process started, someone logged on, a service got installed. What it doesn't get you is the connective tissue an analyst actually needs during triage: full command lines without extra GPO work, file hashes, parent-child chains you can trust, which process opened a socket to which IP, or which process just reached into another process's memory. Sysmon exists to fill exactly those gaps — hashing, network attribution, image/driver load visibility, and inter-process access — without replacing the Security log, which still owns authentication and account lifecycle. In practice most mature SOCs run both side by side and correlate them by time and PID/GUID; treating Sysmon as "the good version of 4688" undersells it — it's a different instrument pointed at different behavior.

One operational note before the per-ID detail: Sysmon assigns each process a `ProcessGuid` that stays unique across the machine's uptime, unlike a PID which gets recycled within hours. If you're building correlation logic across Sysmon IDs (1, 3, 7, 8, 10 all reference process identity), pivot on `ProcessGuid` where the schema exposes it, not raw PID — this is a genuinely common source of false correlation in home-built detections.

---

## Sysmon Event ID 1 — Process Creation

**What it means:** A new process started on the host. This is the workhorse event of the whole Sysmon config — most detection content in a mature SOC touches ID 1 somewhere in the logic.

**Key fields:**

| Field | Notes |
|---|---|
| `UtcTime` | Always UTC — reconcile with local host time carefully during triage |
| `Image` | Full path of the executable that launched |
| `CommandLine` | Full command line, always populated (no GPO dependency) |
| `ParentImage` / `ParentCommandLine` | Parent process path and its full command line |
| `Hashes` | SHA256/MD5/IMPHASH etc., per your Sysmon config |
| `User` | Account context the process ran under |
| `IntegrityLevel` | Low / Medium / High / System |
| `CurrentDirectory` | Working directory at launch |
| `LogonGuid` / `ProcessGuid` / `ParentProcessGuid` | Stable identifiers for correlation |

**Normal vs suspicious:** `winword.exe` spawning `splwow64.exe` for printing — normal. `winword.exe` spawning `powershell.exe -enc <base64>` with a parent command line showing the doc was opened from a Downloads folder — that's the classic macro-dropper chain and worth immediate attention. Same logic applies to `wscript.exe`/`mshta.exe`/`rundll32.exe` appearing as children of Office apps or browsers.

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: "WINWORD.EXE" /n "C:\Users\jmartinez\Downloads\Invoice_4471.docm"
CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAKAAo...
IntegrityLevel: Medium
User: CORP\jmartinez
```

**[ANALYST]** - Do not stop at "PowerShell ran." Pull the parent command line first — it tells you the doc that spawned it, the path it lived in, and whether the user actually double-clicked it or a script did. Base64 in the command line is not proof of malice by itself (some legitimate deployment tooling does this), but combined with a Downloads-folder Office parent, it's a strong indicator worth pivoting into Sysmon ID 3 and ID 7 for the same `ProcessGuid`.

**[ENGINEERING]** - Rather than one giant "suspicious PowerShell" rule, split logic: (1) parent/child pairs that are structurally unusual (Office → script interpreter), (2) command-line content patterns (`-enc`, `-nop`, `-w hidden`, `IEX`, `DownloadString`), (3) integrity-level anomalies (child running at higher integrity than parent, which shouldn't happen without a legitimate elevation path). Layering catches variants that evade any single pattern.

**Native Windows Event ID complement:** 4688 (New process created) is the direct native equivalent, but 4688's `Command Line` field only populates if command-line auditing is explicitly enabled via GPO, and it carries no hashes and no parent command line — only the parent's process name/ID. Where both logs exist, cross-referencing them is useful for gap-detection: if 4688 shows a process that never shows up in Sysmon ID 1 on the same host, your Sysmon service may have gaps (tamper, crash, filtering misconfiguration) worth escalating on its own.

---

## Sysmon Event ID 3 — Network Connection

**What it means:** A process on the host initiated (or in some configs, accepted) a TCP/UDP network connection. This is process-attributed network telemetry — the thing that turns "10.0.4.22 talked to 203.0.113.55" into "`powershell.exe` (PID 4820, run by CORP\jmartinez) talked to 203.0.113.55:443."

**Key fields:**

| Field | Notes |
|---|---|
| `Image` | Process that owns the connection |
| `SourceIp` / `SourcePort` | Local side |
| `DestinationIp` / `DestinationPort` | Remote side |
| `Protocol` | TCP/UDP |
| `Initiated` | True if this host initiated the connection |
| `User` | Account context of the process |
| `ProcessGuid` | Ties back to the ID 1 event for the same process |

**Config dependency to check first:** unlike process creation, Network Connection logging is off in Sysmon's stock configuration — it has to be explicitly enabled (a `<NetworkConnect>` block in the config XML). A host with Sysmon running but no ID 3 events in the SIEM may simply have this event type disabled, not "no network activity." Confirm the deployed config before treating an absence of ID 3 as evidence of anything.

**Normal vs suspicious:** `chrome.exe` connecting to port 443 on a CDN IP — background noise, not worth alerting on in isolation. `sqlservr.exe` or `svchost.exe` initiating an outbound connection to an unfamiliar external IP on port 443 or 8443 with no corresponding update/patch activity — that's the shape of a beacon, especially if it repeats on a suspiciously regular interval.

```text
Image: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\SYSTEM
Protocol: tcp
SourceIp: 10.0.4.22
SourcePort: 51022
DestinationIp: 198.51.100.14
DestinationPort: 8443
Initiated: true
```

**[ANALYST]** - `svchost.exe` making outbound connections isn't automatically bad — plenty of Windows services do this legitimately (WU, telemetry, OneDrive-related services hosted under svchost). What matters is destination reputation, port choice relative to the service, and whether the parent service under that `svchost.exe` instance is one you'd expect to phone home. Check `-k <servicegroup>` in the command line from the matching ID 1 event before escalating.

**[ENGINEERING]** - Sysmon ID 3 volume on a busy endpoint can be substantial; most shops filter out well-known browser/update processes at the config level and alert on the residual — unexpected processes (LOLBins like `certutil.exe`, `mshta.exe`, `regsvr32.exe`, or anything running from `%TEMP%`/`%APPDATA%`) making outbound connections. Joining ID 3 to ID 1 on `ProcessGuid` lets you filter by full command line and parent, not just image name, which cuts a lot of noise from legitimately-named-but-wrong-path binaries.

**Native Windows Event ID complement:** None in core Security auditing. Native Windows logging has nothing that ties a specific process to a specific outbound connection with this level of fidelity — Windows Filtering Platform auditing exists separately from the standard event set covered here and tends to be noisy and rarely enabled. This is a pure capability gap that Sysmon fills; if you're missing Sysmon on a host, you are functionally blind to process-level network attribution from Windows-native sources alone.

---

## Sysmon Event ID 6 — Driver Loaded

**What it means:** A kernel driver was loaded. Low frequency on a healthy endpoint (drivers load mostly at boot and during hardware/software installs), which makes unexpected entries stand out.

**Key fields:**

| Field | Notes |
|---|---|
| `ImageLoaded` | Path to the driver file |
| `Hashes` | Driver file hash |
| `Signed` / `Signature` / `SignatureStatus` | Whether the driver is signed, by whom, and whether the signature validated |

**Normal vs suspicious:** A signed driver from a known vendor (`nvlddmkm.sys`, a printer driver, an EDR sensor's own kernel component) loading once after patch Tuesday or a driver update — normal. An unsigned driver, or a driver with a revoked/expired signature, loading from a user-writable path outside `System32\drivers` — that's the profile of a BYOVD (bring-your-own-vulnerable-driver) attack, frequently used specifically to kill or blind EDR agents before the rest of an intrusion plays out.

**[STAKEHOLDER]** - This is the event category behind most "EDR-killer" incidents you may have read about — attackers loading a legitimate-but-vulnerable signed driver to get kernel-level code execution and disable the security agent, rather than exploiting the OS itself. Detecting this early is high value because it's usually a deliberate precursor to something bigger, not noise.

**[ANALYST]** - Signature status matters more than the vendor name alone — a "signed" driver can still be a known-vulnerable one abused for privilege escalation. If the signature validates but you don't recognize the vendor or the file path is unusual (`C:\Users\Public\` instead of `C:\Windows\System32\drivers\`), treat it as suspicious pending hash lookup against known-vulnerable driver lists.

**[MANAGEMENT]** - Driver-load alerting has a low false-positive footprint compared to process-creation rules, which makes it a good candidate for a low-tolerance, near-zero-suppression alert tier — escalate on sight rather than batching for daily review.

**Native Windows Event ID complement:** None in the covered native set. Driver load activity isn't visible in the standard Security event IDs referenced in this book; this is another area where Sysmon provides visibility native auditing simply doesn't have.

---

## Sysmon Event ID 7 — Image Loaded

**What it means:** A DLL or other image was loaded into a running process. This event type is off in Sysmon's stock configuration and has to be deliberately turned on (the `-l` switch, or an `<ImageLoad>` block in the config XML) — it isn't just filtered heavily, it doesn't fire at all until someone enables it. Once enabled, it immediately becomes the highest-volume event in this cluster by a wide margin, since every process loads dozens of DLLs just to start, which is why almost every config that turns it on at all scopes it to a narrow set of paths, processes, or signature conditions rather than logging everything.

**Key fields:**

| Field | Notes |
|---|---|
| `Image` | The process the DLL loaded into |
| `ImageLoaded` | Path of the loaded DLL/image |
| `Hashes`, `Signed`, `Signature` | Same integrity checks as ID 6, applied to the loaded module |

**Normal vs suspicious:** `explorer.exe` loading shell extension DLLs from `System32` at logon — normal, expected, high volume. A signed, trusted process (`svchost.exe`, `lsass.exe`, a browser) loading an unsigned DLL from a temp or user-profile path it has no business touching — that's the signature of DLL sideloading or process injection via a malicious module drop.

**[ENGINEERING]** - Because of volume, this ID is usually enabled with tight `ImageLoaded` path/hash filters rather than left wide open — e.g., only log loads into a defined watchlist of high-value processes (`lsass.exe`, browsers, RDP-related binaries), or loads of unsigned images from non-standard paths. Correlate against ID 1's `ParentImage`/`Image` for the loading process and, where injection is suspected, against ID 8 for the same target process — sideloading and thread injection frequently show up together in the same intrusion chain.

**Native Windows Event ID complement:** None. Native Windows auditing has no image/module load visibility at all; this is a Sysmon-only capability and the primary reason DLL sideloading and image-load-based injection hunting are feasible on Windows endpoints in the first place.

---

## Sysmon Event ID 8 — CreateRemoteThread

**What it means:** One process created a thread running inside a different process's address space. Outside of a small set of legitimate tools (debuggers, some AV/EDR self-protection mechanisms, a handful of legacy admin utilities), this is not something normal software does, which makes it one of the highest-signal-to-noise IDs in the whole Sysmon set.

**Key fields:**

| Field | Notes |
|---|---|
| `SourceImage` | Process that created the remote thread |
| `TargetImage` | Process the thread was created in |
| `StartAddress` / `StartModule` / `StartFunction` | Where execution begins in the target, when resolvable |
| `SourceProcessGuid` / `TargetProcessGuid` | Correlation identifiers |

**Normal vs suspicious:** Extremely narrow "normal" band — mostly known debugging/monitoring tools and some legitimate EDR internals. Anything else — a script interpreter, an Office process, or an unrecognized binary creating a remote thread in `explorer.exe`, a browser, or worse, `lsass.exe` — should be treated as classic process-injection behavior until proven otherwise.

```text
SourceImage: C:\Users\Public\update.exe
TargetImage: C:\Windows\explorer.exe
StartModule: unknown
```

**[ANALYST]** - `StartModule`/`StartFunction` resolving to "unknown" is itself a signal — legitimate thread creation into a target usually resolves to a named module/export; shellcode injected into freshly allocated memory typically won't resolve to anything recognizable. Pull the source process's full ID 1 record (path, hash, signer, command line) before doing anything else — the injecting binary is almost always the more useful artifact to pivot on than the victim process.

**[ENGINEERING]** - Given how rare legitimate CreateRemoteThread activity is, this is a good candidate for a default-deny detection posture: alert on all instances, then maintain a short, reviewed allowlist for the handful of known-legitimate `SourceImage`/`TargetImage` pairs in your environment (debugging tools, specific EDR components) rather than trying to write suppression logic for "normal" injection behavior — there mostly isn't any.

**Native Windows Event ID complement:** None. There is no native Windows Security event that captures cross-process thread creation; this is a gap Sysmon fills entirely on its own, and it's one of the more defensible reasons to deploy Sysmon even in environments trying to keep logging footprint minimal.

---

## Sysmon Event ID 10 — ProcessAccess

**What it means:** One process opened a handle to another process, typically to read or manipulate its memory. This ID is the backbone of credential-dumping detection, because reading credential material out of `lsass.exe` requires opening a handle to it first.

**Key fields:**

| Field | Notes |
|---|---|
| `SourceImage` | Process requesting access |
| `TargetImage` | Process being accessed (commonly `lsass.exe` in dumping scenarios) |
| `GrantedAccess` | Access mask requested — certain combinations (e.g., those granting `PROCESS_VM_READ` and full memory read rights) are far more relevant than routine query-only access |
| `CallTrace` | Call stack summary, useful for distinguishing tooling behavior |

**Normal vs suspicious:** Plenty of legitimate processes open handles to `lsass.exe` with minimal, query-only access (some AV/EDR agents, certain system utilities) — that's expected background noise you'll need to baseline out. An unsigned or unfamiliar process requesting broad memory-read access to `lsass.exe`, especially anything resembling known credential-access tooling behavior, is a different story entirely and should route straight to an analyst, not a queue.

```text
SourceImage: C:\Users\Public\svhost.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1FFFFF
```

**[ANALYST]** - `svhost.exe` (missing the "c") targeting `lsass.exe` with a broad access mask is about as textbook as this gets — misspelled system-process names in user-writable paths are a persistent, low-effort masquerading trick, and it's still worth checking every time rather than assuming the analyst before you already caught it. Validate the source binary's actual path, signer, and hash — don't trust the process name alone.

**[ENGINEERING]** - Filter on `TargetImage` = `lsass.exe` (and any other credential-relevant processes you care about) combined with `GrantedAccess` values associated with broad read access, rather than alerting on every ProcessAccess event against lsass — plenty of that traffic is benign AV/EDR self-checks with narrower access masks. Maintain an allowlist of known-good `SourceImage` paths/hashes (your own EDR agent, sanctioned admin tooling) and alert on everything outside it.

**[MANAGEMENT]** - Confirmed lsass access from an unrecognized binary is a stop-the-line event, not a next-business-day ticket — SLA for this specific detection category should be measured in minutes, with clear ownership for immediate host isolation authority.

**Native Windows Event ID complement:** None directly, though the account activity that follows a successful credential theft often surfaces later in 4624/4648/4672 (unusual logons, explicit-credential use, privileged logons) elsewhere on the estate — ID 10 is your earliest warning, native Security events are frequently your confirmation that stolen material got used.
