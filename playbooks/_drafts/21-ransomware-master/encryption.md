# Encryption Stage: Detonation Signals and Recovery Sabotage

By the time file content is actually changing on disk, the incident has already moved past containment-is-easy territory. Everything upstream (initial access, persistence, credential access, lateral movement) was the attacker positioning. The encryption stage is the point where the business case for urgency stops being theoretical. This section covers the four detection surfaces that matter most once an operator triggers the encryptor: mass rename/extension-change behavior, entropy-based content detection, VSS/backup sabotage, and ransom note drop patterns.

## Mass File Rename and Extension-Change Patterns

Most commodity and RaaS encryptors do not encrypt in place cleanly — they read the original file, write encrypted content (often to a temp or `.tmp` file), delete the original, then rename the output to a new extension. That sequence generates a very distinctive file-system fingerprint: paired **FileCreate → FileDelete** activity, at high volume, from a single process, across many directories in a short window.

**[ANALYST]** - What normal looks like: a user or backup agent creating/deleting a handful of files per minute in one or two directories. What suspicious looks like: hundreds to thousands of FileCreate/FileDelete events per minute from one `Image` (process), spanning multiple mapped drives, network shares, and user profile folders simultaneously — including files the logged-on user has no obvious reason to be touching (finance shares, other users' Desktop folders over SMB).

**[ENGINEERING]** - Sysmon Event ID 11 (FileCreate) and Event ID 23 (FileDelete) are the primary telemetry. Baseline extension churn per host, then alert on volume + fan-out:

```
// Pseudocode / KQL-style logic
Sysmon
| where EventID in (11, 23)
| where TimeGenerated > ago(5m)
| summarize FileCreateCount = countif(EventID == 11),
            FileDeleteCount = countif(EventID == 23),
            DistinctDirs = dcount(TargetFilename)
          by Image, Computer, bin(TimeGenerated, 1m)
| where FileCreateCount > 200 and DistinctDirs > 20
```

Watch known-bad extension churn (`.locked`, `.encrypted`, `.crypt`, random 4-8 char alphanumeric extensions unique to the RaaS family) but don't hard-code a fixed extension list as your only trigger — new affiliates rotate extensions constantly, and the rename event volume/fan-out is the durable signal, not the string.

## Entropy-Spike Indicators

Windows does not natively log file content entropy — this is EDR/UEBA/file-integrity-monitoring territory, not a Security or Sysmon event field. The principle: legitimate document/database writes have predictable, lower-entropy byte distributions; AES/ChaCha-encrypted output is close to statistically random, which spikes measured entropy toward the theoretical maximum (~8 bits/byte).

**[ENGINEERING]** - If your EDR or file server monitoring tooling exposes a content-entropy or "high randomness write" signal, tune it against known-good compression/backup jobs first (zip, 7z, SQL backups, video transcode output are also high-entropy and will false-positive heavily). Canary/honeyfiles seeded across file shares with FIM watching for entropy change plus rapid modify-time churn are a cheap, high-fidelity tripwire independent of vendor entropy scoring — a change to a file nobody should be touching is unambiguous.

**[ANALYST]** - Entropy alone is not proof; correlate with the FileCreate/FileDelete fan-out above and process lineage before calling it Data Encrypted for Impact (T1486) rather than a benign compression job.

## Shadow Copy and Recovery Sabotage (T1490)

Deleting Volume Shadow Copies and disabling recovery options is close to universal in ransomware playbooks — it happens either just before or immediately as encryption starts, specifically to remove the cheap restore path and force the negotiation.

| Command pattern | Intent |
|---|---|
| `vssadmin.exe delete shadows /all /quiet` | Delete all shadow copies silently |
| `wmic.exe shadowcopy delete` | Same, via WMI |
| `powershell.exe -Command Get-WmiObject Win32_ShadowCopy \| ForEach-Object {$_.Delete()}` | Scripted shadow copy removal |
| `bcdedit.exe /set {default} recoveryenabled No` | Disable boot-time recovery |
| `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` | Suppress recovery prompts |
| `wbadmin.exe delete catalog -quiet` | Destroy Windows Server Backup catalog |

**[ENGINEERING]** - Sysmon Event ID 1 (with full command line always populated) is the reliable source; Windows Security 4688 works only if process command-line auditing is enabled — confirm this in your GPO before relying on it. Alert on any of the above binaries/arguments regardless of parent process, but expect noise from legitimate backup/imaging software (Macrium, Veeam agents) — allowlist by known-good parent process and signed publisher rather than suppressing the command pattern outright.

**[ANALYST]** - Timing matters for the narrative: shadow-copy deletion arriving in the same 1-2 minute window as the FileCreate/FileDelete storm is corroborating; deletion hours earlier during the staging phase is still Inhibit System Recovery but tells you the actor pre-positioned deliberately.

## Ransom Note Drop Detection

Note drop is almost always mass, uniform, and fast — the encryptor writes the same note file (identical name, identical or near-identical content/hash) into every directory it touches, often hundreds to thousands of times in minutes.

**[ENGINEERING]** - Sysmon Event ID 11 filtered on filename patterns catches this cleanly: `README*.txt`, `*_readme*.html`, `HOW_TO_DECRYPT*`, `*_RECOVER_FILES*`, `!DECRYPT*`, or family-specific names. Build the detection on repetition and hash-identity rather than a single filename string:

```
Sysmon
| where EventID == 11
| where TargetFilename matches regex @"(?i)(readme|decrypt|recover.?files|how.?to.?decrypt)"
| summarize NoteCount = count(), DistinctDirs = dcount(TargetFilename) by Image, Computer, bin(TimeGenerated, 5m)
| where NoteCount > 10
```

**[ANALYST]** - A single note in a single folder could be an old artifact left from a prior incident, a security-awareness test file, or a researcher's test drop — validate hash and directory breadth before treating it as active detonation. Dozens of identical notes appearing across a file server tree in the same five minutes is not ambiguous.

## Pulling the Chain Together

The high-confidence detection isn't any one of these signals alone — it's the sequence: unusual process creation (Sysmon 1 / 4688), followed within minutes by VSS/backup sabotage commands, followed by mass FileCreate/FileDelete fan-out, followed by uniform ransom note drops across the same directories. A SIEM correlation rule chaining these four in a bounded time window from a single host or small cluster of hosts is worth far more than any single alert, and it's the artifact you hand to the incident commander as proof encryption is live — not suspected.

**[MANAGEMENT]** - This correlation chain should have a defined SLA of minutes, not hours, and an auto-isolation playbook trigger (network isolation of the affected host/share) tied to it, because every minute between first FileCreate spike and containment is additional encrypted estate. Track mean-time-to-isolation from first VSS-deletion or note-drop alert as a hard KPI reviewed after every ransomware exercise and real event.
