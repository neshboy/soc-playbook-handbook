# Unknown / Unrecognised Executable Execution

**Category:** Endpoint – Execution & LOLBins
**Playbook ID:** EP-013

This playbook is about the alert that fires not because a binary *did something* obviously bad, but because nobody — not your EDR's reputation cloud, not VirusTotal, not your own fleet — has seen it before. No LOLBin parent/child oddity, no encoded PowerShell, sometimes not even a network connection at the point of alert. Just a hash with zero history, running from somewhere it probably shouldn't be, and a verdict of "Unknown" instead of "Clean" or "Malicious." That ambiguity is the entire job here: most of these close as Benign Positive or Insufficient Evidence, and the ones that don't are frequently the highest-value catches an analyst makes all month, because a genuinely novel binary with no reputation anywhere is exactly what a targeted intrusion looks like before anyone's written a signature for it.

## Business Risk

**[STAKEHOLDER]** - Signature and reputation-based defenses only work against things someone else has already seen. A custom-built implant, a freshly packed commodity loader, or a one-off tool compiled for this specific target will show up with a clean AV scan and no reputation hit — the only thing that gives it away is that literally nothing recognizes it. This detection exists to catch that gap between "not yet flagged malicious" and "actually malicious," which is precisely where targeted attacks and pre-ransomware staging tend to sit for the first hours or days of an intrusion.

## Severity / Priority Default

**Medium**, escalating to **High** when the binary is unsigned *and* executing from a user-writable path *and* has a network callout or spawns a script interpreter within seconds of launch. Downgrades toward **Low** quickly once provenance is confirmed as an internal build or a legitimate new software rollout.

## MITRE ATT&CK Techniques

- T1204 User Execution
- T1105 Ingress Tool Transfer
- T1027 Obfuscated Files or Information (packed/high-entropy binaries evading static and reputation-based detection)

Follow-on techniques frequently pivot into T1059.001/.003 (interpreter spawned by the unknown binary), T1547.001 (Registry Run key persistence), or T1055 (process injection) — treat those as branch investigations into other playbooks in this book, not as part of this alert's core scope.

## Trigger / Detection Logic Summary

Fires when EDR/NGAV file-reputation lookup returns an **Unknown/Not-Classified** verdict for an executable that was permitted to run (audit mode) or blocked (enforce mode) under an application-control policy (AppLocker, WDAC, or equivalent EDR execution-prevention rule), combined with one or more of:

- Zero prior executions of this exact SHA256 anywhere in the fleet ("first-seen" hash), and low or no engine detections on public reputation lookup — not "clean," just "nobody has an opinion yet."
- No valid Authenticode signature, or a signature whose publisher isn't in the org's known-good publisher list.
- Execution path under `%TEMP%`, `%APPDATA%`, `\Downloads\`, `\Users\Public\`, or a ProgramData folder with no matching software-inventory entry.
- File carries a Mark-of-the-Web / alternate data stream indicating it arrived from the internet, an email attachment, or removable media rather than an internal software distribution channel.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Core evidence — hash, full path, `Signed`/`SignatureStatus`/`Signature` fields, parent, command line, integrity level |
| Windows Security | 4688 (New Process) | Fallback where Sysmon isn't deployed; command line requires auditing enabled |
| Sysmon | 15 (FileCreateStreamHash) | Alternate-data-stream/Mark-of-the-Web on the binary — tells you it came from the internet or an attachment |
| Sysmon | 11 (FileCreate) | Timestamp/path of the binary landing on disk, and anything it drops afterward |
| Sysmon | 3 (Network Connection) / 22 (DNSEvent) | Follow-on callout attributed to the exact `ProcessGuid` |
| Sysmon | 6 (Driver Loaded) / 7 (Image Loaded) | Unusual driver or DLL sideload behaviour tied to the same process |
| Sysmon | 10 (ProcessAccess) | Handle opens to sensitive targets (e.g. `lsass.exe`) — escalates severity immediately |
| Sysmon | 12/13/14 (RegistryEvent) | Persistence write following execution |
| Security / System | 4698, 7045, 4697 | Scheduled task or service created as a follow-on persistence mechanism |
| Microsoft-Windows-PowerShell/Operational | 4104, 4103 | If the unknown binary spawns a scripting interpreter |
| EDR platform log | (vendor-specific, not a Windows/Sysmon ID) | File reputation verdict, prevalence count, and quarantine/block action — this is usually where the "Unknown" classification itself lives |

## Key Fields to Inspect

**[ANALYST]**

- `Image` / full path — case and folder matter; a binary named `svchost.exe` sitting in `\AppData\Local\Temp\` is not the real `svchost.exe`, regardless of name
- `Hashes` (SHA256) — the pivot point for every reputation lookup, internal prevalence check, and threat-intel query you'll run
- `Signed` / `SignatureStatus` / `Signature` (Sysmon fields) — unsigned, invalid, or revoked is meaningfully different from "signed by a publisher we've simply never allow-listed"
- `Description` / `Product` / `Company` (PE metadata, if populated) — blank or generic metadata on a binary claiming to be enterprise software is a tell
- `ParentImage` / `ParentCommandLine` — how did this thing actually get launched: double-click by a user, a script, a scheduled task, an install package?
- `IntegrityLevel` and `User`/`LogonId` — interactive human context vs. service/automation context
- Zone identifier / Sysmon 15 stream hash — confirms internet or attachment provenance
- EDR prevalence count — "seen on 1 of 4,000 endpoints" is a very different risk profile than "seen on 1 of 4,000 endpoints, and that one endpoint is a domain controller"

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Signature | Signed by an internal build system or a known vendor certificate, even if newly seen | Unsigned, self-signed, or signed by a certificate with no relation to the claimed publisher |
| Execution path | Program Files, a software-deployment staging folder, a documented dev/build share | `%TEMP%`, `%APPDATA%\Roaming`, `\Downloads\`, `\Users\Public\` |
| Provenance | Pushed via SCCM/Intune/patch pipeline, or compiled locally by a known dev account | Mark-of-the-Web present, arrived as an email attachment or browser download with no ticket/change record |
| Fleet prevalence | Rolls out to many hosts within hours/days as a version bump | Exactly one host, one execution, no corresponding deployment |
| Behaviour after launch | Normal application startup, UI window, expected file/registry activity | Immediate network callout, spawns `cmd.exe`/`powershell.exe`, opens a handle to `lsass.exe`, self-deletes (Sysmon 23) shortly after running |

## Investigation Steps

1. Pull the Sysmon Event ID 1 record for the alerting process in full — hash, path, `Signed`/`SignatureStatus`, parent process and command line, integrity level, `ProcessGuid`.
2. Check EDR file reputation and prevalence: is this hash truly novel fleet-wide, or just new to this one host? Cross-check the SHA256 against VirusTotal and any internal threat-intel feed — "0 detections today" doesn't mean clean, it means unsubmitted or genuinely new.
3. Establish provenance. Check Sysmon Event ID 15 for a Mark-of-the-Web ADS and Event ID 11 for the file's creation timestamp/path — did it arrive via browser download, email attachment, removable media, or an internal deployment tool? Correlate with the user's browsing/mail activity in the same window if provenance isn't obvious from telemetry alone.
4. Walk the process tree both directions — what launched this binary (user double-click, script, installer, scheduled task) and what it spawned afterward. A user-launched unknown binary that immediately shells out to `cmd.exe` is a materially different story than one that just opens a UI and sits idle.
5. Check Sysmon Event ID 3/22 for any network connection or DNS resolution attributed to the exact `ProcessGuid`, allowing a few minutes either side for clock drift and ingestion delay.
6. Check Sysmon Event ID 10 for handle opens to `lsass.exe` or other sensitive processes, and Event ID 6/7 for unexpected driver loads or DLL sideloading — either materially raises severity regardless of hash reputation.
7. Check for persistence: Sysmon 12/13/14 registry writes (Run keys), or 4698/7045/4697 for a scheduled task/service created around the same time.
8. Search the SIEM/EDR fleet-wide for the same hash, filename, or signing certificate thumbprint on other hosts to establish scope before closing.

## True Positive Indicators

- Unsigned or falsely-signed binary executing from a user-writable path, with Mark-of-the-Web indicating internet/attachment delivery.
- Immediate post-execution network callout to an uncategorized domain or raw IP, or a DNS query for a newly registered domain.
- Process opens a handle to `lsass.exe`, loads an unexpected unsigned driver, or spawns a script interpreter with an encoded/obfuscated command line.
- Confirmed to be a packed or high-entropy binary with no legitimate PE metadata, and it self-deletes (Sysmon Event ID 23) shortly after execution.
- Same hash or signing certificate subsequently appears on additional hosts with no deployment record.

## False Positive / Benign Positive Indicators

- Internal tool built by an engineering or automation team without a code-signing pipeline — common in orgs that haven't invested in internal signing; verify against the team and their build/source repo.
- Legitimate new software version whose hash simply hasn't propagated to public reputation clouds yet, especially on release day — check the vendor's official release notes/hash if available.
- SCCM/Intune-deployed package running for the first time on this particular host, but with a clear deployment record on other hosts in the same wave.
- Renamed or repackaged internal automation tool that should already be in the software asset inventory but isn't — a process gap for detection engineering to close, not an incident.

## Escalation Criteria

Escalate to Tier 2 / IR when the binary opens a handle to `lsass.exe` or another credential-bearing process, when it establishes a network callout to infrastructure with no legitimate business tie, when the same hash or certificate thumbprint appears on more than one host without a deployment record, when the affected host is a server or domain controller, or when provenance traces back to a phishing delivery rather than an internal source — any of those turns "unrecognised binary" into an active intrusion investigation.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority |
|---|---|
| EDR-isolate the single endpoint pending investigation | Tier 1/2 analyst, no additional approval, reversible |
| Quarantine/block the specific hash via EDR | Tier 2 analyst |
| Shift the binary/publisher from AppLocker/WDAC audit to enforce, fleet-wide | Tier 2 analyst + detection engineering sign-off (can break legitimate software if publisher is broad) |
| Kill process and collect memory/forensic image before removal | Tier 2 analyst / IR |
| Isolate a server or domain-controller-class asset | IR lead + infrastructure owner sign-off (production impact) |

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once an unsigned binary in a user-writable path shows a network callout or spawns an interpreter (High).

## Example Query (Splunk SPL)

```spl
index=sysmon EventCode=1
| where NOT match(SignatureStatus, "Valid")
| where match(Image, "(?i)\\\\(Temp|AppData|Downloads|Public)\\\\")
| stats count min(_time) as first_seen by Hashes, Image, ParentImage, ComputerName, User
| where count < 5
| sort - first_seen
```

## Closure Criteria

Close as **True Positive** once the host is isolated/remediated, the hash/certificate is blocked fleet-wide, and no further callout or persistence activity is observed for 24 hours. Close as **Benign Positive** once provenance is confirmed against a build system, deployment record, or vendor release, and the binary is added to the known-good software inventory. Close as **Insufficient Evidence** when the file has already been deleted with no surviving Sysmon 11/15 record, command-line auditing was off, or the host's EDR telemetry retention window has already rolled past the execution time — say so plainly in the case note rather than guessing at a verdict.

**Example case note:**
> 2026-09-15 09:41 UTC — EDR flagged `winupdate_helper.exe` (SHA256 `a1b2...`) as Unknown/Not-Classified, executing from `C:\Users\r.chen\AppData\Local\Temp\` on host `WKS-ENG-031`. Sysmon ID 15 confirmed Mark-of-the-Web ADS present; ID 11 timestamp lines up with a Chrome download 40 seconds prior from a file-sharing link in a personal webmail tab (not corporate mail). No signature (`SignatureStatus=Unsigned`). ID 3 showed outbound to 203.0.113.44:443 within 6 seconds of launch; ID 10 showed no `lsass.exe` handle access. Hash not found on VirusTotal at time of triage; submitted for analysis. Fleet search found zero other occurrences. Host isolated, hash blocked at EDR, user interviewed — confirmed they downloaded a "PDF converter" from a search-ad link. Closed as True Positive; user re-imaged rather than cleaned given unknown persistence risk.
