# EP-023 — Shadow Copy (VSS) Deletion

## Playbook ID & Name
**EP-023** — Shadow Copy (VSS) Deletion (Endpoint – Persistence & Impact)

## Business Risk
**[STAKEHOLDER]** - Shadow copies are the built-in, no-extra-license safety net that lets IT restore a file, a folder, or in some configurations a whole volume without reaching for the offsite backup. When that safety net gets cut, the organization's actual recovery position collapses to whatever the offsite/immutable backup can provide — and if that backup is also stale, disconnected, or itself a target, there may be no recovery position at all. This alert almost never shows up on its own; in the intrusions where analysts see it, it is the last quiet step before files start encrypting, which means the decision window between "we saw VSS get wiped" and "we have a full ransomware event" is measured in minutes, not hours. Executives should read a confirmed VSS-deletion event as a countdown, not a line item.

## Severity/Priority Default
**Critical** on servers, domain controllers, file shares, backup infrastructure, or any host outside a documented backup/maintenance window. **High** on standard workstations pending parent-process review — still needs same-shift triage, because workstation VSS wipes are a known ransomware self-encryption pattern too, just with a smaller blast radius than a file server.

## MITRE ATT&CK Technique(s)
- **T1490** Inhibit System Recovery (primary — this is the canonical technique for VSS/shadow copy/backup catalog destruction)
- Almost always a precursor to, or bundled with: **T1486** Data Encrypted for Impact (the deletion exists to remove the undo button before encryption starts)
- Frequently paired with: **T1562.001** Impair Defenses (stopping the EDR/AV agent or the VSS/backup service itself before or immediately after the deletion), **T1543.003** Create or Modify System Process: Windows Service (a throwaway remote-exec service, e.g. PsExec-style, used to run the deletion command on a remote host), **T1053.005** Scheduled Task/Job (deletion staged via a scheduled task instead of interactive execution)

## Trigger / Detection Logic Summary
Alert on process creation (Sysmon Event ID 1 or Security 4688 where command-line auditing is enabled) matching known shadow-copy or recovery-inhibition command patterns: `vssadmin.exe delete shadows`, `wmic.exe shadowcopy delete` (or the modern `wmic /namespace:\\root\cimv2 path Win32_ShadowCopy delete`), PowerShell `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance` / `Get-WmiObject ... Remove-WmiObject`, `diskshadow.exe` invoked with a script containing `delete shadows all`, `wbadmin.exe delete catalog -quiet`, and `bcdedit.exe` invocations toggling `recoveryenabled no` or `bootstatuspolicy ignoreallfailures`. Treat the `/all` and `/quiet` flag combination on `vssadmin` as higher-confidence than a scoped `/for=<volume> /oldest` call. Because several ransomware families and EDR-killer toolkits call the VSS APIs directly (`IVssBackupComponents`) or drive `diskshadow` from a dropped script rather than typing the command interactively, don't rely on `vssadmin.exe` process creation alone — Sysmon 11 FileCreate for a `.txt`/`.ds` diskshadow script dropped into a temp path immediately before a `diskshadow.exe` launch, and a sudden absence of expected VSS-related Sysmon 1 activity combined with a spike in file rename/write activity, are both valid secondary triggers.

## Required Log Sources & Event IDs
| Source | Event ID(s) | Purpose |
|---|---|---|
| Sysmon | 1 | Full command line + parent command line for `vssadmin.exe`, `wmic.exe`, `diskshadow.exe`, `powershell.exe`, `bcdedit.exe`, `wbadmin.exe` |
| Security log | 4688 | Same process-creation confirmation on the native log; command line only present if auditing is enabled |
| Security log | 4624, 4672 | Logon type and privilege context of the account executing the deletion — this needs local admin/SYSTEM to succeed |
| Sysmon | 11 | FileCreate for dropped `diskshadow` scripts, or the ransom-note/encrypted-file burst that typically follows |
| Sysmon | 23 | FileDelete — confirms files (or the diskshadow script itself) being removed post-execution, anti-forensics behavior |
| Sysmon | 12/13/14 | RegistryEvent — VSS service start-type changes, `SystemRestore\DisableSR`, or other recovery-related keys touched around the same time |
| System log | 7045 | New service installed — flags a throwaway remote-exec service (e.g., PsExec-pattern) used to run the deletion command on a remote host |
| Security log | 4697 | Service installed (Security log equivalent of 7045), if that auditing subcategory is enabled |
| Security log | 4698 | Scheduled task creation, if the deletion was staged as a task rather than run interactively |
| Security log | 1102 | Audit log cleared — frequently shows up in the same session as anti-forensics cleanup around a VSS wipe |
| PowerShell logs | 4103, 4104 | Module logging and script block text — de-obfuscates `Remove-CimInstance`/`Remove-WmiObject` one-liners hidden behind `-enc` |

## Key Fields to Inspect
**[ANALYST]**
- **CommandLine (Sysmon 1) / Command Line (4688)** — the exact flags matter: `/all /quiet` (mass wipe, high suspicion) vs `/for=D: /oldest` (scoped cleanup, backup-tool pattern).
- **ParentImage / ParentCommandLine** — was this launched from `explorer.exe` by an interactive user, from `cmd.exe`/`powershell.exe` spawned by `wmiprvse.exe` (remote WMI execution, common lateral-movement signature), or from a legitimate backup binary (`Veeam.Backup.Service.exe`, `wbengine.exe`, `MBAMservice.exe`)?
- **User / Subject (4688) and the tied Logon ID** — pivot back to the originating 4624 to see Logon Type (Type 3 network logon from a remote host is a red flag for this specific action), Source Network Address, and whether 4672 fired alongside it (privileged token).
- **IntegrityLevel (Sysmon 1)** — should be High/System for this command to succeed at all; a failed attempt from a Medium-integrity process is still worth logging as an attempted TP.
- **Hashes / SignatureStatus** — legitimate `vssadmin.exe`/`wmic.exe`/`diskshadow.exe` are signed Microsoft binaries in `System32`; a same-named binary running from another path is a masquerading attempt, not a real VSS operation.
- **7045 Image Path / Service Name** — random-looking service names (`{8f3a...}`, single letters) created moments before the deletion command strongly suggest remote-exec tooling rather than routine administration.
- **Sysmon 11 timestamps immediately following** — a burst of file renames/writes to new extensions across many directories within minutes of the VSS command is the single strongest corroborating signal that this is pre-encryption staging, not maintenance.

## Normal vs Suspicious Pattern
| Attribute | Normal / Expected | Suspicious |
|---|---|---|
| Command scope | `vssadmin delete shadows /for=D: /oldest /quiet` — single volume, oldest snapshot only | `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, or `diskshadow` script with `delete shadows all` — everything, everywhere, no scoping |
| Parent process | Backup agent binary (`wbengine.exe`, `Veeam.Backup.Service.exe`, `vssvc.exe` internal calls), or `sqlservr.exe`-triggered VSS writer cleanup | `cmd.exe`/`powershell.exe` spawned from `wmiprvse.exe`, `psexesvc.exe`, a macro-spawned Office process, or a freshly installed throwaway service (7045) |
| Account | Dedicated backup service account, or SYSTEM inside a scheduled backup job | Standard user account, or a domain/local admin account with no history of running this command on this host |
| Timing | Falls inside a known, recurring backup/maintenance window | One-off execution, off-hours, no ticket, clustered with discovery or credential-access alerts earlier in the session |
| Host scope | Single host, or a documented backup-schedule cohort | Multiple hosts in the same subnet/domain hit within a short window — classic ransomware pre-staging across a fleet |
| Follow-on activity | Nothing unusual — backup job proceeds, disk space reclaimed | Mass file rename/encryption (Sysmon 11 spike), `bcdedit` recovery-disable calls, `wbadmin delete catalog`, or a ransom note drop within minutes |

## Investigation Steps
1. Pull the exact command line from Sysmon 1 (preferred, always populated) or Security 4688 (only if command-line auditing is enabled — confirm this before assuming it's missing on purpose) and note the flags: scoped vs. `/all`, `/quiet` or interactive.
2. Trace ParentImage/ParentCommandLine and the Creator Process chain — identify whether this was interactive (explorer → cmd), remote (`wmiprvse.exe`, `psexesvc.exe`, WinRM host process), or backup-software-driven.
3. Resolve the executing account via Subject/User, then pull its originating 4624/4672 — check Logon Type and Source Network Address to see if this account authenticated from a remote host minutes earlier, and whether the token carried admin-equivalent privileges.
4. Check 7045/4697 in the same time window for a newly installed service that could have been the remote-execution vehicle, and check 4698 for a scheduled task created to run the deletion instead.
5. Look immediately forward in the timeline for Sysmon 11 (FileCreate) and 23 (FileDelete) bursts — a sudden spike of file writes/renames across user or share directories in the following 5-15 minutes is the strongest indicator this is active ransomware, not cleanup.
6. Check for companion anti-forensics activity: 1102 (audit log cleared), a stopped/uninstalled Sysmon or EDR service, `bcdedit` recovery-disable calls, or `wbadmin delete catalog` — attackers frequently chain several recovery-inhibition actions together rather than relying on VSS deletion alone.
7. Query for the same command pattern, hash, or source account across other hosts in the environment — this technique is regularly pushed fleet-wide in a single automation pass right before mass encryption.
8. Cross-check EDR verdict and any Sysmon 3/22 network activity from the same process tree in the surrounding window (C2 callback, staging-server connection) to build the full picture before writing the disposition.

## True Positive Indicators
- `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, or a `diskshadow` script wiping all shadow copies, executed outside any documented backup/maintenance activity.
- Command launched from a remote-execution parent (`wmiprvse.exe`, `psexesvc.exe`, a throwaway service from 7045) rather than a backup product.
- Executed under a compromised or unusual admin/service account with a 4672 privileged logon minutes prior and a Type 3 (network) 4624 from an unexpected source.
- Immediately followed by mass file rename/write activity (Sysmon 11) or a ransom-note drop — confirms the encryption-precursor pattern.
- Companion `bcdedit` recovery-disable calls, `wbadmin delete catalog -quiet`, or a VSS/backup service being stopped (7045/service-state change) in the same session.
- Same command/account/hash observed hitting multiple hosts in a short window.

## False Positive / Benign Positive Indicators
- Scoped `vssadmin delete shadows /for=<volume> /oldest` run by a backup service account inside a recurring, ticketed backup or disk-cleanup job.
- Parent process is a known, signed backup/RMM/AV product performing routine shadow-copy lifecycle management (Veeam, Windows Server Backup, Macrium, Acronis).
- Admin manually clearing old restore points under an approved change ticket to reclaim disk space on a storage-constrained volume.
- VDI/golden-image refresh workflows that intentionally reset shadow copies as part of a documented rebuild process.
- No follow-on file-modification spike, no companion recovery-inhibition or anti-forensics indicators, and the host/account match an established, recurring pattern in the environment.

## Escalation Criteria
Escalate to IR/Tier 2 immediately — treat as a likely active ransomware event, not a routine finding — if: the command used `/all` scope outside a maintenance window; the parent process is a remote-exec vehicle or freshly installed service; the executing account shows signs of prior compromise (unusual logon type/source, recent privilege escalation); a mass file-modification burst appears in the following minutes on this or any other host; or companion anti-forensics/recovery-inhibition indicators (1102, bcdedit changes, wbadmin catalog deletion, EDR/Sysmon service tampering) are present in the same timeframe. Any hit on a domain controller, backup server, or file server warrants an immediate bridge call regardless of how confident the initial triage feels — this is not a technique worth sitting on to gather more evidence first.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Isolate the host from the network (EDR containment)** — Tier 2 analyst authority for a single workstation or server the moment TP indicators are present; for a domain controller or core backup server, requires IR Lead or on-call SOC Manager sign-off given the business-continuity blast radius, but this should not delay isolation beyond minutes given the ransomware precursor risk.
- **Disable/lock the executing account** — IAM/on-call manager approval if it's a shared service account (automation dependencies may break); standard user or clearly compromised admin accounts can be disabled at analyst discretion pending investigation.
- **Kill the remote-exec service (7045 artifact) and terminate the process tree** — Tier 1/2 authority once confirmed malicious; preserve command line, hash, and full process tree as evidence before removal.
- **Fleet-wide hunt for the same command/hash/account across other hosts** — SOC Manager approval to authorize a scripted sweep, since a positive hit cascade may require invoking the organization's ransomware IR plan.
- **Escalate to full ransomware IR playbook (executive bridge, legal, backup-integrity verification)** — CISO/IR Lead authority; triggered automatically once a mass file-modification burst or multi-host pattern confirms this wasn't an isolated event.

## Example Query
Splunk SPL — flag recovery-inhibition command patterns from Sysmon process creation:

```spl
index=sysmon EventCode=1
| regex CommandLine="(?i)(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|diskshadow|Remove-(Cim|Wmi)Instance.*ShadowCopy|wbadmin.*delete\s+catalog)"
| eval scope=if(match(CommandLine,"(?i)/all"), "ALL_VOLUMES", "scoped")
| table _time, ComputerName, User, ParentImage, ParentCommandLine, Image, CommandLine, scope
| sort - _time
```

## Closure Criteria
Close as **True Positive – Contained** once the host is isolated, the executing account and remote-exec vehicle (if any) are identified and remediated, evidence (command line, hash, process tree, any follow-on file-modification indicators) is preserved, and — if any encryption activity is confirmed — the full ransomware IR playbook has been engaged rather than closed at this ticket level. Close as **Benign Positive / Expected Activity** once the command, account, parent process, and timing all match a documented backup or maintenance workflow, with no follow-on file-modification spike. Close as **Insufficient Evidence** only after confirming command-line auditing and Sysmon were actually enabled and collecting on that host at the time — a missing 4688 command line or an absent Sysmon 1 entry due to a coverage gap is not the same as confirming nothing happened; log the telemetry gap for Engineering separately from the case disposition.

**Example case-note line:** *"Sysmon EventID 1 on FS01-CHICAGO (10.20.4.15, file server) shows `vssadmin.exe delete shadows /all /quiet` at 03:12 UTC under account svc_helpdesk, ParentImage powershell.exe spawned from wmiprvse.exe (remote WMI exec originating from 10.20.4.9, no ticket). No scheduled backup job registered for this account. Sysmon 11 shows 420+ files renamed to `.lockbit24` extension across \\FS01\Finance\ within 3 minutes of the VSS command. 1102 not observed. Host isolated via EDR at 03:15 UTC, svc_helpdesk disabled, source host 10.20.4.9 flagged for the same sweep, ransomware IR bridge opened — closed True Positive, escalated to full IR."*
