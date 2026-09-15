# EP-022 — Mass File Modification (Ransomware-Adjacent)

**Category:** Endpoint - Persistence & Impact

## Business Risk

**[STAKEHOLDER]** - This is the alert you want firing while a handful of files are affected, not after eight thousand of them have a new extension and a ransom note sitting in every folder. Mass file modification is usually the last visible stage before, or the opening minutes of, a ransomware detonation - file servers, user shares, ERP data directories, backup repositories, all rewritten in a matter of minutes. The business exposure isn't just downtime: it's recovery cost, potential ransom/extortion decision-making, regulatory notification if the encrypted data included personal or financial records, and the very real chance that the attacker deleted or encrypted the backups first specifically so restoration isn't an option. Whether to pay, whether to disclose, and how far to isolate the network are decisions for the incident commander and executive leadership, not the SOC - but the SOC buys the time to make those decisions well instead of in a panic.

## Severity / Priority Default

**Critical / P1**, always, on first credible trigger. This is one of the few playbooks in the book where there is no default downgrade path - a confirmed benign explanation (documented backup job, approved encryption tool, bulk migration) closes the case, but the starting posture is "assume detonation in progress" until proven otherwise. Time-to-first-response should be measured in single-digit minutes, not the standard SLA tier.

## MITRE ATT&CK Techniques

- **T1486** - Data Encrypted for Impact (the core behavior)
- **T1490** - Inhibit System Recovery (shadow copy deletion, backup catalog deletion, boot recovery disabled - almost always co-occurs)
- **T1562.001** - Impair Defenses: Disable or Modify Tools (AV/EDR killed or uninstalled minutes before detonation)
- **T1021.002** - Remote Services: SMB/Windows Admin Shares (encryption spreading to other hosts over network shares)
- **T1053.005 / T1543.003** - Scheduled Task / Windows Service (mass-deployment mechanism used to trigger the encryptor on many endpoints near-simultaneously)
- **T1078.002** - Valid Accounts: Domain Accounts (compromised admin credentials used to push the payload at scale)
- **T1105** - Ingress Tool Transfer (staging the encryptor binary before detonation)
- **T1027** - Obfuscated Files or Information (packed/crypted encryptor binaries, common with commodity ransomware builders)

## Trigger / Detection Logic Summary

Fires on abnormal file-write/file-delete velocity attributed to a single process (or small set of processes) across a large number of distinct files and directories in a short window - typically expressed as "N file creates/renames/deletes per process per host within T minutes" exceeding a tuned baseline, or on canary/deception files (planted decoy documents in file shares) being touched at all. Strengthen the signal by correlating with the classic pre-detonation checklist: shadow copy deletion (`vssadmin`, `wmic shadowcopy delete`, `wbadmin delete catalog`), recovery options disabled (`bcdedit /set recoveryenabled no`), and a security-tool-tampering event in the same host/timeframe. A single file rename is noise. Thousands of file writes plus a shadow-copy-deletion command line plus a new file extension appearing across a share is not.

## Required Log Sources & Event IDs

| Source | Event ID | Why |
|---|---|---|
| Sysmon | 11 (FileCreate) | The core signal - encrypted output files, ransom note drops (`README.txt`, `DECRYPT_INSTRUCTIONS.html`, etc.), attributed to the responsible process |
| Sysmon | 23 (FileDelete) | Original files removed after encryption, and shadow-copy/backup file deletion - archived by Sysmon even when the attacker tries to clean up |
| Sysmon | 1 (Process Creation) | The encryptor binary launch, plus `vssadmin.exe`, `wbadmin.exe`, `bcdedit.exe`, `wmic.exe` invocations with full command line, parent chain, hashes |
| Sysmon | 3 (Network Connection) | SMB connections fanning out to multiple hosts/shares from one source - lateral spread pattern |
| Windows Security | 4688 | Fallback for the same process-creation events if Sysmon isn't deployed everywhere; command line only if CLI auditing is on |
| Windows Security | 4697 / System 7045 | Encryptor pushed and installed as a service across multiple endpoints for coordinated mass execution |
| Windows Security | 4698 | Scheduled task created to trigger detonation at a set time - the classic "stage now, fire at 02:00" pattern |
| Windows Security | 4624 / 4648 | Compromised admin account logon (Logon Type 3/network or 10/RDP) or explicit-credential use pushing the payload to multiple targets |
| Windows Security | 1102 | Audit log cleared - anti-forensics before or immediately after detonation |
| Windows Security | 4719 | Audit policy weakened ahead of the attack - attacker blinding logging before the noisy part starts |

## Key Fields to Inspect

**[ANALYST]**
- `TargetFilename` and file extension pattern on Sysmon 11/23 - is a consistent new extension being appended across unrelated file types? Are files both created and deleted for the same base name in quick succession (encrypt-then-delete-original)?
- `Image` / `ProcessGuid` tying the file events back to one specific process - is it a known LOB app, or an unrecognized/renamed binary?
- `CommandLine` on Sysmon 1 / 4688 for `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set {default} recoveryenabled no`, `wbadmin delete catalog -quiet`
- `Hashes` of the executable performing the writes - check against threat intel even if the filename looks legitimate (ransomware binaries are routinely renamed to `svchost.exe`, `explorer.exe`, etc.)
- `ParentImage` / `ParentCommandLine` - was this launched interactively, by a scheduled task, or by a service?
- UNC paths (`\\fileserver01\finance$\...`) in the file events - confirms encryption is reaching network shares, not just local disk
- `Service Name` / `Image Path` on 7045/4697, and `Task Content` XML on 4698 - the actual deployment mechanism, often the fastest way to find every affected host at once
- `Source Network Address` / `Workstation Name` on 4624/4648 - the pivot host the attacker is pushing from, frequently a domain controller or a compromised admin workstation
- File write **rate per minute per host** - the single most useful derived field for separating "something odd happened" from "an active encryption run is in progress right now"

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Backup software (Veeam, Acronis, Windows Server Backup) rewriting its own backup repository files on a documented schedule | Files across unrelated departments (Finance, HR, Engineering shares) modified within the same few minutes by the same process |
| File sync/cloud tools (OneDrive, Dropbox, SharePoint sync) touching files a user actively edited | A consistent, unfamiliar extension appended to thousands of otherwise-unrelated files (`.locked`, `.enc_x7`, random 5-8 char strings) |
| AV/EDR engine performing a signature update or quarantine-rename of a handful of flagged files | `vssadmin`/`wbadmin`/`bcdedit` recovery-disable commands executed minutes before or during the file-write spike |
| Legitimate disk/file encryption rollout (BitLocker, EFS `cipher /e`) run under a documented change ticket, gradual pace | A ransom note file (`README`, `HOW_TO_DECRYPT`, `RESTORE_FILES`) appearing in the same directories as the modified files |
| Scheduled task tied to a known maintenance job (defrag, index rebuild, media transcode) | New/unrecognized scheduled task or service created just before the write spike, deployed to multiple hosts near-simultaneously |
| Admin account logs on interactively for routine server maintenance | Domain admin or service account authenticates to many hosts in rapid succession (4624/4648) immediately preceding file activity on each |

## Investigation Steps

1. Pull the Sysmon 11/23 volume for the affected host(s): file count, rate per minute, extension pattern, and the exact `Image`/PID responsible. Confirm this is an active, ongoing write pattern versus a completed historical event.
2. Isolate the responsible process's Sysmon 1 record - full command line, parent chain, hash, signature status, integrity level. Check the hash against internal and external threat intel immediately; don't wait for a full writeup to do this step.
3. Search the same host and timeframe for `vssadmin`, `wmic shadowcopy`, `wbadmin`, `bcdedit` command lines (Sysmon 1/4688) and any 1102/4719 events - these confirm recovery-inhibition and anti-forensics intent, not just data damage.
4. Check Sysmon 3 for outbound/lateral SMB connections from the same process or PID - is this contained to one host, or spreading to file servers and other endpoints over admin shares?
5. Pivot on 4624/4648 for the account driving this - is it a compromised admin/service account, and what other hosts has that account authenticated to in the last several hours? This defines your blast-radius estimate.
6. Check 4697/7045 and 4698 across the environment (not just the triggering host) for the same service name, image path, or task name/content - mass ransomware deployment almost always reuses one mechanism across many machines, and finding it lets you scope and contain in one pass instead of host-by-host.
7. Confirm backup integrity out-of-band with the backup team - has the backup repository itself been touched, encrypted, or had its catalog deleted? This changes the entire recovery conversation and needs to go up the chain immediately regardless of investigation status.
8. Document every affected host, share, and account as you find them in a running list - this incident will be handed to IR/leadership before your investigation is "finished," and a partial-but-accurate scope beats a complete report that arrives too late.

## True Positive Indicators

- Sustained high-rate file create/delete activity from one process across multiple unrelated directories or shares
- Consistent unfamiliar file extension applied across many file types (documents, images, databases) that have nothing else in common
- Ransom note file dropped in the same directories as the modified files
- Shadow copy/backup deletion commands executed in the same timeframe as the write spike
- Encryptor binary is unsigned, freshly written to disk, or has a hash matching known ransomware families
- Mass deployment artifact (service, scheduled task) with identical name/path pushed to multiple hosts from one source account/system

## False Positive / Benign Positive Indicators

- Documented backup, replication, or archival job (Veeam, Acronis, Windows Server Backup, Robocopy mirror) running on its known schedule against its known target paths
- Approved disk/file-level encryption rollout under an active change ticket, applied gradually rather than as a burst
- Large legitimate batch job - media transcoding, PDF re-generation, data migration, index rebuild - with a plausible business owner who can confirm it on request
- AV/EDR quarantine or signature-update activity renaming/moving a small, explainable set of files, not a mass unrelated-file pattern
- File sync client catching up after being offline, producing a burst of writes that map to one user's own recently-edited files, not an entire share

## Escalation Criteria

Escalate immediately to IR/CIRT and page the on-call incident commander if: the write pattern spans more than one host, a ransom note is present, shadow copy or backup deletion commands are confirmed, the driving account has domain admin or broad service-account reach, or backup repositories show any sign of being touched. Do not wait for "full scope" before escalating - the initial page can and should go out on the first confirmed indicator; scope refinement happens in parallel with the incident bridge, not before it opens.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Network-isolate the affected endpoint(s) via EDR - Tier 2 analyst can execute unilaterally the moment mass encryption behavior is confirmed; notify IR lead within 5 minutes, not 15, given the blast-radius speed of this scenario.
- Kill the responsible process tree on affected hosts - Tier 1/2, no separate approval, log immediately.
- Disable the compromised account(s) driving the spread - IR lead or on-call manager approval given business disruption, but treat this as urgent-approve, not routine-approve, once lateral spread is confirmed.
- Segment or disable the affected file share(s)/SMB access at the network level - requires network team + IR lead sign-off; balance "stop the spread" against "don't destroy forensic state on the file server" if backups are also at risk.
- Verify and, if needed, isolate the backup infrastructure itself from the rest of the network - backup/infrastructure team plus IR lead jointly, this is often the single highest-value containment action in the entire incident.
- Formal ransomware incident declaration, legal/comms engagement, and any ransom-related decision - CISO/executive incident commander only, never a SOC-level call.

## Example Query (Splunk SPL, Sysmon FileCreate/FileDelete)

```spl
index=sysmon (EventCode=11 OR EventCode=23)
| bin _time span=2m
| stats dc(TargetFilename) as file_ops, values(TargetFilename) as sample_files
    by _time, Computer, Image, ProcessGuid
| where file_ops > 200
| sort - file_ops
```

## Closure Criteria

Close as **True Positive** only after containment is confirmed effective (process killed, hosts isolated, spread stopped), full scope of affected hosts/shares/accounts is documented, and the finding is handed to IR for the recovery phase - this playbook's SOC-side closure is "contained and scoped," not "resolved," since recovery and any disclosure decisions extend well past SOC ownership. Close as **Benign Positive** when the write pattern is fully attributed to a documented job or approved tool with a confirmable owner. Close as **Insufficient Evidence** only in narrow cases - e.g., the host went offline before full Sysmon telemetry could be pulled - and flag the gap explicitly rather than letting a fast-moving host go quiet without a scoped explanation.

**Example case note:** *"FS-PROD-03 (\\\\fileserver01\\finance$) showed 4,812 Sysmon FileCreate events and 4,790 FileDelete events in an 8-minute window, all attributed to PID 6620, image `svc_update.exe` (unsigned, hash not previously seen, dropped to C:\\Windows\\Temp\\ four minutes prior via Sysmon 11). New extension `.rcvr7` applied across .docx/.xlsx/.pdf files; `RECOVER_FILES.html` note dropped in every touched directory. Sysmon 1 confirms `vssadmin.exe delete shadows /all /quiet` executed 90 seconds before the spike from the same parent process. 4648 shows the deployment account svc-backupadm authenticating to six additional file/app servers in the prior 20 minutes. Host isolated 03:14 UTC, account svc-backupadm disabled 03:17 UTC pending password reset, IR bridge opened 03:19 UTC, backup team confirmed backup repository BK-VAULT-01 unaffected. Verdict: True Positive, T1486/T1490, contained and handed to IR for recovery."*
