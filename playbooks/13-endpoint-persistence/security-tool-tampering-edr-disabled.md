# Security Tool Tampering / EDR Disabled

## Playbook ID & Name

**EP-024 — Security Tool Tampering / EDR Disabled** (Endpoint category, subcategory: Persistence & Impact)

**[STAKEHOLDER]** - This alert fires when someone (or something) turns off the endpoint protection that's supposed to be watching a machine. On its own it doesn't encrypt data or steal anything - but it's almost always the setup move for something worse. An attacker who has already gained a foothold blinds the sensor before running the payload that actually hurts the business: ransomware, credential theft, or data exfiltration. Treat a confirmed tamper event as "the alarm system was cut before the break-in," not as a standalone nuisance alert. The business decision here is speed - every minute the endpoint runs blind is a minute nobody can see what's happening on it.

## Severity/Priority Default

**Critical / P1.** This is one of the few alert types where "wait and see" is the wrong instinct. Even a false positive investigation should be fast, because the cost of a missed true positive is disproportionately high - it's a precursor, not an outcome.

## MITRE ATT&CK Techniques

- **T1562.001** - Impair Defenses: Disable or Modify Tools (primary technique for this playbook)
- **T1543.003** - Create or Modify System Process: Windows Service (malicious service used to load a kernel driver, or to stop/delete the EDR's own service)
- **T1027** - Obfuscated Files or Information (the tampering tool itself is frequently packed or has a legitimate-looking, re-signed binary name)
- **T1105** - Ingress Tool Transfer (the EDR-killer utility usually has to be downloaded or copied onto the host first)
- **T1055** - Process Injection (relevant when the tampering method is user-mode API unhooking rather than a driver-based kill, i.e. injecting into a legitimate process to patch AV/EDR hooks in ntdll or the sensor's own DLL)

## Trigger / Detection Logic Summary

Alert fires on any of the following, individually or - far more concerning - in combination within a short window on the same host:

1. The EDR/AV agent's own Windows service is stopped, disabled, or deleted outside of a scheduled maintenance/patch window.
2. A known EDR-killer tool signature, LOLBin sequence (`sc.exe`, `net.exe`, `taskkill.exe`, `PowerShell` cmdlets like `Set-MpPreference`), or command line referencing the sensor's process/service name is observed.
3. A new kernel driver is loaded (Sysmon Event ID 6) that is unsigned, signed with a known-revoked/leaked certificate, or matches a known vulnerable driver used in "Bring Your Own Vulnerable Driver" (BYOVD) EDR-killing (Terminator, EDRSandblast, kill-floor style tooling).
4. Registry changes disabling Defender/AV real-time protection, tamper protection, or adding broad exclusions (Sysmon 12/13/14 on `HKLM\SOFTWARE\Microsoft\Windows Defender\...` or the sensor's own config hive).
5. Security audit policy changed (4719) shortly before or after the tamper event - attacker blinding both the EDR and native Windows logging in the same session.
6. The vendor platform's own tamper-protection alert (e.g., a Microsoft Defender Tamper Protection block, or an equivalent third-party EDR self-defense event) fires independently of SIEM correlation - this is often the fastest, highest-confidence signal and should short-circuit the rest of the logic when present.

**[ENGINEERING]** - Correlate service-state change + LOLBin process creation + driver load within a 10-minute rolling window per host. Single-event triggers on this playbook are noisy (patch tooling, agent upgrades); the value is in the co-occurrence.

## Required Log Sources & Event IDs

| Source | Event IDs | Purpose |
|---|---|---|
| Windows Security log | 4688, 4697, 4719, 1102 | Process creation (with command line if auditing enabled), service install, audit policy change, log clear |
| Windows System log | 7045 | Service Control Manager - new service install (distinct source from 4697, catches services 4697 sometimes misses) |
| Sysmon | 1, 3, 6, 7, 10, 11, 12, 13, 14, 23 | Process creation w/ full command line + parent, network callbacks post-tamper, driver load, DLL load, ProcessAccess (unhooking via injection), file drop of killer tool, registry persistence/config changes, cleanup of dropped tooling |
| PowerShell logs | 4103, 4104 | Captures `Set-MpPreference`, `Uninstall-WindowsFeature`, obfuscated disable scripts |
| EDR/AV platform native telemetry | vendor tamper-protection alert, agent heartbeat/health status | Fastest and most authoritative signal that self-defense was triggered or the agent went offline |

## Key Fields to Inspect

**[ANALYST]**

- Sysmon 1 / 4688: `CommandLine`, `ParentImage`, `ParentCommandLine`, `IntegrityLevel` (tampering requires admin/SYSTEM - check how that privilege was obtained), `User`
- Sysmon 6: `ImageLoaded` (driver path), `Signed`, `Signature`, `Hashes` - cross-reference hash against known vulnerable/EDR-killer driver lists
- Sysmon 12/13/14: `TargetObject` (registry path), `Details` (new value), `EventType`
- 4697 / 7045: `Service Name`, `Service File Name`/`Image Path`, `Start Type`, `Service Account` - a service running as `LocalSystem` pointing at a temp-folder binary is a red flag on its own
- 4719: `Subcategory`, old vs new `Audit Policy Change` value, `Subject`
- Vendor EDR console: agent last-checkin timestamp, "protection status," tamper-protection event detail, uninstall/policy-change history

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| EDR service stop/restart tied to a change ticket, during a maintenance window, initiated by an IT admin account via the management console | EDR service stopped via `sc.exe stop`/`net stop` from an interactive or remote session, no matching change record |
| Agent upgrade shows a brief (seconds) service restart with matching install log from the vendor's deployment tool | Agent process/service disappears and does not come back; no corresponding vendor deployment job |
| Defender exclusions added by SCCM/Intune policy push, matching a documented app compatibility exception | Broad exclusions (`C:\`, `*.exe`, entire user profile) added via registry or PowerShell by a local admin session minutes after a suspicious download |
| Driver loads tied to known hardware/software vendors, signed, appear during driver update cycles | Unsigned or oddly-named driver load immediately followed by EDR agent going silent |
| Scheduled uninstall via approved decommission workflow (asset retirement) | Uninstall/tamper attempt on a production, in-use endpoint with no retirement ticket |

## Investigation Steps

1. **Confirm the tamper actually happened** at the platform level - check the EDR console for agent health/last-checkin and any native tamper-protection alert before trusting SIEM correlation alone. Ingestion delay on the SIEM side is common; the console is usually faster.
2. **Establish the timeline.** Pull Sysmon 1/4688 for the affected host in the 30 minutes before and after the tamper event - what process/user initiated it, and what ran immediately afterward (this is usually where the actual malicious payload shows up).
3. **Identify the account and its logon context.** Cross-reference the Logon ID from the tampering process back to the originating 4624/4648 - was this an interactive console logon, RDP, or a service account executing remotely? Compare against that account's normal behavior baseline.
4. **Check for companion defense-evasion activity** - 4719 audit policy changes, 1102 log clearing, and Sysmon 12/13/14 registry changes around the same window. Multiple blinding actions together is a strong true-positive indicator.
5. **Inspect the driver/tool itself if applicable.** Pull the file hash from Sysmon 6/11, check signature status, and submit the hash to whatever malware intel source your team uses. Note the file path - temp directories, Downloads, or unusual application folders are common drop locations.
6. **Look for lateral spread.** Check if the same command line, hash, or driver has appeared on other hosts in the environment - default lookback 7 days; extend to 30 days once confirmed True Positive. EDR-killer tools are frequently staged for multi-host use right before a ransomware detonation.
7. **Determine what happened while the sensor was blind.** Review whatever telemetry remained available - network logs, proxy/firewall, other host-based agents, Sysmon if it survived - for the gap period. Don't assume "no EDR alert" means "nothing happened"; it may mean nothing was watching.
8. **Validate against the change management system** before closing - if there's a legitimate ticket, confirm the timing, requester, and scope actually match what was observed on the host.

## True Positive Indicators

- LOLBin or known EDR-killer command line stopping/deleting the sensor's service, with no matching change ticket
- Unsigned or blocklisted kernel driver load immediately preceding sensor silence
- Vendor tamper-protection alert fired and blocked (or worse, succeeded)
- Follow-on suspicious process execution, credential access attempts, or outbound connections in the window the sensor was down
- Same tooling/hash observed across multiple hosts in a short period
- Tampering account has no legitimate reason to touch security tooling (e.g., a finance department service account)

## False Positive / Benign Positive Indicators

- Scheduled agent upgrade or reinstall via the vendor's own deployment/RMM tooling, timestamps line up exactly
- IT-initiated uninstall tied to a documented device retirement/re-image ticket
- Endpoint management platform pushing a legitimate exclusion policy (verify against the change record, not just plausibility)
- Local admin troubleshooting a known agent conflict with another security product, escalated through the helpdesk beforehand
- Driver load matches a newly deployed, signed hardware/software vendor driver with no correlation to sensor downtime

## Escalation Criteria

Escalate to IR/Tier 3 immediately (do not wait for full investigation) when any of:

- Tamper is confirmed and there is no matching change record
- Tamper occurred on a server, domain controller, or any Tier 0/1 asset
- Multiple hosts show the same tampering pattern within the same operational window
- Any evidence of activity during the blind window (new processes, network connections, credential access indicators)
- 1102 log clearing or 4719 audit policy change accompanies the tamper event

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Trigger | Approval |
|---|---|---|
| Isolate host from network (EDR network containment) | Confirmed tamper, no change ticket, standard endpoint | On-call SOC lead, no additional approval needed for single endpoint |
| Isolate host from network (EDR network containment) | Confirmed tamper on a server, domain controller, or other Tier 0/1 asset | IR lead + infrastructure owner sign-off (production impact) - if the owner is unreachable within 10 minutes and active follow-on activity is confirmed, on-call SOC lead may isolate unilaterally and document the exigent-circumstances justification for IR review |
| Force re-enable/reinstall agent remotely | Any confirmed tamper | SOC lead |
| Disable/reset compromised account credentials | Tampering account not IT admin, or IT admin account behaving abnormally | IR lead + IAM/account owner notification |
| Full incident declaration and IR engagement | Server/Tier 0 asset, multi-host pattern, or evidence of follow-on activity | IR manager |
| Forensic image before remediation | Any case heading toward confirmed malicious with legal/compliance exposure | IR manager, coordinate with legal if regulated data involved |

SLA target: triage start within 5 minutes of alert for this playbook given its severity default; escalation decision within 30 minutes.

## Example Query (Microsoft Sentinel - KQL)

```kql
SecurityEvent
| where EventID in (4697) or (EventID == 4688 and CommandLine has_any ("sc stop","sc delete","taskkill","Set-MpPreference","net stop"))
| where CommandLine has_any ("MsMpEng","SentinelAgent","CSFalconService","EDR") or ServiceFileName has_any ("Defender","Falcon","Sentinel")
| project TimeGenerated, Computer, Account, CommandLine, ServiceFileName
| join kind=inner (SysmonEvent | where EventID == 6) on Computer
| project TimeGenerated, Computer, Account, CommandLine, DriverImageLoaded, Signed
```

## Closure Criteria

Close as confirmed malicious only after the blind-window activity is fully accounted for (or affirmatively ruled absent via surviving telemetry), the account/host is contained, and IR has signed off if escalated. Close as Benign Positive/Expected Activity when the change record, timing, and scope fully match observed behavior. Close as Insufficient Evidence if the sensor never actually went down (console shows healthy heartbeat) and no supporting log source confirms a tamper attempt occurred - this happens more often than people expect due to noisy LOLBin patterns from legitimate scripts.

**Example case note:**
> 2026-09-15 14:12 UTC - Sensor on WKS-FIN-0417 (user jsawyer, corp\example.com) went silent per EDR console at 13:58. Sysmon 1 shows `sc.exe stop SentinelAgent` launched from an elevated cmd.exe spawned by explorer.exe, no parent automation tooling. No matching change ticket in ServiceNow. Cross-checked 4624 for jsawyer's Logon ID - interactive console logon, no RDP/remote indicator. No Sysmon 6 driver load observed, no follow-on process execution in the 22-minute gap before agent was force-reinstalled. Account confirmed innocent - user was following outdated internal wiki instructions to "fix a slow laptop." Closed as Benign Positive; wiki page flagged for correction, user re-briefed by team lead.
