# GPO Changes

## Playbook ID & Name
**IAM-013 — Group Policy Object (GPO) Changes** (Category: Identity & Active Directory — Account & Authentication)

## Business Risk
**[STAKEHOLDER]** - Group Policy is how we push security controls — password rules, firewall state, logon restrictions, admin group membership, startup scripts — to every domain-joined machine at once. An attacker who can edit a GPO doesn't need to touch a thousand endpoints individually; they touch one object in AD and it fans out fleet-wide on the next refresh cycle. That's the same lever we use for good, which is exactly why it's attractive for persistence, mass credential harvesting, or turning off defenses across the estate in one move.

## Severity/Priority Default
**High** for any GPO edit made outside a documented change window or by an account not on the GPO admin/delegation list. **Medium** for in-window changes by known GPO admins pending content review (what did the change actually do). Escalate to **Critical** immediately if the change touches Default Domain Policy, Default Domain Controllers Policy, or any GPO linked to the Domain Controllers OU.

## MITRE ATT&CK Technique(s)
**T1484.001 Domain or Tenant Policy Modification: Group Policy Modification** is the core technique here — editing or linking a Group Policy Object to alter settings across scope, for defense evasion or privilege escalation. Depending on what the GPO change actually delivers, also map the downstream payload to:
- **T1543.003** Create or Modify System Process: Windows Service — GPO deploying/altering a service
- **T1053.005** Scheduled Task/Job: Scheduled Task — GPO pushing a scheduled task
- **T1547.001** Boot or Logon Autostart Execution: Registry Run Keys — GPO Preferences pushing autorun registry values
- **T1562.001** Impair Defenses: Disable or Modify Tools — GPO used to disable Defender, firewall, or audit settings fleet-wide
- **T1098** Account Manipulation — GPO Restricted Groups used to add accounts to local admin
- **T1078.002** Valid Accounts: Domain Accounts — a legitimate but compromised admin credential used to make the edit

## Trigger / Detection Logic Summary
Be upfront about the gap: the native Directory Service audit events that log GPO object create/modify/link/delete/permission-change directly are not part of this book's supplied Event ID set, and in a lot of real environments "Audit Directory Service Changes" isn't even enabled on the DCs because of the volume it generates. So this playbook detects GPO tampering indirectly, through the tools used to make the change and through what shows up on endpoints afterward. Trigger conditions:
- 4688 process creation for `gpmc.msc`, `mmc.exe` with a GroupPolicy MMC snap-in, `gpedit.msc`, or `powershell.exe`/`pwsh.exe` invoking the GroupPolicy module, outside a change-managed maintenance window.
- 4103/4104 PowerShell logging capturing GroupPolicy cmdlets: `New-GPO`, `Set-GPO`, `Remove-GPO`, `Set-GPLink`, `Set-GPRegistryValue`, `Set-GPPrefRegistryValue`, `Set-GPPermissions`, `Backup-GPO`/`Import-GPO`, or raw `gpupdate /force` / `gpresult` used for reconnaissance.
- A privileged account (4672 present alongside 4624) not on the known GPO-delegation list touching any of the above.
- Fleet-wide correlation: a burst of identical downstream events (4697/7045, 4698, 4719, or a spike of 1547.001-pattern registry autoruns) hitting multiple hosts within the same GPO refresh window (roughly 90–120 minutes, or on next reboot for computer-side policy) — that fan-out pattern is the real fingerprint of a GPO push, far more than any single endpoint event.

## Required Log Sources & Event IDs
| Source | Event IDs | Purpose |
|---|---|---|
| Security log, Domain Controller | 4688, 4648, 4672, 4624/4625, 1102 | Who touched GPO tooling, with what privilege, and did they cover tracks |
| PowerShell Operational log, DC & admin jump hosts | 4103, 4104 | Actual GroupPolicy cmdlets and parameters executed |
| Security log, endpoints fleet-wide | 4697, 7045, 4698, 4719 | Downstream effects of a policy push landing on clients |
| Security log, DC | 4728/4732/4738 | If GPO change was really a Restricted Groups push manipulating membership |

## Key Fields to Inspect
**[ANALYST]**
- 4688: `Creator Process Name` (was `gpmc.msc` launched from `mmc.exe` under an interactive session, or from a remote PSExec/WinRM parent — the latter is far more suspicious), `Command Line` if auditing is on, `Subject Account`.
- 4104: full script block text — look for `-Server`, `-Domain`, target GPO GUID/name, and the actual registry path or value being set via `Set-GPRegistryValue`/`Set-GPPrefRegistryValue`. This is where you find out *what the change actually does*.
- 4648: `Account Whose Credentials Were Used` vs `Subject` — a helpdesk account explicitly authenticating as a Domain Admin to touch GPMC is a pattern worth chasing on its own.
- 4719: `Subcategory`, old value vs new value — did logging just get narrowed or turned off domain-wide.
- 7045/4697 fleet-wide: `Service File Name`/`Image Path` — same binary path appearing on many hosts near-simultaneously is the GPO fan-out signature.
- 1102 on the DC that hosts the GPMC console session — check `Subject` immediately, this is rarely accidental.

## Normal vs Suspicious Pattern
Normal: a named GPO admin, during a scheduled change window, RDPs or uses PAW/jump-host, opens GPMC, edits a specific documented GPO, closes it, files a change ticket. PowerShell logging shows a handful of targeted cmdlets against one GPO. No log-clearing, no privilege escalation mid-session, downstream effect matches the change ticket exactly.

Suspicious: GPO editing tools launched from an account outside the delegation group; edits made outside change windows, especially late night/weekend; edits to Default Domain Policy or a GPO linked at the domain root rather than a scoped OU; `Set-GPRegistryValue` writing to autorun or Defender exclusion paths; a fan-out of identical new services/scheduled tasks across dozens of hosts within the same refresh window with no corresponding change ticket; 1102 on the DC shortly after the session.

## Investigation Steps
1. Identify the account and session (`Subject`, Logon ID) that ran the GPO tooling or PowerShell cmdlets — confirm the account sits on the actual GPO delegation/admin list, don't assume it because the title says "admin."
2. Pull the 4103/4104 script block for that session and reconstruct exactly which GPO GUID/name was touched and what setting changed — this is the single most important step, everything else is context.
3. Cross-reference against the change management ticket queue for that time window. No ticket doesn't automatically mean malicious, but it removes the easiest benign explanation.
4. Check for 4648 explicit-credential use immediately before the edit — was a higher-privilege account borrowed for this specific action.
5. Check 4672 on the session logon to confirm what privilege level the token actually held when the edit happened.
6. Run `gpresult /r` or review GPMC's "Group Policy Results" against a sample affected host to confirm the setting actually propagated as expected, and pull the fleet-wide correlation for downstream 4697/7045/4698/4719/1547.001-pattern events tied to the same time window and OU scope.
7. Check for 1102 on the DC used for the session and on any endpoint where you'd expect audit evidence of the downstream payload.
8. If the change touches Restricted Groups or local admin membership, pull 4728/4732/4738 to confirm what accounts actually gained access as a result.

## True Positive Indicators
- GPO edit made by an account not on the delegation list, especially right after a 4648 credential-borrowing event.
- Script block shows a registry value pointed at an autorun path, a Defender/firewall exclusion, or a Restricted Groups membership add for an unfamiliar account.
- Fleet-wide downstream effect (new service, new scheduled task, or audit policy change) with no matching change ticket, landing simultaneously across many hosts.
- 1102 on the DC in the same session window as the edit.
- Edit targets Default Domain Policy, Default Domain Controllers Policy, or a GPO linked at the domain/DC OU rather than a narrowly scoped OU.

## False Positive / Benign Positive Indicators
- Change matches an open ticket and window, made by a listed GPO admin, downstream effect matches exactly what the ticket describes.
- SCCM/Intune co-management or a GPO backup/DR automation account (service account) performing scripted `Backup-GPO`/`Import-GPO` on a schedule — this is where analysts get burned if they don't already know the service account exists; validate it against the known automation inventory rather than treating every non-human account as suspicious.
- Repeated `gpresult`/`gpupdate` runs from helpdesk troubleshooting a specific user's policy application — noisy but benign, confirm scope was read-only.
- Lab/test OU GPO edits that never link to production OUs — check GPO link scope before escalating.

## Escalation Criteria
Escalate to Tier 2/IR immediately if: the edited GPO is linked to Domain Controllers OU or Default Domain Policy; the editing account isn't on the delegation list and there's no ticket; 1102 appears in the same window; downstream fan-out includes new services/scheduled tasks pointing to unfamiliar binaries/paths; or Restricted Groups changes add an unrecognized account to a privileged local group across multiple hosts.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- Revert the GPO to prior version via GPMC backup/restore, or unlink the GPO from its OU as an immediate stopgap — AD team lead or on-call IR can authorize unlink/revert without waiting for full RCA once fan-out is confirmed malicious.
- Disable the account that made the edit and force credential reset — requires IAM/on-call IR sign-off; if it's a service account, notify the automation owner before disabling to avoid breaking legitimate backup/DR jobs.
- Force `gpupdate /force` (or reboot) across affected scope to push the reverted policy back out — coordinate with infrastructure/change management, this is itself a fleet-wide change and needs the same care as the original one.
- Emergency Change Advisory Board (CAB) approval required for any revert touching Domain Controllers Policy or Default Domain Policy, even under incident conditions — get verbal/Slack sign-off from CAB chair or delegate, formal ticket to follow.

## Example Query (Microsoft Sentinel / KQL)
```kql
union SecurityEvent, Event
| where EventID in (4688, 4103, 4104)
| where (EventID == 4688 and NewProcessName has_any ("gpmc.msc","gpedit.msc","mmc.exe"))
   or (EventID in (4103,4104) and RenderedDescription has_any
       ("Set-GPRegistryValue","New-GPO","Set-GPLink","Remove-GPO","Set-GPPermissions"))
| where AccountName !in ("SVC-GPO-BACKUP","SVC-DR-AUTOMATION")
| project TimeGenerated, Computer, AccountName, EventID, NewProcessName, RenderedDescription
| order by TimeGenerated desc
```

## Closure Criteria
Close as **True Positive** only once the specific GPO setting change is identified, reverted/confirmed intentional-malicious, source account contained, and fleet-wide downstream artifacts (services/tasks/registry values) remediated on affected hosts. Close as **Benign Positive** when the edit matches an approved change ticket and scope. Close as **Insufficient Evidence** if PowerShell/command-line auditing wasn't enabled for the session and the actual setting changed cannot be confirmed — flag as a logging gap for the AD team, don't just close it quietly.

Example case-note line: *"4104 script block from jdoe-adm on DC01 (Logon ID 0x3F2A1) at 2026-09-15 02:14 UTC shows Set-GPRegistryValue against GPO 'Default Domain Policy' writing DisableAntiSpyware=1 under Defender path; jdoe-adm not on GPO delegation list, no CAB ticket; 7045 fan-out of matching registry state observed on 14 endpoints 02:20-03:40 UTC; GPO reverted via backup 2026-09-10, account disabled pending IR — escalated to Tier 2 as True Positive, T1562.001."*
