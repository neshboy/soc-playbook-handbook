# Windows Event ID Reference Cluster: High-Signal & PowerShell Events (1102, 4103, 4104)

Most Windows event IDs are useful in volume - you build a baseline, you watch for deviation. This cluster is different. Event ID 1102 fires rarely and almost always means someone did something deliberate to the audit trail itself. Event IDs 4103 and 4104 are the two logs standing between "we have no idea what that PowerShell command actually did" and having the literal script text in front of you. If you only get budget to enable three non-default audit settings on a Windows estate, these three are a defensible shortlist - they punch well above their ingestion cost.

Scoping note: 1102 lives in the Security log and needs nothing beyond default auditing being intact. 4103 and 4104 live in a separate log - `Microsoft-Windows-PowerShell/Operational` - and neither is enabled by default. Both need Group Policy (Administrative Templates > Windows Components > Windows PowerShell) or an equivalent Intune configuration pushed out before you'll see a single event. If you went looking for PowerShell telemetry after an incident and found none, that's not a SIEM pipeline bug - it's an unconfigured GPO, and it's worth flagging to engineering as its own finding.

## Event ID 1102 — The Audit Log Was Cleared

**What it means in plain terms:** someone (or something running under an account's context) cleared the Security event log. Not "the log rotated" or "the log hit its size cap and started overwriting old entries" - an explicit clear action, the log-file equivalent of wiping a whiteboard. This event is written by the Windows Eventlog service itself, and critically, it is one of the very last events written before the log is empty, which is why it survives the clearing it's describing.

**Where it appears:** Security log, source `Microsoft-Windows-Eventlog` or `Microsoft-Windows-Security-Auditing` depending on OS version, category "System" / "Audit Log was Cleared."

**Important fields:**

| Field | Notes |
|---|---|
| `Subject: Security ID` | SID of the account that cleared the log |
| `Subject: Account Name` / `Domain Name` | Resolved account and domain |
| `Subject: Logon ID` | Ties back to the originating logon session (4624) |

That's a short field list, and that's not an oversight on Microsoft's part or in this reference - 1102 isn't designed to tell you much on its own. It's a tripwire. The investigative value comes almost entirely from what surrounds it in time, not from the event itself.

**What normal looks like:** honestly, close to nothing. A human being should almost never need to manualy clear the Security log - log management is handled by retention policy, size caps, and SIEM forwarding, not by clicking "Clear Log" in Event Viewer. The closest thing to legitimate is a documented, change-controlled log-management task (decommissioning a host, resetting a broken logging pipeline) performed by a known service account with a change ticket attached, at a matching time.

**What suspicious looks like:** basically everything else. 1102 on a domain controller, on a server that just had a suspicious authentication event, or on any host near other high-severity activity (new admin account creation, service installation, ransomware file drops) should be treated as a near-certain anti-forensics attempt until proven otherwise. Attackers clear logs specifically to break the timeline an analyst would otherwise reconstruct - seeing 1102 fire is often the strongest single indicator that you're dealing with a deliberate, hands-on-keyboard actor rather than commodity malware.

**[STAKEHOLDER]** - This should generate an automatic, no-exceptions page regardless of time of day. The risk isn't just "something bad happened" - it's "something bad happened and someone tried to make sure we couldn't prove what." Breach-notification timelines often hinge on reconstructing attacker actions; losing that ability moves an incident from "contained and scoped" to "assume the worst and notify broadly."

**Related Event IDs to correlate:** 4624/4625 (who logged on around the clearing time), 4672 (privileged logon), 4697/7045 (service installed around the same window - log clearing often pairs with tooling deployment), 4688 (process that issued the clear command, if command-line auditing is enabled), 4719 (audit policy changes - attackers sometimes disable auditing categories instead of, or alongside, clearing the log).

**Common false positives:** legitimate log-management automation or vendor decommissioning scripts that weren't documented well enough for the on-call analyst to recognize on sight. Genuinely rare - most "false positive" 1102s are really "true positive event, benign intent, poor change documentation," itself a process finding worth raising even when the activity turns out fine.

**What to correlate it with:** the full timeline of the Logon ID in the Subject field - what did that session do in the ten minutes before and after clearing the log. Check for corresponding Sysmon Event ID 1 process creation around the same timestamp if Sysmon is deployed on that host, since Security-log auditing being cleared doesn't touch Sysmon's separate log.

**Example investigation narrative:** at Vantage Point Logistics, `VPL-FILESRV02` generates a 1102 at 02:47 local time, Subject Account Name `svc-backup` - a service account nobody remembers being granted interactive logon rights. The analyst pulls the Logon ID and finds a 4624 six minutes earlier, Logon Type 10 (RemoteInteractive), Source Network Address `192.168.10.23`, a workstation belonging to a contractor who left four months prior but whose account was never disabled. A 4697 fires eleven minutes after the log clear, installing a service named `WinDefendUpdate` with an image path in `C:\Users\Public\` - not a real Defender component, but a staged persistence mechanism. The attacker cleared the log specifically to hide the RDP logon. The account is disabled, the host isolated, and the case escalates to a full compromise assessment.

**Example SIEM query (KQL, Microsoft Sentinel):**

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, SubjectAccount, SubjectUserSid, SubjectLogonId
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4624
    | project LogonTime = TimeGenerated, Computer, TargetLogonId = TargetLogonId, LogonType, IpAddress
) on $left.SubjectLogonId == $right.TargetLogonId, $left.Computer == $right.Computer
| project TimeGenerated, Computer, SubjectAccount, LogonType, IpAddress, LogonTime
```

## Event ID 4103 — PowerShell Module Logging (Executing Pipeline)

**What it means in plain terms:** 4103 records the fact that a PowerShell pipeline ran, along with the cmdlet name and the parameters passed to it. Think of it as a structured, cmdlet-level activity log - not the full script text (that's 4104's job), but enough to see "someone ran `Invoke-Expression` with this parameter" or "someone ran `Get-ADUser` with these filters" without needing the raw script block.

**Where it appears:** `Microsoft-Windows-PowerShell/Operational` log, requires the "Turn on Module Logging" Group Policy setting enabled (typically configured for module name `*` to cover everything, though it can be scoped to specific modules).

**Important fields:**

| Field | Notes |
|---|---|
| `Message` / `Payload` | Contains the cmdlet/pipeline details, including parameter names and values as executed |
| `ContextInfo: Host Application` | The full command line of the process hosting the PowerShell engine - powershell.exe, powershell_ise.exe, or a third-party app hosting the engine |
| `ContextInfo: Engine Version` | PowerShell engine version in use |
| `ContextInfo: User` | Account context the pipeline ran under |
| `EventID`/severity | Level is typically Information; parameter values considered sensitive by some providers may be masked |

**What normal looks like:** administrators running `Get-`, `Set-`, and `New-` cmdlets against AD, Exchange, or Azure modules during business hours from known admin workstations or jump boxes, scheduled tasks invoking known maintenance scripts, and monitoring/backup agents that are themselves built on PowerShell modules.

**What suspicious looks like:** `Invoke-Expression`, `Invoke-WebRequest`/`iwr`-aliased downloads, `Add-MpPreference -ExclusionPath` (adding a Defender exclusion), `Invoke-Mimikatz`-style function names, or `New-Object Net.WebClient` download-and-execute patterns - especially from a Host Application command line unlike an admin's normal tooling, or on a workstation with no business running administrative modules.

**[ANALYST]** - Don't alert on cmdlet name in isolation - `Invoke-Expression` piping in content from `Invoke-WebRequest` in the same pipeline is a materially different finding than either cmdlet appearing alone in routine automation. Pull the full Payload field, not a truncated preview, before writing off a hit.

**Related Event IDs to correlate:** 4104 (script block text for the same session - always check both together, they're normally sequential in time and PowerShell's `Engine Lifecycle` events bracket a session's start/stop), 4688 (the parent `powershell.exe` process creation and its command line, if command-line auditing is enabled), Sysmon Event ID 1 (parent-child process lineage - what launched PowerShell in the first place).

**Common false positives:** configuration-management tooling (DSC, SCCM/Intune remediation, monitoring agents) using cmdlets that look alarming out of context, such as download-and-run patterns baked into patch deployment. Security tooling itself frequently uses PowerShell under the hood and will generate 4103 noise that needs baselining early or it drowns everything else.

**What to correlate it with:** the matching 4104 events by `ScriptBlockId`/timestamp for full script content, and proxy/firewall logs for any destination referenced in a `Invoke-WebRequest`/`WebClient` call to see whether the download succeeded.

**Example investigation narrative:** an alert fires on `VPL-WKS-118` for 4103 activity containing `Add-MpPreference -ExclusionPath` targeting `C:\ProgramData\Intel\` - on first look, classic pre-malware staging. The analyst pulls Host Application from ContextInfo, finds `powershell.exe -File C:\Program Files\VendorTool\deploy.ps1`, and confirms VendorTool is a legitimate, recently onboarded endpoint agent whose installer excludes its own working directory per documented vendor guidance. The case closes as Expected Activity, and the analyst flags the behavior to engineering for the suppression baseline instead of re-triggering the same alert every deployment cycle.

**Example SIEM query (SPL, Splunk):**

```spl
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| rex field=Message "HostApplication=(?<host_app>.+)"
| rex field=Message "Payload=(?<payload>[\s\S]+)"
| search payload="*Invoke-Expression*" OR payload="*WebClient*" OR payload="*DownloadString*"
| table _time, ComputerName, User, host_app, payload
```

## Event ID 4104 — PowerShell Script Block Logging

**What it means in plain terms:** this is the big one. 4104 logs the actual text of the script block that PowerShell is about to execute - including, in most cases, script content after PowerShell's own de-obfuscation/decoding logic has run. If an attacker hands PowerShell a Base64-encoded, compressed, character-reversed mess specifically to dodge string-matching detections, 4104 frequently still captures the readable script underneath because it logs at the point the engine has already parsed it into something executable.

**Where it appears:** `Microsoft-Windows-PowerShell/Operational` log, requires "Turn on PowerShell Script Block Logging" Group Policy. Large script blocks get split across multiple 4104 events sharing the same `ScriptBlockId`, tagged with `MessageNumber`/`MessageTotal` so you can reassemble them in order.

**Important fields:**

| Field | Notes |
|---|---|
| `ScriptBlockText` | The actual script content - the reason this event exists |
| `ScriptBlockId` | GUID tying together fragments of the same block and linking related 4103 activity |
| `Path` | Source `.ps1` file path, when the script came from a file rather than an interactive pipeline |
| `MessageNumber` / `MessageTotal` | Fragment ordering for scripts split across multiple events |
| Event `Level` | Normally Information; PowerShell's built-in heuristics escalate certain script blocks to Warning level based on suspicious content patterns (obfuscation indicators, known-bad function names) - Warning-level 4104s are worth prioritizing in triage |

**What normal looks like:** signed, version-controlled deployment and maintenance scripts running from known paths (`C:\Scripts\`, a software deployment share), readable code with sensible variable names, matching what your configuration-management tooling is documented to run, at times that line up with maintenance windows or ticket-driven changes.

**What suspicious looks like:** heavily obfuscated content even after decoding (nested `-EncodedCommand`, string concatenation designed to break signature matching, `[char]` array reconstruction of function names), reflective/in-memory loading patterns (`[System.Reflection.Assembly]::Load`, `Invoke-ReflectivePEInjection`-style content), AMSI-bypass strings, or a script block with no `Path` value running interactively when your environment expects everything to execute from signed files on a deployment share.

**[ENGINEERING]** - Build detections around the Warning-level escalation first, since PowerShell's own scoring engine has already flagged suspicious constructs - a lower-volume starting point than string-matching every obfuscation pattern from scratch. Layer keyword/regex detections for known offensive tooling and AMSI-bypass strings on top, and expect to tune out your own red-team/pentest activity if you run one.

**[ANALYST]** - Read the whole reassembled script, not just the fragment that tripped the alert - a benign-looking opening block followed by a download-and-execute tail is a common pattern, and truncated review is how obfuscated payloads get waved through.

**Related Event IDs to correlate:** 4103 (parameter/cmdlet context for the same `ScriptBlockId`/session), 4688 (parent process command line and PID, if enabled), Sysmon Event ID 1 (full process lineage, since PowerShell is frequently spawned by an Office application or a scheduled task rather than launched directly by a user).

**Common false positives:** legitimate obfuscation-adjacent patterns from commercial software - some vendor-shipped modules use encoded strings or dynamic function construction for mundane licensing or update-check reasons, and will trip naive "any encoded command = alert" rules constantly. Internal red-team and vulnerability-scanning tooling that intentionally mimics attacker tradecraft is another recurring source - make sure scheduled pentest windows are on the analyst's radar before a shift starts.

**What to correlate it with:** proxy/DNS logs for any domain or IP referenced in the decoded script (a runtime-constructed URL string won't show up cleanly in 4103's parameter view, but sits in plain text in the 4104 body), and EDR/AV telemetry for whether anything downloaded actually executed afterward.

**Example investigation narrative:** a Warning-level 4104 fires on `VPL-WKS-204`, a finance department workstation. The reassembled `ScriptBlockText` shows a `-EncodedCommand` payload decoding to a script that pulls content from `hxxp://185.220.101[.]44/upd.ps1` via `Net.WebClient` and invokes it directly in memory, no file ever touching disk - a classic fileless-downloader pattern. `Path` is empty (interactive, not a script file), and the correlated 4688 shows parent process `winword.exe`. Email logs confirm the user opened `invoice_overdue.docm` twenty minutes earlier. Proxy logs show the outbound request was blocked by category (newly registered domain), so the second-stage payload never landed - the case closes as True Positive, contained at the network layer, with the host still rebuilt out of caution since script block logging alone doesn't prove nothing else ran locally before the block.

**Example SIEM query (KQL, Microsoft Sentinel via Windows Event forwarding):**

```kql
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| extend ScriptBlockText = tostring(parse_xml(EventData).DataItem.EventData.Data)
| where EventLevel == 3 // Warning-level escalations first
    or ScriptBlockText has_any ("EncodedCommand", "WebClient", "DownloadString", "IEX", "Reflection.Assembly")
| project TimeGenerated, Computer, ScriptBlockText
| sort by TimeGenerated desc
```

## Correlation Cheat Sheet

| If you see... | Also pull... | Why |
|---|---|---|
| 1102 | 4624/4625, 4672, 4697/7045, 4719 | Establish who cleared the log, whether the session was privileged, and what else happened around it |
| 4103 | 4104, 4688, Sysmon 1 | Get full script text and process lineage for the same session |
| 4104 (Warning) | 4103, 4688, Sysmon 1/3, proxy/DNS logs | Confirm what the script actually did and whether any network callback succeeded |

**[MANAGEMENT]** - All three event sources need a review cadence, not just an alert rule. 1102 warrants a standing rule: any occurrence outside documented, ticketed log-management activity escalates to Critical severity automatically, no analyst discretion at triage. Module and script block logging need periodic (quarterly is reasonable) tuning reviews - vendor software changes its PowerShell usage over time, and yesterday's suppression list stops matching today's noise. Assign that tuning to whoever owns the detection engineering backlog, not to whichever analyst got paged the most that quarter.
