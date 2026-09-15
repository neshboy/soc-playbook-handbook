# Windows Event ID Reference: Logon & Session Events

Every incident that touches a Windows host eventually comes back to one question: who was logged on, from where, and with what token. The six events in this cluster - 4624, 4625, 4634, 4647, 4648 and 4672 - are how you answer that, and they're the events every analyst has stared at during a 2 a.m. lockout storm or a "why does this service account have a session on a domain controller" ticket.

The thread tying all six together is the **Logon ID** (a hex value like `0x3E7` or `0x1A2B3C`, shown in the raw event as `TargetLogonId` on 4624/4634/4647, and as `SubjectLogonId` on 4672 - since 4672 annotates the same session named in Subject rather than a separate target). It's unique per logon session on that host until reboot, and it's the single most useful pivot field here - every process, every 4648, every logoff for that session carries the same value. If you're not filtering or joining on Logon ID, you're doing it the hard way.

A quick reference before diving in - **Logon Type** (a field on 4624 and 4625, not an event ID) tells you the "how":

| Logon Type | Meaning | Typical source |
|---|---|---|
| 2 | Interactive | Console logon, physical or KVM |
| 3 | Network | SMB share access, most service-to-service auth |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service Control Manager starting a service |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Basic auth over a network connection, cleartext creds |
| 9 | NewCredentials | RunAs with `/netonly` |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Interactive logon using cached domain creds, no DC reachable |

Keep this table nearby - almost every triage of the six events below starts with "what Logon Type is this."

## 4624 — An Account Successfully Logged On

This is the baseline "someone or something got a token on this host" event. It fires on interactive desktop logons, RDP sessions, SMB share connections, service starts, scheduled task launches - anything that creates a logon session. It's one of the heaviest Security log events on any domain controller or file server, which is exactly why undisciplined 4624 collection buries SIEM budgets fast.

**Where it appears:** Security log on the machine where the logon session was created - workstation for console/RDP-to-that-box, file server for share access, domain controller for domain-authenticated logons where the DC processed the ticket.

| Field | Notes |
|---|---|
| Subject | The identity that existed *before* the logon - usually `SYSTEM` for network logons, blank/anonymous for many remote cases |
| New Logon: Account Name / Account Domain / Security ID | The identity that was actually granted the session - this is the one you care about |
| Logon ID | Hex value, correlate everything else to this |
| Logon Type | See table above |
| Process Name | e.g. `C:\Windows\System32\winlogon.exe`, `svchost.exe` |
| Workstation Name | NetBIOS name of the source machine, if supplied |
| Source Network Address | Source IP - can be blank or `-` on local/service logons |
| Source Port | Rarely useful alone, matters when correlating against firewall/NetFlow |
| Authentication Package | NTLM or Kerbero(s) - `Kerberos` for domain auth in a healthy AD environment, `NTLM` warrants a second look on internal traffic that should be Kerberos-capable |

**Normal:** `jsmith` logging on at 08:47 with Logon Type 2 on their assigned workstation, Authentication Package Kerberos, immediately followed later by a matching 4634. A service account logging on with Logon Type 5 at boot, every day, same host, same time window.

**Suspicious:** Logon Type 10 (RDP) to a server from a Source Network Address that's never RDP'd there before, especially off-hours. Logon Type 3 hitting a dozen hosts in sequence from one workstation inside a minute - classic enumeration/lateral-movement shape. NTLM where Kerberos is expected on an internal segment (downgrade, misconfigured service, or a tool that can't negotiate Kerberos cleanly). A Logon ID that immediately spawns 4672 for an account with no business holding admin-equivalent rights.

**[ANALYST]** - Don't stop at "logon succeeded, case closed." Pull the Logon ID and walk forward: what did the session do (4688 if command-line auditing is on, Sysmon Event ID 1 if deployed), did it open any 4648 explicit-credential connections, and when did it close (4634/4647). A 4624 alone is a data point, not a verdict - a lot of 4624 investigations resolve as Benign Positive (helpdesk remoted in) or Expected Activity (maintenance window), not confirmed malicious.

**Related events to correlate:** 4625 (was this preceded by failed attempts), 4634/4647 (session teardown), 4672 (privileged token), 4648 (did this session then pivot elsewhere), 4768/4769/4771 (Kerberos side of the same authentication on the DC), 4776 (if NTLM was used against a DC).

**Common false positives:** VPN/NAT concentrators making every remote worker's Source Network Address look identical (you lose the real client IP unless the VPN device logs it separately); service accounts with high-frequency Logon Type 3 that look like enumeration but are just backup/monitoring jobs; load balancer health checks authenticating on a schedule.

**Example investigation narrative:** A 4624 fires on `FS01.northwind.local` for `svc-backup`, Logon Type 3, from `10.20.4.55` - unremarkable, it does this nightly. A second 4624 twelve minutes later for the same account, same Logon Type, but Source Network Address `10.20.9.187` (a workstation, not the backup server) got a second look. That workstation's local log showed a 4648 right before it: `runas /netonly` using the backup account's credentials, harvested from a misconfigured scheduled task that stored them in plaintext. Verdict: True Positive - credential misuse confirmed, account rotated, task remediated.

```kql
// KQL - Microsoft Sentinel / SecurityEvent table
// Flag 4624 logons where Authentication Package is NTLM on servers that should be Kerberos-only
SecurityEvent
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| where LogonType in (2,3,10)
| where Computer has "FS01" or Computer has "DC01"
| project TimeGenerated, Computer, TargetUserName, TargetDomainName, LogonType, IpAddress, LogonProcessName
| order by TimeGenerated desc
```

## 4625 — An Account Failed to Log On

The failure twin of 4624. Same triggering conditions, different outcome - credentials were rejected, the account was locked/disabled, or the logon type itself was denied by policy.

**Where it appears:** Same machine that would have generated the 4624 - the box being logged into, not necessarily where the attempt originated.

| Field | Notes |
|---|---|
| Account Name | Identity that was attempted - can be garbage/typo'd if the source is guessing |
| Failure Reason | Human-readable summary |
| Status / Sub Status | Hex codes, sub status is where the real detail lives |
| Logon Type | Same coding as 4624 |
| Source Network Address | Attempt origin, subject to the same NAT/VPN caveats as 4624 |
| Caller Process Name | What local process initiated the attempt, when populated |

Sub status codes worth memorizing:

| Sub Status | Meaning |
|---|---|
| 0xC000006A | Bad password |
| 0xC0000064 | User does not exist |
| 0xC0000234 | Account locked out |
| 0xC0000072 | Account disabled |

**Normal:** An occasional 0xC000006A from a human who fat-fingered their password, followed shortly by a successful 4624. A handful of 0xC0000064 hits from vulnerability scanners probing default account names on a known schedule.

**Suspicious:** A burst of 0xC000006A for one account across many source IPs (password spraying against a single identity) or many accounts from one source IP (spraying in the other direction, or classic brute force) in a tight time window. 0xC0000064 hits against names like `administrator`, `admin`, `backup` from an external-facing Source Network Address - account enumeration. A steady drip of failures against a service account that never normally fails, right before a 4740 lockout.

**[ANALYST]** - Always check the Logon Type on the failures. Ten thousand 0xC000006A at Logon Type 3 against a file server is a different animal from the same count at Logon Type 10 against an RDP-exposed jump box - the latter sits closer to the perimeter and usually ranks higher priority.

**Related events to correlate:** 4624 (did any of the attempts eventually succeed), 4740 (lockout that resulted), 4771 (Kerberos pre-auth failure equivalent on the DC, often fires alongside or instead of 4625 depending on protocol), 4776 (NTLM validation failure detail from the DC's perspective).

**Common false positives:** Stale saved credentials on a mapped drive or scheduled task retrying after a password change - looks like an attack, is really IT forgetting to update one config; mobile sync clients hammering a mail server with an outdated password; a decommissioned service account still referenced somewhere, failing on every scheduled run.

**Example investigation narrative:** SIEM alert fires for 400+ 4625 events in fifteen minutes against `DC02`, sub status 0xC000006A, spread across 60 usernames, all from `198.51.100.23` - an external IP behind an RDP gateway rule that should have been retired months ago. Low attempt count per account, broad account coverage, single source: password spraying. No corresponding successful 4624 for any sprayed account. Verdict: True Positive - external spray, blocked at the firewall, no evidence of compromise - the stale gateway rule gets written up as a separate finding.

```spl
`` SPL - Splunk, assumes Windows TA field extraction ``
index=wineventlog EventCode=4625
| bin _time span=15m
| stats dc(Account_Name) as distinct_accounts, count by src_ip, _time
| where distinct_accounts > 20 AND count > 50
| sort - count
```

## 4634 — An Account Was Logged Off

The system-level teardown of a logon session - fires when a session ends, whether that's a clean logoff, a share disconnect, a service stopping, or Windows tearing the session down on shutdown/reboot without an explicit logoff.

**Where it appears:** Same host that generated the matching 4624.

**Key correlation point:** the Logon ID on 4634 matches the Logon ID from the originating 4624 - that's the whole value of this event. On its own it says almost nothing.

**Normal:** A 4634 a few hours after the matching 4624, session duration consistent with a normal working day, or immediately after a 4647 (see below) for a clean interactive logoff.

**Suspicious:** Rarely suspicious alone. What matters is the absence of one, or a very short-lived session (4624 immediately followed by 4634 seconds later) on an account/host pairing where that's not the normal pattern - can indicate a scripted task, a credential test, or a tool that logs on, does something, and logs off fast (some lateral-movement tooling behaves exactly like this).

**[ANALYST]** - Session duration (4634 timestamp minus matching 4624 timestamp) is the useful derived metric. Extremely short sessions on interactive Logon Types deserve a second look; long-lived sessions with no matching 4634 for days usually just mean an orphaned RDP session nobody closed - housekeeping, not an incident.

**Related events to correlate:** 4624 (mandatory pairing via Logon ID), 4647 (was this a deliberate user logoff or a session teardown some other way).

**Common false positives:** none really - this is a low-signal, high-volume housekeeping event. The false positive risk here is analyst fatigue from treating every 4634 as worth individual attention; it isn't. Use it for session-duration math and Logon ID closure, not as a standalone alert trigger.

## 4647 — User Initiated Logoff

The deliberate counterpart to 4634 - fires when a user actually clicks "Sign out" or runs `logoff`, as opposed to the session ending some other way (network drop, forced disconnect, service stop, shutdown). A 4647 typically fires immediately before a 4634 for the same Logon ID: 4647 records the intent, 4634 records the actual close.

**Where it appears:** Same host as the session that's ending, interactive/RDP sessions primarily - this event doesn't really apply to service or batch logons, which just get torn down and generate 4634 without a 4647.

**Normal:** User finishes their shift, clicks sign out, 4647 fires followed within the same second or two by 4634 with matching Logon ID.

**Suspicious:** Again, rarely interesting alone. What's worth flagging is the *absence* of 4647 on a session that ended anyway - the session was torn down by something other than the user (network loss, an admin forcing a logoff, a crash, or a tool killing the session programmatically). If you suspect an attacker rode an RDP session and fled when EDR fired, a 4634 with no preceding 4647 on what should be a normal interactive session is a small but real tell.

**[ANALYST]** - Use the presence or absence of 4647 as a sanity check on how a session really ended, when that matters to a case - e.g., an HR investigation where someone claims they logged off before an incident and the evidence needs to support or contradict that.

**Related events to correlate:** 4624 (the session being closed), 4634 (the actual closure that follows).

**Common false positives:** none of real concern; this event is about as low-noise as the Security log gets. The only "false positive" pattern worth knowing is that some remote access tools and thin-client setups generate 4647 even on brief reconnects, which can look like a user logging off and back on repeatedly when it's really a flaky network link.

## 4648 — A Logon Was Attempted Using Explicit Credentials

This one earns its keep in almost every lateral-movement investigation. It fires whenever a process running as one identity uses a *different* set of explicit credentials to authenticate somewhere - `runas`, mapping a drive with alternate creds, `mstsc` with a saved alternate account, scheduled tasks configured to run as another user, or any tool calling `LogonUser`/`CreateProcessWithLogonW`-style APIs with credentials that don't match the current session.

**Where it appears:** The source machine - where the explicit-credential logon was *initiated*, not the target. Analysts sometimes go looking for 4648 on the destination server and find nothing, because it only logs on the originating host.

| Field | Notes |
|---|---|
| Subject | The account and Logon ID of the *current* session doing the acting |
| Account Whose Credentials Were Used | The alternate identity being authenticated as - this is the one attackers are usually trying to reuse |
| Target Server | Hostname/IP being connected to |
| Process Name | The binary that initiated the explicit-credential logon |

**Normal:** A sysadmin logged on as their standard account runs `runas /user:northwind\svc-app01 cmd.exe` to test a service account interactively, Target Server matches something the sysadmin actually manages, Process Name is `runas.exe` or a legitimate admin tool. Scheduled tasks configured with a service account and "run whether user is logged on or not" generate this at every trigger - expected and typically high-volume on task servers.

**Suspicious:** A workstation account whose "current session" is a standard user, generating 4648 with Account Whose Credentials Were Used set to a domain admin or a service account, targeting multiple servers in short succession - the fingerprint of stolen credentials being tested for lateral movement (touches on the Valid Accounts and Lateral Movement themes in MITRE ATT&CK generally, no specific technique ID attached since none was confirmed here). Process Name that isn't a normal admin tool - unexpected scripting engines or LOLBins initiating explicit-credential connections.

**[ENGINEERING]** - Baseline which Process Name + Account Whose Credentials Were Used + Target Server combinations are expected (scheduled tasks, known admin workflows) and alert on new combinations, rather than alerting on every 4648 - far too high-volume on a well-managed estate with lots of legitimate service accounts.

**Related events to correlate:** 4624 on the Target Server shortly after (did the attempt succeed and open a session there), 4672 if that resulting session was privileged, 4688/Sysmon Event ID 1 for the process that triggered the explicit logon.

**Common false positives:** Password managers and PAM tools legitimately brokering alternate credentials during normal checkout workflows; backup software authenticating to remote shares under a dedicated account; any properly configured scheduled task running as a service account - common, and mostly noise once baselined.

**Example investigation narrative:** Analyst is chasing a phishing case where `jsmith` opened a malicious attachment. Sysmon Event ID 1 shows the attachment spawning `powershell.exe`, followed within the minute by a 4648 on `jsmith`'s workstation: Subject `jsmith`, Account Whose Credentials Were Used `northwind\svc-sql01` - a SQL service account `jsmith` has no reason to know the password for - Target Server `SQL02.northwind.local`. A matching 4624 appears on `SQL02` seconds later, Logon Type 3, for `svc-sql01`, followed by 4672 showing elevated database rights. Verdict: True Positive - credential theft and immediate lateral use, `svc-sql01` rotated, `jsmith`'s workstation imaged.

```kql
// KQL - flag 4648 events where the credential used doesn't match common baseline patterns
SecurityEvent
| where EventID == 4648
| where SubjectUserName !endswith "$"          // exclude machine accounts
| where TargetUserName has "svc-"               // credentials used belong to a service account
| where SubjectUserName != TargetUserName
| summarize Attempts=count(), Targets=make_set(TargetServerName) by SubjectUserName, TargetUserName, bin(TimeGenerated, 1h)
| where Attempts > 3 or array_length(Targets) > 1
```

## 4672 — Special Privileges Assigned to New Logon

Fires alongside a 4624 (same Logon ID, same timestamp window) whenever the resulting token carries admin-equivalent privileges - Domain Admins, local Administrators, or any account holding sensitive rights like `SeDebugPrivilege` or `SeBackupPrivilege`. It doesn't replace 4624; it rides shotgun on it to flag "and this one's privileged."

**Where it appears:** Same machine as the paired 4624 - domain controllers see this constantly for admin logons and DC service accounts; workstations should see it rarely, only for accounts actually meant to hold local admin there.

**Key fields:** Subject Account Name/Domain/SID and Logon ID (matching the 4624), plus the privileges assigned to the token. There's no separate "target account" field - this event is a privilege annotation on the same logon.

**Normal:** A domain admin logging onto a domain controller to patch, tightly time-boxed, matching a known change window. Built-in `SYSTEM` and local service accounts generating this constantly at boot - expected noise, and the reason 4672 needs filtering before it reaches an analyst's queue.

**Suspicious:** A standard user account suddenly generating 4672 on a host it's never held privileges on - the token picked up admin-equivalent rights, either legitimately (added to the wrong group) or not (privilege escalation, harvested admin credentials). 4672 immediately following a 4648 on a server the acting user has no business administering. A spike in 4672 across many hosts in a short window from one account - could be a mass patch run, or a compromised admin credential touching everything at once.

**[STAKEHOLDER]** - This is the event that answers "did anyone use admin rights on that box, and who" - the question auditors and incident leads ask first. Reducing unnecessary 4672 volume (fewer standing admin rights, more just-in-time elevation) directly shrinks how many logons the SOC has to individually assess.

**[MANAGEMENT]** - 4672 volume per account, tracked over time, is a decent input into a privileged-access review. An account generating far more 4672 events than its documented role calls for is a standing-privilege finding, not just a SOC alert.

**Related events to correlate:** 4624 (mandatory pairing, same Logon ID), 4648 (was the privileged logon reached via explicit-credential use elsewhere), 4728/4732 (recently added to a privileged group - explains a new 4672 pattern), 1102 (a privileged session immediately followed by the audit log being cleared is about as high-priority as this cluster gets).

**Common false positives:** Backup/monitoring service accounts needing `SeBackupPrivilege`/`SeRestorePrivilege`, firing on every scheduled run across the fleet; break-glass emergency admin accounts used during outages, rarely pre-baselined as expected; patch management tooling authenticating with elevated rights across hundreds of hosts on a schedule - looks like mass compromise until you check the change calendar.

```spl
`` SPL - Splunk, correlate 4672 with a recent group-membership change for the same account ``
index=wineventlog EventCode=4672
| eval acct=Account_Name
[ search index=wineventlog (EventCode=4728 OR EventCode=4732) earliest=-7d
  | eval acct=Member_Name
  | table acct ]
| stats count by acct, Computer, _time
| sort - _time
```

Taken together, these six events map a session end to end: attempt (4625) or success (4624), whether it carried elevated rights (4672), whether it pivoted on someone else's credentials (4648), and how it ended (4634/4647). None of them alone proves malice - legitimate administration, backups and scheduled tasks generate every "suspicious" pattern above in isolation. The Logon ID is what turns six low-context events into one coherent timeline, and that timeline is usually the fastest route from "something looks odd" to a defensible verdict, whichever verdict that turns out to be.
