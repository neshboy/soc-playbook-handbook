# SMB Scanning

## Playbook ID & Name
**NW-017 — SMB Scanning (Port 445/139 Enumeration, Share and Session Discovery)**

## Business Risk
**[STAKEHOLDER]** - SMB scanning is almost always the reconnaissance step immediately before a real intrusion gets worse, not the intrusion itself. Someone is walking the hallway checking which doors are unlocked and which ones have a "C$" or "ADMIN$" sign on them. On its own it doesn't move or destroy data, but it tells an attacker (or a compromised host acting on an attacker's behalf) exactly where to point the next tool - credential spraying, PsExec-style lateral movement, or ransomware staging. The decision that matters here is speed: catching this at the enumeration stage is cheap, catching it after a foothold has already pivoted onto three more servers is not.

## Severity / Priority Default
**Medium** as a baseline - internal host enumerating shares across a subnet with no attribution to a known tool. **High** when null-session/anonymous enumeration is combined with authentication attempts, when the source has no legitimate reason to talk SMB (e.g., a print kiosk or a marketing laptop), or when any target is a domain controller or file server holding regulated data. **Critical** if SMB (445/139) is reachable from outside the network boundary at all - that's a standalone exposure finding regardless of who's scanning it.

## MITRE ATT&CK Technique(s)
- **T1046 Network Service Discovery** - the core technique; identifying which hosts on a segment have SMB open and responsive.
- **T1595 Active Scanning** - applies if the source is external/pre-engagement rather than a foothold already inside the network.
- **T1087 Account Discovery** - null-session or authenticated enumeration frequently pulls local user/group lists off targets alongside share names.
- **T1069 Permission Groups Discovery** - enumeration tools commonly walk share ACLs and group membership as part of the same pass.

If enumeration is followed by an authenticated session against `ADMIN$`/`C$` and file execution or a new service, that's a technique pivot into **T1021.002 Remote Services: SMB/Windows Admin Shares** - flag it and hand off to the lateral-movement playbook, don't try to close both under this one.

## Trigger / Detection Logic Summary
Alert fires when a single source generates SMB session/tree-connect activity (TCP 445, or legacy 139/NetBIOS) against an unusual number of distinct destination hosts in a short window, particularly where the sessions are short-lived, low-byte, and concentrated on administrative or hidden shares (`IPC$`, `ADMIN$`, `C$`) rather than a normal file share a user would actually work in. This is the SMB-specific horizontal-scan pattern - same shape as generic port scanning, but the share-name and session-type detail is what turns "port 445 was touched" into "someone was enumerating shares and possibly accounts."

## Required Log Sources & Event IDs
| Source | What it gives you |
|---|---|
| Windows Security log - Event ID **5140** | A network share object was accessed - basic share connect record |
| Windows Security log - Event ID **5145** | Detailed File Share audit - checks whether the client could be granted access; this is where you see `IPC$` enumeration vs. real `C$`/`ADMIN$` access, plus the requesting source address |
| Windows Security log - Event ID **4624** (Logon Type 3) | Successful network logon - confirms whether enumeration was authenticated or anonymous |
| Windows Security log - Event ID **4625** (Logon Type 3) | Failed network logon - repeated failures across multiple hosts alongside scanning = spray-and-scan combo |
| Windows Filtering Platform - Event ID **5156** / **5157** | Connection permitted/blocked on 445/139 at the host firewall |
| Sysmon Event ID **3** | Network connection - confirms an internal host as the scan source |
| Sysmon Event ID **1** | Process creation - surfaces the tool doing the enumerating (PowerShell, `net.exe`, `nmap`, Python-based frameworks) |
| Firewall / NetFlow / Zeek `conn.log` and `smb_mapping.log` | Connection tuples and, where Zeek is deployed, protocol-level tree-connect and named-pipe detail without needing host-side auditing at all |

Worth knowing before you go hunting: **Event ID 5145 is not enabled by default.** It requires Advanced Audit Policy → Object Access → "Audit Detailed File Share" (Success and Failure), and it's noisy enough that a lot of environments only turn it on for file servers and domain controllers, not every workstation. If a scan touched only workstations, you may have nothing but the connection-level record (5156/Sysmon 3) and no share-level detail - that's a real telemetry gap, not a sign nothing happened.

## Key Fields to Inspect
**[ANALYST]**
- Source IP/host and destination count - how many distinct hosts did it touch on 445/139 in the window.
- Account name on the session - especially `ANONYMOUS LOGON`, which is the classic signature of null-session enumeration tools.
- Share name accessed - `IPC$`-only touches are pure enumeration; `ADMIN$`/`C$` access is a step toward staging or execution.
- Access mask on the 5145 event - was it a read/list operation (enumeration) or a request consistent with write/execute (staging).
- Logon type (3 = network) and authentication protocol (NTLM vs. Kerberos) - heavy NTLM against many hosts from one source is atypical for normal domain traffic.
- Process that generated the traffic on the source host (Sysmon Event ID 1) if internal - legitimate inventory/backup agents vs. an unrecognized script or binary.
- Session duration and bytes transferred - enumeration sessions are short and near-zero-byte; anything with a real data transfer afterward isn't a scan anymore.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Backup software (Veeam, Windows Server Backup) hitting `C$`/`ADMIN$` on a nightly schedule across the server fleet | Workstation with no backup/inventory role suddenly connecting to dozens of peer hosts on 445 |
| SCCM/Lansweeper/asset-discovery tool enumerating admin shares from a known management IP | Widespread `ANONYMOUS LOGON` sessions touching `IPC$` across a subnet |
| File server itself showing high share-access volume - that's users doing their jobs, not scanning | A host that has never touched SMB before generating a burst of tree-connects in minutes |
| A sysadmin's jump host running scheduled remote-admin scripts against a known server list | Enumeration followed almost immediately by failed logons (4625) across multiple hosts, then a successful one |

## Investigation Steps
1. Check the source against known backup, inventory, and vulnerability-scan tooling and their documented schedules - this closes a large share of these tickets fast.
2. Establish scan shape and scope: distinct destination host count, timeframe, and whether it's confined to 445/139 or part of a broader port sweep (cross-reference the port-scanning playbook if so).
3. Pull 5145/5140 detail from a sample of targets - which shares were touched, and was it `IPC$`-only or did it reach `ADMIN$`/`C$`.
4. Determine authentication context: anonymous/null session, or an authenticated account? If authenticated, is that account's normal job function consistent with talking to dozens of hosts over SMB?
5. Correlate with 4625 failures across the same targets in the same window - a scan paired with credential guessing is a materially different case than a scan alone.
6. If the source is internal, pull the EDR/Sysmon process tree to identify what generated the traffic, and check for concurrent credential-access or discovery alerts on that same host.
7. Look for the pivot: any successful Type 3 logon to `ADMIN$`/`C$` shortly after enumeration, or a new scheduled task/service appearing on any touched host - that's the handoff to a lateral-movement investigation.
8. Document the host list, shares touched, and authentication outcome, and note explicitly if Detailed File Share auditing wasn't enabled on any target you needed it for.

## True Positive Indicators
- Non-tooling internal host enumerating `IPC$`/`ADMIN$` across many peers in a short window, especially with `ANONYMOUS LOGON`.
- Enumeration immediately followed by a successful authenticated connection to `ADMIN$`/`C$` on one or more targets.
- Scan paired with failed-logon spikes on the same targets (T1110 spray-and-scan combination).
- SMB (445/139) reachable from an external/untrusted source at all - severity escalates on discovery alone.
- Known offensive tooling artifacts in the process tree (enumeration frameworks, scripted `net view`/`net use` loops).

## False Positive / Benign Positive Indicators
- Confirmed backup, SCCM/Lansweeper, or vulnerability-scanner source within its documented schedule.
- File/print server generating high share-access volume as normal user traffic, not as a scan source.
- DFS namespace referral traffic that legitimately touches multiple servers behind one user request.
- Duplicate 5145/5140 events from dual-homed hosts or multiple log collectors - a parsing/ingestion issue, not a security event.

## Escalation Criteria
Escalate to Tier 2/IR when the source has no tie to an approved tool and is enumerating broadly with anonymous or credential-guessing behavior; when enumeration is followed by successful authenticated access to an admin share; when the activity correlates with other discovery or credential-access alerts on the same host; or when SMB is found reachable from outside the trust boundary - the last one goes to network/infra immediately as a standalone exposure finding, independent of who was scanning it.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Block source host at the switch/firewall** - Tier 1 can action under standing SOP if the source is external with no business justification; internal sources require IR lead approval and should be treated as a suspected-compromise workflow.
- **Disable the account used in authenticated enumeration** - requires IAM/on-call sign-off given the business impact of disabling a live account; service accounts flagged for known misuse can move faster under a pre-agreed exception.
- **Restrict SMB between VLANs/segments where it isn't required** - owned by network engineering with a change ticket; not a unilateral SOC action, but SOC should open the finding.
- **Remove internet-facing SMB exposure** - highest-urgency escalation to network/infra regardless of scanner intent; SMB has no legitimate reason to be internet-reachable.

## Example Query (Microsoft Sentinel - KQL)
```kql
SecurityEvent
| where EventID in (5140, 5145)
| where ShareName has_any ("IPC$", "ADMIN$", "C$")
| summarize TargetsHit = dcount(Computer), Shares = make_set(ShareName),
            Accounts = make_set(SubjectUserName) by IpAddress, bin(TimeGenerated, 15m)
| where TargetsHit > 10
| sort by TargetsHit desc
```

## Closure Criteria
Close as **True Positive** once the host/account list is confirmed, the enumeration isn't tied to approved tooling, and especially if it's paired with credential guessing or a follow-on authenticated share access - open a linked lateral-movement case if it pivoted. Close as **Benign Positive** when the source is a verified backup/inventory/vuln-scan tool inside its schedule. Close as **Insufficient Evidence** when Detailed File Share auditing wasn't enabled on the touched hosts and no share-level detail can be recovered - say so explicitly rather than defaulting to benign because the SMB layer went dark.

**Example case note:** *"Host FIN-WKS-22 (10.20.6.51, primary user sgupta) connected to 34 distinct hosts on 445/tcp across the finance and ops subnets, 09:14-09:19. Event ID 5145 on 6 sampled targets shows ANONYMOUS LOGON enumerating IPC$ only - no ADMIN$/C$ access, no successful Type 3 authenticated logon on any target. Host has no assigned inventory/backup role. Sysmon Event ID 1 shows python.exe spawning from a Downloads-path script (update_check.py), consistent with an enumeration framework. Escalated to IR, host isolated pending forensic review, IAM notified re: sgupta - no credential misuse confirmed at time of closure. Closed True Positive (reconnaissance confirmed); IR case IR-2026-0914 opened for suspected host compromise."*
