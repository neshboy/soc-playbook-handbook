# Appendix 36B: Quick Reference - Sysmon Event IDs & MITRE ATT&CK Technique Index

Same idea as 36A: this is the strip-the-narrative version. Sysmon chapters cover configuration, filtering strategy, and per-event-ID hunting workflows in depth - this page is what you pull up mid-investigation when you need to remember what Event ID 8 actually means, or which ATT&CK sub-technique covers Kerberoasting versus AS-REP Roasting. If a row here doesn't jog your memory, the source chapter has the full field breakdown and worked query.

## Sysmon Event ID Index

Sysmon IDs are not sequential in coverage - Microsoft added categories over multiple releases, which is why 2, 4, 5, 9, 16, 19, 20, 21, and 24-29 don't appear below. This table only lists the IDs actually referenced elsewhere in this book.

| ID | Name | What It Captures | Why It Matters |
|----|------|------------------|-----------------|
| 1 | Process Creation | Full command line (always, unlike 4688 where it's conditional), parent command line, hashes if configured, integrity level, current directory | Richer than the Security log's 4688 - this is your primary process telemetry source when Sysmon is deployed |
| 3 | Network Connection | Source/destination IP and port, protocol, the process that made the connection | Ties outbound/lateral network activity to a specific binary, not just a socket |
| 6 | Driver Loaded | Kernel driver load, hash, signature status | Rootkit and EDR-killer detection - unsigned or newly-seen drivers are the flag |
| 7 | Image Loaded | DLL/image loaded into a process | Core telemetry for DLL sideloading and injection hunting - very high volume, almost always filtered in production configs |
| 8 | CreateRemoteThread | One process creating a thread inside another process | Classic process injection indicator |
| 10 | ProcessAccess | One process opening a handle to another process | Core to credential-dumping detection - lsass.exe as the target process is the headline case |
| 11 | FileCreate | File creation with process attribution | Dropped payloads, staged tooling, ransomware note creation |
| 12/13/14 | RegistryEvent | Key/value create-or-delete (12), value set (13), key/value rename (14) | Persistence via Run keys and service keys lives here |
| 15 | FileCreateStreamHash | File created with an alternate data stream | Mark-of-the-web tracking on downloaded files, or ADS used to hide data |
| 17/18 | PipeEvent | Named pipe created (17) / connected (18) | Several C2 frameworks and lateral movement tools communicate over named pipes |
| 22 | DNSEvent | DNS query with the requesting process attached | Ties a beacon or suspicious lookup back to the exact process that made it, not just the resolver log |
| 23 | FileDelete | File deletion, archived by Sysmon | Anti-forensics and ransomware cleanup behavior after encryption or staging |

**[ANALYST]** - If you only have budget to tune four Sysmon event IDs before the noise drowns the SOC, tune 1, 3, 10, and 11 first. Event ID 7 (Image Loaded) is the one that will flood your pipeline fastest - don't enable it fleet-wide without a tight include/exclude filter already written.

**[ENGINEERING]** - Sysmon field names differ slightly by ingestion pipeline (raw XML `EventData` names vs. your SIEM's normalized schema - e.g., Sentinel's `DeviceProcessEvents`/`DeviceNetworkEvents` tables, Elastic's `winlog.event_data.*`, Splunk's Sysmon TA field extractions). Confirm the actual field name in your environment before copy-pasting a query from the hunting chapters - the event ID and the underlying data are constant, the column name is not.

## MITRE ATT&CK Technique Quick Reference

Grouped below by primary tactic for lookup speed. ATT&CK is a matrix, not a hierarchy - several of these techniques (Valid Accounts, Process Injection, Scheduled Task/Job, Use Alternate Authentication Material) legitimately span multiple tactics depending on how they're used. Where that applies, the technique is listed under its most common role in this book and cross-referenced elsewhere.

### Reconnaissance & Initial Access

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1595 | Active Scanning | - |
| T1190 | Exploit Public-Facing Application | - |
| T1566 | Phishing | .001 Attachment, .002 Link |
| T1078 | Valid Accounts | .002 Domain Accounts, .004 Cloud Accounts |

### Execution

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1204 | User Execution | - |
| T1059 | Command and Scripting Interpreter | .001 PowerShell, .003 Windows Command Shell |
| T1053 | Scheduled Task/Job | .005 Scheduled Task |

### Persistence

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1098 | Account Manipulation | .002 Additional Email Delegate Permissions |
| T1098.001 | Account Manipulation - Additional Cloud Credentials | - |
| T1136 | Create Account | - |
| T1547 | Boot or Logon Autostart Execution | .001 Registry Run Keys |
| T1543 | Create or Modify System Process | .003 Windows Service |

### Privilege Escalation

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1055 | Process Injection | - |
| T1078 | Valid Accounts | .002 Domain Accounts, .004 Cloud Accounts (cross-ref: Initial Access) |
| T1053 | Scheduled Task/Job | .005 Scheduled Task (cross-ref: Execution) |

### Defense Evasion

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1027 | Obfuscated Files or Information | - |
| T1562 | Impair Defenses | .001 Disable or Modify Tools |
| T1218 | System Binary Proxy Execution | .005 Mshta, .010 Regsvr32, .011 Rundll32 |
| T1550 | Use Alternate Authentication Material | .002 Pass the Hash, .003 Pass the Ticket |
| T1207 | Rogue Domain Controller (DCShadow) | - |

### Credential Access

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1110 | Brute Force | .001 Password Guessing, .003 Password Spraying, .004 Credential Stuffing |
| T1003 | OS Credential Dumping | .001 LSASS Memory, .006 DCSync |
| T1558 | Steal or Forge Kerberos Tickets | .001 Golden Ticket, .002 Silver Ticket, .003 Kerberoasting, .004 AS-REP Roasting |
| T1552 | Unsecured Credentials | .001 Credentials In Files, .005 Cloud Instance Metadata API |

### Discovery

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1087 | Account Discovery | - |
| T1069 | Permission Groups Discovery | - |
| T1482 | Domain Trust Discovery | - |
| T1046 | Network Service Discovery | - |
| T1538 | Cloud Service Dashboard | - |
| T1580 | Cloud Infrastructure Discovery | - |

### Lateral Movement

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1021 | Remote Services | .001 RDP, .002 SMB/Windows Admin Shares, .004 SSH |
| T1550 | Use Alternate Authentication Material | .001 Application Access Token, .002 Pass the Hash, .003 Pass the Ticket (cross-ref: Defense Evasion) |

### Collection

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1114 | Email Collection | .003 Email Forwarding Rule |
| T1119 | Automated Collection | - |
| T1530 | Data from Cloud Storage | - |

### Command and Control

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1071 | Application Layer Protocol | .004 DNS |
| T1572 | Protocol Tunneling | - |
| T1090 | Proxy | - |
| T1105 | Ingress Tool Transfer | - |

### Exfiltration

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1567 | Exfiltration Over Web Service | - |
| T1048 | Exfiltration Over Alternative Protocol | - |

### Impact

| ID | Technique | Sub-Techniques Covered |
|----|-----------|--------------------------|
| T1486 | Data Encrypted for Impact | - |
| T1490 | Inhibit System Recovery | - |
| T1531 | Account Access Removal | - |

**[ANALYST]** - Sub-techniques matter for write-ups, but don't let the taxonomy slow down triage. Tag the parent technique first (T1003, T1558, whichever applies), finish containment and evidence collection, then go back and nail down the exact sub-technique for the closure report. A DCSync (T1003.006) and an LSASS dump (T1003.001) get handled very differently once you're mid-investigation - the parent ID alone won't tell you which runbook to open.

**[MANAGEMENT]** - If your detection catalog or SIEM alert rules only tag techniques at the parent level (e.g., every Kerberos-ticket-abuse alert filed as generic T1558 with no sub-technique), that's a maturity gap worth raising at the next detection engineering review. Sub-technique tagging is what lets you answer "which ATT&CK sub-techniques do we have zero coverage for" instead of a vaguer "do we cover credential access."

## Sysmon-to-ATT&CK Cross-Reference

The pairing analysts actually use under time pressure - which Sysmon event ID gives you the evidence for which technique family. This is a starting point, not an exhaustive mapping; most real detections correlate two or three of these together rather than firing on one event ID alone.

| Sysmon ID | Primary ATT&CK Techniques It Supports |
|-----------|------------------------------------------|
| 1 (Process Creation) | T1059, T1204, T1218, T1053, T1027 |
| 3 (Network Connection) | T1071, T1090, T1572, T1105, T1048 |
| 6 (Driver Loaded) | T1562.001 |
| 7 (Image Loaded) | T1055, T1027 |
| 8 (CreateRemoteThread) | T1055 |
| 10 (ProcessAccess) | T1003.001 |
| 11 (FileCreate) | T1486, T1105, T1552.001 |
| 12/13/14 (RegistryEvent) | T1547.001, T1543.003, T1562.001 |
| 15 (FileCreateStreamHash) | T1204, T1105 |
| 17/18 (PipeEvent) | T1021, T1572 |
| 22 (DNSEvent) | T1071.004 |
| 23 (FileDelete) | T1490, T1486 |

**[ENGINEERING]** - Building a correlation rule off this table, don't stop at a single Sysmon event ID matching a technique's "shape." T1003.001 (LSASS Memory) triggered purely on Event ID 10 will burn you with false positives from legitimate EDR/AV agents that also open handles to lsass.exe - filter GrantedAccess rights and the calling process's signer/path before alerting, and cross-check against a second signal (unexpected parent process, unsigned caller, unusual access mask) rather than firing on ProcessAccess to lsass.exe alone.
