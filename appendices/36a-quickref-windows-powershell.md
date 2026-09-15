# Appendix 36A: Quick Reference - Windows Event IDs, Logon Types & PowerShell Logging

Print this one, laminate it, tape it to the monitor. Everything below is pulled straight from the detailed chapters on Windows logon/session events, process/service events, account/group management, Kerberos/NTLM, and PowerShell logging - this appendix strips the narrative and leaves you the lookup table. Field-level detail and query patterns live in the chapters this appendix indexes back to; if a one-liner here doesn't jog your memory, go back to the source chapter.

## Windows Security Event ID Index (Security log unless noted)

### Logon, Logoff, and Session Events

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4624 | Successful logon | Account authenticated - check Logon Type and Source Network Address before trusting it |
| 4625 | Failed logon | Authentication rejected - Sub Status code tells you why (bad password, disabled, locked, unknown user) |
| 4634 | Account logged off | Session teardown - correlate Logon ID back to the originating 4624 |
| 4647 | User initiated logoff | Deliberate logoff by the user, distinct from a system-driven session teardown |
| 4648 | Logon attempted using explicit credentials | RunAs or alternate-credential connection - a classic lateral movement breadcrumb |
| 4672 | Special privileges assigned to new logon | Fires alongside 4624 when the token is admin-equivalent - flags privileged logons |

### Process Execution

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4688 | New process created | Process launch - Command Line field only populates if command-line auditing is enabled |
| 4689 | Process exited | Process termination with exit status |

### Services and Scheduled Tasks

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4697 | Service installed (Security log) | New service registered - check Service File Name for an unexpected binary path (Windows Server 2016 / Windows 10 and newer only - on older OS versions, 7045 in the System log is the only service-install signal) |
| 7045 | New service installed (System log) | Same story as 4697 but from the Service Control Manager source in the System log, not Security |
| 4698 | Scheduled task created | Task Content field carries the XML with the actual action/command |
| 4699 | Scheduled task deleted | Task removed - often anti-forensic cleanup after a persistence mechanism did its job |
| 4700 | Scheduled task enabled | Task re-activated |
| 4701 | Scheduled task disabled | Task deactivated without deletion |
| 4702 | Scheduled task updated | Existing task's action/trigger changed - re-check Task Content |

### Audit Policy Tampering

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4719 | System audit policy changed | Subcategory + old/new setting - someone is dimming the lights before doing something noisy |
| 1102 | The audit log was cleared | Extremely high-signal anti-forensics event - Subject field tells you who cleared it |

### Account Lifecycle

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4720 | User account created | New account provisioned - check who created it and whether it was expected |
| 4722 | User account enabled | Dormant or newly created account switched on |
| 4723 | Password change attempt (self-service) | User changed their own password |
| 4724 | Password reset attempt (by someone else) | An admin or helpdesk account reset a password on someone else's behalf |
| 4725 | User account disabled | Account deactivated |
| 4726 | User account deleted | Account removed |
| 4738 | User account changed | Check Changed Attributes - can be innocuous or a sign of privilege/UPN/SPN tampering |
| 4740 | Account locked out | Caller Computer Name shows the real source of the bad attempts in a lockout storm |
| 4767 | Account unlocked | Lockout cleared, by whom and when |

### Group Membership Changes

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4728 | Member added to security-enabled global group | Check Group Name - Domain Admins additions here matter a lot |
| 4729 | Member removed from security-enabled global group | Group membership reduced |
| 4732 | Member added to security-enabled local group | Local group escalation, e.g. local Administrators |
| 4733 | Member removed from security-enabled local group | Local group membership reduced |

### Kerberos and NTLM Authentication

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4768 | Kerberos TGT requested | Initial authentication to the KDC - Result Code tells you success/failure reason |
| 4769 | Kerberos service ticket requested | High volume, usually filtered - Ticket Encryption Type 0x17 (RC4) is the classic Kerberoasting flag; the more complete rule is to flag any type other than AES (0x11/0x12), which also catches DES (0x1/0x3) |
| 4771 | Kerberos pre-authentication failed | Failure Code 0x18 = bad password - useful companion to 4768 for auth failure hunting |
| 4776 | DC attempted to validate credentials (NTLM) | Legacy/NTLM auth path - Error Code mirrors the same bad-password/unknown-user/locked-out logic as Kerberos |

### Reconnaissance-Flavoured Events

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4798 | A user's local group membership was enumerated | Someone queried what groups a user belongs to (Windows Server 2016 / Windows 10 and newer only) |
| 4799 | A security-enabled local group membership was enumerated | Someone queried group membership - watch breadth/frequency from a single source (Windows Server 2016 / Windows 10 and newer only) |

### PowerShell Logging

| ID | Name | One-Line Meaning |
|----|------|-------------------|
| 4103 | PowerShell module logging | Pipeline execution details and parameters (Microsoft-Windows-PowerShell/Operational log) |
| 4104 | PowerShell script block logging | Records the actual script block text, including de-obfuscated content in many cases |

**[ANALYST]** - Under pressure, prioritize 4688 (what ran), 4624/4625 with Logon Type (how they got in), and 4104 (what the script actually said). Everything else is supporting context.

## Quick Sub Status / Result / Error Code Lookup

These codes ride inside the events above and are what actually separates "somebody fat-fingered their password" from "somebody is running a spray." Don't skip past them.

### 4625 - Failed Logon (Status/Sub Status)

| Code | Meaning |
|------|---------|
| 0xC000006A | Bad password |
| 0xC0000064 | User does not exist |
| 0xC0000234 | Account locked out |
| 0xC0000072 | Account disabled |

### 4768 - Kerberos TGT Requested (Result Code)

| Code | Meaning |
|------|---------|
| 0x0 | Success |
| 0x6 | Client not found in directory |
| 0x12 | Account revoked or disabled |
| 0x18 | Pre-authentication failed / bad password |

### 4771 - Kerberos Pre-Authentication Failed (Failure Code)

| Code | Meaning |
|------|---------|
| 0x18 | Bad password |

### 4776 - NTLM Credential Validation (Error Code)

| Code | Meaning |
|------|---------|
| 0xC0000064 | Unknown user |
| 0xC000006A | Bad password |
| 0xC0000234 | Locked out |

**[ANALYST]** - 4768 and 4776 codes describe the same rejection reasons as 4625's sub status, just at different points in the auth chain (Kerberos vs. NTLM, DC-side vs. workstation-side). Pivoting from a 4625 on a workstation back to the DC, expect a matching flavor of failure, not an identical code - the protocol changed, the "why" didn't.

## Windows Logon Types

Every 4624 and 4625 carries a Logon Type. This is the single fastest way to tell "someone sat at the keyboard" from "a service reached out over the network" from "someone RDP'd in."

| Type | Name | What It Means |
|------|------|----------------|
| 2 | Interactive | Local console logon - physical keyboard/screen at the machine |
| 3 | Network | SMB share access, most service-to-service and `net use` connections - no cached credentials left on the target |
| 4 | Batch | Scheduled task execution context |
| 5 | Service | Service startup using a configured service account |
| 7 | Unlock | Workstation unlock after screen lock |
| 8 | NetworkCleartext | Network logon where credentials were sent in cleartext to the authenticating system |
| 9 | NewCredentials | RunAs /netonly - new outbound credentials while the existing session stays put |
| 10 | RemoteInteractive | RDP / Terminal Services logon |
| 11 | CachedInteractive | Logon using cached domain credentials, no DC contact required |

**[ANALYST]** - Type 3 on a domain controller from a workstation IP at 3am is normal-shaped noise most nights (backup agents, monitoring, print spoolers). Type 10 (RDP) to a server with no change ticket, or Type 2 on a server that should only ever see Type 3/5, is where you start pulling the thread. Type 9 shows up legitimately with admin tooling that stashes alternate creds - don't auto-escalate on Type 9 alone, check what ran next.

**[ENGINEERING]** - Logon Type is filterable in every SIEM (Sentinel's `LogonType`, Splunk's `Logon_Type`, Elastic's `winlog.event_data.LogonType`). Baseline the expected Logon Type per asset role and alert on the mismatch rather than blocklisting individual source IPs - IPs churn, role expectations don't.

## PowerShell Logging: 4103 vs 4104

Both events live under **Microsoft-Windows-PowerShell/Operational**, not the Security log - a common miss when someone builds a query against the wrong channel and gets zero results, then assumes PowerShell logging isn't enabled.

| Aspect | 4103 (Module Logging) | 4104 (Script Block Logging) |
|--------|------------------------|-------------------------------|
| What it captures | Pipeline execution details, cmdlet names, parameter values | The actual script block text as executed |
| De-obfuscation | No - shows what was invoked, not decoded payloads | Yes, in many cases - logs content after PowerShell's own de-obfuscation |
| Best for | Confirming which cmdlets ran and with what arguments | Reading `-EncodedCommand` / obfuscated payload content in plain text |
| Volume | Moderate - one entry per pipeline execution | Can be high - large or looped scripts generate multiple entries |
| GPO setting | Turn on Module Logging | Turn on PowerShell Script Block Logging |
| Typical gap | Silent if module logging isn't enabled or the module isn't loaded | Silent on PowerShell v2 fallback (downgrade attack) if v2 isn't also disabled |

**[ANALYST]** - When 4104 shows an empty or trivially short script block but you know something ran, check for a PowerShell v2 downgrade dodging script block logging, or a payload passed via `powershell.exe -Command` that landed in 4688's Command Line field instead. Cross-reference 4688 with 4103/4104 - they should tell the same story from two angles. If they don't, that gap is itself a finding.

**[ENGINEERING]** - Script block logging splits multi-line scripts into multiple events tied together by `ScriptBlockId` - group by that field before counting "how many suspicious scripts ran," don't treat entry count as incident count.

**[MANAGEMENT]** - Module and script block logging are Group Policy settings (Administrative Templates > Windows Components > Windows PowerShell), not something retroactively enabled after the fact. If these aren't on fleet-wide, raise it with the GPO owner now, not during the next incident retro.
