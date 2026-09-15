# Privileged Account Login

**Category:** Identity & Active Directory - Account & Authentication
**Playbook ID:** IAM-006

A privileged account login isn't inherently an incident - your Tier-0 admins log in every day, and if every one of those events paged someone at 2am you'd have an unusable detection within a week. What this playbook actually watches for is a privileged credential being used *somewhere it shouldn't be*: off the jump host, outside the change window, over a logon type that admin accounts don't normally use, or immediately after a chain of events that looks like credential theft rather than routine admin work. The telemetry is dense (4624/4672 pairs alone can run into the thousands per day in a mid-size AD forest), so this is as much a filtering and enrichment problem as it is an investigation problem. Get the baseline wrong and you'll either drown in noise or miss the one login that mattered.

## Business Risk

**[STAKEHOLDER]** - Privileged accounts (Domain Admins, Enterprise Admins, Tier-0 service accounts, local admin-equivalent break-glass accounts) can touch anything in the environment: read every mailbox, push GPOs to every endpoint, dump every credential in the domain. A privileged login from an unexpected host, at an unexpected time, or via an unexpected path is one of the strongest early signals of a domain-wide compromise in progress - most serious AD breaches involve privileged credential misuse at some point before impact. The decision this playbook supports is fast: is this admin doing admin work on the admin path, or is this a stolen/misused credential that needs to be shut down before it's used to dump the whole domain.

## Severity / Priority Default

- **Default:** High (P2) - any confirmed privileged logon outside expected baseline starts here, not lower.
- **Escalates to Critical (P1)** when the logon originates from a non-domain-joined or external source, when it's immediately followed by DCSync-style replication requests, LSASS access, or new privileged account/group changes (4720/4728/4732), or when the account is a break-glass/emergency-access account that should never be in routine use.
- **De-escalates to Medium (P3)** only after confirmed benign context (approved change ticket, on-call admin, known PAW) is verified - never de-escalate purely on "looks routine."

## MITRE ATT&CK Techniques

- **T1078 Valid Accounts** (.002 Domain Accounts) - the account itself is legitimate; the misuse is in how/where/when it's used
- **T1550 Use Alternate Authentication Material** (.002 Pass the Hash, .003 Pass the Ticket) - privileged logon from an unexpected host with no matching interactive password entry is the classic tell
- **T1558 Steal or Forge Kerberos Tickets** (.001 Golden Ticket, .002 Silver Ticket) - forged tickets present as privileged Kerberos activity with anomalies in encryption type, realm, or ticket lifetime
- **T1021 Remote Services** (.001 RDP, .002 SMB/Windows Admin Shares) - the lateral movement vector a stolen privileged credential is usually used over
- **T1003 OS Credential Dumping** (.001 LSASS Memory, .006 DCSync) - the near-term follow-on once a privileged session is established
- **T1087 Account Discovery** - frequently precedes targeting of a specific privileged account

## Trigger / Detection Logic Summary

Fires on a 4624 (or 4776 for NTLM-path validation) where the authenticating account is a member of a monitored privileged group (Domain Admins, Enterprise Admins, Schema Admins, a defined Tier-0 service-account watchlist, or any account with 4672 special-privilege assignment on the same Logon ID) **and** one or more of the following baseline deviations is true:

1. Source Workstation Name / Source Network Address is **not** in the approved PAW/jump-host allowlist.
2. Logon Type is not on the account's expected list (e.g., Type 3/network from a random workstation for an account that should only ever log on interactively at a PAW or Type 10/RDP to a jump host).
3. Logon occurs outside the account's normal active hours or outside an open, approved change window.
4. Logon is immediately preceded by a 4648 explicit-credential logon from a non-admin host (credential used from somewhere it was never typed).
5. First-ever logon for this account/host pair (no historical baseline).

## Required Log Sources & Event IDs

| Source | Event IDs | Why |
|---|---|---|
| Domain Controller Security log | 4624, 4672 | Core pairing - successful logon plus the special-privileges flag confirms admin-equivalent token |
| Domain Controller Security log | 4768, 4769, 4771 | Kerberos path - realm, client address, ticket encryption type (RC4/0x17 anomalies), pre-auth failures |
| Domain Controller Security log | 4776 | NTLM fallback validation - flags legacy auth on an account that should be Kerberos-only |
| Domain Controller Security log | 4648 | Explicit-credential use - the "someone typed/used this credential from here" signal for lateral movement |
| Source & target endpoint Security log | 4624, 4634, 4647, 4688 | Confirms session lifecycle and what process ran under the privileged token after logon |
| Endpoint Sysmon/PowerShell logs | 4103, 4104 | Catches scripted/obfuscated activity executed immediately after a privileged logon |
| Domain Controller Security log | 4728, 4732, 4720 | Follow-on account/group manipulation using the privileged session |
| Domain Controller Security log | 1102, 4719 | Anti-forensics / audit-blinding attempts riding on the privileged token |

## Key Fields to Inspect

**[ANALYST]**
- **New Logon Account Name / SID** on 4624 - confirm it's actually the privileged account and not a similarly-named decoy or a stale group membership that should have been removed.
- **Logon Type** - Type 2 (interactive) or Type 10 (RemoteInteractive/RDP) to a designated PAW/jump host is normal for human admins; Type 3 (network) showing up for an interactive-only admin account is a strong anomaly; Type 5 (service) should only ever match a documented service account.
- **Workstation Name / Source Network Address / Source Port** - is this a known PAW, jump host, or automation host? Anything outside the allowlist gets flagged regardless of everything else looking fine.
- **Process Name** on 4624 (e.g., `winlogon.exe` for console vs `svchost.exe`-hosted services for RDP/Terminal Services) - helps distinguish interactive human logon from a service or scheduled process using the credential.
- **Authentication Package** - Kerberos expected for domain-joined admin activity; NTLM on an account that never uses NTLM is worth a second look (could indicate a downgrade attack or an unusual application still hardcoded to NTLM).
- **4672 Privileges list** - confirms which specific privileges (e.g., SeDebugPrivilege, SeBackupPrivilege) were granted, useful for scoping what the session could actually do.
- **4648 Target Server Name and Account Whose Credentials Were Used** - if this precedes the 4624, it tells you the credential was pulled from a different session/host than where it's now being used.
- **Ticket Encryption Type** on 4768/4769 - RC4 (0x17) requests for a privileged account in an environment that should be AES-only is a golden/silver ticket forgery indicator worth pulling into a dedicated Kerberos-ticket-abuse investigation.

## Normal vs Suspicious Pattern

| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Source host | Fixed set of 2-3 PAWs or a jump-host cluster, consistent day to day | New/unrecognized hostname, workstation VLAN, or an IP outside the admin subnet |
| Logon Type | Type 2/10 for human admins, Type 5 for known services only | Type 3 (network) appearing for an account with no legitimate remote-service reason, or Type 10 to a host that isn't a jump host |
| Timing | Business hours or a logged, approved change window; on-call rotations documented | 03:00 local with no change ticket, or immediately after hours on a Friday before a long weekend |
| Preceding activity | Nothing unusual - direct interactive logon | A 4648 explicit-credential event from an unrelated workstation moments before, or recon-flavored 4798/4799 activity against the account shortly before |
| Authentication path | Kerberos, AES encryption, consistent realm | Sudden NTLM fallback, RC4 ticket encryption, or a Client Address that doesn't match any known subnet for that account |
| Follow-on activity | Routine admin tooling (RSAT, AD Users and Computers, patch deployment) | LSASS access, DCSync-pattern replication requests, new privileged group membership changes minutes after logon |

## Investigation Steps

1. Confirm group membership and privilege scope at time of logon - pull current AD group membership and cross-check against 4728/4732 history in case the account was recently and unexpectedly added to a privileged group.
2. Validate the source: is the Workstation Name / Source Network Address a documented PAW or jump host? Check the PAW/jump-host inventory, not memory - allowlists drift.
3. Check Logon Type against the account's documented expected logon types. An account that's supposed to be RDP-to-jump-host-only showing Type 3 network logons to a file server is a real anomaly, not a rounding error.
4. Pull any 4648 events in the 15 minutes prior, on both the source and any related hosts, to see whether this credential was staged/used from somewhere else first (Pass the Hash/Pass the Ticket signature).
5. Correlate with the human owner: is this admin on shift, on the change calendar, or reachable to confirm they initiated the session? Treat "I can't reach them" as an escalation trigger, not a dead end.
6. Review what ran under the token after logon - 4688 process creations, 4103/4104 PowerShell activity, and whether any of it touches LSASS, ntds.dit, or replication APIs (DCSync pattern).
7. Check for immediately following account/group manipulation (4720, 4728, 4732, 4738) or audit tampering (1102, 4719) that would indicate the session is being used to entrench access.
8. Document the finding with source, destination, logon type, and preceding/following activity, then apply the disposition and containment matrix below.

## True Positive Indicators

- Source host is not a recognized PAW/jump host and the owning admin cannot confirm initiating the session.
- Preceded by a 4648 from an unrelated workstation (credential relay/reuse pattern) or by LSASS-adjacent process activity on the source host.
- Kerberos ticket anomalies - RC4 encryption where AES is standard, unusually long ticket lifetimes, or a realm/Client Address mismatch consistent with forged tickets.
- Followed by DCSync-pattern replication requests, new privileged accounts/groups, or audit log tampering.
- Break-glass/emergency-access account shows any logon activity at all outside a declared emergency-use event.

## False Positive / Benign Positive Indicators

- Logon matches an open, approved change ticket and the admin confirms initiating it from a known device (new laptop enrolled but not yet added to the PAW allowlist is a common, fixable cause).
- Vendor/MSP admin performing scheduled maintenance from a documented, pre-approved external management host.
- Service account logon tied to a known scheduled job (backup, patching orchestration) that legitimately runs with elevated rights on a predictable schedule - verify against the job scheduler, don't just assume.
- New jump host recently added to rotation but not yet propagated to the detection allowlist - benign, but log it as a detection-tuning gap, not a clean dismissal.

## Escalation Criteria

Escalate to Tier 2 / IR immediately if any of the following are true:
- Source host is unrecognized and the admin cannot be reached or denies initiating the session.
- A 4648 credential-reuse pattern or LSASS-adjacent process activity precedes the logon.
- Any activity resembling DCSync, Golden/Silver Ticket forgery indicators, or audit log clearing (1102) follows the logon.
- The account involved is a break-glass, Enterprise Admin, or Schema Admin account.

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Approval Needed | Notes |
|---|---|---|
| Force re-authentication / kill active session (Logon ID) | Tier 2 analyst, standard SOP on suspected TP | Fast, low-collateral stopgap |
| Reset password + invalidate Kerberos tickets for the account | IAM team or on-call IR lead | Required once credential misuse is suspected; coordinate timing with account owner to avoid business disruption |
| Disable account entirely | IR lead + AD platform owner joint sign-off | For confirmed compromise; Tier-0 accounts require director-level notification per most privileged-access policies |
| Isolate source host (EDR network containment) | IR lead | If source host is compromised, not just the credential |
| Rotate krbtgt account (twice) | AD platform owner + IR lead, planned change | Only for confirmed Golden Ticket activity - high-impact action, requires coordinated execution across the forest |

Review cadence: PAW/jump-host allowlist and privileged-account baseline reviewed monthly by the IAM/detection engineering owner; every P1/P2 privileged-login incident reviewed in the weekly SOC/IAM sync regardless of final disposition.

## Example Query (Microsoft Sentinel KQL)

```kql
SecurityEvent
| where EventID == 4624
| where AccountType == "User"
| join kind=inner (SecurityEvent | where EventID == 4672) on LogonId, Computer
| where Account in (PrivilegedAccountWatchlist)
| where WorkstationName !in (ApprovedPAWList)
| project TimeGenerated, Account, Computer, WorkstationName, IpAddress, LogonType
```

## Closure Criteria

Close as **True Positive** only after source, credential-use path, and any follow-on activity are fully scoped, with containment (session kill, password reset, or account disable) logged and the AD platform owner notified. Close as **Benign Positive** when an approved change ticket or confirmed admin action explains the deviation - update the PAW/allowlist baseline so the same pattern doesn't re-alert. Close as **Insufficient Evidence** only when the admin cannot be reached within the SLA window and no follow-on malicious indicators appear after 24 hours of monitoring - keep the account on an active watchlist rather than closing cleanly.

**Example case note:**
`2026-09-15 02:10 UTC - 4624/4672 pair for jsmith-adm (Domain Admins) at DC02, Logon Type 3 (network) from 10.44.8.19 (unrecognized host, not on PAW allowlist). Preceded at 02:07 UTC by 4648 explicit-credential event on WKSTN-0447 targeting DC02. Admin jsmith unreachable during initial contact window; escalated to IR. Session (Logon ID 0x3F2A11C) killed, password reset, Kerberos tickets invalidated. WKSTN-0447 isolated for forensic review - preliminary EDR triage shows credential-dumping tool artifacts. Escalated to full incident, Tier-0 notification sent to AD platform owner.`
