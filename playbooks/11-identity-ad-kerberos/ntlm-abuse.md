# Playbook: NTLM Abuse (Downgrade, Relay Follow-On, Brute Force & Pass the Hash Authentication)

## Playbook ID & Name
**IAM-024 — NTLM Abuse (Legacy Authentication Downgrade, Password Guessing/Spraying, and Hash-Based Lateral Logons)**

## Business Risk
**[STAKEHOLDER]** - NTLM is the authentication protocol Kerberos was supposed to have replaced two decades ago, and it is still switched on in almost every AD environment because some printer, backup agent, or line-of-business app from 2011 refuses to talk anything else. That legacy footprint is exactly what an intruder relies on: NTLM doesn't require the domain controller to vouch for a live password the way Kerberos pre-authentication does, its hash can be captured and reused without ever cracking it (pass-the-hash), and it can be coerced or downgraded into revealing credential material to a listener the attacker controls. The practical business impact is that a single stolen hash from one laptop can turn into an admin session on a file server, then a domain controller, inside the same afternoon — with almost none of the "wrong password" friction a normal attack generates. Decisions that matter here — disabling NTLM on a segment, resetting a service account, forcing a password change on a VIP account — usually have to go through whoever owns those legacy systems, which is why this playbook exists: to get evidence in front of that decision-maker fast, before the lateral movement finishes.

## Severity/Priority Default
**High** for any confirmed NTLM authentication using dumped/relayed material against a privileged account or a Tier 0 asset; **Medium** for an isolated NTLM logon anomaly pending validation; **Critical** if the account carries Domain Admin-equivalent rights (confirmed via 4672) or the target is a domain controller.

## MITRE ATT&CK Technique(s)
- T1550.002 — Use Alternate Authentication Material: Pass the Hash (primary mechanism once NTLM material is captured)
- T1110 — Brute Force (.001 Password Guessing, .003 Password Spraying) — NTLM validation is the classic surface for both, since it doesn't carry Kerberos's pre-auth lockout tuning in every environment
- T1078.002 — Valid Accounts: Domain Accounts (the account being used is legitimate; only the possession of it is not)
- T1021.002 — Remote Services: SMB/Windows Admin Shares (the usual delivery vehicle once an NTLM session is established — psexec-style tooling, admin shares, WMI)
- T1003.001 — OS Credential Dumping: LSASS Memory (upstream enabler — this is usually where the NTLM hash came from; treat as a related precursor incident, not part of this playbook's scope)

NTLM relay itself (forcing a victim host to authenticate to an attacker-controlled listener, e.g. via coerced authentication) is in scope for detection but has no dedicated technique ID in this handbook's reference set — describe it by name in case notes rather than tagging it.

## Trigger / Detection Logic Summary
**[ENGINEERING]** Three distinct patterns all fall under "NTLM abuse" and are worth separating in your rule logic rather than lumping into one alert:

1. **Unexpected NTLM where Kerberos should have happened.** A domain-joined, Kerberos-capable source host authenticating to a domain resource via `Authentication Package: NTLM` instead of Kerberos is the single strongest anomaly signal — it usually means either a relay/coercion chain forced the fallback, or a tool deliberately used NTLM to leverage a stolen hash (Kerberos can't be forged with just an NTLM hash the way NTLM sessions can be replayed).
2. **NTLM brute force / password spraying.** A burst of 4776 failures (`Error Code 0xC000006A`) against one or many accounts from a single source workstation, or 4625 with Logon Type 3 across many target accounts from one source IP in a short window — the NTLM equivalent of the 4771 pattern used for Kerberos pre-auth spray detection.
3. **Pass-the-hash lateral spread.** The same account producing successful `Authentication Package: NTLM`, Logon Type 3, 4624 events against multiple distinct destination hosts within a tight window, frequently paired with 4648 (explicit credentials) on the originating host and 4672 if the account is privileged.

## Required Log Sources & Event IDs
| Source | Event ID(s) | Purpose |
|---|---|---|
| Domain Controller Security log | 4776 | NTLM credential validation by the DC — Logon Account, Source Workstation, Error Code |
| Target host Security log | 4624 | Successful logon — Authentication Package, Logon Type, Source Network Address, Workstation Name |
| Target host Security log | 4625 | Failed logon — Status/Sub Status, Logon Type, Source Network Address (spray/brute force evidence) |
| Originating host Security log | 4648 | Explicit-credential logon — often precedes a pass-the-hash tool launching a session elsewhere |
| Target host Security log | 4672 | Special privileges assigned — flags whether the compromised account is admin-equivalent |
| Endpoint Security log | 4688 | Process creation — psexec/wmic/rundll32 invocations tied to the lateral hop |
| PowerShell Operational | 4103/4104 | Script block capture — Invoke-TheHash, Invoke-WMIExec, and similar PowerShell pass-the-hash tooling |
| Security log (originating account before dump) | 4738/4719 | Account tampering or audit policy changes covering tracks around the credential-theft window |

## Key Fields to Inspect
**[ANALYST]**
- **4624/4625 — Authentication Package**: `NTLM` where you'd expect `Kerberos` on an internal, domain-joined-to-domain-joined connection is the anomaly to chase first
- **4624/4625 — Logon Type**: `3` (network) is the expected type for both legitimate NTLM fallback and abuse — Type 2/10 in the same chain would suggest something else entirely
- **4624 — Workstation Name**: legitimate NTLM sessions usually populate a real NetBIOS name; blank, generic (`WORKSTATION`), or mismatched-versus-Source-Network-Address values are a relay/tooling tell
- **4624 — Source Network Address / Source Port**: cluster by source across destinations — one source hitting five hosts in two minutes is the lateral-spread signature
- **4776 — Source Workstation** vs. the real originating IP from network telemetry — relay chains frequently show a Source Workstation that doesn't match where the traffic actually came from
- **4776 — Error Code**: `0xC0000064` (unknown user) mixed with `0xC000006A` (bad password) across many account names from one source = spray; a wall of `0xC000006A` against one account = guessing
- **4648 — Account Whose Credentials Were Used** vs. **Subject**: mismatch confirms alternate/explicit credential use, a hallmark of pass-the-hash tooling
- **4672 — Privilege list**: confirms blast radius the moment the compromised account is admin-equivalent anywhere it lands

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| NTLM used by a printer, scanner, backup appliance, or non-domain-joined device that genuinely cannot do Kerberos | NTLM used by a fully domain-joined, Kerberos-capable workstation talking to a domain-joined server |
| One or two 4776 failures from a user who mistyped a password, followed by a success | Dozens of 4776 failures across many different account names from one Source Workstation in minutes |
| 4624 NTLM logons cluster around known legacy app servers and stay consistent day to day | The same account authenticating via NTLM to three, four, five *new* hosts within a short window |
| 4648 explicit-credential logons tied to known RunAs/service automation, same account pattern every day | 4648 immediately followed by 4624 NTLM logons to unrelated hosts, especially paired with 4688 for `psexec.exe`, `wmic.exe`, or unsigned remote-admin tooling |
| Workstation Name in 4624/4776 consistently matches the known hostname for that source IP | Workstation Name blank, spoofed, or inconsistent with the IP that generated the event |

## Investigation Steps
1. Pull all 4624/4625/4776 events where `Authentication Package = NTLM` for the account and time window in question; note Logon Type, Source Network Address, Source Port, and Workstation Name for each.
2. For any hit where the source host is known to be domain-joined and Kerberos-capable, check whether a corresponding 4768/4769 exists nearby — if Kerberos was skipped for no operational reason, escalate your suspicion of relay/coercion or deliberate NTLM abuse.
3. On the domain controller, compare 4776 Source Workstation against actual network-layer source data (firewall/NetFlow, VPN concentrator logs, proxy logs) — mismatches are the clearest relay indicator you'll get from Windows logs alone.
4. Check 4648 on the apparent originating host immediately prior to the NTLM logons — explicit-credential use there points to a local tool (Mimikatz pass-the-hash module, Invoke-TheHash, CrackMapExec/NetExec-style tooling) rather than a normal interactive session.
5. Run 4672 against the account to determine whether it carries admin-equivalent rights on any of the hosts touched — this decides whether you're looking at a contained nuisance or a Tier 0 exposure.
6. Pivot to endpoint telemetry (4688, 4103/4104) on the originating host for credential-dumping and lateral-movement tool markers — LSASS access attempts, `procdump`, `comsvcs.dll` MiniDump invocations, or PowerShell modules associated with hash-passing.
7. Map the full lateral graph: every distinct destination host that saw a successful NTLM 4624 from the account within the incident window is a confirmed hop, not a maybe — build the timeline in hop order.
8. Check whether this maps to a scheduled pentest/red-team window before treating it as real; also check 4719/1102 around the same time for anyone trying to blind or scrub the audit trail mid-attack.

## True Positive Indicators
- NTLM authentication where Kerberos was available and expected, with no legitimate explanation (relay, forced downgrade, deliberate hash-based tooling)
- One account producing successful NTLM logons against multiple new destination hosts within minutes, especially paired with 4648 on the source and 4688 for admin/lateral-movement tooling
- Workstation Name blank, spoofed, or inconsistent with actual network-layer source data in 4624/4776
- 4776 failure bursts across many distinct account names from a single Source Workstation (spray) or many failures against one account (guessing), outside any known password-rotation event
- Follow-on 4672 showing the compromised account is admin-equivalent on a newly touched host, or the target is a domain controller

## False Positive / Benign Positive Indicators
- Legacy printers, scanners, NAS appliances, or backup agents that are documented as NTLM-only and consistently show the same source/destination pattern day over day
- Cross-forest or cross-domain access where Kerberos trust isn't configured and NTLM fallback is the designed behavior
- A genuine user password change or account lockout/unlock cycle producing a short burst of 4776 failures followed by a clean success — check timing against helpdesk tickets before assuming spray
- Application pools or service accounts intentionally configured for NTLM due to a vendor limitation — should already be documented in your NTLM baseline/allow-list; if it isn't, this is a hygiene finding to open separately, not necessarily an incident
- Approved penetration test or red team engagement with signed rules of engagement covering the observed window and source IP

## Escalation Criteria
Escalate to Tier 2/IR immediately if: the account touched by NTLM logons is confirmed admin-equivalent (4672) on any destination; the target of a successful NTLM logon is a domain controller or other Tier 0 asset; endpoint evidence confirms credential-dumping or pass-the-hash tooling (Mimikatz, Invoke-TheHash, NetExec/CrackMapExec-style activity) on the originating host; or a 4776/4776-adjacent Source Workstation mismatch indicates an active relay chain still in progress. Treat lateral spread across three or more distinct destination hosts within a short window as active credential-theft-in-progress, not a hygiene finding.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Immediate (Analyst/Tier 2, no approval needed)**: Isolate the originating host from the network if credential-dumping tooling is confirmed; disable network logon (deny "Access this computer from the network") for the compromised account on affected hosts pending review.
- **Force password reset on the compromised account** — invalidates the stolen NTLM hash; requires Identity/AD team approval and coordination if the account underpins production services or automation.
- **Restrict/disable NTLM via GPO** ("Network security: Restrict NTLM" settings, or full NTLM disablement on a segment) — architectural change, requires AD Engineering + Change Advisory Board sign-off; test against the legacy-device inventory first, this is where outages happen if you move too fast.
- **Revoke active sessions / force logoff** on hosts touched during the lateral-spread window — coordinate with server owners to avoid interrupting production workloads mid-transaction.
- SLA: containment decision on privileged-account NTLM abuse within 1 hour of confirmed detection; password rotation completed within 4 hours for Tier 0/1 accounts; NTLM restriction policy changes tracked as a project with a documented compatibility test, not an emergency change, unless active exploitation is confirmed.

## Example Query (Microsoft Sentinel — KQL)
```kql
SecurityEvent
| where EventID == 4624 and AuthenticationPackageName == "NTLM" and LogonType == 3
| where TargetUserName !endswith "$"
| summarize DestHosts = dcount(Computer), Hosts = make_set(Computer)
    by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where DestHosts >= 3
| order by DestHosts desc
```

## Closure Criteria
Close as **True Positive - Contained** once the originating host is isolated/remediated, the compromised account's password is rotated, no further NTLM logons from that account appear across a 24-hour watch period, and any downstream systems touched during the lateral-spread window have been checked for persistence. Close as **Benign Positive** when the pattern maps to a documented legacy device, cross-domain trust behavior, or approved pentest with matching source IP and engagement window. Close as **Insufficient Evidence** when the originating host can't be identified (common with relay chains behind NAT or when upstream network telemetry has already rolled off retention), but log the exposed NTLM usage as a standing hardening finding regardless of verdict.

**Example case note:** *"4624 NTLM/Type3 logons for acct dthompson observed against FILESRV02, SQLPROD01, and DC01 (10.10.5.10, 10.10.5.22, 10.10.1.5) within a 6-minute window, Workstation Name blank on all three — inconsistent with known hostname WKS-DT-114 for source IP 10.10.40.87. 4648 on WKS-DT-114 at 09:14:02 shows explicit-credential use immediately prior. 4688 confirms wmic.exe invocation at 09:14:05. 4672 confirms dthompson carries local admin on SQLPROD01 only, not domain admin. WKS-DT-114 isolated 09:41, password rotated 09:52, no further NTLM logons in 24h watch. Closed True Positive - Contained; NTLM restriction GPO review opened as JIRA AD-1204."*
