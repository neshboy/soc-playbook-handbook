# Internal Network Reconnaissance

## Playbook ID & Name
**NW-002 — Internal Network Reconnaissance (Post-Foothold Discovery Activity)**

This playbook covers discovery-phase behavior observed *after* an actor already has a foothold inside the network — a workstation, a service account, a VPN session — and is now mapping hosts, shares, accounts, groups and trust relationships before deciding where to move next. It is distinct from external-facing scanning against internet-exposed assets; the signal here is internal, lateral, and usually the first concrete evidence that "just a phishing click" turned into "someone is inside and looking around."

## Business Risk
**[STAKEHOLDER]** - Reconnaissance is the planning stage of an intrusion, not the damage stage — but it's the cheapest point to stop it. An attacker enumerating file shares, domain admins, and trust relationships from a marketing laptop is telling you exactly where they intend to go next (finance shares, domain controllers, the acquired subsidiary's domain). Catching this early is the difference between an incident report and a ransomware notification to the board. The business cost of ignoring it is measured in what comes two to five days later, not on the day itself.

## Severity/Priority Default
**Medium**, escalating to **High** if recon activity originates from a server, a privileged account, or targets domain controllers / identity infrastructure directly. Escalate to **Critical** if recon is immediately followed by credential access or lateral movement attempts.

## MITRE ATT&CK Techniques
- T1595 Active Scanning (when the internal segment itself is being probed like external infrastructure — VLAN sweeps, exposed management interfaces)
- T1046 Network Service Discovery (port/service sweeps against internal hosts)
- T1087 Account Discovery (local and domain account enumeration)
- T1069 Permission Groups Discovery (group membership, privileged group enumeration)
- T1482 Domain Trust Discovery (trust enumeration, cross-domain/cross-forest mapping)
- T1021.002 SMB/Windows Admin Shares (frequently the immediate follow-on once shares are mapped)
- T1071.004 Application Layer Protocol: DNS (when recon is conducted via bulk internal DNS queries/zone-style enumeration rather than direct host probing)

## Trigger / Detection Logic Summary
Alert fires on a statistically abnormal volume or breadth of discovery-oriented activity from a single host/identity within a short window: a spike in distinct internal destination IPs/ports contacted, a burst of LDAP queries against unusual attributes, execution of known recon tooling or built-in discovery commands (`net view`, `net group`, `nltest`, `Get-ADUser`, `ipconfig /all` chained with `arp -a`), or SMB session/tree-connect activity against an abnormally high number of distinct hosts. Detection is almost always a correlation rule (count of distinct destinations over time), not a single event.

## Required Log Sources & Event IDs
| Source | Event ID / Field | Purpose |
|---|---|---|
| Windows Security (domain controllers) | 4768 (TGT request), 4769 (Service ticket request), 4776 (NTLM validation) | Bulk/unusual ticket requests suggesting account enumeration or SPN sweeps |
| Windows Security (workstations/servers) | 4624 (Logon), 4625 (Failed logon), 4648 (Explicit credential logon) | Repeated logon attempts across many hosts from one source |
| Windows Security (file servers/DCs) | 5140 (Network share accessed), 5145 (Detailed share access check) | SMB share enumeration breadth |
| Sysmon | Event ID 1 (Process creation), Event ID 3 (Network connection) | Recon command-line execution, outbound connection fan-out |
| Sysmon / DNS logs | Event ID 22 (DNS query) | Bulk internal DNS lookups, SRV record enumeration for domain mapping |
| Firewall / NetFlow / Zeek | conn logs, flow records | Port sweep pattern, distinct-destination fan-out, unusual protocol mix |
| LDAP / AD audit | Directory Service Access logs | Enumeration of privileged groups, trust objects, SPNs |

## Key Fields to Inspect
**[ANALYST]**
- Source host, logged-on user (SID and UPN — not just the friendly name), and process lineage (parent → child)
- `CommandLine` for the executing process — look for `net view`, `net group "Domain Admins" /domain`, `nltest /domain_trusts`, `Get-ADGroupMember`, `dsquery`, or third-party tools (nmap, masscan, SoftPerfect, AngryIP, BloodHound/SharpHound signatures)
- Count of **distinct destination IPs** and **distinct destination ports** per source host per time window (this is the single most useful derived field for this playbook)
- SMB `TreeName` / share paths accessed — recon usually touches many shares briefly rather than one share deeply
- Kerberos `TicketOptions` and `ServiceName` fields for signs of SPN enumeration ahead of Kerberoasting
- DNS query names — sequential or dictionary-style hostname lookups, SRV record queries for `_ldap._tcp` or `_kerberos._tcp`
- Time-of-day relative to the account's established baseline

## Normal vs Suspicious Pattern
Normal: helpdesk and sysadmin accounts routinely run `net view`, ping sweeps, or vulnerability scanners (Nessus/Qualys) from known, documented source hosts on a schedule the SOC has on file. IT asset-discovery tools also generate broad internal scanning traffic — but from a small, static, whitelisted set of hosts.
Suspicious: the same behavior originates from a standard end-user workstation, a service account with no administrative charter, or a host that has no scheduled-scan record; breadth is wide (dozens to hundreds of hosts) and fast (minutes, not hours); it's paired with process names or command lines inconsistent with any approved tool; or discovery activity precedes a credential-access or lateral-movement technique from the same source within the same session.

## Investigation Steps
1. Identify the source host and the authenticated identity (interactive user vs. service account vs. scheduled task context) at the time of the activity.
2. Pull the full process tree around the flagged event — what spawned the recon command, and what did the recon command spawn afterward.
3. Quantify the scan: distinct destination IPs, ports, and protocols touched in the window, and compare against that host's own 30-day baseline.
4. Check whether the source host or account is on the SOC's approved-scanner/asset-management whitelist (Nessus, Qualys, ServiceNow Discovery, SCCM, etc.) with a matching schedule.
5. Cross-reference against the initial-access timeline for that host — was there a recent phishing click, suspicious login, or new scheduled task/service creation preceding this?
6. Check the destinations targeted — is the actor hitting a broad/random sweep, or specifically domain controllers, backup servers, and privileged-account infrastructure (a much stronger TP indicator)?
7. Review DNS and LDAP query logs from the same host for domain trust or privileged-group enumeration in the same window.
8. If any credential-access or lateral-movement indicator is found downstream, immediately pivot to the relevant credential-access or lateral-movement playbook and treat this as a linked, ongoing incident rather than a standalone alert.

## True Positive Indicators
- Recon tooling (nmap, SharpHound, AD Recon scripts) executed from a non-administrative host or user context
- Enumeration specifically targeting domain controllers, Tier-0 assets, or privileged groups (Domain Admins, Enterprise Admins)
- Recon immediately followed by authentication attempts against newly discovered hosts, or by T1021.002 SMB session activity against multiple targets
- Source host/account has no scan authorization on record and no legitimate administrative function
- Obfuscated or LOLBin-wrapped discovery commands (encoded PowerShell running `Get-ADUser`/`Get-ADGroupMember` variants)

## False Positive / Benign Positive Indicators
- Source matches an approved vulnerability-scanning or asset-discovery platform with a documented schedule
- IT/helpdesk staff performing legitimate troubleshooting (`net view` to check a colleague's shared printer, a single `ping` sweep during a subnet migration)
- Newly onboarded monitoring/EDR agent performing an initial network-topology baseline sweep
- Change-window activity tied to a documented migration, decommission, or DR test — verify against the change calendar before closing as benign

## Escalation Criteria
Escalate immediately to Incident Response if: recon targets identity infrastructure (domain controllers, PKI, PAM/vault) directly; the source account has privileged group membership; recon is followed within the same session by credential dumping, Kerberoasting-style ticket requests, or new lateral connections; or the activity spans multiple subnets/sites suggesting a compromised jump host rather than a single workstation.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- Network isolation of the source host (EDR network-containment or switch port shutdown) — Tier 1/2 analyst authority under standing SOC containment policy for confirmed unauthorized recon.
- Disable/force password reset on the associated account if it is not a known service account tied to production automation — requires IAM or on-call engineering sign-off to avoid breaking dependent jobs.
- Temporary suspension of a compromised service account's Kerberos/NTLM rights — requires AD team approval given blast-radius risk.
- Broader segmentation changes (VLAN ACL tightening, firewall rule deployment) — Network Engineering owns execution; SOC provides justification and scope; Change Management approval required outside of active-incident emergency change process.

## Example Query (Microsoft Sentinel — KQL)
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemotePort in (22,23,80,135,139,389,445,3389,5985)
| summarize DistinctHosts = dcount(RemoteIP), DistinctPorts = dcount(RemotePort)
    by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where DistinctHosts > 25 and DistinctPorts > 3
| sort by DistinctHosts desc
```

## Closure Criteria
Close as **True Positive** once the source host is contained and credential/lateral-movement follow-through is ruled in or handed to IR with a documented linked-incident reference. Close as **Benign Positive** when the source is confirmed on the approved-scanner whitelist with a matching schedule. Close as **Expected Activity** when tied to a documented change/migration window. Close as **Insufficient Evidence** when logs are incomplete (e.g., NetFlow retention already rolled over, workstation Sysmon not yet deployed) and no corroborating telemetry exists — do not force a verdict just to clear the queue.

**Example case-note line:** *"WKS-MKT-118 (user jsalinas) generated SMB tree-connects to 47 distinct hosts and ran `net group \"Domain Admins\" /domain` at 14:22 UTC; no scanner whitelist match, no change record; host isolated via EDR, account disabled pending IAM review, escalated to IR as linked precursor to case INC-20260915-0091."*
