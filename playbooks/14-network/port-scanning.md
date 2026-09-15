# Port Scanning

## Playbook ID & Name
**NW-001 — Network Port Scanning (Host/Service Discovery, Pre-Exploitation Recon)**

## Business Risk
**[STAKEHOLDER]** - Port scanning is almost never damaging by itself, but it is the doorbell ring before someone tries the handle. Left uninvestigated, a scan that finds an exposed RDP or database port on a production host turns into an intrusion within hours. The real cost here is triage time at scale — most orgs see this alert fire dozens of times a day — so the risk we're managing is analyst fatigue burying the one scan that actually matters.

## Severity / Priority Default
**Low** for a single scan blocked at the perimeter with no successful connections. **Medium** for scans that reach live hosts or return open-port responses. **High** when the source is internal (possible compromised host doing lateral recon) or the target is a Tier-0 asset (domain controller, PCI segment, jump host).

## MITRE ATT&CK Technique(s)
- **T1595 Active Scanning** — external actor probing your perimeter before engagement.
- **T1046 Network Service Discovery** — internal-facing version, typically post-compromise, used to map reachable services/subnets from a foothold.

If the scan is followed by a login attempt against a discovered service, that activity belongs to a separate playbook (see T1110 Brute Force or T1021 Remote Services) — note the pivot here, don't re-litigate it in this one.

## Trigger / Detection Logic Summary
Alert fires when a single source IP generates connection attempts to an unusual number of distinct destination ports and/or destination hosts within a short time window, disproportionate to the responses received (mostly RST, ICMP unreachable, or no response — i.e., low "success ratio"). Two shapes matter:
- **Vertical scan** — one destination host, many ports (port sweep).
- **Horizontal scan** — one destination port, many hosts (service sweep, e.g., "who has 3389 open").

## Required Log Sources & Event IDs
| Source | What it gives you |
|---|---|
| Perimeter firewall (Palo Alto/Fortinet/Cisco ASA) traffic/deny logs | Source/dest IP, port, action (allow/deny), session count |
| IDS/IPS (Suricata/Snort) | Signature hits, e.g. ET SCAN / ET POLICY categories |
| NetFlow / Zeek `conn.log` | Connection tuples, duration, bytes, flags — best for ratio math |
| Windows Filtering Platform (host firewall) | Event ID **5156** (connection permitted), Event ID **5157** (connection blocked) — useful when the scan reaches internal hosts |
| Sysmon | Event ID **3** (Network connection) — confirms if an internal host is the *source* of the scan (compromised endpoint) |
| Cloud VPC/NSG flow logs (AWS VPC Flow Logs, Azure NSG Flow Logs) | Same tuple-level data for cloud-hosted assets |

## Key Fields to Inspect
**[ANALYST]**
- Source IP, source ASN/geo, and whether it's on any allowlist for authorized scanning (Qualys, Tenable, Rapid7 ranges, pentest scope doc).
- Distinct destination port count and distinct destination host count per source, per time window.
- TCP flags — SYN-only floods vs. completed handshakes (SYN/ACK/ACK) tell you whether anything actually opened.
- Response distribution: ratio of RST/no-response vs. successful connect. A near-100% RST ratio is classic scan noise; a handful of successful connects mixed in is the part you chase.
- Bytes transferred and session duration — legitimate scans (and real recon) are near-zero-byte, sub-second sessions. Anything with payload after the "scan" phase is no longer a scan, it's the next stage.
- If source is internal: hostname, logged-on user, EDR process tree around the timestamp (what spawned the connections — PowerShell, a scanner binary, a scripted loop).

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Known vuln-scanner IP, matches scheduled scan window in change calendar | Unrecognized external IP, no scheduled activity, sequential/incrementing port order |
| Cloud load-balancer or uptime-monitor health checks on 1-2 known ports | Wide port range (1-1024 or full 65535) hit in seconds/minutes |
| Internal asset-inventory tool (Lansweeper, SCCM) sweeping subnets on a cron | Internal host with no scanning function suddenly enumerating peer subnets |
| Printer/IoT broadcast chatter misclassified by IDS | Scan immediately followed by a connect-and-hold session to a discovered open port |

## Investigation Steps
1. Pull the source IP and check it against the approved-scanner allowlist and the vulnerability-management scan calendar first — this closes a large fraction of these tickets in under two minutes.
2. Classify the scan shape: vertical (one host, many ports) or horizontal (one port, many hosts), and get the exact port list/range and target list from firewall or Zeek logs.
3. Check the response ratio — did anything come back SYN/ACK? Cross-reference against your asset inventory to see if any of the "hit" ports correspond to services that should not be internet- or subnet-reachable.
4. Confirm perimeter disposition: was the traffic blocked/dropped at the firewall, or did it reach the host (Event ID 5156/permitted, or Sysmon Event ID 3 on the target)?
5. If external source: run threat-intel/reputation lookup (known scanner infra like Shodan/Censys/Shadowserver vs. known-malicious infrastructure). Check for prior sightings of this IP in your SIEM.
6. If internal source: identify the host and logged-on user, pull EDR process history for what initiated the connections, and check for concurrent alerts (credential dumping, new scheduled tasks, C2-style outbound traffic) that would indicate the host itself is compromised and doing recon rather than a legitimate tool running.
7. Check for a temporal follow-on — did the scan get chained into an exploit attempt, login attempt, or lateral movement session against a discovered open port within the following minutes/hours?
8. Document scope, disposition, and whether any exposed service needs a firewall-rule/ACL fix regardless of intent (a scan that finds an open port you didn't know about is a finding even if the scanner was benign).

## True Positive Indicators
- External IP with no scan authorization, sequential port order, wide port range, hitting internet-facing production assets.
- Internal host (not an inventory/vuln tool) enumerating other subnets — strong lateral-movement/recon signal, treat as likely compromise.
- Scan source correlates with known-malicious infrastructure in threat intel.
- Scan immediately followed by an exploit attempt, login attempt, or successful data-bearing connection to a discovered port.
- Distributed scan — same target hit from many rotating source IPs in a short window (recon-as-a-service / botnet scanning).

## False Positive / Benign Positive Indicators
- Source IP matches an approved vulnerability scanner and falls inside the scheduled window (Benign Positive — confirm and close, don't just suppress silently).
- Cloud health-check or load-balancer probing (single/few ports, regular interval, always from provider's known ranges).
- Internal CMDB/asset-discovery tool with documented schedule.
- Duplicate alerts from log-forwarding misconfiguration (same scan logged twice by two collectors) — an ingestion/parsing issue, not a security event; flag to engineering separately.
- Authorized pentest or bug-bounty activity within an active scope agreement.

## Escalation Criteria
Escalate to Tier 2/IR when: the scan reaches a Tier-0 or PCI-scoped asset; source is internal and not tied to a known tool; scan is followed by any successful authentication or exploit attempt against the discovered port; source IP matches known threat-actor infrastructure; or the same target is scanned by more than a handful of distinct rotating IPs (distributed recon), which usually means the target itself is now interesting to someone.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Block source IP/CIDR at perimeter firewall** — Tier 1 can action directly under standing SOP when source is external and no legitimate business tie is found; no ticket approval needed for this narrow action.
- **Isolate internal host** — requires IR lead approval; treat as a suspected-compromise workflow, not a routine scan closure.
- **Geo-block / rate-limit for distributed scanning** — requires network engineering plus a change ticket; not a unilateral SOC action.
- **Allowlist a confirmed benign scanner** — requires SOC lead sign-off before modifying the detection rule, and must be logged in the exceptions register with a review date (don't let allowlists become permanent and unreviewed).
- **Firewall-rule/ACL fix for an unexpectedly open port** — owned by the asset/network team; SOC opens the finding, doesn't close the underlying exposure itself.

## Example Query (Splunk SPL — firewall/Zeek index)
```spl
index=firewall OR index=zeek_conn earliest=-1h
| stats dc(dest_port) as ports_hit dc(dest_ip) as hosts_hit
        count as attempts values(action) as actions by src_ip
| where ports_hit > 15 OR hosts_hit > 15
| sort - ports_hit
```

## Closure Criteria
Close as **True Positive** only after confirming scope (which hosts/ports), disposition (blocked vs. reached), and whether any follow-on exploitation occurred; open a separate exposure ticket if an unexpected open port was found regardless of scanner intent. Close as **Benign Positive** when the source is verified as an authorized scanner/tool within its schedule. Close as **Insufficient Evidence** when firewall retention has already rolled the relevant flow logs and the source can't be attributed with confidence — note the log-gap explicitly rather than defaulting to benign.

**Example case note:** *"Vertical scan, 412 distinct ports, src 203.0.113.44 (no ASN match to approved scanner list) against web01.example.com (10.20.4.15) over 90s, 100% RST — no successful connects, blocked at perimeter FW rule DENY-INBOUND-DEFAULT. No follow-on activity in 24h window. Closed Benign Positive — pending: added 203.0.113.44 to watchlist for repeat activity."*
