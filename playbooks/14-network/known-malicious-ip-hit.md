# Known Malicious IP Hit

## Playbook ID & Name
**NW-009 — Known Malicious IP Hit (Network Category)**

## Business Risk
**[STAKEHOLDER]** - A device on our network talked to (or was probed by) an IP address already confirmed bad by threat intelligence — this is one of the cheapest, highest-confidence detections we have, and it's often the earliest external signal that something else has already gone wrong. Ignoring it risks letting a C2 channel, data exfiltration path, or active exploitation attempt run unchecked; the business decision here is usually "block now, investigate after" rather than the reverse.

## Severity/Priority Default
**Medium**, auto-escalating to **High** if the internal party is a server, domain controller, privileged workstation, or the connection direction is outbound-with-data (beacon/exfil pattern) rather than a blocked inbound probe. Confirmed C2 callback from a production asset = **Critical**.

**Related Playbook:** See Playbook NW-010 (Known Malicious Domain Hit) for the same threat-intel-match workflow keyed on domain rather than IP indicators — the two commonly fire together on the same connection attempt.

## MITRE ATT&CK Techniques
- **Inbound direction** (external IP → our asset): T1595 Active Scanning, T1190 Exploit Public-Facing Application, T1046 Network Service Discovery
- **Outbound direction** (our asset → external IP): T1071.004 Application Layer Protocol: DNS, T1090 Proxy, T1572 Protocol Tunneling, T1105 Ingress Tool Transfer, T1567 Exfiltration Over Web Service, T1048 Exfiltration Over Alternative Protocol

## Trigger / Detection Logic Summary
Fires when a network flow (firewall, proxy, DNS resolution, NDR sensor, or cloud VPC flow log) contains a source or destination IP matching a threat intelligence indicator with a "malicious" or "high confidence" verdict — commercial TI feed, CISA/US-CERT indicator sharing, internal IOC list from a prior incident, or a TOR exit node / known botnet C2 list. The SIEM correlates the raw flow against the TI feed table on ingest; this is a lookup-match alert, not a behavioral one, so the entire investigation hinges on figuring out *why* the match happened and what actually crossed the wire.

## Required Log Sources & Event IDs
No single vendor exposes this as a numbered Windows/Sysmon Event ID — it's a flow-level match, so pull from:
- Firewall / NGFW allow-deny logs (Palo Alto, Fortinet, Check Point, etc.)
- Proxy / Secure Web Gateway logs (if outbound HTTP/HTTPS)
- DNS resolver / recursive DNS logs (query → resolved IP)
- NetFlow/IPFIX or cloud VPC flow logs (AWS VPC Flow Logs, Azure NSG Flow Logs)
- IDS/IPS signature alerts (Suricata/Snort) correlated to the same flow
- EDR process-to-network telemetry on the internal host, to tie the flow to a specific process
- Threat Intel Platform (TIP) match/enrichment log — records which feed, confidence score, and indicator age triggered the alert

## Key Fields to Inspect
**[ANALYST]**

| Field | Why it matters |
|---|---|
| `src_ip` / `dst_ip` | Confirm which side is the malicious indicator and which is ours |
| `direction` | Inbound-blocked vs outbound-allowed changes the whole risk calculus |
| `action` (allow/deny) | If the firewall already blocked it, this is containment evidence, not a live incident |
| `dest_port`, `protocol` | Port 443/80 outbound looks like normal web traffic; odd ports (4444, 8081, high ephemeral) raise suspicion |
| `bytes_sent` / `bytes_received` | Large outbound byte count = possible exfil; near-zero on a "connection" = likely scan/probe |
| `dns_query` + `resolved_ip` | Was the malicious IP reached via a hardcoded IP or a resolved domain? Domain-based hits point to a specific delivery/C2 method |
| `process_name`, `parent_process`, `cmdline` (EDR) | Identifies what on the host initiated the connection — browser, scheduled task, PowerShell, unknown binary |
| TI feed name, indicator first-seen/last-seen, confidence score | An indicator that's 18 months old and low-confidence is treated very differently than a fresh, high-confidence hit tied to active campaign reporting |
| Recurrence count for this src/dst pair | One-off vs beaconing at a regular interval |

## Normal vs Suspicious Pattern
**Normal / expected**: a single inbound connection attempt from a scanning IP that the firewall denied by default policy (background internet noise — this happens constantly and rarely warrants more than a log note); a proxy log showing a user briefly hit a domain that was *later* added to a feed after the fact (indicator lagging behind actual risk); shared-hosting IPs where the malicious flag belongs to a different tenant on the same address.

**Suspicious**: outbound traffic *allowed* by the firewall to a high-confidence C2 indicator, especially with regular time-interval beaconing, non-browser process ownership, or DNS queries to a domain resolving to the flagged IP right before the connection; any inbound hit that got a `200 OK`/successful response from an internet-facing app rather than a clean deny.

## Investigation Steps
1. Confirm direction and firewall action first — inbound-denied hits are lower priority than outbound-allowed ones.
2. Pull the TI enrichment record: feed source, confidence score, indicator category (C2, scanner, TOR, botnet, phishing host), and first/last-seen dates.
3. Identify the internal asset (hostname, owner, business function) and pull EDR telemetry to find the initiating process and parent chain.
4. Check DNS logs for any query that resolved to the flagged IP in the preceding 15–30 minutes — this tells you if it was domain-driven or hardcoded-IP driven.
5. Review flow volume and timing across the retention window — look for beaconing intervals or a large one-time upload (exfil pattern).
6. Check the asset's recent history for related alerts (AV/EDR detections, phishing click, prior scheduled-task or PowerShell activity) that could explain how it reached that IP.
7. If outbound and allowed, isolate the host or block the destination at the firewall/proxy pending verdict, per approval matrix below.
8. Search environment-wide for other hosts contacting the same indicator, to size the scope before closing.

## True Positive Indicators
- Outbound connection allowed to a high-confidence, recently-active C2 or malware-distribution indicator
- Beaconing pattern (regular interval, consistent payload size) to the flagged IP
- Non-browser process (script host, unsigned binary, admin tool) driving the connection
- DNS resolution to the flagged IP immediately preceding the flow, tied to a phishing click or suspicious document execution

## False Positive / Benign Positive Indicators
- Inbound connection already denied by default-deny firewall policy, single occurrence, no response sent
- Indicator flagged for shared/CDN infrastructure (cloud provider IP ranges reused across many tenants)
- Stale indicator (feed last-seen well over a year old, no corroborating telemetry)
- Legitimate business traffic to a domain that shares infrastructure with a flagged IP but resolves independently now (re-verify current DNS resolution — indicators drift)

## Escalation Criteria
Escalate to Tier 2 / IR if: traffic was allowed (not denied) and outbound; the asset is a server, domain controller, or privileged endpoint; beaconing is confirmed; data volume outbound exceeds baseline; or the same indicator is contacted by more than one host (lateral spread or shared compromise). Escalate to IR lead immediately if C2 tooling or ransomware staging is suspected (T1486, T1490 downstream risk).

## Containment Options & Approval Authority
**[MANAGEMENT]**

| Action | Approval Authority | SLA |
|---|---|---|
| Block destination IP/domain at firewall/proxy | SOC Analyst (Tier 1), auto-approved for high-confidence feeds | Immediate |
| Isolate host via EDR | Tier 2 Analyst / Shift Lead | Within 15 min of TP confirmation |
| Disable user account (if credential compromise suspected) | IR Lead + IT Ops | Within 30 min |
| Firewall rule rollback if benign business impact | Network Engineering + SOC Manager sign-off | Same business day |

## Example Query
```kusto
let MaliciousIPs = ThreatIntelligenceIndicator
    | where Active == true
    | project NetworkIP;
CommonSecurityLog
| where DeviceAction == "allow"
| where DestinationIP in (MaliciousIPs)
   or SourceIP in (MaliciousIPs)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          SentBytes, ReceivedBytes, DeviceAction
| order by TimeGenerated desc
```

## Closure Criteria
Close as **True Positive** once the indicator, initiating process, and disposition (blocked/isolated) are documented and scope is confirmed contained. Close as **Benign Positive** when the flow was denied by policy with no data exchanged and no follow-on activity. Close as **Insufficient Evidence** if flow logs expired before enrichment completed (retention gap) and no corroborating host telemetry exists.

**Example case-note line:**
`2026-09-15 03:41 UTC — WKS-FIN-042 (10.20.14.53) made outbound TLS connection to 203.0.113.77:443 (TI: high-confidence C2, last-seen 2026-09-10), allowed by FW rule OUT-WEB-01; EDR shows powershell.exe (parent: winword.exe) as initiator following a phishing attachment open at 03:38 UTC. Host isolated 03:52 UTC, IOC blocked network-wide, account disabled pending forensic triage. Classified True Positive — initial access via T1566.001, C2 via T1071.004/T1090.`
