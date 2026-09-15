# NW-018 – RDP Scanning (Network Reconnaissance)

## Business Risk
**[STAKEHOLDER]** - RDP is one of the most common initial-access vectors for ransomware crews and opportunistic criminals; when someone is scanning your address space for open port 3389, that's the reconnaissance step that precedes a brute-force or exploit attempt against a Remote Desktop endpoint. It matters because it's an early, cheap warning signal - catching it here is far cheaper than catching the intrusion three steps later. Decisions about blocking scan sources and about whether RDP should be internet-facing at all sit with the network/infrastructure owner, not the SOC alone.

## Severity / Priority Default
**Low-Medium** for a bare scan with no follow-on authentication activity. Escalates to **High** immediately if the scan is followed by successful or high-volume failed logons against the scanned host(s), or if the source is internal (i.e., a host on your own network is doing the scanning).

## MITRE ATT&CK Mapping
- **T1595** Active Scanning - external internet-wide or targeted scanning of the org's public IP ranges for open RDP.
- **T1046** Network Service Discovery - internal/lateral scanning, usually from an already-compromised host mapping RDP-listening peers.
- **T1021.001** Remote Services: RDP - if the scan transitions into actual connection/logon attempts.
- **T1110** Brute Force (.001 Password Guessing, .003 Password Spraying) - the near-certain next step if the scan finds an open listener; treat as the linked follow-on playbook.

## Trigger / Detection Logic Summary
Alert fires when a single source IP touches TCP/3389 (or an RDP-aliased port) against an unusual number of distinct destination IPs within a short window (horizontal scan), or against a single host across a wide port range that includes 3389 (vertical scan / general service sweep). Also fires on IDS/IPS signature hits for RDP cookie/negotiation probes, and on repeated TCP resets or half-open connections concentrated on 3389 from one source.

## Required Log Sources & Event IDs
| Source | What it gives you |
|---|---|
| Perimeter firewall / NGFW session logs | src/dst IP, dst port, action (allow/deny), bytes, session count |
| NetFlow / IPFIX | volumetric confirmation of fan-out pattern |
| IDS/IPS (Snort/Suricata-class) | signature hits for RDP scanning/enumeration tools |
| Windows Security Event Log | 4625 (failed logon), 4624 (successful logon, Logon Type 10 = RemoteInteractive), 4648 (explicit credential use), 4776 (NTLM validation) on the targeted host(s) |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | connection/NLA negotiation attempts on the RDP listener itself |
| EDR network telemetry | outbound connection attempts if the scan source is an internal endpoint |
| Threat intel feed | reputation on the source IP/ASN (known scanner infra vs. hostile) |

## Key Fields to Inspect
**[ANALYST]** - src_ip, dst_ip (and count of distinct dst_ip values), dst_port, protocol flags (SYN-only vs full TCP handshake vs completed RDP X.224 negotiation), timestamp density (bursty vs. steady drip), geo/ASN of source, and - critically - whether any 4625/4624 events exist on the target host in the same window with a matching source IP. A scan with zero logon attempts behind it is a very different animal from a scan that walks straight into 4625 spam.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Scheduled vuln scanner (Qualys/Nessus/Rapid7) hitting known IP ranges on a known cadence, from a known internal scanner subnet | Unrecognized source IP, external ASN, hitting 3389 across dozens/hundreds of destinations in minutes |
| Single host, single port check from monitoring tooling (uptime/health checks) | Sequential IP sweep pattern (10.20.0.1, .2, .3...) suggesting automated tooling, not a human |
| Scan source pre-approved in the scanning-schedule allowlist | Scan immediately followed by 4625 bursts or a successful 4624 Logon Type 10 |
| Internal asset discovery tool with a documented change ticket | Scan originating from a workstation/server that has no business doing network scanning (possible pivot host) |

## Investigation Steps
1. Identify the source IP(s), whether external (internet-facing) or internal, the count/list of destination IPs and ports touched, and the time window.
2. Check firewall/IDS logs for the connection depth - was this SYN-only (basic port sweep, e.g., masscan/nmap) or did it complete RDP protocol negotiation (banner grab, more deliberate targeting)?
3. Cross-reference targeted hosts against the asset inventory - is 3389 supposed to be reachable from that source at all? A scan hitting a host that shouldn't have RDP exposed is itself a finding, independent of the scanner's intent.
4. Pull 4625/4624/4648 logs for the targeted host(s) in the same window to see if the scan escalated into actual authentication attempts.
5. If the source is internal, treat the host as potentially compromised - pull EDR process history, scheduled tasks, and other outbound connections before assuming it's "just IT running a scan."
6. Check the source IP/ASN against threat intel and against your own scanning-schedule allowlist (Qualys/Nessus ranges, pentest windows).
7. Confirm exposure duration and NLA/patch status of any targeted host that answered on 3389 - this feeds the remediation conversation even if the scan itself closes benign.
8. Decide and document: block, allowlist, or escalate to the brute-force/exploit playbook if evidence progresses past pure reconnaissance.

## True Positive Indicators
- Sequential or randomized sweep across many destination IPs on 3389 from a single unrecognized source.
- Completed RDP negotiation frames (not just SYN) indicating a fingerprinting tool rather than a stray packet.
- Source IP matches known scanning infrastructure with a history of follow-on brute-force campaigns, or is not on any approved scanner list.
- Immediate pivot into 4625 bursts or a 4624 Logon Type 10 success against a scanned host.

## False Positive / Benign Positive Indicators
- Source matches an approved internal vulnerability scanner subnet and a documented scan schedule/change ticket.
- Source is an authorized pentest engagement with signed rules of engagement covering the window.
- Monitoring/uptime tooling (e.g., PRTG-style checks) performing a single connect-and-close per host, no fan-out.
- Internal network mapping tool run by IT with a change record - benign but should still trigger a "why is 3389 reachable from here" follow-up.

## Escalation Criteria
Escalate to Tier 2 / IR immediately if: the scan is followed by a successful RDP logon from the same source; the source is internal (possible pivot from an already-compromised host - this overlaps with T1046); the targeted host is a domain controller, jump box, or other crown-jewel asset; or the source IP correlates with known ransomware-affiliate infrastructure in threat intel.

## Containment Options & Approval Authority
**[MANAGEMENT]** - Short-term perimeter block of the source IP/ASN at the firewall can be executed by the on-shift SOC analyst under standing authority. Geo-blocking or disabling public-facing RDP entirely (moving behind VPN/RDP Gateway with NLA and MFA) requires sign-off from Network Engineering, and typically goes through Change Management given the operational impact. Isolating an internal host suspected of being the scan source (EDR network containment) requires IR-lead approval per standard containment SLA (target: initiate within 30 minutes of confirmed internal-source scanning). Any permanent ACL/firewall rule change goes through the normal CAB process; track MTTD/MTTR for these events monthly and review the scanning-schedule allowlist quarterly so it doesn't silently rot.

## Example Query (Splunk SPL)
```spl
index=firewall dest_port=3389
| bin _time span=5m
| stats dc(dest_ip) as unique_targets, values(action) as actions, min(_time) as first_seen, max(_time) as last_seen by src_ip, _time
| where unique_targets > 15
| sort -unique_targets
```

## Closure Criteria and Example Case Note
Close as **Benign Positive** when the source is confirmed as an approved scanner/pentest with no unauthorized logon activity, or as **Expected Activity** for routine monitoring tooling. Close as **Insufficient Evidence** if the source can't be attributed and no follow-on activity ever materializes after the retention window. Escalate/keep open if any authentication activity is tied to the same source.

> *Case note example:* "2026-09-15 03:14 UTC - Firewall logs show src 203.0.113.44 (unregistered, ASN flagged as known scanning provider) touching TCP/3389 across 41 distinct hosts in 10.20.0.0/24 over 6 minutes, SYN-only, no completed RDP negotiation. Cross-checked 4625/4624 on all 41 targets for the same window - zero auth attempts. No match to internal scanner allowlist. Blocked source at perimeter FW (rule REQ-8842). Flagged WKS-FIN-014 and two other hosts to Infra team - 3389 should not have been reachable from WAN on these; ticket INF-2291 opened for ACL review. Closing this event as Benign Positive (no logon activity); tracking ACL fix separately."
