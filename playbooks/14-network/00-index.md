# Category: Network

Every playbook in this folder starts from the same kind of evidence: something crossed a wire, and either the destination, the volume, the timing, or the protocol shape doesn't fit what that host normally does. Network alerts are keyed off flow, session, and query-level telemetry rather than host telemetry - you're rarely looking at a process tree here, you're looking at who talked to whom, how often, in what direction, and whether that pattern matches the baseline for that host, that segment, or that user. A workstation in the finance VLAN making a DNS query is unremarkable. The same workstation making forty thousand DNS queries to a domain registered six days ago, in a slow steady drip every ninety seconds, is a different story - and that story is usually told entirely in flow and query logs, long before EDR or the Windows event log has anything relevant to say.

The other thing this category has in common is where it sits in the kill chain: recon feeds targeting, C2 selection and beaconing sustain a foothold, tunnelling and suspicious TLS hide the channel, and large outbound transfers close the loop on exfiltration. Because of that, these playbooks rarely stand alone in practice. A port scan against a subnet and a firewall deny spike from the same source twenty minutes later aren't two separate low-priority tickets, they're one reconnaissance sweep. A beaconing alert and a DNS tunnelling alert on the same host inside the same hour is a materially different case than either in isolation. Pull the thread on adjacent playbooks in this folder before closing anything as isolated noise.

**[STAKEHOLDER]** - This category is where most "is data actually leaving the building" questions get answered, and where early-stage reconnaissance shows up before it turns into a headline incident. A port scan alert closed as Benign Positive is cheap. A large outbound transfer or a confirmed C2 beacon closed too slowly is not - this is the category with the shortest fuse between first detection and irreversible loss.

## Log sources and tooling that matter most

- **Firewall/NGFW logs** (Palo Alto, Fortinet, Cisco ASA/Firepower, etc.) - allow/deny decisions, zone, rule hit, translated (NAT) source, and session duration are the backbone of nearly every playbook here.
- **NetFlow / IPFIX / VPC flow logs** - volume, direction, port, and duration when full packet capture isn't retained or available; often the only surviving record once a session has aged out of firewall logs.
- **DNS query logs** (resolver logs, Zeek `dns.log`) - query name, query type, response code, and requesting host; essential for tunnelling, C2 domain generation, and known-malicious-domain hits.
- **Proxy / secure web gateway logs** - URL, category, user-agent, and the authenticated user behind a shared egress IP; frequently the only place a host's real identity survives NAT.
- **NDR/IDS** (Zeek, Suricata, Corelight, or vendor equivalents) - protocol metadata, JA3/JA3S TLS fingerprints, SNI, and signature hits that flow logs alone can't provide.
- **Threat intelligence / IOC feeds** - IP and domain reputation, sinkhole and Tor-exit-node lists, feed a large share of this category's automated matches.
- **NAT, DHCP lease, and identity mapping tables** - required to turn a firewall's translated source IP back into an actual host and user; without this step half these playbooks stall at "an IP did something."

**[ENGINEERING]** - Most detections here are built on ratios and cadence, not single events: connection count per source per time window, jitter between beacon intervals, query volume per domain, bytes-out relative to a per-host or per-segment baseline. Static thresholds age badly - a rule tuned for a 50-person office breaks the day someone stands up a backup job that legitimately moves gigabytes overnight.

## Friction specific to this category

NAT and shared egress IPs routinely collapse ten or fifty real hosts into one line in a firewall log, and if the NAT translation table has already rotated out by the time you're investigating, mapping the alert back to an actual endpoint can turn into a multi-team ask. Sampled NetFlow undercounts connections at scale, encrypted TLS payloads limit content inspection to metadata (SNI, JA3, certificate details) rather than anything definitive, and DNS-over-HTTPS quietly removes visibility from traditional resolver logs entirely. Add timezone mismatches between an on-prem firewall appliance and the SIEM, EPS throttling that silently drops log volume during a spike, and threat intel feeds that are stale, over-broad, or tagging shared cloud IP space - and a fair number of tickets in this category resolve to Insufficient Evidence not because nothing happened, but because the telemetry needed to prove it either wasn't retained or was never collected in the first place.

## Playbooks in this category

| # | Playbook | Primary reference technique(s) |
|---|----------|----------------------------------|
| 1 | Port Scanning | T1046, T1595 |
| 2 | Internal Network Reconnaissance | T1046, T1087, T1069, T1482 |
| 3 | External Reconnaissance | T1595, T1046 |
| 4 | C2 Communication | T1071 |
| 5 | Beaconing | T1071 |
| 6 | DNS Tunnelling | T1071.004, T1572 |
| 7 | Large Outbound Data Transfer | T1048, T1567 |
| 8 | Suspicious TLS | T1071 |
| 9 | Known Malicious IP Hit | Varies - IOC match, not technique-specific |
| 10 | Known Malicious Domain Hit | Varies - often T1071.004 |
| 11 | Tor Activity | T1090 |
| 12 | Proxy Avoidance Tooling | T1090 |
| 13 | Firewall Deny Spike | T1046, T1595 |
| 14 | Unusual Destination Country | Varies - context-dependent (T1071 / T1567 / T1048) |
| 15 | Unexpected Inbound Service Exposure | Configuration/exposure risk - often precursor to T1190 |
| 16 | Lateral Movement (Network View) | T1021 (.001 RDP, .002 SMB, .004 SSH) |
| 17 | SMB Scanning | T1046, T1021.002 |
| 18 | RDP Scanning | T1046, T1021.001, T1110 |
| 19 | SSH Attacks | T1021.004, T1110 |

**[MANAGEMENT]** - Track false-positive rate per playbook alongside mean-time-to-triage; scanning and firewall-deny alerts tend to run high-volume and low-severity, while beaconing, DNS tunnelling, and large outbound transfer carry outsized impact per incident. Review threat intel feed quality (stale IOC ratio, shared-hosting false positives) on a recurring cadence with detection engineering rather than only when an analyst flags a bad match.
