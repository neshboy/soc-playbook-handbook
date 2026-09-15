# Firewall Deny Spike

## Playbook ID & Name
**NW-013 — Firewall Deny Spike (Anomalous Volume of Blocked Connections)**

## Business Risk
**[STAKEHOLDER]** - Every firewall in the environment drops traffic constantly - that's the job. This playbook exists for the moment the *volume* of drops stops looking like background noise and starts looking like a signal: someone probing the perimeter for a way in, an infected workstation hammering a blocked C2 channel, or a segmentation rule doing exactly what it's supposed to do while an application team quietly breaks. The financial exposure isn't the denies themselves - it's what a deny spike is usually the leading edge of (a breach attempt or an active infection) or the trailing edge of (a change that just took down a business workflow). Either way, a spike that gets triaged as "just noise" three times in a row is the one that turns into an incident-review question of "did we see this coming."

## Severity / Priority Default
**Low** when the spike is a single source hitting a single rule with 100% drop and zero successful sessions (classic scan/probe shape). **Medium** when the spike spans many destination rules/zones, includes an internal source, or shows any allowed session mixed into the deny pattern. **High** when the spike originates from an internal host talking to many external destinations in short bursts (fan-out beaconing/C2 fingerprint), targets a Tier-0 segment (DC VLAN, OT/ICS network, PCI zone), or coincides with a change freeze (i.e., nobody touched firewall rules, so the denial volume shift has to be explained by something else).

## MITRE ATT&CK Technique(s)
- **T1595 Active Scanning** - external source generating high-volume denied inbound connections while probing the perimeter for open ports/services.
- **T1046 Network Service Discovery** - internal source generating high-volume denied connections while sweeping across VLANs/segments from an existing foothold, hitting segmentation rules it shouldn't be able to cross.

A deny spike is a symptom, not a technique in its own right - direction and destination pattern tell you which story you're actually in. An internal host throwing thousands of outbound denies at rotating external IPs on a short interval looks more like blocked C2/beaconing (see the Beaconing and C2 Communication playbooks, both keyed on **T1071**) or an attempted tunnel/proxy (**T1572**, **T1090**) than classic discovery - note the pivot, investigate it under this playbook, but don't force-fit the ATT&CK mapping if the shape doesn't match.

## Trigger / Detection Logic Summary
Alert fires when the count of DENY/DROP actions in the firewall log, aggregated per source IP, per rule, or per zone-pair over a rolling window (typically 5-15 minutes), exceeds a statistical baseline (e.g., 3-5 standard deviations above the trailing 7/14-day average for that same window-of-day) or a fixed threshold tuned per environment. Two shapes matter:
- **Concentrated spike** - one source IP or one source/destination pair driving the bulk of denies (scan, probe, misconfigured retry loop).
- **Distributed spike** - many sources hitting the same destination/rule (DDoS-style, or many internal hosts newly blocked by a rule/ACL change - almost always an operational event, not an attacker).

## Required Log Sources & Event IDs
| Source | What it gives you |
|---|---|
| Perimeter/internal firewall logs (Palo Alto, Fortinet, Cisco ASA/Firepower, Check Point) | Action (deny/drop/reset), rule name/ID, zone pair, src/dst IP and port, NAT'd source, session count |
| NetFlow / IPFIX / VPC or NSG flow logs | Corroborating flow-level counts when firewall log retention has already rolled off |
| IDS/IPS (Suricata/Snort) | Signature correlation - confirms whether denied traffic also matched a known-bad pattern |
| Zeek `conn.log` | Connection tuples and duration for anything that straddles allow/deny on the same host pair |
| Change management / CMDB | Firewall rule-change history - the fastest way to rule out "we did this to ourselves" |
| DHCP lease table / NAT translation table | Required to map a NAT'd or dynamically-leased source IP back to an actual internal host |

## Key Fields to Inspect
**[ANALYST]**
- **Action field** - deny, drop, and reset are not always the same thing in every vendor's log; know which one your platform logs for a rule match vs. a stateful teardown.
- **Rule name/ID hit** - is it the default deny-all catch-all rule, or a specific segmentation/egress rule? A spike against the catch-all is usually recon; a spike against a named egress-filtering rule is usually a host trying to reach somewhere it's specifically not allowed to.
- **Source IP and whether it's internal or external** - direction changes the entire investigation path.
- **Destination IP/port diversity** - one destination hit repeatedly (retry-loop shape) vs. many rotating destinations (scan or fan-out C2 shape).
- **Zone pair** (e.g., trust→untrust, DMZ→trust, guest→corp) - tells you which segmentation boundary is under pressure.
- **Interval/cadence between denied attempts** - fixed-interval retries (every 30s/60s) suggest an application or malware retry loop rather than a human-driven scan.
- **NAT'd source vs. real internal host** - a shared egress IP can hide dozens of real hosts behind one line in the log; you need the NAT table timestamped close to the event, not today's snapshot.
- **Any allowed sessions inside the same time window from the same source** - a deny spike that includes even a handful of successful connects changes the whole risk calculus.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Deny volume matches a known scheduled vuln scan or pentest window | Deny volume with no corresponding change ticket, scan schedule, or known tool signature |
| Deny spike immediately follows a firewall rule-change deployment (new tighter ACL) | Deny spike during a change freeze with no rule modification in the audit trail |
| Broken/misconfigured application retrying a stale destination IP on a fixed interval, single destination | Internal host generating denies against dozens of rotating external IPs in short bursts |
| Internet background radiation - opportunistic bot scanning hitting the default deny-all rule at low, steady rate | Sudden step-change in deny rate against a specific internal segment (e.g., PCI VLAN) from a host with no business reason to talk there |
| IoT/printer/legacy device chatter to a decommissioned server, denied by an ACL cleanup | Deny pattern that matches known C2 beacon cadence (near-fixed interval, small consistent packet size) rather than random retry noise |

## Investigation Steps
1. Confirm the spike is real and not a collector/parsing artifact - check for duplicate log forwarding, a recent syslog/collector change, or an EPS-throttling drop-and-replay that can double-count events during ingestion delay.
2. Pull rule-change history and the vulnerability-scan/pentest calendar for the affected window first; a large share of these close in minutes once you confirm "we did this to ourselves" or "this is the scheduled Tuesday scan."
3. Classify direction and shape: external source hitting inbound rules (probable scanning, T1595) vs. internal source hitting outbound/internal segmentation rules (probable discovery or blocked C2, T1046/T1071/T1090/T1572).
4. If internal source, resolve the NAT'd/leased IP to an actual host and user via the DHCP/NAT tables timestamped to the event, not current state - tables rotate fast and yesterday's mapping is not today's.
5. Check destination diversity and interval regularity - one repeated destination on a fixed cadence smells like a broken app or a beacon; many rotating destinations in short bursts smells like a scan or a fan-out C2 fallback list.
6. Cross-reference for any allowed session in the same window from the same source - even one successful connect inside a deny spike means something got through, and that session needs its own full review, not a footnote.
7. If the internal host is implicated, pull EDR telemetry (process history, recent binary drops, scheduled task or service creation) to check for a compromise story that explains the traffic, and check for concurrent alerts from adjacent Network-category playbooks (port scanning, beaconing, DNS tunnelling) fired by the same host.
8. Document the rule(s) hit, the disposition (fully blocked vs. partial success), and whether the underlying rule/ACL needs adjustment regardless of intent - a deny spike against a rule that shouldn't exist anymore, or one that's now blocking legitimate business traffic, is a finding either way.

## True Positive Indicators
- External source with no scan authorization generating sustained high-volume denies against internet-facing rules, source not resolvable to a known-benign scanner/cloud health-check range.
- Internal host generating denies against many rotating external destinations with fixed-interval cadence and small, consistent payload size - a fallback-C2-list or blocked-beacon fingerprint.
- Internal host denied while attempting to cross a segmentation boundary it has no business reason to reach (workstation VLAN hitting the PCI or OT segment).
- Deny spike immediately preceded or followed by a related alert on the same host (port scan, DNS tunnelling signature, known-malicious IP/domain hit).
- Any successful (allowed) session embedded within an otherwise-denied burst pattern - the denies were the failed attempts, the one allow is the one that matters.

## False Positive / Benign Positive Indicators
- Deny volume traced to a recent, authorized firewall rule-change or segmentation tightening (Benign Positive - the control is working as designed).
- Source IP matches the vulnerability-management scan schedule or an approved pentest scope window.
- Misconfigured or misbehaving internal application/service retrying a stale or decommissioned destination on a fixed interval - an operational ticket, not a security incident, but still worth routing to the app owner.
- Duplicate/inflated counts from a log-forwarding or SIEM parsing issue (same deny logged by two collectors, or timestamp/timezone mismatch between firewall appliance and SIEM making a normal spike look concentrated in the wrong window).
- Legitimate internet background-radiation scanning (Shodan/Censys/Shadowserver-class ranges) hitting the default deny-all rule at a rate consistent with prior baseline for that source class.

## Escalation Criteria
Escalate to Tier 2/IR when: the source is internal and cannot be explained by a known tool, scheduled job, or approved change; the deny pattern matches a known beaconing/C2 cadence; any allowed session is found inside the denied burst; the target segment is Tier-0 (domain controllers, PCI, OT/ICS); the spike correlates with another Network-category alert on the same host within the same window; or the same destination/rule is hit by many distinct rotating external sources in a short period (possible early-stage or ongoing DDoS, which also needs infrastructure/network engineering paged in parallel).

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Block source IP/CIDR at perimeter** - Tier 1 can action directly under standing SOP for external sources with no legitimate business tie; log the action either way.
- **Isolate internal host** - requires IR lead approval; treat as suspected-compromise workflow once an internal source shows a beacon-like or discovery-like deny pattern with no benign explanation.
- **Emergency ACL/rule rollback** (when the spike is self-inflicted by a bad change) - owned by network engineering under standard change process; SOC flags it, doesn't roll it back unilaterally.
- **Rate-limiting or geo-blocking for distributed/DDoS-shaped spikes** - requires network engineering plus a change ticket; coordinate with any existing DDoS-mitigation provider/service before making perimeter changes.
- **Allowlisting a confirmed benign source/scanner** - requires SOC lead sign-off, logged in the exceptions register with a mandatory review date.

## Example Query (Splunk SPL - firewall index)
```spl
index=firewall action=deny earliest=-15m
| bucket _time span=1m
| stats count as denies dc(dest_ip) as dests dc(dest_port) as ports
        values(rule_name) as rules by src_ip, _time
| stats sum(denies) as total_denies max(dests) as max_dests
        max(ports) as max_ports by src_ip
| where total_denies > 500 OR max_dests > 25
| sort - total_denies
```

## Closure Criteria
Close as **True Positive** only after confirming source attribution (external reputation or internal host/user identity), the deny shape (scan vs. fan-out vs. segmentation-boundary probe), and whether any allowed session or related alert accompanied the spike - open a linked ticket for any host requiring isolation or further EDR review. Close as **Benign Positive** when tied to a confirmed scheduled scan, approved change, or a known-misbehaving application, with the owning team notified. Close as **Insufficient Evidence** when firewall log retention has already aged out the relevant window and NetFlow can't fill the gap - state the log-gap explicitly in the case note rather than defaulting to benign.

**Example case note:** *"Deny spike on rule DENY-DMZ-TO-CORP, src 10.44.8.21 (host FIN-WKS-014, user j.alvarez), 2,140 denies over 12 min against 61 distinct external IPs on port 443, ~45s interval per destination - matches beacon-fallback-list cadence, not a manual scan. No allowed sessions found in window. EDR pulled: unsigned binary update_svc.exe present in AppData, spawned by explorer.exe 20 min prior. Host isolated, IR lead notified, escalated to Compromise Assessment queue. Closed as True Positive - pending forensic triage."*
