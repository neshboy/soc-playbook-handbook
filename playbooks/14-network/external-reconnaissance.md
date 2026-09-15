# Playbook: External Reconnaissance

**Playbook ID & Name:** NW-003 — External Reconnaissance (Pre-Compromise Scanning & Enumeration)

**Business Risk**
**[STAKEHOLDER]** - External recon is the noisy, unglamorous stage that precedes almost every serious intrusion — someone is drawing a map of what we expose to the internet before deciding where to push. Left unreviewed, it tells an attacker which doors are unlocked; caught early, it's a free early-warning signal that costs nothing but analyst time to act on. The decision this playbook supports is simple: is this scan background internet noise, or is it targeted enough that we should tighten a specific exposed asset before it gets exploited.

**Severity/Priority default:** Low-to-Medium (P4/P3). Most recon is untargeted mass-internet scanning and closes as Expected Activity. Escalate to P2 when scanning is narrow, sequential, and clearly targeted at a specific asset, or when it's immediately followed by exploitation attempts.

**MITRE ATT&CK Techniques:** T1595 Active Scanning, T1046 Network Service Discovery. Frequently a precursor to T1190 Exploit Public-Facing Application — treat any correlation between a recon event and a subsequent exploit attempt against the same asset as a single elevated case, not two separate tickets.

## Trigger / Detection Logic Summary

Fires when a single external source IP (or small cluster of IPs sharing an ASN/subnet) generates connection attempts against an unusual number of distinct destination ports and/or destination hosts on internet-facing infrastructure within a short window, OR when perimeter IDS/IPS signatures for scanning tools (Nmap, Masscan, ZGrab, Nuclei, dirb/gobuster-style web fuzzing, Nikto) fire against a public IP range. Also triggers on DNS zone transfer attempts (AXFR) from non-secondary IPs, subdomain brute-force patterns against authoritative DNS, and abnormal spikes in 4xx/404 responses on public web apps consistent with directory/endpoint enumeration.

## Required Log Sources & Event IDs

There are no Windows or Sysmon Event IDs relevant to this playbook — the telemetry lives entirely at the network perimeter, not the endpoint.

| Source | What it provides |
|---|---|
| Perimeter firewall / NGFW (Palo Alto, Fortinet, Cisco ASA/FTD) | Allow/deny logs, port/protocol, session count per source IP |
| IDS/IPS (Suricata, Snort, vendor NGFW threat logs) | Signature hits for scan tools, vuln-scan signatures, banner-grab patterns |
| NetFlow / IPFIX / Zeek `conn.log` | Fan-out ratio: one source IP touching many destination ports/hosts |
| WAF (Cloudflare, AWS WAF, Azure Front Door/App Gateway, F5) | HTTP request patterns, path enumeration, 403/404 ratios, bot-signature matches |
| DNS logs (authoritative + resolver) | AXFR attempts, subdomain brute-force query volume, NXDOMAIN bursts |
| CDN / edge logs | Geographic and ASN origin of request bursts |
| Threat intel feeds | Known scanner infrastructure (Shodan, Censys, GreyNoise-classified benign scanners) |

## Key Fields to Inspect

**[ANALYST]**
- Source IP, source ASN/organization, reverse DNS (many legitimate researchers self-identify: `census8.shodan.io`, `data.censys.io`)
- Destination IP(s) and whether they're a single host or a spread across the public IP range
- Distinct destination port count per source IP per time window
- Protocol/port pattern — sequential (1,2,3...) suggests a scripted scanner; a curated list of high-value ports (22, 443, 3389, 8443, 8080, 9200) suggests a human picking targets
- HTTP User-Agent and request path (look for `/wp-admin`, `/.env`, `/.git/config`, `/actuator`, admin panel probes)
- TLS/JA3 fingerprint of the client where available — commodity scanners have well-known fingerprints
- Timing: is this a single burst, or slow-and-low scanning spread over days to stay under threshold alerting

## Normal vs. Suspicious Pattern

| Normal / Expected | Suspicious |
|---|---|
| Known internet-wide research scanners (Shodan, Censys, GreyNoise-tagged, university research ranges) touching common ports broadly and repeatedly across the whole internet | Scanning concentrated on your ASN/CIDR specifically, not broad internet sweep |
| Vulnerability-scanning vendor you contracted (Qualys, Tenable, Rapid7 authenticated/external scan) hitting your range on a known schedule | Unscheduled scan traffic with no matching change record or scan authorization |
| Uptime/monitoring services (Pingdom, UptimeRobot) probing a handful of known ports | Scan followed within minutes/hours by exploit attempts (SQLi, path traversal, auth brute force) against the same asset |
| Search engine/CDN crawlers respecting robots.txt | Enumeration of non-linked admin paths, `.git`, backup files, cloud metadata endpoints |

## Investigation Steps

1. Pull the fan-out metrics for the source IP: distinct destination ports, distinct destination hosts, total session count, and time span of the activity.
2. Check the source IP against threat intel and known-scanner allowlists (Shodan/Censys/GreyNoise). If it's a benign, self-identified research scanner and the pattern matches broad internet-wide scanning (not targeted), this is a fast Expected Activity close.
3. Correlate against your scheduled vulnerability-scanning calendar and change records — confirm whether this is your own contracted scanner or a partner's authorized pen test window.
4. Identify exactly which assets were touched and cross-reference against your external attack surface inventory — is the exposed service/port something that should even be internet-facing?
5. Search for any follow-on activity from the same source (or same subnet/ASN) against the touched assets in the hours after the scan — exploit attempts, credential stuffing, login attempts.
6. If web-layer recon (WAF/access logs), review request paths for enumeration of sensitive endpoints (`.env`, `.git`, admin consoles, API docs) and check whether any of those returned a 200 instead of 403/404.
7. If DNS-layer (zone transfer or subdomain brute force), confirm no unauthorized AXFR succeeded and review which subdomains were queried — a hit on an unadvertised subdomain can itself be an information leak worth investigating separately.
8. Document scope and severity, then decide: log-and-monitor, block at perimeter, or escalate for asset hardening.

## True Positive Indicators
- Targeted, sequential probing of your specific range with no matching authorization
- Directed enumeration of non-public paths/admin panels that succeed (200 OK) rather than get blocked
- Recon immediately followed by exploitation attempts against the discovered service
- Successful or partial AXFR response, or discovery of internal hostnames via subdomain brute force

## False Positive / Benign Positive Indicators
- Confirmed contracted vulnerability scan or authorized pen test in the change window
- Self-identified research/internet-mapping scanner with broad, non-targeted internet-wide pattern
- Uptime monitoring or CDN health checks from known provider ranges
- Search engine crawler respecting robots.txt with no enumeration of blocked paths

## Escalation Criteria
Escalate to P2/Incident when: recon is followed by a successful exploitation attempt or unauthorized access; an internal-only endpoint or credential file is discovered exposed; AXFR or metadata-endpoint probing succeeds; or the source is attributed to a known threat actor infrastructure cluster via TI enrichment.

## Containment Options & Approval Authority

**[MANAGEMENT]** - Blocking a known-benign research scanner ASN requires no approval — SOC analyst discretion, logged in the case. Blocking a source IP/subnet at the perimeter firewall for active malicious recon is standard analyst action under existing runbook authority, no change ticket needed for a temporary block. Any permanent architecture change (removing a service from internet exposure, restructuring firewall rules, WAF rule changes affecting production traffic) requires Network/Infrastructure team sign-off and a standard change record. SLA target: triage within 4 business hours for P3/P4, 30 minutes for P2 escalations tied to confirmed follow-on exploitation. Metric tracked monthly: recon-to-exploitation correlation rate, used to prioritize attack-surface reduction.

## Example Query (Splunk SPL — firewall/IDS fan-out detection)

```spl
index=firewall dest_zone=DMZ action=allowed
| bin _time span=5m
| stats dc(dest_port) as ports_touched, dc(dest_ip) as hosts_touched, values(dest_port) as port_list by src_ip, _time
| where ports_touched > 15 OR hosts_touched > 10
| sort - ports_touched
```

## Closure Criteria

Close as **True Positive** (contained) when the source is blocked and no follow-on exploitation occurred; close as **Expected Activity** when the scan matches an authorized/contracted scanner; close as **Benign Positive** when attribution confirms a known non-hostile research scanner with no targeted pattern; close as **Insufficient Evidence** when the source IP has no reverse DNS, no TI hits, and traffic volume is too low to characterize intent — but still log the IP for trend tracking.

**Example case-note line:**
`2026-09-15 14:22 UTC - src 203.0.113.44 (AS-XXXX, no rDNS) touched 43 distinct ports across 6 DMZ hosts in 4 min; no matching scan authorization; blocked at perimeter FW (rule REC-EXT-0091, 24h); no follow-on exploitation observed in next 12h window; closed as True Positive (contained).`
