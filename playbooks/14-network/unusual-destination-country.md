# NW-014 — Unusual Destination Country (Outbound Network Traffic)

**Category:** Network | **Sub-category:** Geo-Anomaly / Egress Monitoring

## Business Risk

**[STAKEHOLDER]** - When a workstation, server, or service account starts talking to a country the business has no footprint in, it's usually one of three things: an employee on personal VPN/travel, a SaaS/CDN edge node that GeoIP tagged wrong, or a compromised host beaconing to attacker infrastructure or shipping data out the back door. The financial exposure isn't the alert itself, it's what's riding on that connection - stolen credentials, customer PII, source code, or a ransomware stager. This playbook is the tripwire that catches lateral movement and exfiltration attempts *after* initial access has already succeeded elsewhere, which is exactly when other controls have already failed once.

## Severity / Priority Default

| Condition | Default Severity |
|---|---|
| Single low-volume connection, sanctioned/embargoed country, unknown process | **High** |
| Sustained/periodic beacon pattern (regular interval, low jitter) to novel country | **High** |
| Large outbound data volume (>50MB in one session or cumulative in 1hr) to novel country | **Critical** |
| Single connection, known cloud/CDN ASN, business-plausible country | **Low** (auto-triage candidate) |
| Repeat offender host/user, previously closed as benign | **Medium** (re-baseline needed) |

Default queue priority: **P2**, escalates to **P1** on confirmed data volume above threshold or match against known C2/threat-intel infrastructure.

## MITRE ATT&CK Technique(s)

| Technique | Relevance |
|---|---|
| T1071.004 – Application Layer Protocol: DNS | C2 or exfil channel disguised as DNS to unusual TLD/registrar in the destination country |
| T1090 – Proxy | Traffic routed through relay/proxy infrastructure hosted in an unexpected jurisdiction |
| T1572 – Protocol Tunneling | Tunneling egress traffic to mask true destination or protocol |
| T1567 – Exfiltration Over Web Service | Data pushed to cloud storage/collaboration service whose regional endpoint resolves to an unusual country |
| T1048 – Exfiltration Over Alternative Protocol | Non-standard port/protocol used for outbound transfer to the flagged destination |
| T1105 – Ingress Tool Transfer | Inbound tool/payload staged from infrastructure in the flagged country before further activity |

## Trigger / Detection Logic Summary

Fires when a connection (outbound TCP/UDP session, DNS resolution, or proxy transaction) resolves - via GeoIP/ASN enrichment - to a country that is **not present** in the organization's rolling 90-day baseline of destination countries for that host, user, or business unit, **and** the destination is not on the approved allow-list (known SaaS regions, CDN anycast ranges, partner VPN endpoints). Additional weighting applied for: sanctioned/embargoed jurisdictions (per current OFAC/threat-intel guidance), bulletproof-hosting or low-reputation ASNs, and volume/frequency outliers relative to the host's own history.

This is a **behavioral/statistical** detection, not a signature match - it depends entirely on having a clean baseline and accurate GeoIP data. Both degrade over time and need periodic review.

## Required Log Sources & Event IDs

No Windows or Sysmon Event ID is required to trigger this detection - it is a network-layer control. Primary sources:

| Source | What it provides |
|---|---|
| Perimeter firewall traffic logs (Palo Alto, Fortinet, Check Point) | Session start/end, src/dst IP, port, bytes sent/received, App-ID |
| Web/forward proxy logs (Zscaler, Blue Coat, Squid) | URL, category, user identity, bytes, TLS SNI |
| NetFlow / IPFIX / sFlow | Flow records for hosts not traversing the proxy |
| DNS resolver logs | Query name, response IP, query type, resolving client |
| Cloud VPC/VNet flow logs (AWS VPC Flow Logs, Azure NSG Flow Logs) | East-west and egress flow metadata for cloud workloads |
| GeoIP/ASN enrichment feed (MaxMind or equivalent) | Country, ASN, ASN organization name attached at ingest |
| Sysmon network-connection telemetry (where deployed) | Process-to-destination mapping on the endpoint, useful for pivoting from IP to binary |

## Key Fields to Inspect

**[ANALYST]**

- `src_ip`, `src_host`, `src_user` / service account tied to the session
- `dst_ip`, `dst_port`, `dst_country`, `dst_asn`, `dst_asn_org`
- `bytes_sent` vs `bytes_received` (ratio matters - heavy `bytes_sent` is the exfil tell)
- `session_duration`, `session_count` in trailing 24h (beacon regularity)
- `app_id` / `url_category` (proxy) - is this tagged as "unknown", "newly registered domain", or "high risk"?
- TLS `SNI` / JA3 fingerprint if available - self-signed or non-standard cert on the far end is a red flag
- Parent process and command line for the host if Sysmon/EDR data is available - what actually opened this socket
- DNS query name resolving to the flagged IP - does the domain look machine-generated or does it match a legitimate vendor

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Traveling employee's laptop hits corporate VPN gateway first, then egresses locally from a hotel/ISP in the visited country | Direct, unauthenticated egress from a domain-joined desktop that never left the building, per badge/VPN logs |
| Destination ASN belongs to a recognized cloud provider (AWS, Azure, GCP, Cloudflare) regional edge | Destination ASN is a small hosting provider, VPS reseller, or previously flagged in threat intel |
| Bursty, human-driven traffic pattern (browsing, downloads, then idle) | Fixed-interval beacon (e.g., every 58-62 seconds) with near-identical payload size |
| `bytes_received` >> `bytes_sent` (downloading content) | `bytes_sent` >> `bytes_received` (uploading data) sustained over multiple sessions |
| Known SaaS domain resolving to a regional CDN edge in that country | Free dynamic-DNS or newly-registered domain (WHOIS <30 days) resolving to the flagged country |

## Investigation Steps

1. **Confirm the enrichment.** Cross-check the flagged country/ASN against at least one secondary GeoIP source before doing anything else - GeoIP databases are wrong often enough (especially for anycast CDN ranges) that this single step closes a meaningful chunk of alerts as Benign Positive.
2. **Identify the process/user.** Pivot from `src_ip` to the owning host and logged-on user/service account. If EDR/Sysmon coverage exists, find the parent process that opened the connection - browser, scheduled task, PowerShell, unknown binary.
3. **Check travel/VPN context.** Query the VPN concentrator and, if available, travel/expense or badge system for the user. A confirmed business trip closes a large share of these as Expected Activity.
4. **Assess volume and directionality.** Pull the full session/flow history for this src-dst pair over the last 7-30 days. Look at `bytes_sent`/`bytes_received` ratio and timing regularity, not just the single alerting event.
5. **Threat-intel match.** Check `dst_ip`, `dst_asn`, and any associated domain against current threat-intel feeds (known C2 infrastructure, sanctioned-entity lists, sinkhole lists).
6. **Correlate with endpoint telemetry.** If the host has EDR/Sysmon, look for related process creation, credential access, or file staging activity around the same timestamp - an isolated network anomaly with zero supporting host activity is a weaker case than one with a matching PowerShell download or archive-and-stage pattern.
7. **Check for concurrent DNS activity.** Look at DNS logs for that host in the surrounding window - unusual TXT/NULL record queries or high query volume to the same parent domain suggests T1071.004 tunneling rather than a one-off web request.
8. **Determine scope.** If confirmed suspicious, search the same `dst_ip`/`dst_asn`/domain across the entire environment for other hosts contacting it - this is rarely a single-host event once it's real.

## True Positive Indicators

- Fixed-interval beaconing to a low-reputation ASN with no legitimate business justification
- Large or steadily growing outbound byte count with no corresponding user activity (idle session, off-hours)
- Destination matches current threat-intel indicator (C2 IP, known malware infrastructure)
- Domain is newly registered, uses DGA-like naming, or was resolved immediately before the connection with no prior history
- Host shows supporting evidence of compromise: unexpected process, credential-access tooling, scheduled task creation, disabled security tooling

## False Positive / Benign Positive Indicators

- Confirmed employee travel, verified against VPN/badge/expense records
- Destination ASN is a known CDN/cloud edge that GeoIP has mis-tagged to a headquarters or regional billing country rather than physical POP location
- Third-party vendor or SaaS tenant genuinely hosted in that region (verify against vendor documentation/contract)
- Mobile device roaming on a carrier network whose exit IP geolocates differently than the user's actual location
- Retention/parsing gap: proxy log shows the request was blocked by category policy before it actually egressed (session never fully established) - check `action` field before treating this as a confirmed connection

## Escalation Criteria

Escalate to Incident Response / Tier 2 when **any** of the following are true:

- Confirmed or strongly suspected data exfiltration (large outbound volume, no benign explanation)
- Destination matches an active threat-intel indicator or sanctioned-entity list
- Supporting endpoint evidence of compromise (credential dumping, tooling disabled, unauthorized process)
- Same destination contacted by more than one host/user - potential lateral spread or shared C2
- Service account or privileged account is the source of the connection

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Required | Notes |
|---|---|---|
| Block destination IP/domain at perimeter firewall/proxy | SOC Shift Lead | Low-risk, reversible; do this first if TP confidence is high |
| Isolate endpoint via EDR | SOC Shift Lead (business hours), On-call IR Manager (after hours) | Confirm host identity twice - isolating the wrong asset is a recurring, costly mistake |
| Disable/suspend user or service account | IT Security Manager + asset/data owner sign-off | Service account disablement can break production jobs; verify dependencies first |
| Full network segment block (ASN or country-level) | CISO or delegate | Business-impacting; requires review of legitimate traffic that may also use that ASN |
| Law enforcement / regulator notification (sanctions match) | CISO + Legal/Compliance | Mandatory review if destination matches an OFAC or equivalent sanctioned-entity list |

SLA target: initial triage within 30 minutes for Critical/High severity, containment decision within 2 hours of confirmed True Positive.

## Example Query (Splunk SPL)

```spl
index=firewall OR index=proxy
| iplocation dst_ip
| lookup approved_countries_lookup Country OUTPUT is_approved
| where isnull(is_approved) AND Country!="Unknown"
| stats count, sum(bytes_out) as total_bytes_out,
        values(dst_ip) as dest_ips, earliest(_time) as first_seen
        by src_ip, user, Country, dst_asn
| where total_bytes_out > 5000000 OR count > 20
| sort -total_bytes_out
```

## Closure Criteria

Close as **True Positive** only after containment action is logged and confirmed effective (no further sessions to the destination post-block). Close as **Benign Positive** when travel/VPN/vendor context is verified and documented with the corroborating source. Close as **Expected Activity** for recurring, pre-approved business connections - and file a request to add the destination to the allow-list so it stops re-alerting. Close as **Insufficient Evidence** only after threat-intel check, volume review, and endpoint correlation have all been attempted and documented - not simply because GeoIP "might be wrong."

**Example case note:**
> 2026-09-15 14:22 UTC - Alert NW-014-00481: host FIN-WKS-0231 (user j.alvarez) established 3 sessions to 203.0.113.44 (AS-EXAMPLE-HOST, tagged Country=RO) over 40 minutes, 68MB sent / 2MB received, no matching VPN/travel record. No prior 90-day baseline for this dst_asn on this host. Endpoint EDR shows powershell.exe spawned from winword.exe 6 minutes before first connection. Escalated to IR as True Positive (suspected phishing-delivered exfil). Host isolated 14:31 UTC, account j.alvarez disabled pending investigation, dst_ip blocked at perimeter 14:33 UTC.
