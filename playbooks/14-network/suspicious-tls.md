# NW-008: Suspicious TLS

## Business Risk

**[STAKEHOLDER]** - Attackers hide command-and-control, data theft, and malware delivery inside encrypted traffic because it looks like normal HTTPS to most security tools. Missing this means ransomware staging or data exfiltration goes unnoticed until it's too late to stop; catching it early is one of the few remaining chances to interrupt an intrusion before impact, without needing to break encryption for every user in the building.

## Severity / Priority Default

**Medium**, escalating to **High** when the destination matches known-bad threat intel, when the source host is a domain controller, jump box, or internet-facing server, or when more than one internal host is beaconing to the same suspicious endpoint. Escalates to **Critical** if paired with large outbound data volume or confirmed malware execution on the source host.

## MITRE ATT&CK Technique(s)

T1071.001 Application Layer Protocol: Web Protocols (C2 blended into HTTPS traffic), T1572 Protocol Tunneling, T1090 Proxy, T1567 Exfiltration Over Web Service, T1048 Exfiltration Over Alternative Protocol, T1105 Ingress Tool Transfer.

## Trigger / Detection Logic Summary

Alert fires when a TLS session exhibits one or more anomaly conditions relative to a baseline of "normal" enterprise HTTPS traffic: certificate/SNI mismatch, self-signed or freshly-issued certificate, known-malicious JA3/JA3S or JARM fingerprint, deprecated TLS/cipher negotiation, TLS handshake to a raw IP with no accompanying DNS resolution, or regular low-jitter connection intervals consistent with beaconing. This is a network-layer detection - it does not require decrypting payload, it works off handshake metadata that is visible even when the session itself stays encrypted.

## Required Log Sources & Fields

No Windows or Sysmon event IDs are cited here deliberately - this detection lives almost entirely in network telemetry, not host event logs.

| Source | What it gives you |
|---|---|
| Zeek/Bro `ssl.log` | negotiated version, cipher, curve, JA3/JA3S, SNI, resumption flag |
| Zeek/Bro `x509.log` | issuer, subject, SAN list, validity window, serial, key type |
| Zeek/Bro `conn.log` | duration, byte counts (orig/resp), connection state, ports |
| NGFW / proxy logs (Palo Alto, Fortinet, Zscaler, Squid) | SNI, category/reputation verdict, action taken, decrypted-or-not flag |
| IDS/IPS (Suricata/Snort) TLS alerts | signature match on cert anomalies, JA3 blocklist hits |
| DNS resolver logs | pre-connection resolution (or absence of one) |
| NetFlow/IPFIX | flow volume, packet timing, destination ASN |
| EDR network module (product-agnostic) | process-to-socket mapping when host telemetry is available |

## Key Fields to Inspect

**[ANALYST]**

- `ssl.server_name` (SNI) vs. `x509.san.dns` and `x509.subject` - do they actually match?
- `ssl.ja3` / `ssl.ja3s` - client and server fingerprint; check against internal threat intel and known toolkit hashes (e.g., default Cobalt Strike JA3s are well documented in public threat feeds - don't hardcode them as gospel, they change).
- `x509.certificate.not_valid_before` / `not_valid_after` - certs issued minutes or hours before first use are a strong tell.
- `x509.issuer` vs `x509.subject` - identical values mean self-signed.
- `ssl.version` and `ssl.cipher` - TLS 1.0/1.1 or export-grade ciphers on outbound traffic from a modern client is abnormal.
- Destination port - 443 is expected; 4443, 8443, 8080-with-TLS, or TLS on an unexpected port (e.g., 53, 25) is a tunneling/T1572 tell.
- `conn.duration`, `orig_bytes`, `resp_bytes` - long-lived low-volume sessions with regular check-ins look like beaconing; large `orig_bytes` with a short session looks like exfil.
- Destination IP/ASN - hosting provider vs. known SaaS CIDR ranges; newly observed IP for this environment.
- DNS correlation - was there a resolution for this domain in the preceding minutes, or did the client connect straight to an IP with SNI spoofed to something unrelated (domain fronting pattern)?

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Certificate age at first use | Days to years old, from a public CA (DigiCert, Let's Encrypt, Sectigo) | Minutes to hours old, self-signed or from a CA with no other presence in your traffic |
| SNI vs cert SAN | Match | Mismatch, or SNI blank while cert SAN lists something unrelated |
| TLS version | 1.2/1.3 | 1.0/1.1, or unusual extension ordering (JA3 outlier vs fleet baseline) |
| Session cadence | Irregular, tied to user activity | Fixed interval, low jitter (e.g., every 60s ± 2s) with no user activity on the host |
| Destination resolution | Preceding A/AAAA lookup in DNS logs | No DNS lookup, direct IP connection, or DNS-over-HTTPS to a resolver you don't manage |
| Destination reputation | Known SaaS/CDN ASN, aged domain | Bulletproof hosting ASN, domain registered in the last 30 days |
| Port | 443 | Non-standard port carrying TLS, or TLS-looking traffic on a port normally reserved for something else |

## Investigation Steps

1. Pull the full `ssl.log`/`x509.log` (or equivalent proxy log) entries for the source host and destination for the alerting window plus 24 hours before/after.
2. Extract JA3/JA3S and certificate fields; check issuer, validity window, and SAN list against SNI.
3. Check destination reputation - WHOIS/domain age, ASN owner, passive DNS history, and any hits in your threat intel platform or public feeds (VirusTotal, urlscan.io equivalents your org has licensed).
4. Correlate against DNS logs for the same source host in the minutes prior - resolved locally, resolved via public DoH, or no resolution at all.
5. Identify the process/user on the source host via EDR network telemetry if host agent is present; note parent process and binary path/hash.
6. Review `conn.log` volume and timing across the full session history to this destination - is this a one-off, or a pattern that's been running for days/weeks unnoticed?
7. Check whether other internal hosts have contacted the same destination, JA3, or cert serial - lateral spread of the same implant looks like multiple hosts sharing one C2 fingerprint.
8. Confirm whether the traffic was allowed or blocked by proxy/firewall policy, and whether TLS inspection/decryption is available for this segment to get payload-level confirmation.

## True Positive Indicators

- JA3/JA3S or JARM matches a known C2 framework fingerprint from threat intel.
- Certificate issued within minutes/hours of first observed use, self-signed, generic or randomly generated CN.
- SNI/cert SAN mismatch with no CDN/load-balancer explanation.
- Fixed-interval beaconing with no corresponding user activity on the host.
- Destination domain registered within the last 30 days, hosted on infrastructure with no legitimate business relationship.
- Multiple hosts independently contacting the same suspicious fingerprint/destination.
- Large outbound byte count immediately following a suspicious handshake (possible T1567/T1048 exfil).

## False Positive / Benign Positive Indicators

- Internal appliances (backup software, some IoT/OT devices, older printers) using self-signed certs by design and by known business function - verify against asset inventory before closing.
- Vulnerability scanner or attack-surface-management tool generating TLS probes across the estate - check scan schedules.
- CDN/edge-node churn causing IP or cert rotation that looks like a "new" destination but resolves to the same known SaaS provider.
- JA3 collision - remember JA3 is a fingerprint of the TLS client library, not the application; many unrelated benign tools (curl, older Python requests, some backup agents) can share a JA3 with malicious tooling. Don't close or escalate on JA3 alone - always corroborate with cert data, destination reputation, and behavior.
- Legacy line-of-business or POS systems still negotiating TLS 1.0/1.1 for known compatibility reasons, already tracked in the exception register.
- Analyst needs to validate this first before assuming malicious - a single suspicious field rarely stands alone as proof.

## Escalation Criteria

Escalate to Incident Response / Tier 2 when: JA3, cert hash, or destination IP/domain matches active threat intel; the source host is a domain controller, admin workstation, or internet-facing server; more than one host shares the same fingerprint or destination; sustained or high-volume outbound transfer follows the handshake; or TLS tunneling is confirmed carrying non-HTTPS protocol traffic on port 443 (T1572).

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority |
|---|---|
| Block destination IP/domain at firewall or proxy | Network/Security Engineering on-call, documented in change log |
| DNS sinkhole the domain | SOC Lead |
| Isolate host via EDR network containment | SOC Lead, or Incident Commander once IR is engaged |
| Force TLS decryption/inspection on the segment | Security Engineering + Legal/Privacy sign-off (interception policy applies) |
| Revoke/reissue internal PKI certificate (if internal CA cert is the one misused) | PKI/Identity team owner |

Standing SLA: triage within 30 minutes for High/Critical severity, containment decision within 2 hours of confirmed TP.

## Example Query

Splunk SPL against Zeek `ssl` and `x509` logs, flagging self-signed certs issued shortly before use, seen on non-standard TLS ports:

```spl
index=zeek sourcetype=ssl_log
| join ja3 [search index=zeek sourcetype=x509_log]
| eval cert_age_hrs=(_time - not_valid_before)/3600
| where cert_age_hrs < 2 AND issuer==subject
| where dest_port!=443
| table _time, src_ip, dest_ip, dest_port, server_name, ja3, ja3s, issuer, cert_age_hrs
```

## Closure Criteria

Close as **True Positive** (confirmed malicious C2) with IR case reference once the JA3/cert/destination is confirmed against threat intel and containment is applied; close as **Benign Positive** when the certificate/JA3 traces to a documented internal appliance or approved vendor tool; close as **Insufficient Evidence** when telemetry gaps (no TLS decrypt available, DNS logs not retained long enough, proxy log rotation) prevent confirming either way - re-open if the same fingerprint recurs.

Example case note:

> 2026-09-15 14:02 UTC - HOST-FIN-WK07 (10.12.4.55) established TLS 1.2 session to 198.51.100.212:8443, SNI absent, cert self-signed (issuer=subject, "CN=localhost"), issued 2026-09-15 13:47 UTC (15 min before use). JA3 72a589da586844d7f0818ce684948eea matches known Cobalt Strike default profile per internal TI feed. No prior DNS resolution for this IP. 40 outbound sessions over 6 hours at ~58s intervals, 1.2MB total egress. EDR shows parent process powershell.exe spawned from winword.exe. Escalated to IR as confirmed C2 (T1071.001/T1105); host isolated via EDR, destination blocked at perimeter firewall, IR case IR-2026-0914 opened.
