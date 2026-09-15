# C2 Communication

**Playbook ID:** NW-004
**Category:** Network | **Playbook type:** Detection & Response

**Scope note:** This playbook covers detecting the *shape and structure* of an active command-and-control channel — protocol/TLS fingerprinting, framework signatures, domain fronting, header and payload anomalies — independent of check-in timing. If the alert that brought you here is purely "connections happen on a suspiciously regular schedule," that's the **Beaconing** playbook's job; the two overlap constantly in real cases (a live C2 channel is very often *also* beaconing between operator sessions) and you should expect to be flipping between them on the same ticket. If the channel is riding DNS queries specifically, hand off the deep dive to **DNS Tunnelling**; if the transport is a known anonymization proxy or VPN-style relay, that's **Tor Activity** / **Proxy Avoidance Tooling** territory.

## Business Risk

**[STAKEHOLDER]** - Once an attacker has a working, undetected communication channel into the environment, everything downstream — credential theft, lateral movement, ransomware staging, data theft — becomes a matter of "when," not "if." This playbook is about spotting the channel by *what it looks like on the wire* (a known attacker toolkit's fingerprint, a mismatched certificate, a domain pretending to be a CDN) rather than waiting for its schedule to give it away, which buys the response team hours or days of extra runway before the attacker gets comfortable enough to act.

## Severity/Priority Default

**High** on any JA3/JA3S, certificate, or HTTP-structure match against a known C2 framework fingerprint, even with only one session observed. **Critical** if domain fronting through legitimate CDN infrastructure is confirmed, if the channel is tied to a server holding regulated data, or if a second-stage payload transfer is observed over the same channel within the investigation window. Do not default this down to Medium just because volume is low — a single successful interactive C2 session can do more damage than weeks of beaconing.

## MITRE ATT&CK Techniques

| Technique | Name | Relevance |
|---|---|---|
| T1071 | Application Layer Protocol | Primary technique — C2 traffic wrapped in HTTP/HTTPS (or another app-layer protocol) to blend with normal outbound traffic |
| T1071.004 | Application Layer Protocol: DNS | Channel type reference only — full mechanics covered in the DNS Tunnelling playbook |
| T1027 | Obfuscated Files or Information | Encoded/encrypted command bodies, base64-wrapped payloads disguised as images/scripts, custom XOR in HTTP response bodies |
| T1105 | Ingress Tool Transfer | Second-stage tool or payload pulled down over the already-established C2 channel |
| T1218 | System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32) | LOLbin frequently used as the local process that opens/maintains the outbound C2 connection |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Operator disabling AV/EDR shortly after confirming the channel is live and stable |

## Trigger / Detection Logic Summary

**[ENGINEERING]** - This detection is signature- and structure-driven rather than cadence-driven: it fires on JA3/JA3S TLS client-hello fingerprints matching known C2 framework families, TLS certificates with attacker-toolkit default/placeholder fields or mismatched SNI-to-cert-CN, HTTP request/response structures matching an unmodified or barely-modified malleable C2 profile (stock cookie names, unmodified default User-Agent strings shipped with the toolkit, predictable URI path patterns), and SNI/Host-header mismatches consistent with domain fronting through a legitimate CDN. It should also flag response bodies with high entropy disguised inside content-types that shouldn't have any (a ".gif" or ".css" response with no valid file structure at all). None of this requires the traffic to be periodic — a single interactive session with the right fingerprint is enough to fire High severity.

## Required Log Sources

- NDR/IDS with TLS fingerprinting capability (Zeek, Suricata, Corelight, or vendor equivalent) — JA3/JA3S hash, certificate fields, SNI
- TLS-terminating proxy / SSL inspection appliance — full decrypted HTTP request/response (headers, cookies, URI, body) where in-scope for inspection
- Secure web gateway / proxy logs — URL, method, User-Agent, category, bytes sent/received, TLS SNI
- NGFW/firewall session logs — source/dest IP, port, protocol, action, session duration
- DNS resolver logs — needed to confirm what the fronted domain actually resolves to versus what the CDN edge served
- EDR network-connection telemetry correlated to initiating process, binary hash, and signer status
- Threat intelligence feeds with C2 framework fingerprint libraries (JA3 watchlists, known malleable-profile indicators)

## Key Fields to Inspect

**[ANALYST]**

- JA3 (client) and JA3S (server) hash — check against internal/vendor watchlists of known C2 framework fingerprints before anything else
- Certificate subject/issuer fields — self-signed, default/placeholder subject strings left over from toolkit defaults, unusually short validity period, issued the same day traffic started
- SNI vs. certificate CN/SAN vs. HTTP Host header — three-way mismatch is the core domain-fronting tell
- HTTP header order, casing, and presence/absence of headers a real browser or the claimed User-Agent would normally send
- Cookie names and structure — session tokens that look like they're carrying encoded command data rather than actual session state
- URI path pattern — generic, unmodified, or template-looking paths inconsistent with the site's real application structure
- Response Content-Type vs. actual body structure — a file claiming to be an image or script that doesn't parse as one
- Timing/size variability across the session — small uniform blips (hand to Beaconing) vs. bursty, variable-sized exchanges consistent with a live operator typing commands
- Initiating process on the endpoint (EDR) — signer, install path, whether it's a LOLbin (`mshta.exe`, `regsvr32.exe`, `rundll32.exe`) acting as the network client
- Whether AV/EDR service state changed on the host shortly after the channel appears

## Normal vs Suspicious Pattern

| Attribute | Normal / Expected | Suspicious |
|---|---|---|
| JA3/JA3S | Matches common browser/library fingerprints seen broadly across the environment | Matches a fingerprint on a known-C2-framework watchlist, or is unique to a single host in the org |
| Certificate | Valid chain to a recognized public CA, CN matches the actual service | Self-signed or freshly issued cert, generic/placeholder subject fields, CN doesn't match the service being claimed |
| SNI vs Host header | Match, and both resolve to the CDN/service they claim to be | SNI shows a trusted CDN edge, but the Host header or decrypted request targets an unrelated backend (domain fronting) |
| HTTP structure | Header order/casing and URI structure consistent with the real application | Header set/order looks like a library default, URI paths are generic/templated, cookie doesn't behave like a real session token |
| Response content | Content-Type matches actual parseable content | Declared as image/script/CSS but the body doesn't parse as one — likely a wrapper for encoded C2 traffic |
| Session rhythm | Either steady app traffic tied to user activity, or a well-documented fixed heartbeat from a known agent | Irregular bursts of variable size consistent with live keyboard-driven operator activity, or perfectly uniform blips from an unknown process |

## Investigation Steps

1. Pull the full session capture or decrypted proxy log for the flagged connection — do not triage on flow metadata alone. Extract JA3/JA3S, certificate details, headers, cookies, URI, and response body/content-type.
2. Check the JA3/JA3S hash and certificate fingerprint against your threat-intel/C2-framework watchlist. A hit here is close to a confirmed verdict on its own; a miss doesn't clear the host, since custom or updated toolkits rotate fingerprints.
3. Compare SNI, certificate CN/SAN, and the decrypted HTTP Host header side by side. A mismatch pointing to a trusted CDN on the outside but something else entirely underneath is domain fronting, not a parsing glitch — validate before dismissing it as one.
4. Pull the initiating process on the endpoint via EDR: binary path, signer, hash, parent process, and any persistence mechanism (scheduled task, service, run key) tied to it.
5. Classify the traffic pattern: tight, uniform, periodic blips point you toward the Beaconing playbook for the cadence analysis; bursty and variably sized exchanges suggest a live operator session and should be treated with more urgency, not less.
6. Check whether a binary was written to disk or a new process spawned shortly after any unusually large inbound response on this channel — that's ingress tool transfer riding the same C2 session.
7. Search the environment for the same JA3/JA3S hash, certificate fingerprint, or destination across other hosts before you scope this as single-host.
8. Check AV/EDR service and configuration state on the host around the time the channel first appeared and again just before detection — a stopped or reconfigured agent shortly after first contact is a strong corroborating signal that this is not incidental traffic.

## True Positive Indicators

- JA3/JA3S or certificate fingerprint matches a known C2 framework on an internal or vendor watchlist
- Confirmed SNI/Host-header mismatch consistent with domain fronting through legitimate CDN infrastructure
- Unmodified or barely modified toolkit default artifacts in headers, cookies, or URI structure
- Response content that fails to parse as its declared content-type, consistent with an encoded payload wrapper
- Ingress tool transfer (new binary/process) immediately following a large inbound response on the channel
- AV/EDR tampering or service stop occurring shortly after the channel's first successful session
- Initiating process is an unsigned binary or a LOLbin with no legitimate reason to be making outbound network calls

## False Positive / Benign Positive Indicators

- JA3 hash collision with a widely used legitimate library or SDK — JA3 fingerprints the TLS client hello only, not the full application, and shared hashes across unrelated software are common; never close solely on a JA3 hit without a second corroborating signal
- Corporate TLS-inspection/MITM proxy altering the observed certificate and fingerprint in ways that look anomalous but are actually your own infrastructure
- Legitimate multi-tenant CDN hosting that structurally resembles fronting (many unrelated customers behind the same edge) without any actual mismatch once fully decrypted
- Authorized red-team or penetration-test engagement using a commercial C2 framework under a signed rules-of-engagement — check the active test calendar before escalating
- Security research/scanning tooling deliberately using C2-adjacent fingerprints for detection validation purposes (should be pre-registered with the SOC, but isn't always)

## Escalation Criteria

Escalate to Incident Response immediately on any confirmed framework fingerprint match, confirmed domain fronting, or ingress tool transfer following the initial channel. Escalate regardless of business hours if AV/EDR tampering is observed concurrently — that's usually the point where the operator is settling in for hands-on-keyboard activity. Escalate to a full environment-wide hunt the moment the same fingerprint or destination is found on a second host.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Block destination IP/domain/cert fingerprint at proxy/firewall | SOC Lead (standing authority for confirmed-malicious indicators) | Fast, reversible; do this as soon as a framework match is confirmed |
| Isolate host via EDR network containment | SOC Lead, notify asset owner | Preserves the host for forensics while cutting the live channel |
| Disable associated user/service account | IR Lead + account owner's manager | Only where credential compromise is separately confirmed, not from channel evidence alone |
| Re-enable/restore tampered AV/EDR agent and validate | IR Lead + Endpoint Engineering | Do this only after evidence collection, not before — restoring the agent can tip off an operator mid-session |
| Full segment/VLAN isolation | CISO or designated deputy | Reserved for confirmed multi-host C2 infrastructure or active lateral spread |

## Example Query (Microsoft Sentinel KQL)

```kql
CommonSecurityLog
| where DeviceEventClassID has_any ("tls", "ssl")
| extend JA3 = tostring(parse_json(AdditionalExtensions).ja3Hash)
| where isnotempty(JA3)
| join kind=inner (Watchlist_C2Fingerprints) on $left.JA3 == $right.JA3Hash
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName, JA3, FrameworkName
```

## Closure Criteria

Close as **True Positive** (confirmed C2 channel) once the fingerprint/structure match is corroborated by at least one endpoint-side artifact (process, persistence, or tampering evidence) and containment has been applied and verified. Close as **Benign Positive** when a JA3/certificate hit is traced to a legitimate library, sanctioned red-team engagement, or approved security tooling with documentation on file. Close as **Insufficient Evidence** when TLS inspection wasn't in scope for the session and metadata alone can't confirm or rule out a fingerprint match — flag the gap to Detection Engineering rather than guessing at a verdict.

**Example case-note line:** "Session from APP-SVR-0114 (10.30.6.42) to cdn-assets-static[.]net matched JA3 e7d705a3286e19ea42f587b344ee6865 against the internal C2-framework watchlist; SNI presented a known CDN edge but decrypted Host header pointed to an unrelated backend (confirmed domain fronting). EDR traced the initiating process to `rundll32.exe` spawned outside any normal install/update workflow (T1218.011, T1071); Defender for Endpoint service was stopped 4 minutes after first contact (T1562.001). Host isolated, fingerprint and domain blocked org-wide, escalated to IR — no second host found with the same JA3 during initial sweep, hunt continuing."
