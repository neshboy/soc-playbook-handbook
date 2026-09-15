# NW-010 — Known Malicious Domain Hit

**Category:** Network | **Playbook type:** Detection & Response

## Business Risk

**Related Playbook:** See Playbook NW-009 (Known Malicious IP Hit) for the same threat-intel-match workflow keyed on IP rather than domain indicators — the two commonly fire together on the same connection attempt.

**[STAKEHOLDER]** - This is the alert that fires when a company laptop or server tried to talk to a domain that someone else has already confirmed is bad — a threat intel feed, a vendor, a peer organization's breach report. It's cheap to generate and expensive to ignore: most hits turn out to be a stale feed entry or a shared hosting IP, but a real one means a phishing link was clicked, a payload is trying to phone home, or data is on its way out the door through a service dressed up as something legitimate. The business question this playbook answers is simple — did the block actually stop something, or did something get through before the block existed.

## Severity/Priority Default

**High** when the connection attempt was *allowed* (not blocked) and the domain's threat category is C2, malware distribution, or phishing with high confidence; **Medium** when the connection was blocked/sinkholed at the perimeter before any payload could transit, or the feed confidence/category is generic ("suspicious", low confidence, newly observed); **Low** only after the specific domain has been reviewed and confirmed as a shared-infrastructure false positive, with the underlying feed entry corrected or suppressed.

## MITRE ATT&CK Techniques

| Technique | Name | Relevance |
|---|---|---|
| T1071 | Application Layer Protocol | Malicious domain served over standard HTTP/HTTPS as the transport for C2 or payload delivery |
| T1071.004 | Application Layer Protocol: DNS | Domain used purely as a DNS query target — C2 or exfil riding query/response traffic rather than an established session |
| T1090 | Proxy | Domain resolves to known proxy/redirector infrastructure fronting the real C2 or hosting endpoint |
| T1572 | Protocol Tunneling | Malicious domain is the endpoint for a tunnel wrapping C2 inside an allowed protocol |
| T1567 | Exfiltration Over Web Service | Domain belongs to an abused legitimate web service (paste site, file-share, chat platform) used as exfil or C2 channel |
| T1566.002 | Phishing: Link | User followed a link in email/chat that resolved to the flagged domain |
| T1204 | User Execution | User-driven click/open was the delivery mechanism that generated the domain contact |
| T1105 | Ingress Tool Transfer | Domain served as a staging/download point for a follow-on payload |

## Trigger / Detection Logic Summary

Fires on a match between an outbound DNS query, proxy request, or firewall session destination and an entry in an active threat intelligence source — internal IOC list, commercial feed (e.g., Recorded Future, Microsoft Defender TI), open-source feed (e.g., URLhaus, abuse.ch), or a security vendor's cloud reputation service (e.g., Cisco Umbrella, Zscaler, Palo Alto AutoFocus). This is fundamentally a lookup match, not a behavioral analytic — the detection logic itself is trivial (destination FQDN or resolved domain is present in the blocklist), which means the entire investigative burden sits on the analyst to determine what actually happened around that match, not on the detection to prove intent.

## Required Log Sources

- Secure web gateway / proxy logs — requested URL/FQDN, HTTP method, response code, TLS SNI, category, bytes transferred, action taken
- DNS resolver / DNS security service logs — queried FQDN, record type, response code, returned IP, and whether the response was a sinkhole answer
- NGFW/firewall session logs — resolved destination IP, port, protocol, action (allow/deny), translated source (NAT)
- Threat intelligence platform / IOC-match log — matched indicator, feed source name, confidence score, threat category, first-seen/last-seen dates for that indicator
- Email security gateway logs (when the hit correlates to a link click) — sender, recipient, URL, click-time verdict, attachment hash if applicable
- EDR/endpoint telemetry correlated to the initiating process — used to tie the network event back to a specific browser, script, or binary on the host (no specific Windows/Sysmon event ID is asserted here; use whatever your EDR's process-to-network correlation feature is called in your environment)

## Key Fields to Inspect

**[ANALYST]**

- Action field on the original log line — was the connection **blocked/sinkholed** or **allowed**? This single field usually decides the whole severity call.
- Threat intel match metadata — feed/source name, confidence score, threat category (C2, phishing, malware, newly-registered, DGA-pattern), first-seen date for the indicator itself (a feed entry added yesterday for a domain registered five years ago behaves very differently to one flagged the same day it was registered)
- DNS response — was it a real IP, or a sinkhole/walled-garden address (e.g., `127.0.0.1`, `0.0.0.0`, an internal RFC1918 address returned by your own DNS security layer)? A sinkhole answer means the control already did its job for that query
- Requesting host, logged-on user, and (via EDR correlation) the initiating process/parent process
- Referrer or originating context — did the request follow an email link click, a redirect chain, a script execution, or an app's own background traffic (ad network, analytics SDK)?
- Bytes transferred and response content-type, if the session was allowed before being flagged — determines whether anything actually left or arrived
- Domain WHOIS/registration age, hosting ASN, and passive DNS history — corroborate or challenge the feed's categorization independently

## Normal vs Suspicious Pattern

| Attribute | Benign/expected pattern | Suspicious pattern |
|---|---|---|
| Action taken | Blocked/sinkholed at proxy, firewall, or DNS layer before any session established | Allowed through — session completed, content transferred |
| Feed confidence | Low-confidence, generic "suspicious" tag, or the feed itself has a known high false-positive rate for that category | High-confidence, specific category (active C2, confirmed phishing kit, malware payload host) |
| Domain infrastructure | Shared CDN/hosting IP also serving many unrelated legitimate domains | Dedicated, recently registered infrastructure with no other legitimate tenants |
| Origin of the request | Browser extension telemetry, ad/analytics beacon embedded in an otherwise legitimate page, security scanner itself pre-fetching URLs | Direct navigation following a phishing link, or non-browser process (script host, unsigned binary) making the request |
| Repetition | Single, isolated query, never repeated | Repeated queries/requests, or the same host resolving multiple different flagged domains in a short window |
| User awareness | User reports receiving a suspicious message and the click preceded the alert by seconds/minutes — consistent story | No corresponding user report, and the traffic pattern looks automated (fixed intervals, off-hours, headless user-agent) |

## Investigation Steps

1. Confirm the disposition of the original event first — blocked/sinkholed vs. allowed. If blocked, the priority drops immediately but the ticket still needs closure; if allowed, treat it as a live lead until proven otherwise.
2. Pull the threat intel match record in full — feed source, confidence score, threat category, and indicator first-seen date. Cross-check the domain independently against at least one other reputation source; feeds disagree often enough that a single-source flag shouldn't carry the whole verdict.
3. Resolve the requesting host and logged-on user (through DHCP lease, NAT table, or directory lookup if behind a proxy) and pull EDR telemetry for the initiating process at the timestamp of the query/request.
4. If the connection was allowed, pull proxy logs for the actual transaction — response code, content-type, bytes in/out — and determine whether anything was downloaded, executed, or uploaded.
5. Trace the delivery context backward: was there a preceding email with a link to this domain, a redirect from another site, a script executing on the host, or a scheduled/background process? Check the email security gateway if a phishing link is suspected (T1566.002) and ask the user directly if a report exists.
6. Check whether other hosts in the environment have contacted the same domain or its resolved IP/ASN in the same window — an isolated single-host hit and an organization-wide spray point to very different response paths.
7. If a payload transferred, retrieve or hash the file for sandbox detonation and check EDR/AV verdicts; if credentials were entered on a page served by the domain, treat as a probable phishing capture and begin the separate account-compromise workflow.
8. Document dwell time — first contact timestamp vs. alert/detection timestamp — since blocklist ingestion delay means the "known malicious" status may have applied to the domain well before your feed picked it up.

## True Positive Indicators

- Connection was allowed (not blocked) and a session actually completed with content transferred
- High-confidence, specific-category match (active C2 infrastructure, confirmed phishing kit, malware distribution) corroborated by a second independent source
- Clear delivery chain: phishing email → link click → domain contact, or script/unsigned binary → domain contact
- Domain infrastructure is dedicated, recently registered, and not shared with unrelated legitimate traffic
- Follow-on host activity in the same window: file download and execution, credential entry, or persistence artifacts

## False Positive / Benign Positive Indicators

- Sinkhole/walled-garden response confirms the security control already intercepted the query — nothing reached the actual malicious infrastructure
- Domain shares hosting/CDN IP space with legitimate, unrelated sites (common with cheap shared hosting and some ad-tech), and the feed is flagging the IP or a co-hosted domain rather than content the host actually requested
- Request originated from a browser pre-fetch, ad network beacon, or security scanner itself (some email gateways and EDR products pre-fetch links to test them, which can itself trigger the alert)
- Feed entry is stale — domain was compromised/malicious in the past, has since been cleaned up or re-registered to a different, unrelated owner, and passive DNS/WHOIS no longer supports the original categorization
- Isolated, single query with no session establishment, no repetition, and no corresponding user report or endpoint artifact

## Escalation Criteria

Escalate to Incident Response when: the connection was allowed and content transferred (file download, form submission, credential entry); the delivery chain traces to a phishing email that also went to other recipients; more than one host contacted the same domain/infrastructure; or endpoint telemetry shows execution, persistence, or follow-on network activity after the domain contact. Escalate to the threat intel/detection engineering team (without a full IR case) when the domain turns out to be a confirmed false positive tied to a specific feed — that's a tuning problem, not an incident.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Confirm/reinforce block at proxy, firewall, and DNS layer | SOC Lead (standing authority) | Should already be blocked by definition of "known malicious" — verify all three layers are consistent, not just one |
| Isolate host via EDR network containment | SOC Lead, notify asset owner | Applied when the connection was allowed and endpoint artifacts (execution, persistence) are present |
| Disable/reset credentials entered on the malicious page | IR Lead + account owner's manager | Treat as probable credential capture if the domain hosted a login-style page, even before full phishing confirmation |
| Retroactive organization-wide hunt for the same indicator | SOC Lead, coordinate with Detection Engineering | Triggered once a second host or a delivery-email is confirmed |
| Suppress/correct a confirmed stale or overbroad feed entry | Detection Engineering Lead | Prevents repeat low-value tickets; log the correction with justification, don't just silence the alert |

## Example Query (Microsoft Sentinel KQL)

```kql
let malDomains = ThreatIntelligenceIndicator
    | where Active == true and ThreatType in ("c2","phishing","malware")
    | project DomainName, ConfidenceScore, ThreatType;
CommonSecurityLog
| where DeviceVendor == "Zscaler" or DeviceVendor == "PaloAltoNetworks"
| extend RequestedDomain = tostring(RequestURL)
| join kind=inner malDomains on $left.RequestedDomain == $right.DomainName
| project TimeGenerated, SourceIP, DestinationIP, RequestedDomain, DeviceAction, ConfidenceScore, ThreatType
```

## Closure Criteria

Close as **True Positive** once the delivery chain is confirmed (link click, script, or payload), the connection is verified as allowed with actual data transferred, and containment/credential-reset actions are complete with no repeat contact observed. Close as **Benign Positive** when the destination check confirms the control intercepted the query (sinkhole/block) and no session ever established, or when the specific domain is confirmed shared-infrastructure/stale-feed and corrected upstream. Close as **Insufficient Evidence** when proxy/DNS retention has already rolled off by the time the alert is triaged (a recurring gap with feeds that batch-ingest indicators days after first sighting) and no corroborating endpoint or email telemetry survives — flag the host for a short retroactive watchlist rather than closing silently.

**Example case-note line:** "Proxy log shows WKS-SALES-0417 (10.44.2.19, user j.alvarez) requested `docs-share-portal-cdn7[.]top` at 14:32 UTC following a link click in an email reported by the user at 14:35; Zscaler action=blocked, no session established, DNS resolved to sinkhole address 127.0.0.53 confirming Cisco Umbrella intercepted the query before any payload transfer; no other host in the org has ever contacted this domain; email confirmed as phishing and forwarded to email security for org-wide search; classified Benign Positive for the network event itself, separate phishing case opened for the email vector."
