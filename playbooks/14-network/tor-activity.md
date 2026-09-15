# Tor Activity

## Playbook ID & Name

**NW-011 — Tor Activity (Client Connection to the Tor Network)**

Most SOCs treat this as a binary policy question rather than an investigation, and most of the time that's the right instinct — Tor has almost no legitimate business use case on a standard corporate endpoint. The reason it earns its own playbook instead of a one-line auto-block rule is that the other 5% of cases include ransomware affiliates checking their leak-site status, insiders moving data through a channel that bypasses every proxy control you've paid for, and malware families that ship Tor as a built-in C2 fallback. The alert looks the same in the firewall log either way; the job here is telling those cases apart quickly.

## Business Risk

**[STAKEHOLDER]** - Tor gives whoever is using it an encrypted, multi-hop, attribution-resistant path off the network that walks straight past URL category filtering, DLP inspection, and most proxy logging - the same controls the business is relying on to know when data leaves. When it shows up on a workstation it's almost always either a policy violation (unapproved browsing, evading monitoring) or a sign that something has already compromised the host and is using Tor as a communication or exfiltration channel. Either way, the business question is the same: what left, and who authorized it. There is close to zero legitimate day-to-day use case for Tor on a managed corporate asset outside of a narrow, ticketed research/OSINT exception.

## Severity/Priority Default

**Medium** as the default for a single workstation with a short-lived Tor session and no unusual data volume, pending investigation. Escalate to **High** if the source is a server, domain controller, or privileged-user asset, if the session persists across multiple days, or if it's paired with any other alert (beaconing, large outbound transfer, credential access activity) in the same window. Escalate to **Critical** if there's evidence of data staging/exfiltration over the Tor circuit or if the host shows ransomware precursor behavior — several ransomware affiliate toolkits use Tor for C2 fallback or to reach their negotiation/leak-site infrastructure.

## MITRE ATT&CK Techniques

| Technique | Context in this playbook |
|---|---|
| **T1090** — Proxy | Core technique — Tor is a multi-hop anonymizing proxy network; this is the primary classification for any confirmed Tor circuit traffic |
| **T1572** — Protocol Tunneling | Applies when Tor traffic is wrapped in a pluggable transport (obfs4, meek) to look like ordinary HTTPS to a CDN, specifically to evade DPI/proxy detection |
| **T1048** — Exfiltration Over Alternative Protocol | Applies when meaningful data volume moves outbound over the Tor circuit instead of the host's normal web/mail/cloud-storage channels |
| **T1567** — Exfiltration Over Web Service | Applies when data is staged to a paste site, file-drop, or onion-service endpoint reachable only via Tor |

**T1105 (Ingress Tool Transfer) and T1204 (User Execution) do not apply to the common case this playbook is written for** — an employee deliberately downloading and running the Tor Browser Bundle themselves, with no attacker involved. Both techniques describe an *adversary* staging tooling or socially engineering a user into running something; a self-directed install by the account holder isn't that, and forcing either ID onto a confirmed-non-malware policy case misstates what happened. Only cite T1105/T1204 if the installer itself turns out to be attacker-delivered (e.g., a trojanized "Tor Browser update" pushed via phishing or malware) rather than the user's own deliberate download — that's a materially different, much rarer case.

## Trigger / Detection Logic Summary

Alert fires on outbound connections from an internal source to IP addresses on a current Tor relay/exit-node list (guard, middle relay, or exit node), typically on TCP/9001 (onion routing port) or TCP/9030 (directory port), or on TLS connections matching known Tor/obfs4/meek fingerprint characteristics on port 443. A secondary and often more reliable trigger is DNS: `.onion` is not a resolvable public TLD, so any query for a `.onion` name reaching your DNS logs at all means something on that host either misconfigured its SOCKS proxy or leaked a lookup outside the Tor circuit — either way it's a hard confirmation Tor software is present. Tertiary triggers include NGFW/proxy App-ID or URL-category hits explicitly labeled "tor" or "proxy-avoidance-and-anonymizers," and endpoint telemetry showing known Tor client process names or the circuit-building pattern of 3-4 concurrent long-lived outbound connections established within a few seconds of each other (guard + middle + exit negotiation).

## Required Log Sources & Event IDs

| Source | Field/Event | Why it matters |
|---|---|---|
| Firewall / NGFW logs (Palo Alto, Fortinet, Check Point) | App-ID/category = "tor" or "proxy-avoidance-and-anonymizers"; DestinationIP, DestinationPort, SentBytes/ReceivedBytes | Primary detection surface; category filtering is the fastest confirmation path |
| Proxy / secure web gateway logs (Zscaler, ProxySG) | URL category, authenticated user, bytes transferred | Ties the connection to an identity even behind shared egress NAT |
| DNS logs (resolver query log) | Query name (`*.onion`), source IP | Definitive confirmation signal — `.onion` has no legitimate public resolution path |
| NetFlow / IPFIX | Distinct destination count per source in short window, connection duration, bytes out | Reveals circuit-building pattern (multiple simultaneous long-lived flows) distinct from normal browsing |
| Sysmon on endpoint | **Event ID 1** (Process Create) — `tor.exe`, `firefox.exe` (Tor Browser is Firefox-based), `obfs4proxy.exe`, `torbrowser-install-*.exe` | Confirms client software presence and installation source |
| Sysmon on endpoint | **Event ID 3** (Network Connection) | Confirms the process making the multi-relay connections, not just the network layer |
| Sysmon on endpoint | **Event ID 22** (DNSEvent - DNS query) | Catches leaked `.onion` or bridge-related lookups issued by the process instead of routed through the local Tor SOCKS proxy |
| Windows Security log | **Event ID 4688** (process creation, if command-line auditing enabled) | Alternate source for install/launch evidence where Sysmon isn't deployed |

## Key Fields to Inspect

**[ANALYST]**

- **DestinationIP / DestinationPort against current Tor consensus list** — relay and exit-node lists rotate roughly hourly; confirm the match against a feed refreshed within the last few hours, not a stale one, before treating it as gospel.
- **Number of distinct destination IPs from one source in a short window** — a real Tor circuit build looks like 3-4 concurrent connections to different IPs within seconds, then a sustained low-chatter session; a single connection to one flagged IP is weaker evidence and deserves a second look before you call it Tor.
- **DNS QueryName for `.onion` or Tor bridge/directory domains** — presence at all is significant regardless of volume.
- **Process name, parent process, binary path, and hash** (Sysmon EID 1) — `tor.exe`/Tor Browser's `firefox.exe` running from `Downloads` or a user profile path versus a signed, IT-deployed binary tells very different stories.
- **JA3/JA3S TLS fingerprint** (if NDR/TLS inspection available) — obfs4/meek traffic mimics ordinary HTTPS but the ClientHello fingerprint is often consistent and distinguishable from genuine browser traffic to that destination.
- **SentBytes/ReceivedBytes and session duration** — a short informational lookup looks very different from a session moving tens of megabytes outbound.
- **Command-line arguments and install source** — was the client silently dropped by another process, or did the user manually download the Tor Browser Bundle installer?

## Normal vs Suspicious Pattern

| Normal (rare, exception-only) | Suspicious |
|---|---|
| Documented OSINT/threat-intel researcher on an isolated research VLAN, with a standing change/access ticket on file | No ticket, no documented business justification, running from a standard corporate workstation or server |
| Low connection volume, short session, business hours | Sustained multi-hour or multi-day session, especially recurring across reboots |
| Client installed via approved software deployment, signed binary | Installer run from `Downloads`/`Temp`, unsigned binary, launched by the user manually outside change control |
| No `.onion` DNS leakage (properly routed through local SOCKS proxy) | `.onion` or Tor bridge domain queries appearing directly in resolver logs |
| Isolated to a single known research host | Same pattern appearing across multiple unrelated hosts (suggests malware family with Tor built in, or a compromised build image) |
| Minimal data egress | Large SentBytes volume immediately before/after Tor session start — potential exfil staging |

## Investigation Steps

1. **Validate the match against a current Tor node list.** Confirm the flagged destination IP is actually in the consensus relay/exit list as of the alert time, not a stale threat-intel feed entry — Tor relay churn is high and this is the single most common source of false positives in this category.
2. **Identify the actual source host and user.** Firewall logs frequently show a NAT/proxy egress IP rather than the real endpoint — pull DHCP lease data, NAC/802.1x logs, or proxy authentication records to resolve back to a specific host and identity.
3. **Pull endpoint process telemetry.** Look for `tor.exe`, Tor Browser's `firefox.exe`, `obfs4proxy.exe`, or an installer artifact via Sysmon Event ID 1/3 or EDR. Capture binary path, hash, signer (or lack of one), and parent process chain.
4. **Check DNS logs for `.onion` leakage** and any bridge/directory-service lookups from the same host — this is often the cleanest corroborating evidence and is hard to explain away as anything other than Tor client activity.
5. **Quantify session volume and duration.** Compare SentBytes/ReceivedBytes and connection duration against the host's baseline egress. A multi-hour session moving tens of megabytes changes this from a policy conversation into a potential data-loss incident.
6. **Check for co-occurring alerts.** Cross-reference the same host/time window against beaconing, large outbound transfer, credential access, and process injection alerts — Tor showing up alongside any of those materially changes the read from "policy violation" to "active intrusion."
7. **Look for scope beyond one host.** Pivot across firewall/DNS logs for the same relay IPs or `.onion` pattern on other endpoints — multiple hosts hitting Tor infrastructure simultaneously points at a golden-image misconfiguration or a malware family with Tor C2 built in, not an individual user decision.
8. **Establish business justification, or the lack of one.** Check for an approved research/OSINT ticket referencing that host and user. If there's no ticket and no malware evidence, this becomes a policy/conduct case for the asset owner and HR rather than a pure security incident — document accordingly.

## True Positive Indicators

These are the malware/compromise/exfil case. A confirmed Tor install with no ticket but *no* corroborating evidence below is the more common Policy Violation case, not this one — see Closure Criteria.

- Tor activity co-occurring with other IOCs on the same host (beaconing, credential dumping, ransomware precursor behavior) — consistent with malware using Tor as a C2 fallback or as the channel to reach a leak-site/negotiation portal.
- `.onion` or bridge-domain queries present in DNS logs with no corresponding user-run Tor client explaining them (a leaked lookup from an unrelated process) — points at malware routing through Tor rather than a human browsing session.
- Significant data volume transferred over the Tor session immediately preceding or following the detection, with no user activity explaining it.
- Same signature repeating across multiple unrelated hosts in the same window with no common ticket or exception — suggests a malware family with Tor built in or a compromised build image, not individual user choice.

## False Positive / Benign Positive Indicators

- Approved OSINT/threat-intel or red-team research activity from an isolated, ticketed research host or VLAN.
- Stale Tor node feed flagging an IP that has since rotated out of the Tor consensus (or was never actually a relay — some feeds lag or misclassify shared hosting ranges).
- Security vendor sandbox or research tooling that itself uses Tor egress for anonymized lookups, misattributed to an internal host due to shared/aggregated logging.
- Security research/training lab traffic on a segregated non-production network with no path to production data.
- Insufficient Evidence is the right call when a destination IP matches a Tor list but there's no corroborating process, DNS, or volume signal, and the resolving process is a known-good binary with an unrelated explanation — flag for a short monitoring window rather than forcing a verdict.

## Escalation Criteria

Escalate immediately to IR/Tier 2 if: the host is a server, domain controller, or belongs to a privileged/admin user; the session shows meaningful outbound data volume with no business justification; Tor activity co-occurs with any credential-access, beaconing, or ransomware-precursor alert; or the same pattern appears on more than one host in the same window. A single workstation, short session, no data volume, no corroborating IOC, and no repeat pattern can generally be handled as a standard policy-violation ticket routed to the asset owner rather than a full IR escalation.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Needed | Notes |
|---|---|---|
| Block Tor relay/exit IP ranges and "proxy-avoidance-and-anonymizers" category at firewall/proxy | SOC Team Lead — standing authority, already a common baseline policy | Fast, low business impact; should already be default-deny in most environments |
| Uninstall/remove Tor Browser Bundle from endpoint | SOC Team Lead + asset owner notification | Standard for confirmed unauthorized install with no malware indicators |
| Isolate endpoint via EDR | SOC Team Lead, escalate to IR Lead if server/privileged asset | Reserve for cases with malware/exfil indicators, not a bare policy violation |
| Refer to HR / people manager for conduct review | Security Ops Lead + HR, not security team unilaterally | Appropriate when this is a documented policy violation with no technical compromise evidence |
| Restrict local admin rights / enforce application allowlisting on the segment | IT Engineering + CISO sign-off | Addresses root cause (user was able to install unapproved software) — broader change, not incident-specific |

SLA target: initial triage decision (escalate vs. policy referral vs. close) within 4 hours for Medium severity; within 1 hour for High/Critical given the potential exfiltration window.

## Example Query (Microsoft Sentinel KQL)

```kql
CommonSecurityLog
| where DeviceAction == "allowed"
| where DestinationIP in (_GetWatchlist('TorExitNodes'))
| where DestinationPort in (9001, 9030, 443)
| summarize Connections=count(), BytesOut=sum(SentBytes), BytesIn=sum(ReceivedBytes)
    by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
| where Connections >= 3
| sort by BytesOut desc
```

## Closure Criteria

Close as **True Positive** when Tor use is tied to confirmed malware/C2 activity, credential compromise, or data exfiltration — full IR containment and forensic documentation required. Close as **Policy Violation** when the Tor client/process is confirmed but there's no malware, compromise, or data-loss evidence — this is the more common outcome (a user's own unauthorized install), and gets referred to the asset owner/HR with the technical block/removal applied rather than run as an IR case. Close as **Benign Positive** or **Expected Activity** when the activity traces to an approved, ticketed OSINT/research use case with no data-loss indicators — document the exception and confirm it's tracked against a standing approval rather than re-litigated each time. Close as **Insufficient Evidence** when the IP/category match can't be corroborated by process, DNS, or volume evidence and no repeat pattern emerges — note it for a short watchlist period rather than closing silently.

**Example case note:** *"Workstation WKS-MKT-0447 (10.14.6.203, user t.osei) generated 4 concurrent long-lived connections to distinct IPs on TCP/9001 within an 8-second window, matching current Tor consensus relay list. Sysmon EID 1 confirmed `firefox.exe` under path `C:\Users\tosei\Desktop\Tor Browser\Browser\firefox.exe`, installer artifact `tor-browser-windows-x86_64-portable-13.5.exe` found in Downloads, no signature. No `.onion` DNS leakage observed — client routed correctly through local SOCKS proxy. Session duration 42 minutes, BytesOut 1.8MB — consistent with manual browsing, not bulk exfiltration. No corresponding research/OSINT ticket on file. No co-occurring beaconing, credential-access, or exfil alerts on this host in the prior 14 days. Classified Policy Violation — confirmed unauthorized Tor Browser install, no malware or compromise evidence (T1090; T1105/T1204 not applicable — self-directed download, no attacker involved). Tor Browser removed, category block confirmed active, referred to manager and HR for conduct review; no IR escalation warranted."*
