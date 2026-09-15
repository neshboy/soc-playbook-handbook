# NET-14: Proxy Avoidance / Anonymizer Tooling Usage

**Playbook ID:** NW-012
**Category:** Network
**Also known as:** Anonymizer usage, web-proxy circumvention, censorship-bypass tooling detection

---

## Business Risk

**[STAKEHOLDER]** - When someone on the corporate network routes traffic through Tor, a public VPN, or a CGI web-proxy, every control built on top of the web gateway - content filtering, DLP inspection, malware sandboxing, SSL decryption - goes blind for that traffic. The business isn't just losing visibility into "what site did they visit," it's losing the ability to prove what left the building. That matters for regulatory data-handling obligations and for any insider-threat or HR case that later needs an evidentiary trail.

## Severity / Priority Default

- Default: **P3 / Medium** - policy violation, needs an owner and a call, not a 2 a.m. page.
- Escalate to **P2 / High** if paired with data staging, unusual outbound volume, a privileged account, a resigning/terminated employee, or if the anonymizer traffic correlates with an active incident (malware beaconing, active exfil).
- Escalate to **P1 / Critical** only if there's confirmed large-scale sensitive data exfil riding the tunnel.

## MITRE ATT&CK Technique(s)

| Technique | Sub-technique | Relevance |
|---|---|---|
| T1090 | Proxy | Core technique - traffic relayed through an intermediary to hide true destination/origin |
| T1572 | Protocol Tunneling | Tor, SSH tunnels, VPN-over-HTTPS wrapping disallowed protocols inside allowed ones |
| T1071.004 | Application Layer Protocol: DNS | DNS-over-HTTPS or DNS tunneling used specifically to bypass DNS-based filtering |
| T1567 | Exfiltration Over Web Service | Anonymizer/VPN endpoint doubling as an exfil path once bypass is established |
| T1048 | Exfiltration Over Alternative Protocol | Non-web tunnel (custom port, SSH, ICMP) carrying data out |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Some anonymizer tools attempt to disable or evade local proxy enforcement/SSL inspection |

Note on scope: T1204 (User Execution), T1105 (Ingress Tool Transfer), and T1027 (Obfuscated Files or Information) are deliberately **not** listed above even though they show up in generic anonymizer write-ups. All three describe an adversary tricking or staging tooling on a victim; the case this playbook is written for is an employee voluntarily installing their own anonymizer client with no attacker involved, which those techniques don't actually describe. If a specific case *does* turn out to be attacker-delivered (e.g., a trojanized "VPN client" dropped by malware rather than downloaded by the user), cite T1105/T1204/T1027 on that case directly rather than carrying them as a default label for routine policy violations.

## Trigger / Detection Logic Summary

Detection is layered here - no single log source is reliable on its own:

1. Secure web gateway / firewall App-ID tagging traffic as `proxy-avoidance`, `tor`, `anonymizer`, or `vpn-unsanctioned` category.
2. TLS fingerprint (JA3/JA3S) or SNI matching known circumvention client signatures (Psiphon, Ultrasurf, Lantern, generic Tor client hellos) even when the destination IP rotates.
3. DNS query volume/pattern anomaly - high count of TXT/NULL record queries to a single domain, high subdomain entropy, or queries resolving to known Tor directory authorities / bridge relay ranges.
4. Endpoint telemetry showing execution of a known anonymizer binary name/hash, or a portable executable launched from Downloads/Temp with outbound connections on non-standard ports shortly after.
5. Sustained encrypted session to a consumer VPN ASN or CGI-proxy domain from a host that has no business justification for it (e.g., kiosk, service account, unattended workstation).

## Required Log Sources

- **Secure Web Gateway / Proxy** (Zscaler, Netskope, Bluecoat, Squid) - category and action fields; blocked-but-attempted entries matter as much as allowed ones.
- **Next-gen firewall** (Palo Alto, Fortinet, Check Point) - App-ID/App-Control logs, session logs with bytes-in/bytes-out.
- **DNS resolver/query logs** - internal recursive resolver logs, not just what the proxy happened to see.
- **TLS/SSL decryption or fingerprinting logs** - JA3/JA3S, SNI, certificate issuer/subject.
- **Endpoint (EDR) process-creation and network-connection telemetry** - binary name, hash, parent process, command line, and the process's own outbound connections.
- **DHCP/NAC logs** - to tie an internal IP back to a specific host/user at the time of the session, especially in DHCP-churn or VDI environments.

No specific Windows or Sysmon event ID numbers are asserted in this playbook - map the guidance below to whatever process-creation and network-connection event schema your own EDR/Windows logging pipeline uses. The field-level guidance is written to be schema-agnostic on purpose.

## Key Fields to Inspect

**[ANALYST]**
- `src_user`, `src_host`, `src_ip` - who and what.
- `dest_ip`, `dest_domain`, `sni`, `ja3_hash` - where the traffic actually went; the domain visible in the proxy log is sometimes just the CGI-proxy front door, not the real destination.
- `app_category` / `url_category` (`proxy-avoidance`, `tor`, `anonymizer`).
- `bytes_out`, `bytes_in`, session duration - anonymizer tunnels used for casual browsing look bursty and short; ones used for staging/exfil look sustained and asymmetric (bytes_out much greater than bytes_in).
- `dest_asn`, `dest_geo` - consumer hosting/VPN ASNs, geography mismatched from the expected business footprint.
- DNS fields: `query_name`, `query_type`, `answer`, subdomain entropy, queries-per-minute-per-domain.
- Endpoint fields: process name/hash, parent process, install path (Temp/Downloads/AppData is a stronger signal than Program Files), digital signature status.
- Time-of-day relative to the user's normal working pattern - avoidance traffic meant to dodge an HR or acceptable-use block often clusters at odd hours.

## Normal vs Suspicious Pattern

| Signal | Normal / Expected | Suspicious |
|---|---|---|
| App category | Sanctioned corporate VPN (e.g., GlobalProtect, AnyConnect) to a known concentrator IP | Unclassified/anonymizer category, rotating destination IPs, no corresponding change ticket |
| TLS SNI | Matches a real, resolvable corporate or SaaS domain | SNI blank or mismatched with certificate CN, or SNI is a known CGI-proxy front |
| DNS pattern | Normal mix of A/AAAA queries, low subdomain churn | High-volume TXT/NULL queries, high-entropy subdomains, single domain queried hundreds of times per hour |
| Process origin | Signed installer pushed via software deployment tooling, runs from Program Files | Unsigned/portable exe launched from Downloads or Temp, opens an outbound connection almost immediately |
| Traffic shape | Symmetric or download-heavy browsing | Sustained upload-heavy session (bytes_out >> bytes_in) inside a "browsing" category |
| User context | IT-approved remote-access need, documented travel to a filtering jurisdiction | No documented need; user recently flagged in an HR case, resignation notice, or performance plan |

## Investigation Steps

1. Pull the raw proxy/firewall session for the flagged connection and confirm the category tag isn't a miscategorization - a newly registered domain not yet reputation-scored is a very common false trigger here.
2. Identify the endpoint and user via DHCP/NAC/AD correlation at the exact timestamp. VDI and heavily NAT'd environments make this step easy to get wrong - double-check you have the right host, not just the right egress IP.
3. Check EDR for the responsible process: binary hash, signature status, install path, parent process, and whether it was silently installed (scheduled task, scripted deployment) versus manually downloaded and run by the user.
4. Look at DNS logs for the same host/time window for tunneling indicators (TXT/NULL query volume, subdomain entropy) - this catches DNS-based bypass that proxy-category logic alone won't flag.
5. Quantify data volume across the session(s): total bytes_out over the lookback window, not just the single flagged connection. One connection is a policy question; a week of steady upload-heavy sessions is an insider-risk question.
6. Check whether the same anonymizer signature (JA3 hash or binary hash) shows up on other hosts - isolated user curiosity versus an unsanctioned tool quietly spreading across a team.
7. Review the user's HR/access context through your normal case-management process (recent disciplinary action, resignation notice, access to sensitive data) - this changes urgency, not the underlying technical finding.
8. Confirm whether a documented business exception exists (pentest team, threat-intel research use of Tor, expat employee behind national filtering) before writing this up as a violation.

## True Positive Indicators

- Confirmed execution of a known anonymizer/VPN-avoidance binary with no corresponding change or deployment record.
- DNS tunneling signature (sustained high-entropy TXT queries to a single domain) with no legitimate service explaining it.
- Sustained, asymmetric (upload-heavy) encrypted session through an unsanctioned proxy/VPN category immediately preceding or following access to sensitive repositories or file shares.
- Same anonymizer signature recurring across multiple sessions after the user was previously warned or the tool was previously blocked - points to deliberate evasion, and to T1562.001 if local controls were also tampered with.

## False Positive / Benign Positive Indicators

- Newly registered or low-reputation domain miscategorized by the gateway vendor as `anonymizer`/`proxy-avoidance` - common in the first weeks after a domain goes live.
- Sanctioned corporate VPN client whose App-ID signature drifted after a vendor update and got re-bucketed into the wrong category.
- Approved research, pentest, or threat-intel use of Tor or a VPN under a documented exception logged with the security team in advance.
- Remote worker tethered to a personal hotspot, or travelling through a hotel/airport network that itself routes traffic through a captive-portal proxy - looks like anonymizer traffic but is just unusual consumer routing.
- Browser privacy feature enabled by default in an IT-provided software image, not by user intent.

## Escalation Criteria

Escalate to Tier 2 / Insider Risk or IR when any of the following hold:
- Confirmed sustained data volume through the tunnel that can't be explained by normal browsing.
- The account involved has privileged access, or the host has access to regulated data.
- The user is under active HR action, in a notice period, or has been previously formally warned for the same behavior.
- The anonymizer traffic co-occurs with other suspicious activity in the same window (credential access attempts, mass file access, disabling of endpoint agents).
- Multiple hosts show the identical anonymizer signature, suggesting distribution rather than one-off curiosity.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Block domain/category/JA3 signature at gateway | SOC Tier 2, standing authority | Low-risk, reversible, standard blocklist update |
| Isolate endpoint (EDR network containment) | SOC shift lead, or IR Manager after hours | Use when co-occurring with other malicious indicators, not for policy-only violations |
| Disable user account / force password reset | IR Manager + HR sign-off | Reserved for confirmed exfil or an active insider-risk case |
| Preserve endpoint forensic image | IR Manager, coordinated with Legal/HR | Required before any account or device action if litigation or termination is likely |
| User counseling / acceptable-use notice (no technical action) | Manager + HR, SOC provides evidence package | Most common outcome for first-time, low-volume cases |

SOC's job here is evidence and a containment recommendation - the decision to discipline, terminate, or refer to Legal sits with HR/Legal/line management, not the SOC.

## Example Query

**[ENGINEERING]** Splunk SPL against proxy logs, flagging anonymizer-category sessions with heavy upload volume:

```spl
index=proxy sourcetype=web_proxy
| search category IN ("proxy-avoidance","anonymizer","tor")
| stats sum(bytes_out) as total_out, sum(bytes_in) as total_in,
        count as sessions, values(dest_domain) as domains
        by src_user, src_ip
| where total_out > 50000000 AND total_out > (total_in * 3)
| sort - total_out
```

Adjust the 50 MB upload threshold and the 3x asymmetry ratio to your environment's baseline - a call center desk and an engineering workstation have very different normal upload profiles.

## Closure Criteria

Close as:
- **Policy Violation**: unsanctioned tool confirmed, no malware/compromise evidence, evidence packaged, referred to management/HR, technical block applied.
- **Incident**: confirmed exfil or malicious use, handed to IR for the full incident process.
- **Benign Positive**: legitimate sanctioned VPN or approved exception, category corrected at the gateway to prevent repeat alerts.
- **Insufficient Evidence**: single low-volume DNS/TLS signature hit, no endpoint corroboration, no recurrence - close with a note to reopen if it recurs.

Example case-note line:

> 2026-09-12 14:31 UTC - Host WKS-FIN-0421 (user j.alvarez) flagged for sustained Psiphon-signature TLS session, 340MB upload over 40 min, immediately following access to \\FS01\Finance\Q3_Budget. EDR confirms unsigned exe `pconnect.exe` launched from Downloads at 14:02. No documented business exception on file. Escalated to Insider Risk queue, endpoint isolated pending HR/Legal review. Ref case INC-2026-0914-118.
