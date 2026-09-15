# NW-007: Large Outbound Data Transfer

**Category:** Network | **Playbook ID:** NW-007

## Business Risk

**[STAKEHOLDER]** - An unusually large volume of data leaving the network toward an external or unapproved destination is one of the few signals that maps almost directly to "did we lose something." Whether it's a departing employee zipping up the customer database, a compromised host beaconing a RAT's collection archive to a cloud drive, or a misconfigured backup job pointed at the wrong bucket, the business impact is the same category of pain: regulatory notification, contractual breach, loss of competitive advantage, or all three. This playbook exists to answer one question fast - is data actually leaving, and if so, what, to where, and under whose authority.

## Severity / Priority Default

**High** by default. Downgrade to Medium only after confirming destination reputation is benign (known SaaS tenant, approved partner, corporate cloud storage under the org's own tenant ID) and volume is explainable by a known business process. Upgrade to Critical if the source host also has EDR alerts for credential access, process injection, or defense impairment in the preceding 24 hours - that combination is no longer "possible exfil," it's "confirmed compromise attempting exfil."

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1567 Exfiltration Over Web Service | Data pushed to SaaS/cloud storage, paste sites, or messaging APIs using HTTPS to legitimate-looking domains |
| T1048 Exfiltration Over Alternative Protocol | Data moved over a non-C2 protocol (FTP, SFTP, SCP, raw sockets) separate from the malware's command channel |
| T1071.004 Application Layer Protocol: DNS | Slow-drip exfil via DNS TXT/NULL record encoding when volume is spread across thousands of small queries |
| T1572 Protocol Tunneling | Legitimate protocol wrapping a covert channel (e.g., DNS-over-HTTPS, ICMP tunneling, SSH tunnel to unexpected host) |
| T1090 Proxy | Traffic routed through an internal or external proxy/relay to obscure true destination or blend with normal egress |
| T1530 Data from Cloud Storage | Bulk pull from an org's own cloud storage (S3, Blob, GCS) preceding the outbound push, relevant when the source is SaaS-native rather than an endpoint |
| T1119 Automated Collection | Scripted staging/archiving activity on the host immediately before the transfer spike - look for this as a precursor, not the transfer itself |

## Trigger / Detection Logic Summary

Fires when a single host, user, or cloud identity exceeds a defined outbound volume threshold within a rolling window, AND the destination is external (not in the organization's approved CIDR/domain allowlist), AND (optionally, to cut noise) the destination ASN/reputation score is unrated or the connection uses a protocol/port combination inconsistent with that host's baseline. Most SOCs tune this as two flavors: a **hard threshold** alert (e.g., >1 GB egress from a single workstation in 15 minutes) and a **behavioral baseline deviation** alert (host's 30-day rolling average outbound volume exceeded by 5x or more).

## Required Log Sources & Event IDs

| Source | Data Provided |
|---|---|
| Firewall / NGFW (Palo Alto, Fortinet, Check Point) | Session logs with bytes-sent, bytes-received, src/dst IP, dst port, app-ID, duration |
| Proxy / Secure Web Gateway (Zscaler, Netskope, Blue Coat) | URL category, uploaded bytes, user identity, TLS SNI, file name where available (CASB inline inspection) |
| NetFlow / IPFIX (via flow collector) | Flow volume, direction, top talkers - useful when proxy/FW logs are incomplete or absent |
| DNS logs | Query volume per host, TXT/NULL record types, query length distribution, entropy of subdomain labels |
| EDR (CrowdStrike, Defender for Endpoint, SentinelOne) | Process that owns the network connection, parent process, file access preceding the transfer, archive utility usage |
| Windows Security Event Log | 4688 (process creation) for archiving/compression tools; 5156 (Windows Filtering Platform allowed connection) on hosts with WFP auditing enabled |
| Cloud CASB / SaaS audit logs | Upload/download events to Dropbox, Google Drive, OneDrive personal tenants, file-sharing API calls |
| Cloud provider logs (AWS CloudTrail, Azure Activity Log, GCP Audit Log) | S3 GetObject/PutObject at volume, VPC Flow Logs for egress to non-peered ranges, data transfer billing anomalies |
| DLP (if deployed) | Content-inspection match on regulated data types (PII, source code, PAN) in the outbound payload |

## Key Fields to Inspect

**[ANALYST]**
- `src_ip` / `src_host` - is this a workstation, server, or service account context? Servers with scheduled export jobs behave very differently from a marketing laptop.
- `dst_ip`, `dst_domain`, `dst_asn` - resolve to owning organization. A destination IP owned by a known cloud provider (AWS, Azure, GCP, Cloudflare) is ambiguous by itself - check the actual bucket/tenant, not just the cloud vendor.
- `bytes_sent` vs `bytes_received` - genuine exfil is heavily asymmetric (upload-dominant). A ratio near 1:1 over HTTPS often means normal browsing or a large download, not exfil.
- `duration` and `sustained rate` - one huge burst vs. steady drip over hours. Drip patterns matching DNS or ICMP tunneling behavior deserve separate scrutiny under T1071.004/T1572.
- `dst_port` / `app-id` - is the traffic on the port/protocol that app normally uses, or wrapped (e.g., port 443 traffic that isn't actually TLS)?
- `user` / `logon session` tied to the source process - service account, interactive user, or scheduled task SID?
- Parent process of the network connection (EDR) - `7z.exe`, `WinRAR.exe`, `rclone.exe`, `curl.exe`, `powershell.exe` spawning the transfer is a very different story than `outlook.exe` or `chrome.exe`.
- File staging evidence - recently created archive files (`.zip`, `.7z`, `.rar`) in temp/user directories timestamped just before the transfer.
- TLS SNI / JA3 fingerprint - mismatched SNI vs. certificate CN, or a JA3 hash associated with known exfil tooling (rclone, MEGAsync CLI, custom Python requests stacks).

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Destination | Corporate SaaS tenant (verified tenant ID), known partner IP, backup provider under contract | Personal cloud storage tenant, newly registered domain, IP with no reverse DNS, Tor exit node, dynamic DNS domain |
| Volume vs baseline | Within 2x of the host/user's 30-day average | 5x+ baseline, or absolute volume with no precedent for that asset class |
| Timing | Business hours, aligned with a known job schedule (nightly backup at 02:00 has run this way for a year) | Off-hours, especially just before a resignation date, holiday, or a scheduled outage window |
| Protocol | App-ID matches expected use (e.g., HTTPS to `*.salesforce.com` for CRM) | Protocol mismatch (non-TLS traffic on 443), tunneling indicators, raw sockets on uncommon ports |
| Precursor activity | None, or a known ETL/ELT job kicking off | Archive tool execution, bulk file access across many directories (T1119-style staging), LSASS access or credential-theft alerts in the prior 24 hours |
| Account context | Service account with documented purpose, or user matching their normal job function (finance analyst exporting a finance report) | User account touching data far outside their role (HR export volume from an engineer's laptop) |

## Investigation Steps

1. **Confirm the transfer is real and get exact numbers.** Pull the raw flow/proxy/firewall record for the alerting session - total bytes, direction, duration, protocol. Don't trust the SIEM's rounded summary field; cross-check against a second log source (e.g., firewall session log against NetFlow) since double-counting from asymmetric routing or logging at both perimeter and internal segments is a common false inflation.
2. **Identify the destination.** Resolve `dst_ip`/`dst_domain` to owning org via WHOIS/ASN lookup, check against threat intel and the corporate SaaS/vendor allowlist. Determine if this is a known-good tenant (ask: is this *our* instance of Dropbox/OneDrive, or someone else's?).
3. **Identify the process and user context on the source host.** Pull EDR process tree for the time window - what spawned the network connection, what was its parent, what files did it touch beforehand (staging/archiving behavior).
4. **Check for precursor and concurrent alerts.** Query EDR/SIEM for credential access, defense impairment, or discovery activity on the same host in the prior 24-48 hours. A large transfer arriving with no other context is lower-confidence than one arriving after a chain of suspicious steps.
5. **Validate against known business processes.** Check change records, backup schedules, data-sharing agreements, and ask the asset owner or their manager directly - a surprising number of "exfil" alerts are an undocumented but legitimate export job.
6. **Assess data sensitivity, if DLP or content inspection is available.** Determine whether the payload (or file names/paths staged beforehand) touch regulated or crown-jewel data categories - this materially changes escalation urgency even if the transfer turns out authorized-but-undocumented.
7. **Check for repeat/low-and-slow pattern.** Search historical logs for the same source/destination pair over the prior 7-30 days - a single large spike is different from a host that's been trickling data out daily and just crossed the threshold.
8. **Determine account and asset status.** Is the user account active, recently offboarded, or under a PIP/investigation flag with HR/Legal already? Is the asset corporate-managed or BYOD? This drives who needs to be looped in before containment.

## True Positive Indicators

- Destination is a personal cloud storage account, unaffiliated file-sharing site, or an IP/domain with no legitimate business relationship to the org.
- Archive/compression or transfer-tooling (rclone, WinRAR, curl with upload flags, custom exfil scripts) observed staging or moving the data.
- Transfer immediately follows credential theft, privilege escalation, or defense-impairment alerts on the same host.
- Volume and destination are inconsistent with the user's role and have no corresponding change ticket, backup job, or business justification.
- Departing/terminated employee, or account already flagged for HR/Legal review, moving data shortly before or after resignation notice.
- Beaconing/drip pattern consistent with DNS tunneling or protocol tunneling indicators (T1071.004, T1572) - encoded subdomains, abnormal query volume, non-standard TXT/NULL usage.

## False Positive / Benign Positive Indicators

- Confirmed scheduled backup, replication, or ETL job to an approved destination - check the change calendar and job scheduler logs.
- Large legitimate business file transfer (e.g., annual report to auditors, dataset to an approved analytics vendor) with a paper trail (ticket, email approval, contract).
- Software update, patch download, or OS/agent reimage pulling large data (note: direction matters - this is usually inbound-dominant, so check `bytes_received` isn't mislabeled as sent).
- Video conferencing, screen-sharing, or large legitimate cloud collaboration session (e.g., uploading a large design file to the corporate OneDrive tenant).
- Double-counted flow from asymmetric routing/logging at multiple network segments inflating the apparent volume of a single, smaller real transfer.
- Employee syncing to a corporate-sanctioned personal-device backup that was misclassified as "unapproved" due to an out-of-date allowlist.

## Escalation Criteria

Escalate to IR/Tier 2 immediately if: destination reputation is confirmed malicious or unrated-suspicious, the transfer is tied to a host with concurrent credential-theft or defense-impairment alerts, the data category is regulated (PII, PHI, PCI, source code, trade secrets) per DLP/content inspection, or the account involved is a departing/terminated employee or privileged/service account with no matching change record. Loop in Legal and HR immediately (not after containment) if an insider-threat angle is plausible - evidence handling requirements differ from a pure external-compromise case and acting first can complicate a later personnel action.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- **Block destination IP/domain at firewall/proxy** - SOC Tier 2 can action unilaterally for confirmed-malicious destinations; requires on-call network engineering sign-off for ambiguous SaaS domains shared with other business units.
- **Isolate endpoint via EDR** - Tier 2 analyst authority for hosts showing correlated compromise indicators; notify asset owner within the SLA window (typically 30 minutes) after isolation, not before, if active exfil is suspected.
- **Disable user account / revoke session tokens** - requires IT Security Manager approval; for suspected insider cases, HR and Legal must be looped in before or simultaneously with the disable action, per incident response policy.
- **Suspend service account / rotate credentials** - requires the application/system owner's sign-off given the blast radius of breaking a production integration; emergency exception process applies if active large-scale exfil is confirmed.
- **Preserve forensic evidence** (memory capture, disk image, retain flow/proxy logs beyond default retention) - IR lead authorizes and documents chain of custody, especially where an HR/Legal action may follow.
- Document every containment action with timestamp and approver in the case ticket - this becomes the record referenced in any regulatory notification timeline assessment.

## Example Query

**Splunk (proxy/firewall index, outbound volume by host over rolling window):**

```spl
index=network sourcetype=firewall action=allowed direction=outbound
| where bytes_sent > 500000000
| stats sum(bytes_sent) as total_sent, values(dst_ip) as destinations,
        values(dst_port) as ports, dc(dst_ip) as unique_dsts
        by src_ip, user
| where total_sent > 1000000000
| lookup asset_baseline.csv src_ip OUTPUT baseline_avg_bytes
| eval deviation_ratio = if(isnull(baseline_avg_bytes) OR baseline_avg_bytes=0, null(), round(total_sent / baseline_avg_bytes, 2))
| where deviation_ratio > 5 OR isnull(baseline_avg_bytes)
| sort - total_sent
```

Note on the `deviation_ratio` line: a host missing from `asset_baseline.csv` (new asset, never baselined) or with a zero baseline would otherwise divide to null and get silently dropped by a plain `where deviation_ratio > 5` filter — exactly the case where a brand-new host moving several GB deserves the most scrutiny. The `OR isnull(baseline_avg_bytes)` clause keeps unbaselined hosts in the result set instead of quietly excluding them.

## Closure Criteria

Close as **True Positive** (confirmed exfiltration) only after destination, volume, and data category are validated and containment/notification actions are logged. Close as **Benign Positive / Expected Activity** when the transfer maps to a documented business process, change ticket, or verified corporate-owned destination. Close as **Insufficient Evidence** when flow data exists but source process, user context, or destination content cannot be determined due to log gaps (e.g., proxy bypassed via direct-to-IP TLS, missing DLP inspection) - document exactly which telemetry was missing so the gap can be raised with engineering rather than silently repeating every time this alert fires.

**Example case note:**
`2026-09-15 03:14 UTC - HOST WKS-FIN-0042 (user j.alvarez) sent 2.3GB to 198.51.100.77 (dst_domain: file-transfer-quickshare.example.net, unrated/no business relationship) over HTTPS, port 443, non-standard TLS handshake (JA3 matches known rclone client). Preceded by 7z.exe archiving of \Finance\Q3_Forecasts\ at 03:02 UTC. No matching change ticket or backup schedule. Escalated to Tier 2 IR and notified Finance director + HR per insider-threat protocol; endpoint isolated via EDR at 03:22 UTC; destination blocked at proxy. Classified True Positive (confirmed exfiltration), pending forensic image review.`
