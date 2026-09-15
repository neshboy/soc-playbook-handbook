# Appendix 36C: Quick Reference - Linux Auth Logs, Cloud/M365 Log Sources, Email Headers & Network Investigation Fields

Four lookup tables analysts reach for most outside the Windows world: where Linux actually writes its auth events (varies by distro more than people expect), where the cloud/SaaS logs for an M365 or Azure investigation actually live, what each email header is telling you and where forgers slip up, and the firewall/proxy/DNS fields that seperate a real pivot from another afternoon chasing a scanner. Detailed walkthroughs sit in their own chapters - this is the laminate-it version.

## Linux Authentication Log Locations

Linux logging is not standardized the way the Windows Security log is. The path, the format, and even whether a given event is logged at all depends on the distro family, the init system, and whether `rsyslog`, `syslog-ng`, or `journald` is doing the writing. Check `/etc/rsyslog.conf` (or the systemd journal config) before assuming a log doesn't exist - it may just be routed somewhere non-default, or rotated out already.

| Log Path | Distro Family | What It Contains |
|---|---|---|
| `/var/log/auth.log` | Debian, Ubuntu | SSH logins/failures, `sudo` usage, PAM events, user/group changes |
| `/var/log/secure` | RHEL, CentOS, Fedora, Amazon Linux | Same role as `auth.log` - SSH, `sudo`, PAM, `su` |
| `/var/log/audit/audit.log` | Any distro with `auditd` running | Syscall-level audit records (execve, file access) - keyed by rule, not just auth |
| `journalctl -u sshd` / `journalctl _COMM=sshd` | systemd-based distros | Journal equivalent of `auth.log`/`secure` for the SSH daemon specifically |
| `/var/log/wtmp` | Most distros | Binary login/logout/reboot history - read with `last`, not a text editor |
| `/var/log/btmp` | Most distros | Binary record of failed login attempts - read with `lastb` |
| `/var/log/lastlog` | Most distros | Per-user timestamp of most recent login - read with `lastlog` |
| `/var/log/faillog` | Distros using `pam_tally2`/`faillog` | Historical failed-login counters (largely superseded by `pam_faillock`) |
| `/var/log/sudo.log` (or embedded in `auth.log`/`secure`) | Varies | Dedicated `sudo` command log if `Defaults logfile=` is set in `sudoers` |
| `/var/log/cron` | RHEL/CentOS family | Cron job execution - relevant when persistence rides in on a scheduled task |
| `~/.bash_history`, `~/.ssh/authorized_keys` | Per-user, any distro | Not a syslog entry, but standard evidence - command history and key-based auth trust list |

**[ANALYST]** - On a suspected compromised Linux host, pull `auth.log`/`secure` for the auth trail, `wtmp`/`btmp` for a fast timeline of successful vs. failed sessions, and `~/.ssh/authorized_keys` for every account that could log in without a password. `auditd`, if running, is the richest source but also the noisiest - filter by `key` or `syscall` before reading it raw. Don't assume rotation happened cleanly: `logrotate` compresses old logs to `auth.log.1.gz`, and a lot of first-pass triage misses the incident because nobody thought to `zgrep` the rotated files.

**[ENGINEERING]** - When shipping to a SIEM, normalize on `journald` output where available (structured fields, less regex fragility) rather than parsing free-text `auth.log` lines. On containerized hosts, the "auth log" for a workload is often the container runtime's stdout capture, not a file inside the container at all - `docker logs`/`kubectl logs` becomes the real source, and the host-level auth log only shows the orchestrator's own SSH sessions.

## Common AWS / Azure / Entra ID / M365 Log Sources

Cloud investigations fail more often from "we didn't know that log existed" than from bad detection logic. Retention and licensing tier gate a lot of this - always confirm what's actually enabled before promising a stakeholder you can reconstruct three months of activity.

| Log Source | Platform | Typical Use |
|---|---|---|
| CloudTrail (management + data events) | AWS | API call history - who called what, from where; data events add S3/Lambda object-level activity |
| VPC Flow Logs | AWS | Accept/reject records between ENIs - source/dest IP, port, protocol, bytes, action |
| GuardDuty findings | AWS | Managed threat-detection alerts (credential compromise, recon, crypto-mining, C2) from CloudTrail/DNS/Flow Log telemetry |
| S3 access logs / CloudTrail data events | AWS | Object-level GET/PUT/DELETE on buckets - critical for data-exfil cases |
| Azure Activity Log | Azure | Subscription-level control-plane ops - resource create/modify/delete, role assignments |
| Azure Diagnostic Logs | Azure | Resource-level logs (NSG flow logs, Key Vault access, App Service logs) - enabled per resource |
| Entra ID Sign-in Logs | Entra ID (formerly Azure AD) | Interactive/non-interactive sign-ins - user, app, IP, location, Conditional Access result, risk state |
| Entra ID Audit Logs | Entra ID | Directory changes - user/group/app creation, role assignment, policy edits |
| Entra ID Risky Sign-ins / Risk Detections | Entra ID Protection (P2) | ML risk signals - impossible travel, anonymized IP, leaked credential, atypical travel |
| Microsoft Purview Audit (Unified Audit Log / UAL) | M365 | Cross-workload activity - Exchange, SharePoint, Teams, Power Platform in one searchable log; "Unified Audit Log" survives as the technical/PowerShell-cmdlet name (`Search-UnifiedAuditLog`) even though the product-facing name is now Microsoft Purview Audit |
| Exchange Online mailbox audit log | M365 / Exchange Online | Mailbox-level actions - mail read, moved, forwarded, rules created, delegate changes |
| Message Trace / Mail flow reporting | Exchange Online Protection | Per-message delivery path and disposition - short retention, export early |
| Defender for Office 365 (Threat Explorer) | M365 Defender | Phishing/malware detections and remediation across mail flow |
| SharePoint/OneDrive activity (within UAL) | M365 | File access, sharing link creation, download/sync events |

**[ANALYST]** - For a suspected M365 account compromise, pull Entra ID sign-in logs first (IP, device, Conditional Access outcome, whether MFA was satisfied or bypassed), then cross-reference Microsoft Purview Audit (the Unified Audit Log) for mailbox rule creation, forwarding rule changes, and OAuth app consents - BEC almost always leaves at least one of those fingerprints. Watch for UAL search delay: events can take hours to appear, and default retention on lower licensing tiers is shorter than analysts expect - verify current tier limits rather than assuming 90 or 180 days.

**[ENGINEERING]** - CloudTrail and Entra ID sign-in logs both suffer from service-account and system-app noise that drowns a naive correlation rule; baseline expected caller identities (`userIdentity.type` in CloudTrail, `appId`/`servicePrincipalId` in Entra) before alerting on "unusual API call" or "sign-in from new app." For cross-cloud correlation, normalize timestamps to UTC at ingestion - AWS and Azure logs are UTC by default, but the SIEM's display timezone is a frequent source of "the attacker logged in before the phishing email arrived" false alarms that are actually just a rendering bug.

**[MANAGEMENT]** - Log retention and licensing tier (Entra ID P1 vs P2, M365 E3 vs E5) directly determine investigative reach-back. This should be a documented decision with an owner, not something discovered mid-incident - a 90-day investigative blind spot the business can't tolerate is a licensing conversation, not a SOC workaround.

## Common Email Header Fields for Phishing/BEC Investigation

Headers are read bottom-to-top for the actual mail path (the top `Received` header is the most recent hop, closest to the recipient); everything below that traces back toward the origin.

| Header | What It Tells You | What To Check |
|---|---|---|
| `Received` (each hop) | Chain of mail servers transited, with timestamps and reported IPs | Read bottom-up for chronological order; look for gaps, unexpected hops, or an origin IP inconsistent with the claimed sender's infrastructure |
| `Return-Path` | Where bounce/NDR messages go - the actual envelope sender (MAIL FROM) | Compare against the visible `From` display name - mismatch is a classic spoofing/BEC tell |
| `From` | Display name and address shown to the user | Display name can say anything; the address after the `@` is what matters, and even that can be spoofed without SPF/DKIM enforcement |
| `Reply-To` | Where replies actually route if the recipient hits Reply | A different domain than `From` is a common BEC pattern - victim replies to the "CEO," reply goes to attacker infra |
| `Message-ID` | Unique identifier assigned by the originating mail system | Format and domain often reveal the true sending platform even when `From` is spoofed |
| `Authentication-Results` | Receiving server's verdict on SPF, DKIM, DMARC for this message | Fastest path to a verdict - `spf=fail`, `dkim=fail`, or `dmarc=fail` on a message claiming a trusted domain is high-confidence spoofing |
| SPF (within `Authentication-Results` or `Received-SPF`) | Whether the sending IP is authorized in the claimed domain's SPF TXT record | `pass`/`fail`/`softfail`/`neutral`/`none` - a `pass` only validates the envelope sender's IP, not the `From` display domain |
| DKIM (within `Authentication-Results`) | Whether the message was cryptographically signed by the claimed domain and the signature validates | `pass` means signed content wasn't altered in transit and the signing domain (`d=` tag) controlled the key - check `d=` matches the sender's real domain |
| DMARC (within `Authentication-Results`) | Policy alignment combining SPF/DKIM with the visible `From` domain | `pass`/`fail` plus published policy (`p=none`/`quarantine`/`reject`) - `p=none` blocks nothing even on failure, which is why spoofed mail from DMARC-enabled domains still lands |
| `X-Originating-IP` / `X-Sender-IP` | Non-standard but common header some MTAs add showing the client IP that submitted the message | Not always present or trustworthy if inserted by an untrusted upstream hop, but useful when it exists |
| `Received-SPF` | Verbose SPF result string, distinct from the compact `Authentication-Results` line | Older format still seen from some MTAs - same meaning as SPF result above |

**[ANALYST]** - Don't stop at "DMARC passed, so it's legit." DMARC alignment only proves the `From` domain's owner authorized the sending infrastructure and the signature is intact - it says nothing about whether that domain is a look-alike (`example-corp.com` vs `example.com`) or a compromised legitimate partner. Pull the raw headers (webmail clients hide this behind "show original"/"view source"), and if `Return-Path` and `Reply-To` both point somewhere other than `From`, treat that as your primary lead, not a footnote.

**[ENGINEERING]** - When building detection on `Authentication-Results`, be explicit about which service inserted the header - a forwarded message can carry a stale or attacker-controlled version from an untrusted intermediate hop if your MTA doesn't strip and re-evaluate on ingress. Anchor trust to the header your own receiving infrastructure inserted, not any header present in the message as received from outside.

## Common Firewall / Proxy / DNS Investigation Fields

These three telemetry types get correlated together constantly - a DNS query for a bad domain, a proxy connection to the resolved IP, and a firewall log confirming whether the connection was allowed or blocked. The fields below are what you actually pull first.

| Field | Firewall | Proxy | DNS |
|---|---|---|---|
| Source IP/Port | Originating host and ephemeral port | Client IP making the request | Querying host/resolver IP |
| Destination IP/Port | Target IP and port | Destination IP after resolution | Answer/resolved IP(s) in the response |
| Protocol | TCP/UDP/ICMP, plus app-ID on L7-capable devices | Usually HTTP/HTTPS, sometimes SOCKS | UDP/TCP 53, or DoH/DoT if in use |
| Action/Disposition | Allow, deny, drop, reset | Allowed, blocked (category/reputation), TLS-inspected or bypassed | Answered, NXDOMAIN, blocked by DNS security service |
| Rule/Policy ID | Matched firewall rule | Matched category/policy | Matched blocklist/RPZ zone, if blocked |
| URL/Domain (FQDN) | Only with L7/App-ID inspection | Full requested URL, path and query string on unencrypted traffic | Queried domain name (`qname`) |
| Query Type | N/A | N/A | A, AAAA, TXT, MX, NS, CNAME - unusual TXT volume is a common tunneling tell |
| User-Agent | N/A (unless L7 inspection) | Client app/browser string - useful for spotting scripted tools masquerading as browsers | N/A |
| Bytes Sent/Received | Large outbound relative to inbound is a data-exfil flag | Same, per-request | N/A |
| Authenticated User | Only with identity-aware policy | Proxy-authenticated username, if enforced | N/A unless tied back to DHCP lease/user mapping |
| TLS SNI / Certificate CN | Visible even without decryption | Same - often survives even when payload is encrypted | N/A |
| Session Duration | Start/end timestamps, useful for beaconing analysis | Same | Record TTL - unusually low TTL is common in fast-flux infrastructure |

**[ANALYST]** - Start with the DNS query if you have it: it tells you what the host was trying to reach before you go hunting for the connection in firewall/proxy logs, which may show a different IP if the domain resolves to multiple addresses or sits behind a CDN. If the firewall log shows a `deny` for the destination IP but the proxy log shows an earlier `allow` for the same session, look for a policy change, a rule-ordering issue, or a second path out - a very common source of "we blocked it" claims that don't survive a second look.

**[ENGINEERING]** - Beaconing detection lives mostly in Session Duration/interval and Bytes Sent/Received - regular, low-jitter connection intervals with small, consistent payload sizes are the signature to build correlation logic around, more so than any single blocklist hit. For DNS, don't build tunneling detection on reputation alone; combine query-type distribution (heavy TXT/NULL record use), query volume per host, and subdomain entropy/length, since a first-seen malicious domain won't be on any reputation list yet.

**[MANAGEMENT]** - Retention and correlation across these three log types is an EPS/storage cost decision as much as a security one - full-payload proxy logging gets expensive fast at scale. Set retention SLAs that match your realistic investigative reach-back requirement rather than defaulting to "log everything forever" or trimming retention purely to cut ingestion cost.
