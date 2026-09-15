# Windows Logon Types Reference

Every 4624 and 4625 event carries a Logon Type field, and if you're triaging without looking at it, you're throwing away the single most useful piece of context on the record. The account name tells you *who*. The Logon Type tells you *how* - and how matters more than who when working out whether something is a help desk tech doing their job or an attacker moving laterally with stolen creds. This section covers what each type means, what normal looks like, and the investigation flow to run before writing a verdict. The type numbers don't change meaning between Windows Server versions - learn them once, use them for the rest of your career.

## The Logon Type Table

| Type | Name | What it actually is | Typical trigger |
|---|---|---|---|
| 2 | Interactive | Local console logon - someone physically at the keyboard, or a KVM/iDRAC-style console session | User logs in at a workstation or server console |
| 3 | Network | Credentials presented over the network, no interactive session and no cached creds left on the target | SMB share access, `net use`, most service-to-service calls, print spoolers |
| 4 | Batch | Logon under a scheduled task's execution context | Scheduled Task Service running a job as a stored account |
| 5 | Service | Service startup using a configured service account | SCM starts a service configured to run as a domain or local service account |
| 7 | Unlock | Workstation unlock after screen lock | User re-enters password/PIN to unlock a locked session |
| 8 | NetworkCleartext | Network logon where the credential was sent in cleartext to the authenticating box | Basic-auth IIS sites, some legacy or misconfigured apps, occasionally IIS with ASP scripts calling `LogonUser` |
| 9 | NewCredentials | Existing session kept, but a new set of outbound credentials is attached for network connections | `runas /netonly`, some credential-switching tooling |
| 10 | RemoteInteractive | RDP / Terminal Services logon | User opens a Remote Desktop session to a host |
| 11 | CachedInteractive | Interactive logon validated against cached domain credentials, no DC contacted | Laptop logs in with domain creds while offline or DC unreachable |

That's the full set stamped on 4624/4625 in this environment. A number outside this list in your own tooling is worth checking against Microsoft Learn rather than assumed to be a typo of one of these.

## Walking Through Each Type

**Type 2 - Interactive.** A human sat down and typed a password into a console. Expected constantly on workstations; rarer and more interesting on a domain controller or production server, where admin work should mostly happen over RDP (Type 10) or PowerShell remoting instead. **[ANALYST]** - baseline against asset class: a help desk laptop showing dozens a day is normal, a locked-datacenter finance server showing Type 2 from an account off the approved list is a "find out who has console access right now" moment.

**Type 3 - Network.** The workhorse type - share access, print jobs, most service-to-service auth, `net use`, PsExec's initial connection. No credentials get cached on the target, part of why attackers like it for lateral movement. **[ENGINEERING]** - don't alert on Type 3 volume alone; alert on it combined with something else, e.g. a service account hitting a workstation it's never touched, or a burst against multiple hosts from one source in a short window (lateral-movement/password-spray shape).

**Type 4 - Batch.** Scheduled Task Service logons. A new Type 4 right after a 4698 (scheduled task created) on an account with no prior batch history is a known persistence pattern.

**Type 5 - Service.** Service account startup, ties naturally to 4697 (service installed, Security log) and 7045 (new service installed, System log). A Type 5 moments after either, on an account you don't recognize as a legitimate service account, is a strong lead. **[ENGINEERING]** - correlate first-time-seen Type 5 with 7045/4697 on the same host and time window; catches a meaningful share of malicious-service persistence with just a join on host plus a short time delta.

**Type 7 - Unlock.** Screen unlock, mostly noise. Interesting only when it happens on a host with no business having an active locked session - e.g. the last interactive logon (Type 2) was a different user, or the presumed user is confirmed elsewhere via badge data. A soft signal, surfaced by correlation rather than standing alone.

**Type 8 - NetworkCleartext.** Cleartext credentials handed to the authenticating system - basic-auth web apps, legacy IIS configs, or scripts calling `LogonUser` with plaintext creds. Doesn't necessarily mean the credential was cleartext on the wire (TLS may still wrap it), but the app skipped a challenge-response mechanism. **[STAKEHOLDER]** - unexpected Type 8 usually means an app needs a config fix (move off basic auth) rather than an active intrusion, but still worth a ticket to the app owner - cleartext auth paths are exactly what credential-sniffing depends on.

**Type 9 - NewCredentials.** `runas /netonly` and similar - the original session keeps its identity locally, but a different set of credentials goes out over the network. Admins use this legitimately against a different domain/forest without re-authenticating the whole session; attackers use the same mechanism to stage stolen credentials while keeping their foothold session intact. Same event either way - the type alone won't tell you which.

**Type 10 - RemoteInteractive (RDP).** The type analysts spend the most time on - RDP is both a completely normal admin tool and a top-tier initial-access and lateral-movement vector. Full worked example below.

**Type 11 - CachedInteractive.** Domain credentials validated against the local cache, no DC contact. Normal for laptops on the road or anywhere the DC isn't reachable. More interesting on a machine that should always have DC connectivity, where repeated Type 11 can mean DC connectivity problems (an ops issue) or, less commonly, deliberate isolation from the DC to dodge Kerberos-based detection while still authenticating locally.

## Worked Caution: Type 10 RDP From an Unusual Source

Here's the scenario, written the way it actually lands in a queue:

```text
EventID: 4624
LogonType: 10
Account Name: svc-fin-admin
Account Domain: CORP
Workstation Name: FIN-DC01
Source Network Address: 203.0.113.44
Source Port: 51710
Authentication Package: Negotiate
Time: 2026-09-13 02:47:11 (local, host timezone UTC-5)
```

A 4624 Type 10 from an external-looking source IP, on a privileged account, at 2:47am outside its normal pattern - that's exactly the shape of a suspicious RDP alert, and it should generate a ticket. What it should **not** do is get auto-labeled malicious off this one event. It's a *trigger for investigation*, not a verdict. Plenty of legitimate reasons produce this same log line: an approved after-hours change window, a jump host or VPN concentrator whose public IP looks "external" to naive geo-lookups, an admin in a different timezone, or break-glass access under an active incident ticket.

### The investigation flow, in order

1. **Baseline the account's historical logon locations.** Pull 30-90 days of 4624 Type 10 for `svc-fin-admin`: Source Network Address, typical hours. Has 203.0.113.44 been seen before? Is 2:47am ever normal (month-end close, patch windows)?
2. **Check whether the source IP is a VPN or jump-host egress, not a "real" external address.** Cross-reference against the VPN concentrator's known egress ranges and jump-host inventory. Plenty of "external IP" alerts collapse the moment it turns out to be the corporate VPN's NAT address doing its job.
3. **Check for a ticket or change record covering this access.** An approved maintenance window or break-glass record justifies after-hours privileged access on its own. No ticket doesn't prove malice, but removes the easiest explanation and raises priority.
4. **Check the MFA result for the session**, where the environment requires MFA on privileged RDP (gateway, NPS extension, or conditional-access layer upstream - native RDP itself doesn't log MFA). A satisfied challenge from a known device is reassuring; absent or bypassed MFA is a red flag on its own.
5. **Pull endpoint telemetry for the destination host across the session window.** Look for new process creation (4688), service installs (4697/7045), scheduled task creation (4698), or PowerShell activity (4103/4104) minutes after the 4624. Check for a paired 4672 confirming the token was admin-equivalent, and the matching 4634/4647 logoff for session duration - two minutes at 2am reads very differently than four hours.
6. **Only after 1-5** write the verdict: True Positive (no VPN match, no ticket, MFA missing, followed by service installs and 4104 showing an encoded payload), Benign Positive (VPN egress confirmed, ticket found, MFA satisfied, no odd follow-on activity), or Insufficient Evidence (command-line auditing off so 4688 has no arguments, or an endpoint-agent gap). Insufficient Evidence is a legitimate closure - note exactly what's missing so the next analyst doesn't re-derive it.

Steps 1-4 sit comfortably with an Tier 1 analyst working from documented baselines and the ticket queue. Step 5 usually needs Tier 2 - it's process-tree and cross-log correlation, not a lookup. If step 5 turns up service installs, scheduled tasks, or an encoded PowerShell payload, that's the point to hand off to Tier 3/IR rather than have Tier 2 keep pulling telemetry solo - this split is a starting point to adapt to your own team's staffing, not a fixed rule.

**[ANALYST]** - don't assume no follow-up 4688/4104 means nothing happened; it may just mean auditing wasn't enabled on that host. Confirm the audit policy before treating "nothing found" as "nothing occurred" - conflating those closes real intrusions as benign more often than you'd think.

**[ENGINEERING]** - a useful correlation rule pairs 4624 Type 10 on privileged accounts (via the paired 4672 on the same Logon ID) with source IPs absent from a maintained VPN/jump-host allow-list, outside business hours, with no matching change-ticket ID. Fire it as medium-severity for human review, not an auto-block - timezone-shifted admins and break-glass access make this pattern too false-positive-prone for auto-remediation.

**[MANAGEMENT]** - sits in the privileged-access monitoring use case, owned jointly by SOC and IT operations (who maintain the allow-list and ticket integration). This shape - privileged, after-hours, external-looking RDP - belongs in your highest triage tier, given the asymmetry between a slow response to a live intrusion and a fast dismissal of a benign one. Review the allow-list and business-hours definitions quarterly.

## Quick Cross-Reference: Logon Type to Related Events

| Logon Type | Commonly paired with | Why the pairing matters |
|---|---|---|
| 2 | 4634/4647, 4672 | Confirms local console session start/end and whether it carried privilege |
| 3 | 4648 | Explicit-credential network connections riding on Type 3 are a lateral-movement tell |
| 4 | 4698/4699/4702 | New or modified scheduled task followed by its Batch execution |
| 5 | 4697, 7045 | New/changed service followed by its first service-account startup |
| 8 | - | Flag the authenticating application for a config review regardless of outcome |
| 9 | 4648 | `runas /netonly` sessions frequently show explicit-credential use right after |
| 10 | 4672, 4688, 4103/4104 | Privilege confirmation and post-logon activity on the destination host |
| 11 | 4776 (on the DC, when cache later reconciles) | Confirms whether the cached credential was subsequently validated |

Logon Type on its own answers "how did they get in." The combination with process, service, and scheduled-task telemetry answers "what did they do once they were in" - and that second question is the one that actually decides the verdict.
