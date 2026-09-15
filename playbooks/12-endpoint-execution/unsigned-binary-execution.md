# EP-014: Unsigned Binary Execution

**Category:** Endpoint - Execution & LOLBins

## Business Risk

**[STAKEHOLDER]** - Every modern OS and AV vendor treats code signing as a trust anchor: a valid signature means a known publisher vouches for that binary and it hasn't been tampered with since. An unsigned executable landing on a workstation and running isn't automatically malicious - plenty of legitimate freeware and internal tooling is unsigned - but it's the single most common shape a first-stage payload takes, because it's cheap for an attacker to produce and doesn't require stealing or forging a certificate. This playbook is the workhorse detection for "something new just ran that nobody vetted," and it's usually the earliest point in the kill chain where the SOC has a real chance to stop a loader before it becomes a ransomware event or a data-theft incident. The tradeoff stakeholders need to accept up front: this control is noisy by nature, and tuning it well (allow-listing known internal unsigned tools) is what keeps analysts able to act on the alerts that matter.

## Severity / Priority Default

**Medium** on initial trigger for a standard user workstation. Escalates to **High** immediately if the binary is dropped by a browser/mail client and initiates outbound network activity within seconds of launch, and to **Critical** if the host is a server, domain controller, or executive endpoint, or if credential-access behavior (LSASS handle access) is observed nearby.

## MITRE ATT&CK Techniques

- **T1204** - User Execution (the user, or a script acting on their behalf, launches the binary - primary trigger for most cases)
- **T1105** - Ingress Tool Transfer (how the binary got onto the host in the first place - download, attachment, drop by another process)
- **T1027** - Obfuscated Files or Information (packed/crypted binaries, mismatched or stripped file metadata, high-entropy filenames)
- **T1059.001 / T1059.003** - Command and Scripting Interpreter: PowerShell / Windows Command Shell (common child processes once the binary executes)
- **T1218** (.005 Mshta, .010 Regsvr32, .011 Rundll32) - System Binary Proxy Execution - relevant when the unsigned payload is actually a DLL or script proxied through a signed LOLBin rather than run directly; hand off to the dedicated playbook for that binary if this is the pattern
- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys - common persistence follow-on, covered in depth by the persistence category, referenced here only as a pivot point

## Trigger / Detection Logic Summary

Alert fires on process creation where the executing image fails Authenticode signature validation (`SignatureStatus` not `Valid`, or `Signed=false`) **and** at least one of the following holds: the image resides in a user-writable location (`%TEMP%`, `%AppData%`, `Downloads`, `%ProgramData%`, a mapped/removable drive); the SHA256 hash has zero or near-zero prevalence across the environment's process-creation baseline; the file's internal metadata (`OriginalFileName`, `Product`, `Company`) is empty, generic, or mismatched against the on-disk filename (a classic masquerading tell - e.g. a file named `chrome_update.exe` with no `Company` field and an `OriginalFileName` of `a1b2c3.exe`). Split this into two tiers in the rule logic: a high-fidelity tier (unsigned + user-writable path + zero prevalence) that pages Tier 1 directly, and a lower-fidelity tier (unsigned but signed-adjacent, e.g. self-signed dev certs on a known dev host) that queues for batch triage. Collapsing both into one severity just trains analysts to ignore the alert.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Hashes, `Signed`/`Signature`/`SignatureStatus`, full command line, parent chain, integrity level - the core record for this playbook |
| Sysmon | 11 (FileCreate) | Correlates the binary's drop event - what wrote it, and when, relative to execution |
| Sysmon | 15 (FileCreateStreamHash) | Zone Identifier ADS (mark-of-the-web) confirming the file arrived via download/attachment rather than pre-existing |
| Sysmon | 3 (Network Connection) | Outbound activity attributed to the new process's PID immediately post-launch |
| Sysmon | 22 (DNSEvent) | DNS resolution tied to the same process, useful for beacon domain identification |
| Sysmon | 12/13 (RegistryEvent) | Persistence check - Run key creation/modification tied to the same process or user session |
| Windows Security | 4688 | Fallback/corroborating process-creation record (command line only if auditing enabled) |
| Windows Security | 4697 | Service installation if the binary persists as a service |
| System | 7045 | Service creation (System log SCM source) - often catches what 4697 misses if Security auditing is thin |
| Security | 4698 | Scheduled task creation if persistence is task-based |
| Security | 1102 | Audit log cleared - high-signal anti-forensics if it follows shortly after |

## Key Fields to Inspect

**[ANALYST]**
- `Hashes` (SHA256/IMPHASH) - pivot to internal prevalence data and external threat intel/VirusTotal before anything else
- `SignatureStatus` / `Signed` / `Signature` - don't just trust the boolean; check whether it's genuinely unsigned versus self-signed with a plausible-looking (but unverified) publisher
- `Image` path - user-writable location is the strongest single positional signal
- `OriginalFileName`, `Company`, `Product`, `Description` - metadata mismatch against the on-disk name is a masquerading tell
- `CommandLine` and `ParentImage`/`ParentCommandLine` - what launched it (browser, mail client, another dropper) and what arguments it was given
- `IntegrityLevel` - medium is normal for a user double-click; anything auto-elevated warrants a look at how
- Sysmon 15 `Contents`/zone identifier value - `ZoneId=3` (Internet) confirms browser/mail delivery
- Sysmon 3/22 destination IP, port, and `QueryName` tied to the same `ProcessGuid`, and the delta in seconds between process start and first connection

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Signature status | Unsigned, but matches a cataloged internal tool or known freeware with stable hash history | Unsigned, first time this hash/filename has ever been seen in the environment |
| File location | `Program Files`, a defined internal-tools share, developer build output on a dev-tagged host | `Downloads`, `AppData\Local\Temp`, `AppData\Roaming`, root of `C:\ProgramData`, removable media |
| Metadata | `Company`/`Product` populated and consistent with filename, even if unsigned | Metadata empty, or claims a well-known vendor (e.g. "Microsoft Corporation") while remaining unsigned - a spoofed-metadata red flag |
| Delivery vector | IT deployment tool (SCCM/Intune), manual admin copy, known internal build pipeline | Browser download, email attachment extraction, dropped by another process moments earlier |
| Post-launch behavior | No network activity, or expected local-only operation | Outbound connection/DNS lookup within seconds, followed by additional file drops |
| Persistence | None, or a documented, ticketed change | New Run key, scheduled task, or service tied to the same binary/user session |

## Investigation Steps

1. Pull the Sysmon Event ID 1 record for the process: hash, `SignatureStatus`, full path, command line, parent image/command line, and integrity level. Confirm this is genuinely unsigned and not a signature-check artifact (revocation check failure on a machine with no internet access can misreport as invalid - verify before treating it as a true unsigned finding).
2. Check hash and filename prevalence against your environment baseline and internal tool inventory. If it's a known, cataloged unsigned utility with a stable hash across many hosts, this likely closes fast as Benign Positive - don't spend an hour re-proving what's already documented.
3. Trace delivery: check Sysmon 11 for the file-creation event and Sysmon 15 for a Zone Identifier ADS. A `ZoneId=3` value plus a browser or mail client as the ultimate ancestor process strongly suggests external delivery rather than IT deployment.
4. Walk the parent-child chain (Sysmon 1). `explorer.exe` parent with a recent interactive logon (4624) reads differently than a browser or `OUTLOOK.EXE` parent immediately after an attachment was opened.
5. Pivot on Sysmon 3/22 for the process's PID - any outbound connection or DNS query in the first 60 seconds after launch is worth reputation-checking against threat intel immediately, and note whether the destination is a bare IP, a newly registered domain, or a known CDN being abused for staging.
6. Check for persistence: Sysmon 12/13 registry writes to Run/RunOnce keys, 4698 scheduled task creation, or 4697/7045 service installation tied to the same binary, user, or timeframe.
7. Submit the hash to your sandbox or TI platform if policy allows, and cross-check against other hosts in the environment for the same hash or filename - a single unique hash across multiple endpoints usually means a campaign, not an isolated event.
8. If findings support malicious intent, preserve the sample and relevant Sysmon/EDR telemetry before remediation destroys evidence, then move to containment.

## True Positive Indicators

- Unsigned binary, zero prior prevalence, executed from a user-writable path immediately after a browser download or email attachment extraction
- Metadata mismatch (spoofed `Company`/`Product` field claiming a trusted vendor while remaining unsigned)
- Outbound connection or DNS lookup to a low-reputation or newly registered destination within seconds of execution
- Hash matches a known malware family or loader in threat intel, or detonates with malicious behavior in sandboxing
- Persistence artifact (Run key, scheduled task, service) created by or tied to the same process shortly after launch
- Process access to `lsass.exe`, disabling of AV/EDR components, or spawning of `cmd.exe`/`powershell.exe` with suspicious arguments

## False Positive / Benign Positive Indicators

- Hash matches a cataloged, documented internal tool or known freeware utility with a stable, unchanged hash history across the environment
- Delivery traced to an authorized IT deployment mechanism (SCCM, Intune, RMM push) rather than user-initiated download
- Host is a designated developer/build/test machine and the binary is self-compiled output, consistent with that role
- No network activity, no persistence, and no child processes following execution
- Metadata is consistent and unremarkable (populated `Company`/`Product` matching the filename), even though the file is unsigned by design (many legitimate open-source freeware packages ship this way)

## Escalation Criteria

Escalate to Tier 2/IR when: confirmed outbound beaconing follows execution; the same hash or filename appears on more than one host; the affected asset is a server, domain controller, or VIP endpoint; persistence (Run key, scheduled task, or service) is confirmed; process access to `lsass.exe` is observed (hand off to the credential-dumping playbook); or EDR/AV independently flags the same hash with a malware verdict.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Kill the process and quarantine the file - Tier 1/2 analyst authority once execution is confirmed unsigned and behaviorally suspicious, no separate approval required
- Isolate a standard user workstation via EDR network isolation - Tier 2 analyst may action directly under delegated authority
- Isolate a server, domain controller, or VIP asset - requires IR Lead or on-call manager sign-off before isolation, given business-continuity impact
- Block the associated hash, domain, and IP fleet-wide at EDR/proxy/firewall - SOC Engineering actions on Tier 2 request, logged in the ticket
- Disable the associated user account if credential compromise is suspected - routed to IAM/Helpdesk with IR Lead approval
- Add a hash/path exception to the detection rule for confirmed benign internal tools - requires Detection Engineering review and sign-off, not a unilateral analyst call, to avoid quietly blinding the control

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once the case escalates to High (browser/mail-delivered binary with a network callout) or Critical (server/DC/executive endpoint, or LSASS handle access).

## Example Query (Splunk SPL)

```spl
index=sysmon EventCode=1
| where SignatureStatus!="Valid"
| where match(Image, "(?i)\\\\(temp|appdata|downloads|programdata)\\\\")
| lookup known_unsigned_tools.csv Hashes OUTPUT known_tool
| where isnull(known_tool)
| stats count min(_time) as first_seen by Computer, User, Image, Hashes, ParentImage, CommandLine
```

## Closure Criteria

Close as **True Positive** once the hash/behavior is confirmed malicious via sandboxing or TI, the delivery vector is identified, and containment is verified on every affected host. Close as **Benign Positive** or **Expected Activity** when the hash matches a cataloged internal or freeware tool, delivery traces to an authorized deployment path, and no network/persistence anomalies exist. Close as **Insufficient Evidence** when the file was deleted before hashing/sandboxing was possible and no EDR retro-hunt or backup telemetry can recover it.

**Example case note:**
> 2026-09-15 09:47 UTC - WKS-FIN-021 (finance workstation, user j.alvarez) - Sysmon 1 shows unsigned binary `C:\Users\j.alvarez\Downloads\invoice_update.exe` (SHA256 3f2a9c...d41e) executed, parent `chrome.exe`. `SignatureStatus=Unsigned`, `Company` field empty, zero prior prevalence in environment (checked against 90-day baseline). Sysmon 15 confirmed Zone Identifier ADS (`ZoneId=3`, Internet). Sysmon 3 showed outbound connection to 203.0.113.50:443 approximately 9 seconds post-launch; no prior DNS query logged (direct IP connect). Sysmon 13 recorded a new `HKCU\...\Run\Updater` value pointing back at the same binary roughly 40 seconds later. Classified True Positive - trojan downloader delivered via drive-by/malvertising (T1204/T1105). Host isolated via EDR (Tier 2 authority, standard workstation), hash and destination IP blocked fleet-wide, user notified, account credentials rotated as precaution, no lateral spread confirmed on subsequent hash sweep.
