# Malicious Attachment

## Playbook ID & Name

**EML-004 — Malicious Attachment (File-Based Initial Access via Email)**

This playbook covers the file itself as the weapon, independent of how targeted the lure was — that framing question belongs to the Phishing and Spear Phishing playbooks in this category. Here the question is narrower and more mechanical: did a file arrive, was it opened, and did opening it do anything. Attachment tradecraft has moved almost entirely away from raw `.exe` files (mail gateways catch those trivially) toward container and script formats that either bypass mail-time scanning or rely on the user to do the dangerous step themselves — extracting an archive, mounting an ISO, clicking "Enable Content." Assume the attacker built the file specifically to survive whatever your gateway does, and start from the endpoint side, not the gateway verdict.

## Business Risk

**[STAKEHOLDER]** - A malicious attachment is the cheapest way for an outsider to get code running inside the building, because it uses the recipient's own hands to do the work antivirus signatures and network firewalls can't stop on their own. One opened file can lead to credential theft, a ransomware foothold, or a compromised finance workstation used for wire fraud — and because the "click" happens inside a normal workday, it often looks unremarkable until something downstream (a ransom note, a fraudulent transfer, an odd outbound connection) makes it obvious. Deciding whether to sandbox-detonate every inbound attachment type, and whether to block risky container formats org-wide, is a policy call for the SOC manager or CISO delegate — not something to relitigate on every ticket.

## Severity/Priority Default

**Medium** at intake for a quarantined/blocked attachment with no delivery. **High** if the message was delivered to the inbox regardless of open status. **Critical** if endpoint telemetry confirms the file was opened and a child process spawned, or if the recipient holds privileged/VIP access.

## MITRE ATT&CK Techniques

- T1566.001 Phishing: Attachment
- T1204 User Execution
- T1059.001 Command and Scripting Interpreter: PowerShell
- T1059.003 Command and Scripting Interpreter: Windows Command Shell
- T1218.005 System Binary Proxy Execution: Mshta
- T1218.010 System Binary Proxy Execution: Regsvr32
- T1218.011 System Binary Proxy Execution: Rundll32
- T1027 Obfuscated Files or Information
- T1105 Ingress Tool Transfer
- T1055 Process Injection — seen when the dropped payload is a loader rather than the final malware
- T1547.001 Boot or Logon Autostart Execution: Registry Run Keys — common persistence step after first execution
- T1053.005 Scheduled Task/Job: Scheduled Task — alternate persistence step
- T1562.001 Impair Defenses: Disable or Modify Tools — seen when the payload tries to kill AV/EDR before staging further activity

## Trigger / Detection Logic Summary

Any one of these opens a case:

1. Secure Email Gateway (SEG) / M365 Defender for Office 365 flags an attachment as malware, or a Safe Attachments-style detonation verdict flips to malicious after delivery (the message was already sitting in the inbox before the verdict landed — treat this as urgent, not informational).
2. Attachment matches a known-bad hash, or file type/container heuristics fire: macro-enabled Office document with an external template reference, ISO/IMG/VHD container, LNK file, OneNote file with an embedded object, nested/password-protected archive, or a filename with a double extension (`shipping_label.pdf.js`, `invoice.xlsx.exe`).
3. User-reported suspicious attachment via the Report Message add-in or abuse mailbox.
4. Endpoint-first detection: EDR fires on an Office application (`winword.exe`, `excel.exe`, `outlook.exe`) or `AcroRd32.exe`/`onenote.exe` spawning a scripting interpreter, `mshta.exe`, `regsvr32.exe`, or `rundll32.exe` as a child process — this can arrive before or entirely instead of a gateway alert if the file evaded mail-time scanning.
5. Correlation rule: attachment opened from a location matching a mounted removable/virtual disk (ISO auto-mount behavior) followed by execution of a file from that mount point within seconds.

## Required Log Sources & Event IDs

| Source | What it gives you |
|---|---|
| M365 Defender / Exchange Online Advanced Hunting (`EmailEvents`, `EmailAttachmentInfo`) | Sender, recipient, delivery action, attachment name/hash/type, detonation verdict |
| Secure Email Gateway logs (Proofpoint, Mimecast, etc.) | Independent verdict, sandbox/detonation report, quarantine status |
| EDR process telemetry (e.g., `DeviceProcessEvents` in Defender/Sentinel schema) | Full parent/child process chain from the opening application to any spawned interpreter or LOLBin |
| EDR network telemetry (`DeviceNetworkEvents`) | Outbound connections/DNS resolutions immediately following execution — staging download or C2 beacon |
| EDR file telemetry (`DeviceFileEvents`) | Dropped files, extracted archive contents, files written to `%TEMP%`/`%AppData%`/mounted ISO paths |
| EDR registry telemetry (`DeviceRegistryEvents`) | Run key or other autostart persistence written post-execution |
| Windows Security Event Log (authentication and process-creation auditing, per your build's audit policy) | Local logon context, process creation if not covered by EDR |
| Sandbox/detonation platform (vendor sandbox, or a dedicated detonation appliance) | Behavioral report — network calls, dropped files, registry writes, screenshots of the lure |

## Key Fields to Inspect

**[ANALYST]**

- `FileName`, `FileType`, and `SHA256` from `EmailAttachmentInfo` — check the hash against threat intel before doing anything else; a hash hit ends the "is this malicious" debate immediately. Microsoft's own schema reference notes `SHA256` on this table is frequently unpopulated, so if it's blank, pivot on `FileName`/`FileType` plus the sandbox verdict instead of assuming the absence of a hash means anything.
- True container type versus displayed extension. A `.pdf` icon on a file whose actual type is an ISO or an HTML file (extension mismatch, magic-byte check) is one of the most reliable single tells.
- `DeliveryAction` and `ThreatTypes` in `EmailEvents` — quarantined/blocked versus delivered, and whether the verdict was assigned at mail-time or via post-delivery re-scan.
- On the endpoint: the full process tree from the opening application. Office spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `regsvr32.exe`, or `rundll32.exe` as a direct or near-immediate child is the core signal — legitimate macro-driven business workflows almost never do this.
- `ProcessCommandLine` of the spawned interpreter — look for base64 blobs, `-EncodedCommand`, `-WindowStyle Hidden`, `/i:` scriptlet arguments to `regsvr32.exe`, or a URL embedded directly in the command line (staging download).
- `InitiatingProcessFolderPath` for anything executing out of a mounted ISO/IMG drive letter or an extracted archive path under `%Temp%` — normal software installs don't chain-execute from these locations without a user-initiated installer.
- Any file written immediately after open to `%AppData%\Roaming`, `%LocalAppData%\Temp`, or a scheduled task/run-key artifact created within the same session — persistence staged fast, often within seconds of the lure document closing.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Attachment matches an expected business document type from a known sender (invoice PDF, signed contract, timesheet) | Filename/extension mismatch, double extension, or a container format (ISO/IMG/archive) with no prior business reason for that format |
| Office document opens, user reads/edits content, no child process beyond normal Office helper processes | Office document opens and within seconds spawns a command shell, scripting interpreter, or LOLBin as a child process |
| Macro-enabled template used for a known internal workflow (expense forms, timesheets) with the macro already whitelisted | Macro prompts "Enable Content" on a document from an external sender, then immediately reaches out to an unfamiliar domain |
| Password-protected archive sent because the *business* requires it (legal, HR, security testing) and the password was shared through a separate trusted channel | Password-protected/nested archive sent unsolicited, password given only inside the email body itself (classic AV-evasion pattern) |
| No outbound network activity from the host tied to the document-open event | Outbound HTTP/DNS request to a newly-registered or low-reputation domain immediately after the file was opened |

## Investigation Steps

1. Pull the attachment's hash, true file type, and detonation verdict from `EmailAttachmentInfo`/SEG logs. If a hash match against threat intel exists, treat the message as confirmed malicious and move straight to scoping — don't spend time re-litigating intent.
2. Check `DeliveryAction` — if the message was quarantined/blocked pre-delivery and no user interaction is possible, this closes faster than a delivered message; confirm no secondary copy reached the mailbox via a rule or forward.
3. If delivered, check whether the message was opened (`MailItemsAccessed` in the audit log) and pull the recipient's EDR process tree for the relevant window — this is the step that actually answers "did anything happen," not the gateway verdict.
4. Trace the full process chain from the opening application through any spawned interpreter/LOLBin, noting exact command lines — this is where obfuscated PowerShell or a `regsvr32`/`mshta` scriptlet argument will show up.
5. Check file, registry, and scheduled task telemetry on the host for anything dropped or persisted in the minutes following execution.
6. Check network telemetry for the same host for outbound connections/DNS lookups tied to the execution timeframe — this tells you whether the payload actually staged or beaconed, versus failing silently (blocked by EDR, no internet access, wrong OS target).
7. Search tenant-wide for the same attachment hash, subject line, or sending infrastructure to identify every other recipient — attachment campaigns are frequently sent to a distribution list, not one mailbox.
8. If execution and persistence are confirmed, pivot to standard endpoint containment/eradication workflow (out of scope for this playbook) and hand off with full IOC set: hash, C2 domain/IP, dropped file paths, persistence mechanism.

## True Positive Indicators

- Attachment hash matches a known malware family, or sandbox detonation returns a malicious verdict with observed network/file/registry behavior.
- Confirmed process chain from the opening application to a scripting interpreter or LOLBin, with an obfuscated or URL-bearing command line.
- Outbound connection to a low-reputation or newly-registered domain immediately following the open event.
- Persistence artifact (registry run key or scheduled task) created within the same session as the document open.
- Extension/type mismatch or container-smuggling pattern (ISO/IMG/nested archive) combined with an unsolicited sender and no legitimate business reason for that format.

## False Positive / Benign Positive Indicators

- Legitimate business document using a macro-enabled template that's already known and whitelisted internally, with a process chain limited to expected Office helper processes.
- Password-protected/encrypted attachment used for a genuine compliance or business reason (legal document, HR file, authorized security testing), with the password shared through a separate verified channel rather than the email body itself.
- Heuristic false-positive on file type detection — a legitimately password-protected zip flagged simply because the gateway can't inspect inside it, with sandbox detonation later returning clean once analysts supply the password.
- Authorized internal phishing simulation (check the current test calendar/exception list first — this alone resolves a surprising number of tickets quickly).
- Attachment quarantined/blocked pre-delivery with no user interaction possible and no secondary delivery path found — closes as Benign Positive/no impact once delivery is confirmed fully blocked.
- Insufficient Evidence closure is valid when the message or attachment sample can't be recovered (already deleted/purged before capture) and no endpoint telemetry correlates to any open or execution event — document what was checked rather than guessing at intent.

## Escalation Criteria

Escalate to Incident Response / Tier 3 immediately if any of:

- Confirmed execution with persistence established (registry run key, scheduled task) or a live C2 beacon observed.
- Payload behavior matches a known ransomware precursor loader or credential-theft toolkit.
- Multiple hosts show execution of the same payload, indicating lateral spread or a mass-targeted campaign rather than one recipient.
- The affected user holds privileged access (Domain Admin, finance approval authority, cloud admin role) regardless of whether execution is yet confirmed.
- Attempted defense evasion observed — the payload tries to disable or tamper with AV/EDR before further staging.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Purge attachment/message from all mailboxes it reached (gateway/M365 Defender remediation) | SOC analyst/Tier 2, no additional approval for a confirmed-malicious verdict |
| Block attachment hash and sending domain at the email gateway | SOC Tier 2, informational notice to email admin team |
| Isolate affected endpoint via EDR | SOC shift lead, standard delegated containment authority per IR policy |
| Block C2 domain/IP at firewall/proxy | Network/security team, immediate action authorized for confirmed-malicious indicators |
| Kill and remediate persistence mechanism (run key, scheduled task) | SOC Tier 2/EDR team, coordinate with endpoint owner |
| Org-wide block of a risky container/file type at the gateway (policy-level change) | SOC manager or CISO delegate — this is a standing policy decision, not a per-ticket one |
| Disable account / force credential reset (if attachment led to credential exposure) | SOC shift lead approval, notify account owner's manager |

## Example Query

M365 Defender Advanced Hunting (KQL) — pivot from a confirmed-malicious attachment hash to endpoint execution evidence:

```kusto
EmailAttachmentInfo
| where SHA256 == "a1c3e5f7b9d1c2e4f6a8b0d2e4f6a8c0e2f4a6c8e0f2a4c6e8f0a2c4e6f8a0c2"
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| join kind=leftouter DeviceProcessEvents on $left.RecipientEmailAddress == $right.AccountUpn
| project Timestamp, RecipientEmailAddress, FileName, DeliveryAction, InitiatingProcessFileName, ProcessCommandLine
```

## Closure Criteria

Close only after: attachment hash, true file type, and sandbox/detonation verdict are documented; full recipient list identified tenant-wide; each recipient's endpoint checked for open/execution evidence; any confirmed execution fully remediated (process killed, persistence removed, EDR sweep clean) and malicious infrastructure blocked at gateway/proxy/DNS. A clean sandbox verdict with no endpoint correlation is a valid closure on its own — don't hold a ticket open chasing a verdict that already came back benign.

**Example case note:**
`2026-09-15 09:41 UTC - Attachment "Q3_Statement.iso" delivered to r.oduya@example.com (AP clerk) from first-time external sender at 203.0.113.44; ISO auto-mounted on open, contained LNK launching powershell.exe -enc <base64>. EDR shows outbound connection to 198.51.100.77 within 4 seconds of execution, blocked by network containment before any further callback. Registry run key artifact removed, host isolated and reimaged per standard rebuild policy. Hash and C2 IP pushed to gateway/EDR blocklists. No other recipients found tenant-wide for this hash. Closed as True Positive.`
