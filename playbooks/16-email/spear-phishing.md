# Spear Phishing

## Playbook ID & Name

**EML-002 — Spear Phishing (Targeted Email-Based Initial Access)**

Distinct from bulk/commodity phishing playbooks in this same category: spear phishing is targeted, low-volume, and usually researched — a specific person, a specific pretext, sometimes a spoofed vendor thread lifted from a real prior conversation. Volume-based detections (mass-mail clustering, bulk URL reputation feeds) will often miss these. Treat every spear phish as attacker-directed reconnaissance already spent on your org before the email even lands.

## Business Risk

**[STAKEHOLDER]** - A single well-crafted email to the right person (finance approver, IT admin, exec assistant) can bypass millions spent on perimeter controls, because the attacker is exploiting trust and workflow familiarity, not a technical vulnerability. Realized impact ranges from wire fraud and credential theft to a foothold that leads to ransomware weeks later. Decisions on blocking sender domains org-wide, forcing password resets, or notifying the targeted business unit sit with the SOC manager or CISO delegate, not the analyst on the ticket.

## Severity/Priority Default

**High** at intake (targeted nature alone justifies this over commodity phishing's default Medium). Escalates to **Critical** if the target has privileged access (Domain Admin, finance approval authority, M365 Global Admin) or if credential entry / attachment execution is confirmed.

## MITRE ATT&CK Techniques

- T1566.001 Phishing: Spearphishing Attachment
- T1566.002 Phishing: Spearphishing Link
- T1204 User Execution
- T1078 Valid Accounts (.002 Domain Accounts, .004 Cloud Accounts) — post-credential-theft reuse
- T1114.003 Email Collection: Email Forwarding Rule — common persistence step after mailbox compromise
- T1098.002 Account Manipulation: Additional Email Delegate Permissions
- T1059.001 Command and Scripting Interpreter: PowerShell — payload execution
- T1218.005 System Binary Proxy Execution: Mshta — common macro-to-execution chain
- T1105 Ingress Tool Transfer
- T1027 Obfuscated Files or Information

## Trigger / Detection Logic Summary

Any one of the following opens a case:

1. Secure Email Gateway (SEG) or M365 Defender/Exchange Online Protection flags a message as phishing/malware/spoof *and* the recipient is tagged VIP, has elevated AD/Entra ID roles, or belongs to a previously-targeted department (finance, HR, exec).
2. User-reported phishing (Report Message add-in / abuse mailbox) where the message contains an attachment or link and shows sender/display-name mismatch.
3. Post-delivery detonation: URL/attachment sandbox verdict flips to malicious *after* the message was already delivered (time-of-click re-scan) — this is its own urgent sub-case because the user has already had the email in their inbox.
4. Correlation rule: external sender + lookalike domain (edit distance 1-2 from a known partner/vendor domain) + financial or credential-themed subject keywords + first-time sender to that mailbox.
5. Downstream signal fires first and pivots back to email: a new mailbox forwarding rule, an OAuth app consent grant, or a suspicious sign-in shortly after a flagged message to the same user — treat this as a linked spear-phishing case even if the SEG never alerted on the original email.

## Required Log Sources & Event IDs

| Source | What it gives you |
|---|---|
| M365 Defender / Exchange Online (MessageTrace, Advanced Hunting `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`) | Sender, recipient, headers, attachment hash, URL, delivery/detonation verdict |
| Secure Email Gateway (Proofpoint, Mimecast, etc.) logs | Independent verdict, URL rewrite click logs, sandbox detonation reports |
| Entra ID sign-in logs | Post-click credential use — success/failure, IP, device, conditional access result |
| Entra ID audit logs | Mailbox rule creation, delegate/permission grants, OAuth consent |
| Windows Security Event Log (4624, 4625, 4688, 4698) | Local logon, process creation, scheduled task creation if attachment executed — 4688 command-line capture requires the "Include command line in process creation events" GPO in addition to the base Process Creation audit subcategory |
| Sysmon (Event ID 1 process create, 3 network connection, 11 file create, 22 DNS query) | Macro spawning `mshta.exe`/`powershell.exe`, C2 beacon, dropped payload |
| DNS logs / web proxy logs | Resolution and connection to the phishing/C2 domain, staged malware download |
| EDR telemetry (process tree, command line) | Full execution chain from Office app to child process |

## Key Fields to Inspect

**[ANALYST]**

- Email headers: `Return-Path`, `Reply-To` vs `From` display name, `Authentication-Results` (SPF/DKIM/DMARC pass or fail), originating IP in `Received` chain, X-headers added by the SEG with its verdict/score.
- Envelope sender domain vs display name — spoofed display name with a completely unrelated envelope domain is the single most common giveaway in spear phishing targeting non-technical staff.
- URL destination after redirect chain resolution (not just the first-hop link) — phishing kits chain through legitimate URL shorteners or compromised WordPress sites before landing on the credential page.
- Attachment: file type vs extension (`invoice.pdf.exe`, ISO/IMG containers used to smuggle past mail-time scanning), macro presence in Office docs, hash against threat intel.
- Recipient's mailbox rules (`New-InboxRule` / `Set-InboxRule` in audit log) created in the hours after the email was opened — classic sign of Email Collection persistence.
- Sign-in log immediately following message delivery: impossible travel, new device, ASN mismatch, legacy auth protocol used (bypasses MFA prompts on some tenants).

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| SPF/DKIM/DMARC all pass, sender domain matches display name, known correspondence history | SPF/DKIM fail or `softfail`, display name spoofs a known contact but envelope domain is unrelated or a lookalike |
| Link goes to a known, previously-visited vendor domain | Link chains through a shortener/redirector to a newly-registered domain (WHOIS age under 30 days) |
| Attachment is a routine invoice/PO matching an existing vendor relationship | Attachment is password-protected zip/ISO with no prior business reason, or Office doc prompts "enable content" |
| User reports the email out of caution, no click recorded | Time-of-click telemetry shows the link was opened, followed by a new mailbox rule or unusual sign-in within minutes |
| Sign-in after any legitimate password entry matches user's normal device/location baseline | Sign-in from unfamiliar ASN/country immediately after message delivery, especially with legacy auth or immediate MFA fatigue prompts |

## Investigation Steps

1. Pull the full message from Advanced Hunting / MessageTrace (not just the SEG summary) — get raw headers, attachment hash, and every embedded URL including redirect targets.
2. Check `Authentication-Results` for SPF/DKIM/DMARC and compare `Return-Path`/`Reply-To` against the displayed `From` name. Note any mismatch precisely — this goes in the case note verbatim.
3. Identify all other recipients of the same or a near-identical message (same attachment hash or same lookalike domain) across the tenant — spear phishing sent to a small target list often lands in 2-5 mailboxes, not just the one that got reported.
4. For each additional recipient, check whether the message was opened/clicked (URL click telemetry) and whether any attachment was executed (EDR process tree for that host in the relevant window).
5. If a link was clicked: check the corresponding Entra ID sign-in event for that user in the following 15-30 minutes for anomalous location, device, or auth protocol. Assume credential compromise until sign-in evidence rules it out.
6. If credential compromise is suspected or confirmed: check Entra ID audit logs for new inbox rules, delegate grants, OAuth app consents, and MFA method registration changes in the following 24-48 hours.
7. If an attachment was executed: pull the EDR process tree from the endpoint — look for Office app spawning a scripting interpreter or `mshta.exe`, subsequent network connections, and any dropped files, then hunt for the same file hash / C2 domain across the fleet.
8. Pivot the sender infrastructure — envelope domain WHOIS/registration age, sending IP reputation, any other campaigns hitting the abuse mailbox with the same infrastructure — to size the campaign and decide if this is opportunistic or specifically directed at your org.

## True Positive Indicators

- SPF/DKIM/DMARC failure combined with display-name spoofing of a known internal or vendor contact.
- Attachment hash matches known malware family or detonates with malicious verdict in sandbox.
- URL resolves, after redirect, to a credential-harvesting page mimicking a legitimate login portal (M365, VPN, HR system).
- Confirmed click followed by anomalous sign-in, new mailbox forwarding rule, or OAuth consent grant.
- Message references specific internal project names, org chart details, or an active invoice thread the attacker could only know from prior reconnaissance or a prior compromised mailbox (thread hijacking).

## False Positive / Benign Positive Indicators

- Legitimate newsletter or automated notification misidentified due to a bulk-mail header quirk, no credential-harvest or malware component, SPF/DKIM pass.
- Internal penetration test or authorized phishing simulation (confirm against the current authorized test calendar/exception list before doing anything else — check this first, it saves everyone time).
- Vendor migrated mail infrastructure and SPF record lagged the change — legitimate sender, temporary auth failure. Confirm directly with the vendor contact through a known-good channel, not by replying to the email.
- User reported a message purely out of caution with no click, no execution, and clean sandbox verdict — closes as Expected Activity / user awareness working as intended.
- Insufficient Evidence closure is valid when the message was deleted before capture, no headers or attachment sample could be recovered, and no downstream sign-in or endpoint anomaly correlates — document what was attempted and move on rather than guessing at a verdict.

## Escalation Criteria

Escalate to Incident Response / Tier 3 immediately if any of:

- Confirmed credential harvest for an account with Domain Admin, Global Admin, or wire-approval authority.
- Malware execution confirmed on an endpoint with subsequent C2 beacon or lateral movement indicators.
- Same campaign infrastructure hits more than a handful of mailboxes tenant-wide (scope beyond isolated targeting).
- Evidence of a new mailbox forwarding rule or delegate permission added to a VIP or finance mailbox.
- Thread hijacking detected — attacker replying from a genuinely compromised third-party (vendor/partner) mailbox, which requires coordinated notification to that external party.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Purge message from all recipient mailboxes (SEG/M365 Defender remediation) | SOC analyst/Tier 2, no additional approval needed for confirmed malicious verdict |
| Block sender domain/IP at the email gateway | SOC Tier 2, informational notice to email admin team |
| Disable compromised user account / force sign-out of all sessions and password reset | SOC shift lead approval; notify account owner's manager |
| Remove unauthorized inbox rule / delegate permission / OAuth app grant | SOC shift lead, coordinate with M365 admin to avoid breaking a legitimate concurrent change |
| Org-wide notification / user awareness alert about active campaign | SOC manager or communications/security awareness owner |
| Endpoint isolation via EDR | SOC shift lead, standard containment authority already delegated per IR policy |
| External notification to a compromised vendor/partner (thread hijacking cases) | SOC manager or IR lead, legal/comms may need to be looped in depending on relationship |

## Example Query

M365 Defender Advanced Hunting (KQL) — find other recipients of a matching spear-phish payload once one instance is confirmed:

```kusto
EmailAttachmentInfo
| where SHA256 == "b1946ac92492d2347c6235b4d2611184"
| join kind=inner EmailEvents on NetworkMessageId
| where Timestamp > ago(7d)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
```

## Closure Criteria

Close only after: full recipient list identified and each mailbox checked, credential-compromise status determined (confirmed/ruled out) for every recipient, any malicious infrastructure blocked at gateway/proxy/DNS, and — if execution occurred — endpoint remediated and verified clean by EDR sweep. Attach headers, attachment hash, and sandbox report to the case regardless of verdict.

**Example case note:**
`2026-09-15 14:02 UTC - Spear phish to j.alvarez@example.com (AP Manager), spoofed display name "Marcus Kim" (real vendor contact) over unrelated domain vendor-billing-support[.]com, SPF=fail. Attachment invoice_0914.xlsm contained macro, EDR shows no execution (user did not enable content). No other recipients found for this hash tenant-wide. Sender domain blocked at SEG. Closed as True Positive; message confirmed malicious, no compromise occurred, user did not act on lure. User referred to awareness team for positive reinforcement.`
