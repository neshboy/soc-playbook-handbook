# Category: Email

Email is still the number one initial access vector, and it will probably stay that way for as long as it's the cheapest way to reach a human being who can click something. Every playbook in this folder ultimately traces back to one of two things: someone getting fooled by a message, or someone's mailbox already being under attacker control and being used as a weapon against other people. Those two situations look different on the surface — a junior accountant reporting a weird invoice PDF versus a CFO's mailbox suddenly sending five hundred emails at 3 AM — but the underlying ATT&CK techniques overlap heavily (T1566 Phishing, .001 Attachment and .002 Link, T1204 User Execution, T1078 Valid Accounts, T1114 Email Collection), and the triage muscle memory is the same: figure out who touched what, when, and whether it went anywhere.

What these alerts have in common is that the "victim" and the "evidence" are usually the same object — the mailbox. Unlike an endpoint alert where you can pull a memory dump independent of the user's opinion of what happened, email investigations lean heavily on message headers, mailbox audit logs, and sign-in telemetry that can be altered, purged, or simply never logged in the first place if licensing or retention wasn't configured for it. You are also almost always dealing with a second victim problem: a successful phish rarely stays contained to one inbox, so scoping "who else got this" is part of nearly every playbook here, not an edge case.

## Log sources and tooling that matter here

- **Mail flow / message trace** — Exchange Online Message Trace or on-prem transport logs, for delivery status, sender IP, and whether a message was quarantined, delivered, or bounced.
- **Mailbox audit logs** — Unified Audit Log (Microsoft 365) or equivalent, covering `New-InboxRule`, `Set-Mailbox` (forwarding), mailbox delegation changes, and `MailItemsAccessed`/`Send` operations.
- **Identity sign-in logs** — Entra ID sign-in logs (or your IdP's equivalent) for the account tied to the mailbox — location, IP, device, MFA result, conditional access outcome.
- **Secure Email Gateway / native filtering** — Defender for Office 365, Proofpoint, Mimecast, or similar, for verdicts, URL rewrite/click data, and attachment sandbox results.
- **Detonation/sandbox tooling** — for attachments and links that need a second opinion beyond the vendor verdict.
- **Threat intel** — sender reputation, known phishing kit infrastructure, and any internal "reported by user" pipeline (Report Message button, abuse mailbox, helpdesk tickets).
- **OAuth / app consent logs** — application and service principal sign-in logs, consent grant records, tied to T1098.001 Additional Cloud Credentials style abuse.

**[ANALYST]** - The single most useful artifact across nearly every playbook in this section is the full message header (`Authentication-Results`, `Received` chain, `X-MS-Exchange-Organization-*` headers if you're in M365). Get comfortable reading these cold — SPF/DKIM/DMARC results, the actual originating IP versus the display sender, and hop count. A user forwarding you a screenshot instead of the .eml file is a recurring source of wasted time; always ask for the message itself.

## Where this commonly goes sideways

Email investigations have a specific flavor of friction. Users forward the suspicious message to you, which strips or rewrites headers and breaks your ability to trace the real path — always try to get the original .eml or a proper message trace instead of a forward. URL rewriting/click-time protection (Safe Links and similar) means the URL a user clicked isn't the URL in the raw message, so you're correlating two different link records. Shared or delegated mailboxes make "who actually clicked this" genuinely ambiguous. Retention limits bite hard here too — message trace data ages out fast (often 7–90 days depending on tier), so a report that comes in two weeks late may already have lost its trail. And a large chunk of reported phishing is, honestly, legitimate marketing mail or an internal tool that looks off — Benign Positive and Expected Activity are common, valid closures in this category, not a failure of triage.

## Playbooks in this category

| # | Playbook |
|---|----------|
| 1 | Phishing |
| 2 | Spear Phishing |
| 3 | BEC (Business Email Compromise) |
| 4 | Malicious Attachment |
| 5 | Malicious Link |
| 6 | QR-Code Phishing |
| 7 | Credential Phishing |
| 8 | Internal (Compromised-Account) Phishing |
| 9 | Mailbox Forwarding Rule Abuse |
| 10 | Suspicious Inbox Rule Creation |
| 11 | OAuth App Abuse / Consent Phishing |
| 12 | Impossible Travel (Mailbox Access) |
| 13 | Account Takeover |
| 14 | Mass Outbound Email from Compromised Mailbox |
| 15 | Executive Impersonation |
| 16 | Vendor Impersonation |
