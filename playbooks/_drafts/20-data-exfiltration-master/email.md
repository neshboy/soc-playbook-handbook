# Exfiltration via Email — Personal Webmail, Large Attachments, Auto-Forwarding

*Channel focus for the Data Exfiltration Master Playbook — this section covers telemetry and indicators only. Containment, legal/HR involvement, and cross-channel scoring live in the master document.*

Email is still the highest-volume exfil channel in most environments because it's trusted, encrypted end-to-end from the analyst's viewpoint (TLS to the mail provider), and every user already has a legitimate reason to send mail externally. The job here isn't proving "email left the building" — DLP will tell you that. The job is narrowing down *which* of the three sub-patterns did it: a standing forwarding rule quietly siphoning everything, a one-off large attachment, or a user routing corporate content through a personal webmail tab in a browser.

## 1. Auto-Forwarding Rules and Mailbox Delegation

This is the pattern that gets missed longest because it's set-and-forget — a rule created once during a compromised session keeps working for weeks after the attacker's initial access is closed off.

**Primary telemetry (Microsoft 365 Unified Audit Log / Exchange Online):**

| Operation | What it tells you |
|---|---|
| `New-InboxRule` / `Set-InboxRule` | Rule created/modified — check `Parameters` for `ForwardTo`, `RedirectTo`, `CopyToFolder` combined with move/delete actions that hide the trail |
| `Set-Mailbox` | `ForwardingSmtpAddress`, `ForwardingAddress`, `DeliverToMailboxAndForward` — the classic org-level forward, doesn't show up in the mailbox's visible rules list |
| `UpdateInboxRules` / `New-TransportRule` | Tenant-wide or transport-level forwarding, usually admin-initiated — high blast radius if abused |
| `Add-MailboxPermission`, `Add-RecipientPermission` | Delegate/SendAs/SendOnBehalf grants — maps to **T1098.002** (Additional Email Delegate Permissions) |

**[ANALYST]** - Pull every `New-InboxRule`/`Set-Mailbox` event for the mailbox and check the target address's domain. A forward to `intl-shipping-updates@gmail.com` on a finance mailbox is not a filing rule. Also check whether the rule has `StopProcessingRules $true` and a folder-move action — attackers chain these so the victim never sees the forwarded mail sitting in Sent Items or a visible rule in Outlook's UI. Cross-reference the `ClientIP` and `UserAgent` on the rule-creation event against the user's normal logon geography; a rule created from an ASN the user has never authenticated from is the strongest single indicator in this whole channel.

**[ENGINEERING]** - Baseline query pattern (adapt to your SIEM's UAL ingestion):

```
index=o365_audit Operation IN ("New-InboxRule","Set-InboxRule","Set-Mailbox")
| where match(Parameters, "ForwardTo|RedirectTo|ForwardingSmtpAddress")
| eval external_domain=if(match(Parameters, "@(gmail|outlook|yahoo|proton|mail\.ru)\.\w+"), "personal_webmail", "other")
| where external_domain="personal_webmail"
```
Maps to **T1114.003** (Email Forwarding Rule) under **T1114** Email Collection; if the rule dumps entire folders on a schedule, tag it as **T1119** (Automated Collection) feeding exfil rather than a one-time pull.

**[MANAGEMENT]** - Tenant-wide auto-forward to external domains should be blocked by default transport rule with narrow, ticketed exceptions. Review of active external forwarding rules should run weekly, not annually — this is a five-minute report and it's the single highest-value recurring control in this channel.

## 2. Large or Anomalous Attachment Egress

**Telemetry:** Exchange message tracking logs (Sender, Recipients, MessageSubject, TotalBytes, Transport EventId Send/Fail), Microsoft Purview DLP policy matches (sensitive info type, rule name, override justification if user overrode a policy tip), and mail flow rule hits.

**[ANALYST]** - Look for size outliers against the mailbox's own 30/60-day baseline, not a flat threshold — a mailbox that normally sends 200KB average suddenly pushing an 18MB zip to a webmail domain on a Friday evening is the pattern, regardless of whether 18MB clears some org-wide "large attachment" bar. Check whether the file was renamed or double-extension (`invoice.pdf.zip`) to dodge content inspection, and whether DLP fired but the user clicked "Report False Positive" or provided a business justification — that override text is often the most honest thing in the whole case.

## 3. Personal Webmail Access via Browser

Proxy/firewall/CASB logs are the only place this shows up reliably — corporate mail server logs won't see traffic that never touches Exchange.

**[ANALYST]** - Pull proxy logs filtered to webmail URL categories and known personal-webmail domains (`mail.google.com`, `outlook.live.com` — note the `.live.` vs `.office.` distinction if OWA and personal Outlook.com share infrastructure, `mail.yahoo.com`, `protonmail.com`). Correlate large upload byte counts on POST requests to compose/attachment endpoints, not just page-view volume. On the endpoint, **4688** process creation for the browser combined with **4624**/proxy-authenticated session context establishes who was at the keyboard when the upload happened, since browser history alone doesn't attribute to a Windows logon session on shared or jump-box machines. Maps to **T1567** Exfiltration Over Web Service.

## 4. Narrowing the Channel

| Signal present | Points toward |
|---|---|
| External forwarding rule, no large single send | Standing exfil, **T1114.003** |
| One large attachment, DLP override, no rule | Opportunistic single-event exfil |
| Webmail upload traffic, no Exchange forward | Browser-based, **T1567**, check if bypassing egress proxy entirely (**T1048**) |
| Delegate/SendAs grant on a shared mailbox | Insider or compromised-account collection, **T1098.002** |

**[STAKEHOLDER]** - Not every large attachment or webmail hit is theft — a lot of this closes as Expected Activity (contractor emailing a signed NDA to their personal address to keep a copy, which is against policy but not a security incident) or Benign Positive (a legitimate CRM export sent to an approved partner domain that happens to match a personal-webmail regex). Document the closure reason; the pattern matters more than any single alert.

**[MANAGEMENT]** - SLA for triage on a confirmed external-forward-rule alert should be under one hour given the "silent bleed" characteristic; large-attachment DLP overrides can sit in a daily batch review unless paired with another indicator from this list.
