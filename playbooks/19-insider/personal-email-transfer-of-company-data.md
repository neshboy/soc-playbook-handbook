# Personal Email Transfer of Company Data

## Playbook ID & Name
**INS-005 — Insider Threat: Personal Email Transfer of Company Data**

## Business Risk

**[STAKEHOLDER]** - An employee moves proprietary, regulated, or competitively sensitive information out of corporate email into a personal webmail account (Gmail, Yahoo, iCloud, Outlook.com, etc.), either as a one-off send, a BCC habit, or a standing auto-forward rule that quietly mirrors everything going forward. Once it lands in a personal inbox, the company has no visibility and no real recall option — this is the scenario legal ends up calling "spoliation risk" if it isn't caught before the person walks out the door. It's also one of the most common insider channels precisely because it requires zero technical skill: no tool download, no USB, just the "Forward" button or a mailbox rule most users have never once looked at.

## Severity / Priority Default

**High (Priority 2).** Escalates to **Critical (P1)** when the destination has received regulated data at volume (PII/PHI/PCI, source code, M&A material), when the account is in a resignation/termination window, or when the user has a prior DLP violation for the same behavior. Downgrade to Medium/Low only once content review confirms the material sent was non-sensitive or the transfer was pre-approved.

## MITRE ATT&CK Technique(s)

| ID | Technique | Relevance |
|---|---|---|
| T1114.003 | Email Forwarding Rule | Primary technique — a mailbox rule silently auto-forwards or redirects inbound/outbound mail to an external personal address, often the highest-yield and hardest-to-notice variant of this playbook. |
| T1567 | Exfiltration Over Web Service | Covers manual sends/BCC to personal webmail via OWA, Outlook desktop, or a browser session against a personal Gmail/Yahoo/iCloud account. |
| T1048 | Exfiltration Over Alternative Protocol | Covers cases where the transfer rides IMAP/POP forwarding or a direct SMTP relay path outside the monitored mail-flow route. |
| T1530 | Data from Cloud Storage | Frequent precursor — user pulls the files from SharePoint/OneDrive/Teams before attaching them to the outbound message. |
| T1119 | Automated Collection | Applies when a broad "forward all mail" or "forward mail matching X" rule is used as a standing collection mechanism rather than a single deliberate send. |
| T1098.002 | Additional Email Delegate Permissions | Variant where the user grants Send-As/Full Access delegate permission on their corporate mailbox to a second mailbox or shared account they control, achieving the same effect without a classic forwarding rule. |
| T1071 | Application Layer Protocol | The transport layer for the detection itself — SMTP mail flow or HTTPS webmail traffic is what proxy/mail-gateway logging actually sees. |
| T1552.001 | Unsecured Credentials In Files | Relevant when the attached material includes credential files, API keys, or config exports pulled from a share — raises severity beyond a simple data-handling violation. |

## Trigger / Detection Logic Summary

Fires on any of the following, individually or (more convincingly) in combination:

- A mailbox-level forwarding/redirect rule is created or modified with a target address on a consumer email domain (gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com, protonmail.com, etc.) — via Exchange Online/on-prem transport rule, inbox rule, or `Set-Mailbox -ForwardingSmtpAddress`.
- Outbound mail flow shows a **To, CC, or BCC** recipient on a personal domain, particularly when paired with attachments, sensitivity labels, or DLP keyword/classification matches.
- Proxy/CASB logs show sustained upload volume to a webmail category domain (mail.google.com, outlook.live.com, mail.yahoo.com) inconsistent with normal personal-webmail-checking behavior.
- A previously created forwarding rule is **deleted** shortly after a burst of forwarded mail — the self-cleanup pattern is one of the strongest single indicators in this whole category.

Baselines matter enormously here: almost every user has sent *something* to a personal address at some point (a payslip, a calendar invite, a photo from a work event). The detection logic should weight volume, classification, rule scope (all-mail vs. narrow condition), and timing far more heavily than the mere existence of a personal-domain recipient.

## Required Log Sources & Event IDs

| Source | What it provides |
|---|---|
| M365 Unified Audit Log (Microsoft Purview Audit) / Exchange Online audit | Operations `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Remove-InboxRule`, `Set-Mailbox` (ForwardingSmtpAddress/ForwardingAddress), `Add-MailboxPermission`, `Send`, `MailItemsAccessed` — the authoritative record of rule changes and mailbox access, including deleted rules if you search history rather than current state |
| Exchange message trace / mail flow report | Sender, recipient, subject, attachment count/size, direction, and delivery status for every message — this is how you reconstruct "everything this mailbox sent to that address over the last 90 days" |
| DLP (Microsoft Purview DLP or network/endpoint DLP) | Policy match events on outbound mail: sensitive information type matched, rule name, action taken (block/allow/notify), file/attachment classification label |
| Secure Web Gateway / Proxy (Zscaler, Netskope, Blue Coat, etc.) | Webmail category hits, destination domain, bytes uploaded (attachment via browser compose), user, source IP — needed when the transfer happens through a browser session rather than the managed mail client |
| CASB | OAuth app consent grants (e.g., a personal Gmail account linked as a connected app), browser-isolation or webmail-block policy events |
| Windows Security Event Log | Event ID 4688 (process creation - browser or mail client launch, command line if captured), Event ID 4663 (object access - read of the source file later attached) |
| Sysmon | Event ID 1 (process creation), Event ID 3 (network connection to personal-webmail IP ranges/ASNs), Event ID 11 (file creation - attachment or archive staged in Downloads/Temp immediately before send) |
| Identity provider / SSO logs | New device or new-location sign-in, MFA registration change, or new OAuth grant clustered around the rule-creation timestamp — helps distinguish willful insider action from account compromise |
| HR feed (via case-management liaison) | Resignation date, notice period, PIP status, role change |

## Key Fields to Inspect

**[ANALYST]**
- Mailbox owner UPN, and whether the rule/forward was created by the user directly versus an admin or delegate (admin-level changes via PowerShell warrant a different, more urgent line of inquiry)
- Forwarding/redirect target address and domain — cross-reference against the consumer-domain list and against any approved partner-domain allow-list before assuming malicious intent
- Rule condition scope: "apply to all messages" is a collection mechanism (T1119); a narrow condition ("from specific sender," "with specific words in subject") suggests a targeted, deliberate pull
- Recipient field placement — **BCC to a personal address on an otherwise legitimate client/customer email** is a classic quiet-exfil pattern that's easy to miss in a quick review of the To/CC line
- Attachment name, count, size, hash, and any DLP sensitivity label or classification tag attached to it
- Subject/body keyword hits (client list, roadmap, source, confidential, contract, salary) from DLP or manual review
- Whether the rule was subsequently deleted (`Remove-InboxRule` shortly after a forwarding burst) — check UAL history, not just current mailbox configuration
- Timing relative to HR case flags (resignation, PIP, notice period) and relative to normal working hours
- Source IP/device posture — corporate-managed endpoint vs. unmanaged/BYOD, on-network vs. VPN/off-network

## Normal vs. Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Occasional single email to a personal address with clearly personal or low-sensitivity content (calendar invite, own payslip, expense receipt) | Recurring pattern of business documents, attachments, or client data sent/BCC'd to the same personal address over days or weeks |
| Forwarding rule created by IT with a change ticket, routing to an approved partner or secondary corporate mailbox | Forwarding rule created by the end user, with no ticket, targeting a consumer webmail domain, scoped to "all mail" |
| Personal-domain recipient appears once, isolated, with no DLP classification match | Multiple DLP-classified sensitive-info-type matches on outbound mail to the same external address |
| Rule remains visible in the mailbox configuration indefinitely | Rule is created, used for a forwarding burst, then deleted within hours or days — anti-forensic self-cleanup |
| Timing consistent with the user's normal day-to-day mail habits | Activity clustered in the days immediately before a resignation effective date, right after a PIP notice, or late at night/weekend outside the user's normal pattern |
| Content on review is non-sensitive (personal HR paperwork, internal newsletters) | Content on review includes client lists, source code, pricing models, financial forecasts, or credential/config files |

## Investigation Steps

1. **Pull full context on the triggering event.** Get the alerting rule-creation or mail-send event: actor, target/forward address, timestamp (normalize to UTC — message trace and UAL timestamps drift in ways that trip people up), and whether the change came through OWA, a mobile client, or PowerShell/admin action.
2. **Check for deleted rule history, not just current state.** Search the Unified Audit Log (or on-prem Exchange audit) for `New-InboxRule`/`Set-InboxRule` *and* `Remove-InboxRule` on the same mailbox — the create-use-delete pattern is a strong intent signal that a point-in-time mailbox-configuration check will completely miss.
3. **Reconstruct full mail history to the target address.** Run a message trace/mail-flow report for the sender over a 30-90 day lookback, capturing every message to the forwarding target or any personal-domain recipient, along with subject, attachment names, and sizes.
4. **Pull DLP/classification results on the attachments.** Confirm sensitivity via existing DLP scan results or classification labels rather than opening personal-account content directly — reviewing the actual mailbox of a personal account is a legal/authorization boundary, not a technical one, and usually requires Legal/HR sign-off first.
5. **Trace the data back to its source.** Check whether the attached files were pulled from SharePoint/OneDrive (T1530) or a file share (Windows Event ID 4663 / EDR file-read telemetry) shortly before being attached, and whether that access falls inside the user's normal duties.
6. **Rule out account compromise as the actual cause.** Check identity logs for a new device, new sign-in location, MFA method change, or new OAuth app grant around the rule-creation window — a forwarding rule set up by an attacker who compromised the account is a very different case than a willful insider act, and it changes your containment priorities (credential reset first, HR conversation not applicable).
7. **Correlate with HR/personnel status** through your case-management/HR-liaison process — resignation notice, PIP status, or a role change materially changes severity and next steps; don't query HR systems directly yourself.
8. **Check for a documented business justification** before concluding malicious intent — an approved exception for personal-device use, a ticketed migration/routing change, or manager sign-off can fully explain the pattern. If none exists, escalate per policy; do not contact or confront the user directly without Legal/HR authorization.

## True Positive Indicators

- Auto-forward/redirect rule created with no change ticket, targeting a consumer webmail domain, scoped broadly to "all mail" or a wide condition
- Rule created, used for a forwarding burst, then deleted by the same user shortly afterward
- Multiple attachments carrying confirmed DLP-classified sensitive content sent or BCC'd to a personal address over a short window
- Activity timing tightly clustered before a resignation effective date or shortly after a PIP/termination notice
- Content on review includes client/customer lists, source code, financial models, contracts, or credential/config files
- Repeat behavior on the same personal destination after a prior DLP block or documented warning

## False Positive / Benign Positive Indicators

- Forwarding configuration is IT-approved and ticketed (e.g., interim routing during a mailbox migration or reorg), not personal webmail
- Content reviewed is genuinely low-sensitivity — a calendar invite, a personal HR form, a mistakenly-CC'd personal contact
- Documented exception exists for personal-email use (e.g., a contractor without a corporate mailbox, an approved BYOD arrangement for a specific engagement)
- Destination domain looks like a consumer provider but actually resolves to a custom/vanity domain hosted on that provider for legitimate business use (e.g., a small partner company on Google Workspace) — verify MX records/tenant before concluding "personal"
- Single isolated send with no repeat pattern and content clearly tied to the user's own administrative matters (expense receipt, benefits enrollment)

## Escalation Criteria

Escalate immediately to the Insider Threat Program lead, Legal, and HR liaison when: DLP confirms regulated or high-value proprietary data was transferred; the user is in a resignation/termination window; the rule shows evidence of after-the-fact deletion (anti-forensic behavior); the same user has a prior DLP violation for this exact behavior; or the content involves source code, executive communications, or M&A-related material.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- **Disable/remove the offending forwarding rule or delegate grant** - SOC on-call analyst authority for a clearly unauthorized external-forward rule with no ticket on file; this is a standard technical corrective action, not a punitive one.
- **Temporary outbound block on webmail category or the specific destination domain** for the user at the proxy/mail gateway - SOC lead approval.
- **Suspend mailbox send capability or force step-up re-authentication** - requires IT security manager or Insider Threat Program lead approval.
- **Account suspension or access removal ahead of/at termination** - requires joint HR + Legal + IT security manager sign-off; do not act unilaterally even with strong evidence, this carries legal exposure beyond the technical decision.
- **Preservation/legal hold** on the mailbox, message trace data, DLP logs, and any relevant endpoint image - Legal directs this; SOC's role is to flag the need early and stop routine log rotation/retention cleanup from destroying evidence.
- **Remote wipe/selective wipe on a BYOD device** (if MDM-enrolled and the personal account synced there) - requires Legal + HR sign-off given personal-device privacy considerations; do not initiate on a purely technical decision.

## One Short Example Query

Sample using Microsoft Sentinel KQL against `OfficeActivity` to catch forwarding-rule creation targeting consumer domains:

```kql
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where Parameters has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo")
| where Parameters has_any ("gmail.com","yahoo.com","outlook.com","icloud.com","protonmail.com")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

## Closure Criteria

Close as **True Positive** only after the destination, content classification, rule scope/history, and absence of business justification are all independently verified, and the case has been handed to the Insider Threat Program/HR/Legal for disposition. Close as **Benign Positive** when the forward/send is verified as an approved routing configuration or the content is confirmed non-sensitive. Close as **Insufficient Evidence** when message-trace or DLP logging lacks the classification/attachment detail needed to make a call — log the gap for detection engineering rather than force a verdict.

**Example case note:**
> "2026-09-14 09:18 UTC — pkapoor@solsticedevices.example.com created an inbox rule (`New-InboxRule`, Parameters: RedirectTo=priya.kapoor91@gmail.com, condition=all messages) from WKS-SLS-0447 (10.44.12.63). Message trace shows 11 messages redirected over the following 40 minutes, including two attachments DLP-tagged Confidential-ClientList. Rule was removed (`Remove-InboxRule`) at 10:02 UTC same day. HR liaison confirms pkapoor's last working day is 2026-09-18. Escalated to Insider Threat Program lead and Legal per INS-005 escalation criteria; mailbox forwarding disabled and legal hold requested pending guidance."
