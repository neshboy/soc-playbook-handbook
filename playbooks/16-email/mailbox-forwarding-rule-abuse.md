# Mailbox Forwarding Rule Abuse

## Playbook ID & Name

**EML-009 — Mailbox Forwarding Rule Abuse**

This playbook covers forwarding specifically: mail leaving the mailbox toward an external address, silently and on an ongoing basis, via either an inbox rule or a mailbox-level forwarding setting. It's a sibling to EML-010 (Suspicious Inbox Rule Creation), which covers rules that hide or destroy evidence inside the mailbox (move-to-RSS-folder, auto-delete-and-mark-read tricks BEC actors use). The two often show up together on a compromised mailbox, but forwarding is the one that actually moves data out the door, which is why it gets its own severity treatment.

## Business Risk

**[STAKEHOLDER]** - A forwarding rule turns a single compromised mailbox into a standing collection feed — every invoice, contract, credential reset email, and internal thread that lands in that inbox from the moment the rule is created keeps flowing to the attacker, with zero further effort on their part. This is the mechanism behind a large share of business email compromise wire fraud: the attacker doesn't need to keep logging in, they just wait for a live wire-transfer thread to forward itself over. The decision to reset credentials for a VIP or finance mailbox, or to notify a bank/vendor that a payment thread was exposed, sits with the SOC manager or IR lead, not the analyst who found the rule.

## Severity/Priority Default

**High** at intake for any confirmed external forwarding target with no business justification. Escalates to **Critical** if the mailbox belongs to finance/AP, an executive, HR, or a Global Admin, or if evidence shows financial or credential-bearing mail already flowed through the rule.

## MITRE ATT&CK Techniques

- T1114.003 Email Collection: Email Forwarding Rule — the core technique this playbook detects
- T1078.004 Valid Accounts: Cloud Accounts — the mailbox rule is almost always created using the legitimate, already-compromised credential
- T1078.002 Valid Accounts: Domain Accounts — relevant for hybrid Exchange where the mailbox identity is synced from on-prem AD
- T1098.002 Account Manipulation: Additional Email Delegate Permissions — frequently paired with forwarding to give the attacker a second, quieter access path
- T1098.001 Additional Cloud Credentials — attacker registering an extra MFA method or app password to keep access after the original credential is reset
- T1566.002 Phishing: Link — the common initial-access step that got the credential in the first place
- T1552.001 Unsecured Credentials: Credentials In Files — alternate initial-access path (creds found in a breach dump, a shared drive, or a misconfigured repo)

## Trigger / Detection Logic Summary

Any one of the following opens a case:

1. Unified Audit Log records `New-InboxRule`, `Set-InboxRule`, or `UpdateInboxRules` where the rule parameters include `ForwardTo`, `ForwardAsAttachmentTo`, or `RedirectTo` pointing at an address outside the tenant's accepted domains.
2. `Set-Mailbox` operation with `ForwardingSmtpAddress` or `ForwardingAddress` populated to an external recipient — this is the mailbox-level path, set via admin center/PowerShell rather than an Outlook rule, and it will **not** appear in the user's own Outlook "Rules and Alerts" pane. Treat this as the higher-severity variant because it's specifically the mechanism attackers reach for to survive a "check your inbox rules" awareness campaign.
3. A new inbox rule or mailbox-level forward is created within a short window (correlation rule, typically under 60 minutes) of a risky or anomalous sign-in event for the same identity (new country/ASN, impossible travel, legacy auth protocol, or a sign-in flagged by identity protection).
4. `New-TransportRule`/`Set-TransportRule` at the organization level redirects or BCCs mail matching a condition to an external address — same underlying technique, but tenant-wide and evidence of an Exchange-admin-level compromise, not just a single mailbox.
5. Outbound mail volume anomaly to a single external recipient that correlates with a known forwarding rule (useful when the rule itself predates your detection coverage and you're finding it retroactively during an unrelated investigation).

## Required Log Sources & Event IDs

| Source | What it gives you |
|---|---|
| Microsoft 365 Unified Audit Log — `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Set-Mailbox`, `New-TransportRule`, `Set-TransportRule` | Full rule/mailbox parameters (forward target, conditions, actions), actor, timestamp, `ClientIP`, session/correlation ID |
| Exchange Online / on-prem Exchange admin audit | Confirms whether the change came from the user's own session or an admin/PowerShell session acting on their behalf |
| Azure AD / Entra ID sign-in logs | Sign-in immediately preceding rule creation — location, device, IP, auth protocol, conditional access result, risk level |
| Azure AD Identity Protection risk events | Flags the sign-in as risky independently of your own correlation logic |
| Message Trace / `MailItemsAccessed` (mailbox audit) | What mail actually existed in the mailbox and was accessed/forwarded after the rule went live — this is how you size actual exposure, not just rule existence |
| Tenant outbound anti-spam / remote domains configuration | Whether external automatic forwarding is tenant-blocked, allowed org-wide, or allowed via a specific exception — tells you if this rule required bypassing a control or just walked through an open door |

## Key Fields to Inspect

**[ANALYST]**

- `Parameters` field on the audit record: look specifically for `ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo` (inbox rule) versus `ForwardingSmtpAddress`/`ForwardingAddress` (mailbox-level) — these are two different code paths logged differently, and analysts who only check one miss the other.
- `ClientIP` and `ClientInfoString`/`UserAgent` on the creation event — a PowerShell/remote-session client string on a rule the mailbox owner claims they never touched via Outlook is a strong signal, since a normal user creates rules through OWA or the desktop Outlook client.
- Rule conditions: blanket forward-all versus scoped to subject/body keywords (`invoice`, `wire`, `password`, `w-2`, vendor names) or sender domain — scoped conditions indicate deliberate targeted collection, not just a lazy catch-all.
- Whether the rule also deletes, marks-as-read, or moves the original to a rarely-checked folder (RSS Feeds, Conversation History) — combined with forwarding, this is the classic pattern for hiding a live BEC wire-fraud thread from the real mailbox owner while still exfiltrating it.
- Forward target domain: personal webmail provider, newly registered domain, or a lookalike of a real vendor/partner domain (compare edit distance against known correspondents).
- Companion changes in the same session or within 24-48 hours: `Add-MailboxPermission` (delegate access), MFA method registration, OAuth app consent grants — attackers rarely create just the forwarding rule and stop.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Internal forward to a covering colleague during approved leave, requested via helpdesk ticket, target is an internal mailbox | External SMTP target with no ticket, no leave record, no prior correspondence relationship |
| Rule created through a normal OWA/Outlook session matching the user's usual device and location | Rule created via a PowerShell/admin session, or from a sign-in with unfamiliar ASN/country/legacy auth immediately beforehand |
| Forward-all with a copy retained locally (user still sees the mail) | Silent forward with `DeleteMessage`/move-and-hide action so the owner never sees the original |
| Target is a known partner domain with an existing business relationship and a change record | Target is a personal webmail address, a freshly registered domain, or a one-character-off lookalike of a vendor domain |
| Mailbox-level forwarding matches a visible Outlook rule the user can point to | `Set-Mailbox -ForwardingSmtpAddress` populated with **no** matching Outlook-visible rule — mismatch is a red flag in itself |
| Rule has no content filtering (genuinely just "I'm out, forward everything") | Rule scoped narrowly to financial or credential-related subject/body keywords |

## Investigation Steps

1. Confirm the exact mechanism — pull both inbox-rule audit records (`New-InboxRule`/`Set-InboxRule`) and the mailbox object's `ForwardingSmtpAddress`/`ForwardingAddress` for the affected mailbox. Don't stop at whichever one triggered the alert; check both, since they're independent and attackers sometimes use the mailbox-level path precisely because it's less obvious. To see what's actually configured *right now* (the audit log only tells you what changed and when, not the current live state), run `Get-InboxRule -Mailbox <UPN> | fl Name,Enabled,ForwardTo,RedirectTo,DeleteMessage` and `Get-Mailbox -Identity <UPN> | fl ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward` directly against the mailbox.
2. Pull the creation event's `ClientIP`, `ClientInfoString`, and timestamp, then cross-reference the Azure AD sign-in log for that identity in the preceding hour — was there a risky, out-of-pattern, or legacy-auth sign-in that explains how the actor got in?
3. Resolve the forward target — domain reputation, WHOIS registration age, whether it's a recognized personal webmail provider, and whether it resembles (but isn't) a legitimate partner domain the org actually does business with.
4. Size the exposure using Message Trace and `MailItemsAccessed` — how long has the rule been live, how many messages matched it, and do any of those messages contain financial instructions, credentials, or sensitive HR/legal content. This determines whether you're closing a near-miss or opening a data-exposure incident.
5. Check whether the rule is scoped (keyword/sender conditions) or blanket — scoped rules indicate the attacker knew what they were after, which changes your assumption about intent and possibly who else in the thread needs notifying.
6. Look for companion account manipulation in the same window: delegate permission grants, new MFA methods or app passwords, OAuth app consents, or a paired inbox rule that hides/deletes the original mail.
7. Contact the mailbox owner through an out-of-band channel (phone call, in person — not by replying to any email in that account) to confirm whether they created the rule, and whether they're aware of any leave/coverage arrangement that would explain it.
8. Establish root cause — check recent sign-in risk detections and conditional access logs to determine how the account was accessed (phished credential, credential-stuffing hit, reused password from a breach). This decides whether removing the rule is sufficient or the credential itself needs a full reset and session revocation.

## True Positive Indicators

- External forward target with no business relationship, created from an anomalous or legacy-auth sign-in.
- `Set-Mailbox -ForwardingSmtpAddress` populated with no corresponding Outlook-visible rule — the stealth variant.
- Rule content-scoped to financial, credential, or HR keywords rather than a blanket catch-all.
- Forwarding paired with a delegate permission grant, new MFA registration, or OAuth consent grant around the same time.
- Mailbox owner denies creating the rule and has no leave/coverage record on file.
- Confirmed financial or credential-bearing mail already matched and flowed through the rule.

## False Positive / Benign Positive Indicators

- User configured forwarding to a personal secondary address purely for convenience — against acceptable-use policy, but not attacker activity; still gets removed and the user gets a policy reminder, closes as **Benign Positive**.
- Approved forward to a partner organization for a shared/monitored distribution mailbox, backed by an existing change ticket.
- Delegate/assistant coverage arrangement set up correctly through the helpdesk process ahead of approved leave — closes as **Expected Activity**.
- Rule was already removed (by the user, an admin, or auto-remediation) before the audit log retention window could be reviewed, and no sign-in anomaly or exposure evidence can be recovered — document what was checked and close as **Insufficient Evidence** rather than guessing at intent.
- Tenant-wide automatic-forwarding block was in place and the specific mailbox had a documented, approved exception — confirms the control is working as designed.

## Escalation Criteria

Escalate to Incident Response / Tier 3 immediately if any of:

- Confirmed external forward target on a mailbox belonging to finance/AP, an executive, HR, legal, or a Global Admin.
- Evidence that financial-instruction or credential-bearing mail already matched and flowed through the rule.
- Forwarding paired with a delegate permission grant, transport-rule-level (org-wide) redirect, or OAuth consent grant — indicates broader account or admin-role compromise.
- The same external target address or attacker infrastructure appears on more than one mailbox tenant-wide.
- Root cause traces to a credential that also has access to financial systems, banking portals, or code repositories.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Remove the inbox rule and clear mailbox-level forwarding (`Remove-InboxRule`, `Set-Mailbox -ForwardingSmtpAddress $null`) | SOC analyst/Tier 2, no additional approval needed once confirmed malicious |
| Revoke active sessions/refresh tokens and force re-authentication | SOC shift lead |
| Password reset and MFA re-registration for the affected account | SOC shift lead; notify account owner's manager |
| Remove associated delegate permissions or OAuth app consent grants | SOC shift lead, coordinate with M365 admin to avoid breaking a legitimate concurrent change |
| Tenant-level review/tightening of automatic-forwarding policy (outbound anti-spam / remote domain settings) | SOC manager plus M365 admin — this is a policy change with organization-wide impact |
| Notify finance/legal/affected external party if wire instructions or sensitive data were exposed | SOC manager or IR lead; legal and comms looped in as needed |

## Example Query

Microsoft Sentinel (KQL) — external forwarding rule/mailbox-level forward created against an external target, excluding the tenant's own accepted domains:

```kusto
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| where Parameters has_any ("ForwardTo","ForwardAsAttachmentTo","RedirectTo","ForwardingSmtpAddress","ForwardingAddress")
| extend ForwardTarget = extract(@"(?:ForwardTo|RedirectTo|ForwardingSmtpAddress|ForwardingAddress)\W+([\w\.\-]+@[\w\.\-]+)", 1, Parameters)
| where isnotempty(ForwardTarget) and ForwardTarget !endswith "@northwindtraders.example.com"
| project TimeGenerated, UserId, ClientIP, Operation, ForwardTarget, Parameters
```

## Closure Criteria

Close only after: the exact mechanism (inbox rule vs mailbox-level vs transport rule) is confirmed and removed, the forward target has been assessed for reputation/relationship, exposure has been sized using Message Trace/`MailItemsAccessed`, root cause of the account access is identified (or explicitly documented as undetermined), and any companion account manipulation (delegate, OAuth, MFA changes) has been checked and reversed if unauthorized.

**Example case note:**
`2026-09-15 09:41 UTC - Set-Mailbox forwarding found on a.reyes@northwindtraders.example.com pointing to a.reyes.finance@protonmail.example.com; no matching Outlook-visible inbox rule (mailbox-level path). Creation event ClientIP 203.0.113.77, legacy-auth session, ~20 min after an Identity Protection risky sign-in from the same IP. MailItemsAccessed shows 14 messages matched since creation incl. one AP wire-approval thread. Delegate permissions unaffected, no OAuth consent grants found. Forwarding cleared, sessions revoked, password reset, mailbox owner confirmed via phone she did not create this. Escalated to IR lead due to exposed wire-approval thread; AP team notified to hold that payment pending verification. Closed as True Positive, escalated.`
