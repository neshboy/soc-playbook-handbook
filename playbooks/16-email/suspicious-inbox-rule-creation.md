# Suspicious Inbox Rule Creation

## Playbook ID & Name

**EML-010 — Suspicious Inbox Rule Creation**

This playbook covers the *creation or modification of any mailbox inbox rule* whose conditions or actions look like attacker tradecraft rather than user housekeeping — not just external forwarding (that scenario has its own deep-dive in EML-009, Mailbox Forwarding Rule Abuse, when auto-forward-to-external-address is the dominant or only signal). Here the scope is broader and, honestly, the more common real-world case: rules that quietly delete, move, or mark-as-read messages containing words like "invoice," "password," "unusual sign-in," or "security alert." That behavior is Email Collection with a side of Impair Defenses — the attacker isn't just reading your mail, they're actively blinding the victim and sometimes blinding you.

## Business Risk

**[STAKEHOLDER]** - A single hidden inbox rule can let an attacker sit inside a compromised mailbox for weeks, invisibly redirecting or deleting the exact messages that would tip off the victim or IT (password reset confirmations, MFA alerts, bank verification calls) — this is one of the most common enablers of successful wire fraud and long-dwell-time email compromise. Deciding whether to force a tenant-wide password reset campaign, notify a business unit, or place a legal hold on a payment sits with the SOC manager, CISO delegate, or Finance/Legal depending on what the rule was shielding.

## Severity/Priority Default

**High** at intake. Escalates to **Critical** when the rule targets a finance, executive, or HR mailbox, when it is paired with an anomalous sign-in, or when it is actively shielding an in-flight payment/wire thread from detection.

## MITRE ATT&CK Techniques

- T1114.003 Email Collection: Email Forwarding Rule
- T1562.001 Impair Defenses: Disable or Modify Tools — rules that delete/hide security alerts, MFA notices, or IT communications
- T1078.004 Valid Accounts: Cloud Accounts — the compromised identity used to create the rule
- T1098.002 Account Manipulation: Additional Email Delegate Permissions — frequently created in the same session as the rule
- T1567 Exfiltration Over Web Service — when forwarded/redirected mail lands on a personal webmail or cloud-linked address

## Trigger / Detection Logic Summary

Raw "a new inbox rule was created" is too noisy to alert on by itself — users create rules constantly for entirely boring reasons. The case opens when one of these fires:

1. `New-InboxRule` / `Set-InboxRule` / `UpdateInboxRules` operation where the rule's actions include `DeleteMessage`, `MoveToFolder` (especially to Conversation History, RSS Feeds, or Archive — folders users rarely check), or `MarkAsRead` combined with conditions matching security/finance keywords (`SubjectContainsWords` / `BodyContainsWords` on terms like "password," "verify," "unusual sign-in," "invoice," "wire," "MFA").
2. Any forward/redirect action (`ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo`) pointing to an address outside the tenant's approved domain list.
3. Rule creation occurring within roughly 60 minutes of a risky or anomalous sign-in for the same UPN (new country/ASN, legacy authentication protocol, impossible travel, or an Identity Protection risk flag).
4. Rule created through a non-interactive client — PowerShell, EWS, or Graph API user agent — rather than the Outlook/OWA rules UI, with no corresponding change ticket. Scripted rule creation post-compromise is common; a user manually clicking through Outlook settings is not usually how this looks.
5. Rule has a blank, single-character, or generic name (".", " ", "Inbox Rule 1") designed to blend in or be skipped over during a quick manual review of the rules list — this is a deliberate evasion trick worth flagging on its own even without other signals.
6. Multiple rules created back-to-back on the same mailbox within minutes — redundant/backup rules in case one gets caught.

## Required Log Sources & Event IDs

| Source | What it gives you |
|---|---|
| Microsoft Purview Audit (Unified Audit Log) — Operations `New-InboxRule`, `Set-InboxRule`, `Enable-InboxRule`, `Remove-InboxRule`, `UpdateInboxRules` | Full rule parameters (conditions/actions), actor UserId, timestamp, client IP |
| Exchange Online mailbox audit log (requires mailbox auditing enabled) | `UpdateInboxRules` action independent of admin-level UAL, useful when UAL retention has already aged out |
| Entra ID sign-in logs | IP, ASN, country, device, legacy-auth flag, conditional access result, MFA outcome for the same UPN around the rule-creation timestamp |
| Entra ID Identity Protection | Risky sign-in / risky user flags correlating to the same session |
| Entra ID audit log | Paired delegate grants, Send As/Send on Behalf changes, OAuth app consent, new MFA method registration |
| M365 Defender Advanced Hunting — `CloudAppEvents`, `EmailEvents` | Rule-creation record in hunting form, plus whether any messages actually matched and were acted on by the rule |
| Exchange message trace | Confirms whether forwarded/redirected messages actually left the mailbox, volume, and destination |

## Key Fields to Inspect

**[ANALYST]**

- `Operation` and the full `Parameters` blob — decode the `Actions` and `Conditions` arrays exactly; don't rely on a summarized alert description, read the raw rule definition.
- `ForwardTo` / `RedirectTo` / `ForwardAsAttachmentTo` destination address and domain — internal, known personal address on file, or unfamiliar freemail/lookalike domain.
- `DeleteMessage`, `MoveToFolder`, `MarkAsRead`, and `StopProcessingRules` — the last one is important: `StopProcessingRules=True` on an attacker rule means it runs first and nothing downstream (including any legitimate alerting rule) sees the message.
- `UserId` (who/what made the change) vs the mailbox owner — was this the user themselves, an admin on a help desk ticket, or a service principal.
- `ClientIP` and `ClientInfoString` / user agent — Outlook rich client and OWA look very different from a PowerShell or EWS session string; the latter with no matching change ticket is a strong signal.
- Rule `Name` — blank, whitespace-only, or generic names are a deliberate concealment tactic, treat them as elevated risk on their own.
- Preceding sign-in: `IPAddress`, `Location`, `AppDisplayName`, `AuthenticationRequirement`, `ConditionalAccessStatus`, `RiskLevelDuringSignIn`.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Rule created via Outlook/OWA UI to file newsletters, ticketing-system mail, or automated reports into a named folder | Rule created via PowerShell/EWS/Graph client with no matching change ticket |
| Conditions target a known sender/subject unrelated to security or finance | Conditions target keywords like "password," "verify," "unusual sign-in," "wire," "invoice" |
| Action files mail into a clearly labeled, regularly-checked folder | Action moves mail to Conversation History/RSS Feeds/Archive, or deletes/marks-as-read outright |
| Forward, if present, goes to a documented internal alias or a personal address the user has on file through IT | Forward/redirect goes to an external freemail address or a domain one character off from a partner |
| Rule has a descriptive name matching its purpose | Rule name is blank, a single character, or generic/duplicate-looking |
| Rule creation has no unusual sign-in nearby | Rule creation follows a risky/anomalous sign-in for the same account within the hour |

## Investigation Steps

1. Pull the full audit record for the triggering operation and decode `Parameters` in full — exact `Conditions`, `Actions`, actor `UserId`, `ClientIP`, and `ClientInfoString`.
2. Check sign-in logs for that UPN in the preceding 60–90 minutes for unfamiliar ASN/country, legacy auth, MFA fatigue (repeated prompts then a success), or an Identity Protection risk flag.
3. Enumerate **every** active rule on the mailbox *as it stands right now*, not just the one that alerted — run `Get-InboxRule -Mailbox <UPN> | fl Name,Enabled,Priority,Conditions,Actions,StopProcessingRules` (Exchange Online PowerShell) for the live rule set; the audit log only shows the history of change events, not current state, and a rule edited multiple times can be hard to reconstruct from those events alone. Attackers frequently create more than one rule, and the alerting engine may only have caught the sloppiest.
4. If a forward/redirect action exists, resolve the destination domain (internal? personal freemail? newly registered lookalike?) and pull message trace to confirm whether mail actually left the mailbox, how much, and over what window.
5. Check for paired persistence created in the same session: new delegate/Send As grant, new OAuth app consent, new registered MFA method, or a newly created mailbox rule on a second account from the same IP.
6. Assess what the rule's conditions actually targeted — if security/alert-type keywords are present, this is active evasion; determine whether any real security notification was suppressed during the dwell window, because that gap is your true exposure window, not just the rule's lifetime.
7. Establish the account's entry vector rather than assuming — prior password spray hit, phished credential, token replay — pull the earlier authentication chain. This decides whether a password reset alone is sufficient or a full session/refresh-token revoke is required too.
8. Scope blast radius: what messages were read, deleted, or forwarded before the rule was removed; whether a wire/payment thread was specifically being shielded; whether any outbound mail was sent from the mailbox to other victims while the rule was active.

## True Positive Indicators

- Forward/redirect to an unfamiliar external address, especially personal webmail or a domain a character off from a known partner.
- Rule created via non-interactive client (PowerShell/EWS) with no matching change or help-desk ticket.
- Rule conditions target security, password, MFA, or financial keywords paired with delete/move/mark-as-read actions.
- Rule creation is temporally tied to a risky or anomalous sign-in on the same account.
- Blank, single-character, or deliberately generic rule name; multiple near-duplicate rules created within minutes of each other.
- `StopProcessingRules=True` combined with `DeleteMessage=True` — full inbox pipeline hijack before any other rule or alert can act.

## False Positive / Benign Positive Indicators

- User created the rule via Outlook/OWA UI to organize known senders (newsletters, ticketing add-ins, automated digest mail); no external forward, no security-keyword targeting.
- Legitimate business forwarding to a personal device or a coworker's mailbox during planned leave, requested and documented through the standard change process.
- Mailbox migration or provisioning tooling recreating pre-existing rules during a tenant-to-tenant or on-prem-to-cloud move — check the migration change window before assuming compromise.
- An approved CRM/ticketing add-in that creates its own filing rule as part of normal integration — confirm against the approved application inventory.
- **Insufficient Evidence** is a valid closure when mailbox audit logging was not enabled at the time of the event (a known gap on some older or under-licensed tenants) and no corroborating sign-in anomaly or message trace evidence exists either way — document the logging gap itself as a finding for the engineering backlog rather than guessing at a verdict.

## Escalation Criteria

Escalate to Incident Response / Tier 3 immediately if any of:

- Confirmed external forward/redirect combined with any risky sign-in indicator on the account.
- Rule specifically targets security alert, MFA, or password-reset keywords for deletion — active evasion of detection, not just data collection.
- Evidence ties the rule to an active BEC/wire-fraud thread on a finance mailbox — escalate to IR and notify Finance to hold any pending payment in the same motion.
- The same actor pattern (IP/ASN/client string) is seen creating rules across more than one mailbox — indicates a broader compromise, not an isolated account.
- Mailbox audit logging was disabled, or retention had already aged out, preventing full scoping — escalate for a wider compromise assessment rather than closing on partial evidence.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Remove the malicious inbox rule (`Remove-InboxRule -Mailbox <UPN> -Identity "<RuleName>"`) | SOC analyst/Tier 2, no additional approval needed once malicious intent is confirmed |
| Force password reset and revoke all sessions/refresh tokens | SOC shift lead approval; notify account owner's manager |
| Block destination domain/address at mail flow or DLP | SOC Tier 2, informational notice to email admin team |
| Remove any paired delegate grant / Send As permission / OAuth app consent | SOC shift lead, coordinate with M365 admin to avoid breaking a legitimate concurrent change |
| Legal/Finance hold on an in-flight payment tied to a shielded invoice or wire thread | SOC manager coordinates directly with Finance/Legal — not a unilateral SOC action |
| Enable or verify mailbox audit logging tenant-wide if found disabled | SOC manager escalation to M365 admin/engineering; tracked as a standing gap beyond this ticket |
| Broader compromise assessment across multiple mailboxes | SOC manager or IR lead |

## Example Query

Microsoft Sentinel (KQL) — flag inbox rules with delete/forward actions targeting security or finance keywords:

```kusto
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend RuleActions = tostring(Parameters)
| where RuleActions has_any ("DeleteMessage","ForwardTo","RedirectTo","ForwardAsAttachmentTo")
| where RuleActions has_any ("password","verify","invoice","wire","MFA","security alert")
| project TimeGenerated, UserId, ClientIP, Operation, RuleActions
```

## Closure Criteria

Close only after: the full parameter set of every rule on the mailbox has been reviewed (not just the alerting one), the destination of any forward/redirect action has been resolved and message trace checked for actual mail movement, the account's entry vector has been established or explicitly marked unresolved, any paired persistence (delegate/OAuth/MFA method) has been checked and removed if malicious, and the rule itself has been deleted with the action logged in the case. Attach the decoded rule parameters and sign-in correlation to the case regardless of verdict.

**Example case note:**
`2026-09-15 09:47 UTC - New-InboxRule created on mailbox r.delgado@example.com via EWS client (no matching change ticket), rule named "." with Actions: MoveToFolder=RSS Feeds, DeleteMessage on Conditions: SubjectContainsWords("unusual sign-in","password"). Preceding sign-in from 41.203.x.x (unfamiliar ASN, legacy auth) 22 min prior, flagged Medium risk by Identity Protection. Message trace shows 6 security-notification emails routed to RSS Feeds folder over 3 days before detection, no messages read by user. No forwarding action present, no paired delegate grant found. Rule deleted, account password reset and sessions revoked, mailbox audit logging confirmed enabled going forward. Closed as True Positive; account compromise confirmed (T1114.003/T1562.001), IR notified due to security-alert suppression.`
