# Internal (Compromised-Account) Phishing

## Playbook ID & Name

**ID:** EML-008 | **Name:** Internal (Compromised-Account) Phishing - Lateral Spread from a Trusted Mailbox
**Category:** Email

## Business Risk

**[STAKEHOLDER]** - This is the scenario every awareness-training slide warns about but nobody quite believes will happen to them: a real employee's mailbox is already under attacker control, and the attacker uses it to email other employees - or partners, or customers - because a message from a real colleague inside a real thread is far more convincing than anything an external phishing kit can fake. SPF, DKIM and DMARC all pass, because it genuinely is your tenant sending it. The blast radius is the entire address book and every distribution list that account has visibility into, and the damage compounds fast: each additional mailbox that clicks becomes a second launch pad. This is functionally a worm, just using human trust instead of a software exploit as the propagation mechanism, and it's why "one compromised account" incidents rarely stay single-digit in scope if they're not caught in the first few hours.

## Severity / Priority Default

- **Default:** High. The account is already confirmed or strongly suspected compromised, and it is actively being weaponized against other internal trust relationships - this is not a "maybe" alert.
- **Critical** if the sending mailbox belongs to an executive, finance, or IT/helpdesk role (the accounts recipients are least likely to question), if any recipient has confirmed clicked/entered credentials, or if the blast reached external partners/customers (supply-chain exposure, reputational fallout).

## MITRE ATT&CK Techniques

- **T1078.004 / T1078.002** - Valid Accounts: Cloud Accounts / Domain Accounts (the compromised identity being reused as the delivery mechanism - this is the defining trait of the playbook)
- **T1566.001** - Phishing: Attachment (malicious document/HTML file riding on the internal message)
- **T1566.002** - Phishing: Link (credential-harvesting or malware-staging URL)
- **T1204** - User Execution (recipients opening the attachment or following the link)
- **T1114.003** - Email Collection: Email Forwarding Rule (attacker frequently plants a rule on the compromised mailbox to hide bounce/NDR traffic and reply warnings so the account owner doesn't notice the abuse in progress)
- **T1098.002** - Account Manipulation: Additional Email Delegate Permissions (persistence - a delegate grant survives a simple password reset)
- **T1098.001** - Additional Cloud Credentials (persistence - a newly registered MFA method or app password also survives a password reset)

## Trigger / Detection Logic Summary

**[ENGINEERING]** The signal here is almost never an authentication failure - the message is authentic. Detection has to be behavioral, anchored on deviation from the sending mailbox's own baseline, not on SEG/gateway verdicts that assume external-sender risk.

- **Volume/fan-out anomaly**: a mailbox that historically sends single-digit, mostly 1:1 messages per day suddenly sends to a large distinct-recipient set (internal, and sometimes external) within a short window. Baseline this per mailbox, not tenant-wide - a sales rep and a payroll clerk have very different normal send volumes.
- **Reply-chain hijack pattern**: the malicious message is a reply/forward inside a real, aged thread (matching `In-Reply-To`/`References` headers and an existing `ConversationId`), with content that doesn't match the thread's original topic - a strong TP signal, because it means the attacker mined the mailbox for a credible thread to inject into rather than composing a fresh, obviously-unrelated email.
- **Corroborating identity signal**: an anomalous sign-in (new country/ASN, legacy authentication protocol, impossible travel, or a burst of MFA push prompts) on the sending account in the hours before the send.
- **Payload correlation**: the same URL, attachment hash, or HTML-smuggled page shows up across multiple internal recipients in Threat Explorer/Advanced Hunting within a tight window - this is what turns "one weird email" into a confirmed campaign.
- **Companion rule creation**: a `New-InboxRule`/`UpdateInboxRules` event on the sending mailbox around the same timeframe, especially one that moves or deletes non-delivery reports, "undeliverable" bounces, or reply traffic matching the phishing subject line.

## Required Log Sources & Event IDs

| Source | Event / Operation | Why |
|---|---|---|
| M365 Unified Audit Log (or equivalent mailbox audit log) | `Send`, `MailItemsAccessed` | Confirms the mass-send itself and who/what touched the mailbox around that time |
| M365 Unified Audit Log | `New-InboxRule`, `UpdateInboxRules`, `Set-Mailbox` (forwarding) | Detects the hide-the-evidence rule (T1114.003) commonly planted alongside the send |
| M365 Unified Audit Log | `Add-MailboxPermission`, `Add-RecipientPermission` | Delegate persistence (T1098.002) that survives a password reset |
| Identity provider sign-in logs (Entra ID or equivalent) | interactive + non-interactive sign-ins | Correlates the anomalous logon that precedes/coincides with the send |
| Identity provider audit log | security-info registration, app consent grants | Additional Cloud Credentials persistence (T1098.001) |
| Secure Email Gateway / Defender for Office 365 (or equivalent) | Threat Explorer / campaign view, URL click (Safe Links-style) verdicts | Payload verdict, tenant-wide recipient scope, click telemetry |
| Message Trace | delivery status per recipient | Distinguishes delivered vs quarantined vs bounced, internal vs external split |

## Key Fields to Inspect

**[ANALYST]**

| Field | Source | What to check |
|---|---|---|
| Sender / `SenderFromAddress` | Send event / message header | Confirm it's genuinely the internal mailbox and not a display-name spoof riding on a lookalike domain - internal-phishing and spoofed-internal-display-name cases get triaged very differently |
| Recipient count / recipient list | Send event | Blast size and whether it's internal-only, or leaked to external partners/customers - external spread changes notification obligations |
| `In-Reply-To` / `References` / `ConversationId` | raw header | Reply-chain hijack indicator - does this sit inside a real, older thread |
| `Authentication-Results` (SPF/DKIM/DMARC) | raw header | Expect **pass** - don't use a clean pass to talk yourself out of escalating, that's the whole point of this scenario |
| Client IP / client app string | Send/UAL | Sending client vs the account's normal pattern (e.g., legacy IMAP/SMTP suddenly appearing when the user has only ever used OWA/Outlook desktop) |
| `Operation` | UAL | `New-InboxRule` / `UpdateInboxRules` / `Add-MailboxPermission` timestamps relative to the send |
| Sign-in location / ASN / device | Identity sign-in log | New country, hosting-provider ASN, unregistered device, or legacy auth immediately before the send |
| Click verdict / click time | Safe Links-style click telemetry | Who clicked, and note that verdict time can lag click time - a link "safe" at click may be reclassified malicious minutes later; don't close recipients out on stale verdicts |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Mailbox sends a handful of 1:1 or small-group messages/day, consistent with its role | Sudden blast to dozens/hundreds of internal recipients (and sometimes external ones) in a short window |
| New threads start fresh, or replies stay on-topic within existing threads | A reply is injected into an old, unrelated thread with generic urgency ("Invoice - Action Required", "Password Expiring") that doesn't match the thread's original subject matter |
| Sign-in geography, device, and auth protocol match the user's established pattern | New ASN/country, legacy auth protocol, or an unregistered device appears shortly before the send |
| Any inbox rule on the mailbox is documented and business-justified (e.g., approved forwarding during leave) | A newly created rule quietly moves/deletes bounce, NDR, or reply traffic matching the phishing subject - clearly built to buy the attacker time |
| Writing style, signature block, and tone match the account owner | Signature missing/altered, tone off, or content generic enough to paste into any thread |

## Investigation Steps

1. Pull the full `Send`/message-trace record for the sending mailbox across the alert window - get recipient count, internal-vs-external split, and whether it's a reply-chain hijack (matching `ConversationId`/`References`) or a fresh mass send.
2. Retrieve the raw headers/.eml from at least one recipient copy. Confirm SPF/DKIM/DMARC (expect pass) and compare the send timestamp and client string against the sender's established baseline volume and client.
3. Pull identity sign-in logs for the mailbox owner covering the prior 24-72 hours - look for anomalous geography/ASN, legacy authentication, or an MFA-fatigue pattern (repeated push prompts followed by an accept).
4. Search the audit log for `New-InboxRule`/`UpdateInboxRules`, `Set-Mailbox` (forwarding), and `Add-MailboxPermission`/`Add-RecipientPermission` events on the same mailbox around the same timeframe - a rule hiding bounces/replies is strong corroboration, and a delegate grant is a persistence path that outlives a password reset.
5. Pivot on the payload (URL or attachment hash) tenant-wide via Threat Explorer/Advanced Hunting to scope every mailbox that received or clicked it - this is your real blast radius, not just the original sender's recipient list.
6. For every confirmed click, especially where a credential-harvest page was involved, treat that recipient as a potential secondary compromise - pull their own sign-in logs for the period immediately following the click.
7. Check for T1098.001 persistence on the original account specifically - a newly registered MFA method, an app password, or a new OAuth app consent granted around the compromise window. These are the artifacts that make an attacker walk back in after a routine password reset.
8. Trace the root compromise vector of the original account (prior credential phish, a password-spraying hit, token theft) so remediation addresses the actual entry point - closing this ticket without answering "how did they get in originally" just guarantees a repeat.

## True Positive Indicators

- Mass/blast send from a mailbox that historically sends 1:1 or small-group volume, breaking its own baseline.
- Reply-chain hijack: malicious content injected into a real, aged thread rather than a freshly composed message.
- SPF/DKIM/DMARC pass (expected) combined with a malicious verdict on the URL/attachment from sandbox or Threat Explorer.
- Anomalous sign-in on the sending account preceding the send, with no matching travel/VPN/device-registration explanation.
- A new inbox rule filing bounce/NDR/reply traffic away from the inbox, timed close to the send.
- Multiple recipients reporting the same message via the abuse mailbox/report-phishing pipeline within a short window.

## False Positive / Benign Positive Indicators

- Legitimate mass communication (HR benefits update, IT maintenance notice) sent from a shared or service mailbox not normally used for 1:1 mail - check the internal comms calendar before treating volume alone as evidence.
- A marketing/eDM tool relaying through a real employee's mailbox due to a misconfigured "send-as" setup, not a compromise.
- An authorized phishing-simulation or security-awareness campaign (e.g., KnowBe4, Proofpoint Security Awareness style tooling) - always check the campaign calendar first; this is a recurring, avoidable source of wasted IR hours.
- An inbox rule that looks suspicious in isolation but has a documented, user-confirmed business reason (e.g., forwarding to a personal address during approved leave) - verify directly with the user rather than assuming malicious intent from the rule alone.

## Escalation Criteria

Escalate to Tier 2/IR immediately if any of the following applies: a confirmed credential-harvest click or malware execution on any recipient; a corroborating sign-in anomaly on the source account; the sending mailbox belongs to an executive, finance, or IT/helpdesk role; the blast reached external partners or customers; or a persistence artifact (new MFA method, delegate grant, OAuth consent, forwarding rule) is found on the compromised account, since any of these independently indicate the attacker retains a path back in even after an obvious fix.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Reset password + revoke all active sessions on the compromised account | SOC Tier 2 (no external approval needed) | Immediate, standard first move - do this before anything else |
| Remove malicious inbox rule / delegate grants / suspicious app consents | SOC Tier 2 | Must be done alongside the reset - a reset alone does not remove these persistence paths |
| Purge the malicious message tenant-wide (automated remediation plus manual purge for anything missed) | Email security engineer or Tier 2, tracked via change ticket | Confirm purge coverage - automated tenant-wide remediation frequently misses a handful of mailboxes (already-moved/deleted items, shared mailboxes) |
| Force MFA re-registration / revoke OAuth refresh tokens | IAM Team Lead | Closes off the T1098.001 persistence path specifically |
| Block payload URL/hash tenant-wide at SEG and web proxy | Network/Security Engineering on-call | Fast, low-friction, do regardless of confirmed click count |
| Notify affected recipients and mandate password reset for confirmed clickers | Incident Commander (plus Comms/HR if an executive mailbox or external recipients are involved) | External-recipient notification may carry contractual/regulatory obligations - loop in Legal/Privacy early if partners/customers received the message |

## Example Query

```kql
EmailEvents
| where Timestamp > ago(1d)
| where SenderFromDomain == "northwind.example"
| summarize RecipientCount = dcount(RecipientEmailAddress),
            Recipients     = make_set(RecipientEmailAddress, 5)
          by SenderFromAddress, bin(Timestamp, 1h)
| where RecipientCount > 25
| order by RecipientCount desc
```

## Closure Criteria

Close as **True Positive** once the compromised account is secured (password reset, sessions revoked, MFA re-registered), every persistence artifact (rule, delegate, app consent) is removed, the malicious message is purged tenant-wide, and every recipient who clicked or opened the payload has been individually remediated and checked for secondary compromise. Close as **Benign Positive / Expected Activity** when the send traces to an authorized awareness campaign or a legitimate mass communication misidentified as compromise. Insufficient Evidence closures are rare in this specific playbook since the triggering account is already known/suspected compromised - if payload intent can't be confirmed, keep the account on heightened monitoring rather than closing clean.

**Example case note:**
> 2026-09-15 09:40 UTC - mailbox james.okafor@northwind.example sent "Q3 Invoice Review - Action Required" to 47 internal recipients as a reply inside an 11-month-old finance thread, well outside the account's baseline of ~3 msgs/day, mostly 1:1. Message contained a link to a spoofed O365 login page (Defender verdict: Phish, confirmed via sandbox). Sign-in logs show a legacy-IMAP authentication from an unrecognized ASN 40 minutes prior, no matching travel or VPN entry. Audit log shows a `New-InboxRule` ("RSS Feeds", MoveToFolder + MarkAsRead) created 5 minutes before the send, clearly built to hide reply/NDR traffic. Reset password and revoked sessions on james.okafor, removed the rule, purged the message tenant-wide (automated purge missed 9 mailboxes, cleaned manually). Six recipients clicked per click telemetry - forced password reset on all six, no downstream sign-in anomalies found on any of them as of close. Closed as True Positive.
