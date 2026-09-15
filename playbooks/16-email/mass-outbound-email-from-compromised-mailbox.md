# Mass Outbound Email from Compromised Mailbox

## Playbook ID & Name

**EML-014 — Mass Outbound Email from Compromised Mailbox**

This is the far end of the mailbox-compromise chain covered elsewhere in this category (see BEC and Account Takeover) — the point where the attacker stops quietly reading mail and starts using the mailbox as a weapon against everyone in its address book, and often well beyond it. The defining characteristic that makes this scenario dangerous and distinct: the outbound mail is sent from a genuinely authenticated account on your tenant, so SPF, DKIM and DMARC all pass at the receiving end. Every anti-spoofing control the industry has built over the last decade is irrelevant here, because nothing is being spoofed. The account really is yours; it's just not being driven by the person who owns it anymore.

## Business Risk

**[STAKEHOLDER]** - Once a mailbox starts blasting hundreds of messages an hour, the damage isn't limited to that one account. Every external recipient — customers, vendors, partners — now has a phishing email in their inbox that looks like it came from a trusted contact, because it did. This burns goodwill and can trigger a chain reaction of compromises at other organizations that trust you. There's also a direct operational cost most people don't think of until it happens: mailbox providers and reputation services will throttle or blacklist your sending domain within hours, which can knock out legitimate email delivery for the entire company, not just the compromised account. The decision to notify external recipients, and how, belongs to Communications/Legal, not the SOC — but the SOC has to hand them an accurate recipient list fast, because every hour of delay is more people clicking.

## Severity/Priority Default

**High / P2** at open. Escalate to **Critical / P1** if the outbound content is itself a credential-phishing or malware payload (secondary-victim risk), if the account belongs to an executive or a shared/departmental mailbox with a large external distribution footprint, or if tenant-wide sending has been throttled/blocked by Microsoft or a downstream mail provider as a result.

## MITRE ATT&CK Techniques

- T1078.004 Valid Accounts: Cloud Accounts — the mailbox is being driven through legitimate, authenticated access.
- T1110.001 / T1110.003 Brute Force: Password Guessing / Password Spraying — common initial-access route into the account.
- T1566.001 / T1566.002 Phishing: Attachment / Link — when the mass-sent payload is itself a phishing lure (the most common case, since a freshly compromised mailbox is prime infrastructure for the next round of compromises).
- T1114.003 Email Collection: Email Forwarding Rule — attacker frequently stages a rule to auto-delete non-delivery reports (NDRs) and reply-based warnings so the account owner doesn't notice the flood.
- T1098.002 Account Manipulation: Additional Email Delegate Permissions — occasionally added to retain access if the primary credential gets reset.

## Trigger / Detection Logic Summary

In practice this alert arrives from one of three directions, and it's worth knowing which one you're looking at because it changes how far along the attacker already is:

1. **Microsoft gets there first.** The account trips Exchange Online Protection's outbound spam thresholds and lands in the tenant's Restricted Users list (Security & Compliance / Defender admin center), or the built-in "Suspicious email sending patterns detected" alert policy fires. By the time you see this, sending may already be blocked — which is good for containment but means the burst already happened.
2. **Volume anomaly detected internally.** A correlation rule on message trace / `EmailEvents` catches a sustained spike in outbound send count or unique-recipient count for one mailbox against its own 30-day baseline.
3. **External or downstream report.** A partner organization, customer, or your own abuse mailbox reports "we got a weird email from your employee," or your own outbound reputation monitoring shows a sudden deliverability drop / blacklist listing.

None of these alone confirms compromise — a legitimate mail-merge from HR or a mishandled marketing send can look identical in raw volume terms. The differentiator is always recipient pattern and content, covered below.

## Required Log Sources & Event IDs

Cloud mailbox telemetry only — no Windows Event/Sysmon IDs apply to this scenario.

| Source | What to pull |
|---|---|
| Exchange Online Message Trace | Per-message record: sender, recipient, subject, size, status (delivered/quarantined/failed), timestamp, originating IP |
| Microsoft Purview Audit (Unified Audit Log, M365) | Operations: `Send`, `SendAs`, `SendOnBehalf`, `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, `MailItemsAccessed` |
| Microsoft Defender for Office 365 | "Suspicious email sending patterns detected" alert, Restricted Users entry, tenant outbound spam filter policy hits |
| Entra ID Sign-in Logs | Sign-ins for the mailbox owner immediately preceding the send burst — location, ASN, client app, MFA/legacy-auth status |
| NDR / bounce queue | Volume of non-delivery reports generated by the burst — a strong independent confirmation signal |
| Recipient-side confirmation (partner/abuse reports) | Copy of the actual message as received externally, useful when internal capture is incomplete or delayed |

## Key Fields to Inspect

**[ANALYST]** `SenderAddress` and whether it matches the account under investigation or a Send-As/Send-On-Behalf delegate; `ClientInfoString` / connecting client (REST/Graph, EWS, legacy IMAP/SMTP AUTH, OWA) — attackers commonly use Graph API or EWS scripting to blast mail fast, which looks nothing like normal human OWA/Outlook usage; total `Send` count and unique-recipient count per 15–30 minute bin against the account's own historical baseline; ratio of internal vs. external recipients (a scraped address-book dump often includes stale or non-existent internal addresses, generating internal NDRs too); subject-line and body-hash uniformity across the burst (identical or near-identical template repeated hundreds of times is the single strongest tell); any `New-InboxRule` created in the same window with `DeleteMessage`/`StopProcessingRules` targeting NDR sender addresses or subjects containing "undeliverable"/"delivery status"; source IP/ASN on the triggering sign-in versus the account's normal geography.

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Send volume | Steady baseline (e.g., 40–150/day for a typical user mailbox) | Burst of hundreds within minutes to a few hours, far outside the account's own baseline |
| Recipient list | Known contacts, prior correspondence history, mostly internal or established external partners | Large list of unfamiliar external addresses, alphabetically sequential patterns, contacts scraped from address book/contact list |
| Content | Varied, contextual, human-written | Identical or near-identical subject/body across nearly every message, generic urgency lure ("Invoice overdue," "Shared document," "Password expiring") |
| Sending client | Outlook desktop/mobile, OWA | Graph API / EWS scripted access, or legacy SMTP AUTH the account never used before |
| NDR volume | Occasional bounces, low single digits | Sudden NDR flood matching the burst window, sometimes auto-hidden by a new inbox rule |
| Authentication (receiving side) | SPF/DKIM/DMARC pass — expected, not itself suspicious here | Still passes (this is the trap) — do not rely on auth results to judge maliciousness in this scenario |

## Investigation Steps

1. Pull Message Trace and Unified Audit Log `Send`/`SendAs`/`SendOnBehalf` records for the mailbox across the suspected window (start wide — 48 hours — then narrow); get total send count, unique-recipient count, and time distribution to confirm the burst is real and not a reporting artifact.
2. Check Entra ID sign-in logs for the account in the hours before the burst started; identify the triggering sign-in (new ASN/country/device, legacy auth, MFA bypass or fatigue) — this is your patient-zero event.
3. Query the Unified Audit Log for concurrent mailbox changes: new inbox rules (especially ones targeting NDR/bounce messages), new delegates, or Send-As grants added around the same window.
4. Pull an actual sample of the sent messages (subject, body, any link/attachment) and classify the payload — credential phish, malware attachment, advance-fee lure, or something more mundane. If it's a phishing payload, this case now has secondary-victim exposure and should be treated with that urgency.
5. Confirm current sending status: check the Restricted Users list / outbound spam quarantine in the Defender/Exchange admin center — is the account already blocked from sending, and is the tenant's sending reputation affected more broadly (check outbound deliverability/blacklist status)?
6. Build the full recipient list and split it into internal and external; cross-reference external recipients against known partner/customer contacts — this list is what Communications/Legal will need for notification, so get it accurate rather than fast-and-approximate.
7. Check whether the same source IP/ASN or the same message template touched any other mailboxes in the tenant — password spraying and phishing kits rarely stop at one account.
8. Establish root cause (sprayed credential, phishing click, credential reuse from an external breach) so remediation addresses the actual entry point and not just this one mailbox.

## True Positive Indicators

- Sustained burst of near-identical outbound messages, far outside the account's historical send baseline, to a recipient list that doesn't match the user's normal correspondence pattern.
- Sending client is Graph API/EWS or legacy SMTP AUTH the account has never used, immediately following an anomalous sign-in.
- New inbox rule created to suppress NDR/bounce notifications during or just before the burst.
- Account already flagged Restricted in the M365 admin console due to exceeding outbound thresholds.
- Message payload is a credential-phishing link or malicious attachment — confirms this mailbox is now attacker infrastructure, not just a compromised account.

## False Positive / Benign Positive Indicators

- Legitimate bulk send from HR, IT, or Comms (benefits enrollment reminder, policy update, event invite) sent from a personal mailbox instead of an approved bulk-mail tool — high volume, but content is coherent, recipient list matches a real internal distribution list, and the sender confirms it directly.
- Approved marketing/CRM tool misconfigured to relay through a personal mailbox instead of its dedicated sending domain — closes as Benign Positive once the tool owner confirms and volume drops after reconfiguration.
- Newsletter/digest re-send after a distribution list correction — burst is real but recipients and content are legitimate and expected.
- Insufficient Evidence closure is valid when message trace has already aged out of retention and no other log source (NDR queue, recipient report) can corroborate a volume anomaly that was flagged by a downstream/manual report alone.

## Escalation Criteria

Escalate to IR lead immediately when: the outbound payload is confirmed phishing or malware (secondary-victim notification required), the account is an executive or high-visibility shared mailbox, the same source infrastructure or message template hit more than one mailbox in the tenant, or tenant-wide outbound deliverability has been affected (blacklisting, provider-level throttling) — this last case also needs IT/Messaging engineering pulled in for reputation remediation, which runs on a longer timeline than the security containment.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Force password reset and revoke all active sessions/refresh tokens for the account | SOC analyst, immediate, no additional sign-off needed |
| Suspend/block the account from sending (if not already auto-restricted) | SOC analyst, immediate |
| Remove malicious inbox rule / delegate / Send-As grant | SOC shift lead, coordinate with M365 admin |
| Recall/purge any queued or already-delivered messages still within the tenant's control | SOC shift lead |
| Request removal from the Restricted Users list once remediation is verified | SOC shift lead, requires documented evidence of containment before Microsoft will lift it |
| External notification to affected recipients (partners/customers) | Comms/Legal sign-off — SOC provides the verified recipient list and message sample, does not send the notice itself |
| Engagement with mail-reputation/blacklist providers to expedite delisting | Messaging/Email engineering team, informed by SOC's containment evidence |

## Example Query

```kql
EmailEvents
| where Timestamp > ago(1d)
| where SenderFromAddress =~ "j.alvarez@example.com"
| summarize TotalSent = count(),
            UniqueRecipients = dcount(RecipientEmailAddress),
            ExternalRecipients = countif(RecipientEmailAddress !endswith "@example.com")
          by bin(Timestamp, 15m)
| where TotalSent > 50
```

## Closure Criteria

Close only once: password reset and session revocation are confirmed, any malicious inbox rule/delegate is removed and verified gone, sending capability has been restored only after remediation evidence was accepted (by Microsoft or the relevant mail admin), the full recipient list has been handed to Comms/Legal for external notification where applicable, and root cause (spray, phish click, credential reuse) is documented. Valid closures include True Positive (compromise confirmed and contained), Benign Positive (verified legitimate bulk send), and Insufficient Evidence (volume anomaly reported but not corroborated by retained message trace or NDR data).

**Example case-note line:** *"j.alvarez@example.com sent 612 messages to 598 unique external recipients between 02:10-02:47 UTC, identical subject 'Shared Document - Action Required' with a credential-phishing link; sign-in immediately prior from AS-14061 (unrecognized ASN), legacy SMTP AUTH, no MFA prompt; inbox rule 'ndr-filter' found deleting subject containing 'undeliverable', removed 03:15 UTC. Account auto-restricted by EOP outbound spam threshold at 02:49 UTC. Password reset, sessions revoked, rule deleted, legacy auth disabled for the account. Recipient list (598 external addresses) handed to Comms for notification. Closed - True Positive, compromise confirmed and contained."*
