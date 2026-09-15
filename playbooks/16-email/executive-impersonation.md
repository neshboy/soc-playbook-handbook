# EML-015 — Executive Impersonation (CEO/CFO Fraud, External Spoof or Lookalike Domain)

> Scope note: this playbook covers an attacker *pretending to be* an executive from outside the tenant - display-name spoofing, lookalike/cousin domains, or a freemail account styled to look like the CEO - without necessarily controlling any real mailbox. If the investigation turns up evidence that the executive's actual account was logged into and used to send the message, pivot to EML-003 (Business Email Compromise); the two often get confused at intake but the containment paths diverge fast.

## Business Risk

**[STAKEHOLDER]** - This is the "urgent request from the boss" attack, and it works because it's built entirely around organizational hierarchy and time pressure, not malware. A convincing message asking Finance to rush a wire, AP to change a vendor's bank details, or HR to email a batch of W-2s doesn't need to bypass EDR or exploit anything - it just needs one person who doesn't want to be the reason the CFO's request got delayed. The decision that matters is giving Finance/AP a standing rule: any payment or payroll-data request tied to urgency, secrecy, or a channel change (email instead of the usual portal/call) gets verified out-of-band before action, no exceptions for seniority.

## Severity / Priority Default

**Medium/P2** on detection alone (spoofed/lookalike-domain message flagged or reported, no response yet). Escalate to **High/P1** the moment a user has replied, and to **Critical/P0** if a payment, banking-detail change, gift-card purchase, or bulk PII/payroll disclosure has already occurred or is in flight.

## MITRE ATT&CK Techniques

T1566.001 (Phishing: Attachment), T1566.002 (Phishing: Link), T1204 (User Execution), T1114.003 (Email Collection: Email Forwarding Rule - relevant only in the reply-hijack variant, see below), T1078.004 (Valid Accounts: Cloud Accounts - relevant only if the exec's real account was compromised rather than spoofed).

## Trigger / Detection Logic Summary

Detection fires on one of three patterns, usually correlated together: (1) the sending domain fails or is absent for SPF/DKIM/DMARC alignment against the organization's own domain or a known-good vendor domain; (2) the display name matches or closely resembles a real executive (`Laura Chen`, `Laura Chen (CFO)`) while the underlying envelope address does not belong to the corporate domain - either a lookalike domain (`meridian-logistics.co` vs. the real `meridian-logistics.com`) or a freemail address (`laurachen.cfo@outlook.com`); (3) the message body matches known BEC lures - urgent wire/payment request, gift-card purchase request, request for a vendor bank-account change, or a request for payroll/W-2/PII data - often paired with tone cues like "are you at your desk," "handle this discreetly," or "don't call me, I'm in meetings." None of these alone is a reliable trigger (plenty of legitimate mail fails DMARC due to misconfigured third-party senders); the correlation of display-name-to-executive match + domain mismatch + lure keyword is what should actually page an analyst.

## Required Log Sources & Event IDs

No Windows Event or Sysmon IDs are in scope - this lives in mail flow and gateway telemetry.

| Source | What to pull |
|---|---|
| Secure Email Gateway (Defender for Office 365 / Proofpoint / Mimecast) | Impersonation/anti-spoof detection verdicts, "external sender" tag, quarantine/release history, URL click-time verdicts |
| Message headers (.eml) | `Authentication-Results` (SPF/DKIM/DMARC), `Return-Path`, `Reply-To`, `Received` chain, originating IP |
| Exchange Online Message Trace / mail flow logs | Delivery status, sender IP, recipient list, whether other users received the same or a similar message |
| DNS / passive DNS, WHOIS | Registration date and registrar of the sending domain (freshly registered domains are a strong signal) |
| Unified Audit Log (only if T1078.004 branch is suspected) | Sign-in activity on the real executive's account, to rule in/out actual compromise |
| Helpdesk / abuse mailbox / Report Message telemetry | User-reported copies, especially useful for scoping how many people received the campaign |

## Key Fields to Inspect

**[ANALYST]** `From` display name vs. `From` address (the visible name spoof) and separately `Reply-To` (attacker frequently sets this to a different address than either, so the victim's reply goes somewhere other than what's shown - a strong tell); `Return-Path` and the `Received` chain for the true originating IP/host; `Authentication-Results` line for SPF/DKIM/DMARC pass/fail/none and which domain each check was evaluated against; recipient list and CC/BCC (BEC lures are often sent to a single target, not broadcast, to avoid early detection); domain registration age via WHOIS (anything under 30-60 days old sending finance requests is close to automatic true positive); any attachment (fake invoice PDF, "updated banking details" doc) and its hash against sandbox/AV verdict; and, if the user replied, the full reply thread to see exactly what was promised or sent before the thread was caught.

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Display name vs. address | Matches, or a known/whitelisted third-party sender (payroll provider, bank) | Executive's name/title displayed, address is freemail or a domain one or two characters off the real one |
| SPF/DKIM/DMARC | Pass and aligned to sending domain | Fail, none, or aligned only to an unrelated/newly registered domain |
| Reply-To | Absent, or matches From | Present and different from From, redirecting replies to an address the recipient never sees rendered |
| Request type | Routine business correspondence, references known context (project name, prior thread) | Out-of-band payment/payroll/gift-card request, urgency language, request to bypass normal approval or use a new payment channel |
| Domain age | Established domain, years old | Registered within the last few weeks, privacy-proxy WHOIS |
| Recipient pattern | Normal distribution for that sender/topic | One or a small handful of specific Finance/HR/AP staff targeted, no broader distribution |

## Investigation Steps

1. Get the original message - the .eml file or a proper message trace, not a forwarded copy or screenshot - headers get mangled or stripped by forwarding and you'll lose the SPF/DKIM/DMARC and Received-chain evidence you actually need.
2. Compare the `From` display name against the `From` address and the `Reply-To` address; confirm whether the sending domain is a lookalike/cousin domain, a freemail provider, or the organization's real domain (in which case pivot immediately to the account-compromise branch and open EML-003 in parallel).
3. Check `Authentication-Results` for SPF/DKIM/DMARC outcome and alignment; run WHOIS/passive DNS on the sending domain to check registration age and hosting infrastructure.
4. Use message trace to identify every other recipient of the same or a similar message (same sender infrastructure, same lure template) across the organization - BEC campaigns frequently probe several Finance/AP/HR staff at once.
5. Determine whether any recipient replied, clicked, opened an attachment, or acted on the request; if a reply exists, read the full thread for commitments made (dollar amount, account number, files sent) before the user or a control caught it.
6. If a payment or data disclosure occurred or was requested, notify Finance/Treasury and HR/Privacy immediately - do not wait for full header/domain analysis to finish before that notification goes out.
7. Submit the sending domain/IP/URL and any attachment hash to the email gateway vendor and internal threat intel for blocklisting; check whether the domain or infrastructure has been seen against this org or others before.
8. If evidence points to the executive's real account (aligned SPF/DKIM, sent from the actual corporate domain with no header spoof), stop this playbook and run EML-003 - the containment actions are different (session revocation, mailbox rule audit) and doing header analysis on a legitimately-sent message wastes the response window.

## True Positive Indicators

- Executive display name paired with a freemail address, lookalike domain, or a domain with no prior legitimate mail history to this org.
- `Reply-To` set to an address different from the visible sender, redirecting responses off the record.
- Newly registered sending domain (days to weeks old) combined with a payment, banking-change, or gift-card request.
- Targeted delivery to one or a few Finance/AP/HR individuals rather than a broad distribution, with urgency/secrecy language in the body.
- Attachment or embedded link that sandbox/AV flags, or that leads to a credential-harvest page styled as a document portal.

## False Positive / Benign Positive Indicators

- SPF/DKIM/DMARC pass and aligned to the organization's genuine domain, message simply looks unusual in tone (executive writing informally from a personal device on the road) - verify by callback, likely Benign Positive.
- Legitimate third-party sender (payroll processor, outside counsel, board portal) using a domain not yet added to the allow-list, generating an impersonation-style alert on a real, expected message.
- Internal test/simulated-phishing campaign run by security awareness training, recognizable by known simulation domains or a debrief landing page.
- User reports a message as suspicious that turns out to be a legitimate, if oddly worded, request confirmed directly with the executive - closes as Benign Positive, not every unusual-sounding request is fraud.

## Escalation Criteria

Escalate to IR lead immediately when: a reply committing to a payment/banking change/gift-card purchase has been sent, any funds have moved or are scheduled to move, payroll or PII data was disclosed, or the same lure/infrastructure is confirmed against multiple recipients (campaign, not a one-off). Escalate to Legal/Privacy in parallel if PII or payroll data exposure is confirmed - this can trigger notification obligations independent of whether money moved.

## Containment Options & Approval Authority

**[MANAGEMENT]** Tier 1 (SOC analyst authority, immediate): quarantine/purge the message tenant-wide if still present in other mailboxes, block the sending domain/IP at the gateway, submit URL/attachment for vendor blocklisting. Tier 2 (requires IR lead sign-off): tenant-wide search-and-purge sweep for the same lure template across all mailboxes, addition of the lookalike domain to DNS/brand-monitoring watchlists. Tier 3 (requires Finance/Treasury and Legal, time-critical, run in parallel with technical containment - not after): emergency contact to the receiving bank to attempt a wire recall, HR/Privacy-led notification workflow if payroll or PII data was sent, and a decision on whether to notify the impersonated executive's real contacts (customers/vendors also targeted under their name).

## Example Query

```kql
EmailEvents
| where Timestamp > ago(7d)
| where SenderDisplayName has_any ("Laura Chen","CEO","CFO")
| where SenderFromDomain !endswith "meridian-logistics.com"
| where AuthenticationDetails has "fail" or AuthenticationDetails has "none"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderDisplayName, SenderFromDomain, AuthenticationDetails
```
*Note: `EmailEvents` has no `TimeGenerated` column (its time column is `Timestamp`), and DMARC/SPF/DKIM verdicts live in the single `AuthenticationDetails` string column on `EmailEvents` itself — there is no separate `EmailAuthenticationDetails` table with per-protocol verdict columns in the current Microsoft Defender advanced hunting schema. Adjust the `has` filter to match your tenant's actual `AuthenticationDetails` string format before relying on this query.*

## Closure Criteria

Close only once: the message (and any campaign siblings) is purged or confirmed not actioned by any recipient, the sending domain/IP/attachment is submitted for blocking, Finance/HR has confirmed no funds moved and no sensitive data went out (or has taken over recovery/notification separately if it did), the executive-compromise branch has been explicitly ruled out (or handed to EML-003), and the lure template is documented for gateway rule tuning. Valid closures include True Positive (contained), Benign Positive (verified legitimate sender or request), and Insufficient Evidence (spoofing indicators present but no recipient interaction and sender infrastructure inconclusive).

**Example case-note line:** *"Message received by D. Osei (AP) 2026-09-15 08:52 UTC, display name 'Laura Chen - CFO', envelope address laura.chen@meridian-logistics.co (registered 11 days prior, privacy WHOIS), SPF/DKIM none, DMARC fail, Reply-To set to a separate Gmail address not shown in client. Body requested urgent vendor bank-detail change, marked 'confidential, handle personally.' Osei escalated via Report Message before replying - no funds moved, no reply sent. Domain/IP blocked at gateway, message purged from 2 other mailboxes that received the same template, callback confirms real CFO never sent it. Closed as True Positive — contained, no financial or data impact."*
