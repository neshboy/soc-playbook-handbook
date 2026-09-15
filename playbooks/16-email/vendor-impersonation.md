# EML-016 — Vendor Impersonation (Supplier/Invoice Fraud)

## Business Risk

**[STAKEHOLDER]** - This is the one where Accounts Payable calls the SOC, not the other way around. A convincing vendor-impersonation email asks someone in Finance to update banking details on a supplier record, or to pay an "overdue" invoice to a new account, and by the time anyone questions it the money is gone and unrecoverable. There are two distinct threats hiding under one label: a criminal spoofing your real vendor's brand from a lookalike domain they control (no compromise of the vendor at all), or the vendor's actual mailbox being compromised and used to hijack a live email thread - the second is far harder to catch because the email genuinely comes from the vendor's real address with valid authentication. The business decision that matters is whether AP has a verified callback process for any banking-detail change, because that single control stops nearly every variant of this attack regardless of how good the email looks.

## Severity / Priority Default

**High / P1** on detection of a suspected impersonation attempt with no confirmed financial action. Escalate to **Critical / P0** immediately if a payment, wire, or ACH change has already been submitted or executed against the fraudulent instructions.

## MITRE ATT&CK Techniques

T1566.001 / T1566.002 (Phishing: Attachment / Link), T1204 (User Execution), T1078.004 (Valid Accounts: Cloud Accounts) - when the real vendor mailbox is compromised, T1114.003 (Email Collection: Email Forwarding Rule) and T1098.002 (Account Manipulation: Additional Email Delegate Permissions) - both on the vendor side if their tenant is compromised and observable, T1552.001 (Unsecured Credentials: Credentials In Files) - where invoice attachments are used to harvest AP workflow data, T1090 (Proxy) - impersonation domains frequently sit behind bulletproof/anonymized hosting.

## Trigger / Detection Logic Summary

Two distinct trigger paths feed this playbook. Path one is **domain spoofing**: the secure email gateway or DMARC analysis flags a message claiming to be from a known supplier where the sending domain is a lookalike (typosquat, homoglyph, or added subdomain) rather than the vendor's real registered domain - `acme-supplies.com` instead of `acmesupplies.com`, or a Cyrillic "а" substituted into an otherwise identical string. Path two is **thread hijacking / VEC (Vendor Email Compromise)**: the message authenticates cleanly (SPF/DKIM/DMARC all pass) because it genuinely originated from the vendor's real, compromised mailbox, often as a reply inserted into an existing invoice thread. Because path two produces no authentication failure, the trigger there is behavioral, not cryptographic: a request to change banking details, a shift in payment terms, unusual urgency/secrecy language ("please handle this discreetly," "our usual account is under audit"), or a request routed outside the normal AP ticketing/PO-matching process. Neither path alone is reliable - combine domain reputation/age, authentication results, and payment-change keyword detection into one correlation rule rather than alerting on any single signal.

## Required Log Sources & Event IDs

No Windows Event IDs or Sysmon Event IDs apply to this playbook - it lives in mail flow and cloud audit telemetry. If the investigation pivots into an internal account compromise (attacker replying from an internal mailbox they've taken over), pull that account's Entra ID sign-in and Unified Audit Log (Microsoft Purview Audit) activity separately.

| Source | What to pull |
|---|---|
| Secure Email Gateway (Defender for Office 365 / Proofpoint / Mimecast) | Impersonation/spoof-intelligence verdicts, DMARC/SPF/DKIM results, URL/attachment sandbox verdicts, quarantine and release history |
| Message headers / Message Trace | Full raw headers, `Authentication-Results`, `Received` chain, envelope (P1) vs header (P2) From mismatch, Reply-To address |
| DNS / WHOIS / passive DNS | Domain registration date, registrar, nameservers for the sending domain |
| Vendor master / AP system | Known-good vendor domain(s), historical invoice amounts and bank account on file, PO matching status |
| M365 Unified Audit Log (if internal mailbox implicated) | `New-InboxRule`, `Add-MailboxPermission`, `Send`, `MailItemsAccessed` |
| User report pipeline | Report Message/abuse mailbox submissions referencing the vendor name |

## Key Fields to Inspect

**[ANALYST]** Envelope-From vs header From (P1/P2 mismatch is a strong tell), Reply-To domain vs From domain, `Authentication-Results` (spf=, dkim=, dmarc=), originating IP and its ASN/reputation, domain creation date from WHOIS (anything under 60-90 days old on a "long-standing supplier" is a red flag), display name (does it show the real vendor company name while the underlying address is unrelated), attachment metadata (PDF author/producer field mismatched against the claimed sender), embedded bank account/IBAN/routing number compared against the value on file in the vendor master, subject/body keywords ("updated banking details," "new account," "remittance," "urgent," "confidential"), and - if VEC is suspected - whether the message sits inside a genuine prior thread (References/In-Reply-To headers matching a real historical conversation) versus a cold, unsolicited message.

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Sending domain | Exact match to vendor domain on file, SPF/DKIM/DMARC pass | Lookalike domain, newly registered, or DMARC fail/none on a domain claiming to be a long-standing vendor |
| Reply-To | Matches From domain or absent | Reply-To on a different domain than From, often a freemail or unrelated business domain |
| Banking details | Unchanged for the life of the vendor relationship, changes go through documented AP change-control | Change request arriving only by email, with urgency, and no corresponding AP ticket or PO reference |
| Thread context | Fits a real, ongoing invoice/PO conversation with consistent history | Cold message referencing an invoice number that doesn't exist in the ERP/AP system, or a reply injected into an old thread after a long silence |
| Payment amount | Consistent with historical PO/contract values | Round-number or inflated amount, or "final notice" pressure language not typical of that vendor's prior correspondence |

## Investigation Steps

1. Obtain the original .eml/raw message (not a forward or screenshot) and run full header analysis - confirm SPF/DKIM/DMARC results and compare envelope-From against header-From.
2. Compare the sending domain against the vendor's known-good domain(s) in the vendor master; run WHOIS/passive DNS on any domain that doesn't match exactly and note registration age and registrar.
3. Determine which scenario you're in: if authentication passes cleanly on the vendor's real domain, treat this as suspected Vendor Email Compromise, not simple spoofing - contact the vendor through a verified, independently-sourced phone number (never a number or link from the suspect email) to ask if their mailbox is compromised.
4. If a link or attachment is present, detonate it in sandbox and extract IOCs (URLs, file hashes, any credential-harvesting page mimicking the vendor's real login portal).
5. Search message trace/SIEM tenant-wide for the same sender domain, subject pattern, or attachment hash to scope how many other mailboxes received the same or similar messages.
6. Check with AP/Finance immediately for any payment, wire, or banking-detail change already submitted or scheduled against this vendor - this step should not wait for the rest of the investigation to finish.
7. If a payment was already sent to the fraudulent account, engage Finance/Treasury and Legal at once to attempt a bank recall - the window for this is measured in hours, not days.
8. Document the vendor's legitimate contact details, the fraudulent domain/IOCs, and submit both for blocking at the gateway and web proxy; add the confirmed-good vendor domain and bank details to an internal reference list to speed up the next report.

## True Positive Indicators

- Lookalike or newly registered domain impersonating a known supplier, combined with a banking/payment-detail change request.
- DMARC fail on a message purporting to be from a long-established vendor with a previously clean authentication history.
- Sandbox detonation confirms a credential-harvesting page cloned from the vendor's actual customer/vendor portal.
- AP confirms a wire or ACH change was submitted or executed against the requested new account.
- Vendor confirms (via verified out-of-band contact) that their mailbox or domain was compromised and the message did not legitimately originate from them.

## False Positive / Benign Positive Indicators

- Vendor legitimately changed email platforms or added a new domain, announced and confirmed through a verified channel (not the email itself).
- Vendor merger, acquisition, or rebrand resulting in a genuinely new but properly authenticated domain.
- Internal security-awareness phishing simulation using a vendor-themed template - check the simulation calendar before escalating.
- Employee forwarded a legitimate invoice through a personal email account, producing messy headers but no actual fraud.
- Payment-detail change that, on callback verification with the vendor's known contact, turns out to be a genuine AP-approved update.

## Escalation Criteria

Escalate to IR lead and notify Finance/Treasury and Legal immediately when: a banking/payment-detail change request is confirmed as fraudulent, any wire/ACH/payment has been submitted or executed against fraudulent instructions, the vendor confirms their own mailbox is compromised (this becomes a joint incident requiring coordination with an organization outside your visibility), or the same lookalike domain/attachment is hitting multiple mailboxes across the org. Escalate to Legal/Comms if the impersonation uses your organization's brand against the vendor's customers (reverse case) rather than the vendor's brand against you.

## Containment Options & Approval Authority

**[MANAGEMENT]** Tier 1 (SOC analyst authority, immediate): quarantine/block the fraudulent sender, domain, and any associated URLs/hashes at the mail gateway and web proxy; notify the targeted user(s) not to act on the email. Tier 2 (requires IR lead sign-off): tenant-wide search-and-purge of the same message across other mailboxes; if the compromise is on the vendor's side, formal notification to the vendor's security/IT contact. Tier 3/Client (requires Finance/Treasury and Legal, time-critical): emergency wire recall request to the bank, hold on any pending payment run touching the affected vendor record, and any external notification to the vendor's customers if impersonation runs in the other direction. Approval to resume normal payments to that vendor requires AP management sign-off confirming banking details have been re-verified through a trusted channel.

## Example Query

```kql
EmailEvents
| where Timestamp > ago(14d)
| where AuthenticationDetails has "SPF=fail" or AuthenticationDetails has "DMARC=fail"
| where SenderDisplayName has_any ("Acme Supplies", "Acme", "Invoicing")
| where SenderFromDomain !endswith "acmesupplies.com"
| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, AuthenticationDetails
```

## Closure Criteria

Close only once: the fraudulent domain/sender/URL/hash is blocked at gateway and proxy, all recipients of the same or similar message are identified and confirmed not to have acted on it (or remediated if they did), AP/Finance has confirmed no funds moved on fraudulent instructions - or Treasury/Legal has taken over an active funds-recovery effort as a separate workstream, and (where VEC is suspected) the vendor has been notified through a verified channel regardless of whether they respond before closure. Valid closures include True Positive (fraud attempt blocked before impact, or vendor-side compromise confirmed and the vendor notified), Incident (funds actually moved on fraudulent instructions and Treasury/Legal have taken over a recovery effort), Benign Positive (verified legitimate vendor change), and Insufficient Evidence (suspicious domain reported but no corroborating authentication failure or payment-change request found).

**Example case-note line:** *"Message to ap@contoso.com claiming to be Meridian Steel Co. requesting bank account update on PO-88213; sender domain meridian-steelco.com registered 19 days prior via anonymized registrar, DMARC=fail against meridiansteel.com (vendor of record). No PDF attachment, plain-text request only. AP confirmed no payment submitted; callback to vendor's on-file number confirms their domain was not compromised - pure spoof. Domain and sender blocked at EOP and proxy; vendor notified of impersonation attempt. Closed - True Positive, fraud attempt blocked, no funds impact."*
