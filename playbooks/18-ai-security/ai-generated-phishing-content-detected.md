# AI-013 — AI-Generated Phishing Content Detected

**Category:** AI Security
**Sub-type:** Inbound phishing/BEC content flagged as generative-AI-authored by an email security classifier, or identified by an analyst through the absence of the linguistic tells that used to make phishing easy to spot

## Business Risk

**[STAKEHOLDER]** - The old advice to staff - "watch for bad grammar and spelling mistakes" - stopped being reliable advice a while ago. Generative AI lets a low-skill attacker produce fluent, well-punctuated, correctly-addressed phishing at the same speed and cost as a mass-market spam run, and lets a skilled attacker produce a convincing executive-impersonation email in seconds using nothing more than a target's LinkedIn profile and a press release. The risk isn't a new attack category, it's the old categories (credential phishing, BEC, malware delivery) getting cheaper, faster, and harder for both users and legacy filters to catch on tone alone. The decision to quarantine tenant-wide, force a password reset, or send an org-wide alert sits with the SOC lead and, for anything touching a wire-transfer request or executive impersonation, with the CISO and Finance jointly.

## Severity / Priority Default

**Medium** by default - this is phishing, and phishing is never a "low" default in this handbook regardless of how it was authored. Escalate to **High** immediately if: the email impersonates an executive or vendor in a payment-related request (BEC pattern), a credential-harvesting link is confirmed live in sandbox detonation, or any recipient is confirmed to have clicked and entered credentials.

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1566.002 Phishing: Link | Most AI-generated campaigns center on a link to a cloned login page, OAuth-consent-phishing page, or fake document-share portal - AI is used to write the pretext, not necessarily the payload |
| T1566.001 Phishing: Attachment | AI-drafted lure text paired with a malicious document or HTML smuggling attachment; also covers AI-assisted deepfake voice/video files used as a supporting attachment in a more elaborate BEC pretext |
| T1204 User Execution | The point where the AI-crafted pretext actually works - user clicks the link or opens the attachment because the content read as legitimate |
| T1078.004 Valid Accounts: Cloud Accounts | Harvested credentials reused to sign into the victim's cloud identity (Entra ID/Okta/Google Workspace) shortly after a successful click |
| T1114.003 Email Collection: Email Forwarding Rule | Common post-compromise persistence step after a successful AI-phishing-driven account takeover - attacker adds a silent forwarding/inbox rule to keep visibility into the mailbox |

## Trigger / Detection Logic Summary

Three distinct trigger paths feed this playbook, and they carry different confidence levels - treat them accordingly:

1. **Vendor AI-content classifier hit:** Your email security platform (Microsoft Defender for Office 365, Abnormal Security, Proofpoint, Mimecast, or similar) scores a message's body as high-probability LLM-generated using its own language model, and pairs that score with a phishing/malicious-intent verdict. This is a probabilistic signal, not a confirmed verdict - treat the score as a prioritization cue, not proof.
2. **Volume/variance fingerprint:** A wave of messages hits multiple mailboxes in a short window that are semantically identical (same pretext, same ask, same call-to-action) but textually distinct in wording, subject line, and structure - a signature that exact-hash and fuzzy-hash phishing detection tends to miss, and a classic tell of an attacker regenerating the same template through an LLM per recipient to defeat static matching.
3. **Analyst/user-reported, content-based:** A user or analyst flags a message that "reads too well" for its context - polished tone, perfect idiom, hyper-specific personalization (correct title, correct project name, correct recent-hire date) at a scale or speed that doesn't match manual research effort - but which doesn't match any known campaign signature.

## Required Log Sources & Fields

There are no Windows or Sysmon event IDs native to this detection surface - primary telemetry lives in cloud email security and identity platforms. If the investigation extends into attachment execution on an endpoint, hand off to the relevant playbook in `12-endpoint-execution` for that portion; don't try to force endpoint IDs into this section.

- **Email security gateway / secure email gateway logs** (Microsoft Defender for Office 365 - `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo` in Advanced Hunting; Proofpoint TAP; Abnormal Security case detail) - sender/recipient, subject, authentication results, detection method, vendor AI-content or generative-content confidence field (field name is vendor-specific).
- **URL/link protection logs** (Safe Links, Proofpoint URL Defense click logs) - click timestamp, click verdict (blocked/allowed/pending), user agent, source IP of the click.
- **Microsoft 365 Unified Audit Log / Google Workspace audit log** - `New-InboxRule`, `Set-InboxRule`, mailbox delegate additions, sign-in events following a click.
- **Identity provider sign-in logs** (Entra ID, Okta, Google Workspace) - sign-in immediately following a confirmed click, source IP/ASN, device compliance state, MFA satisfaction method.
- **Sandbox/detonation service logs** (built into the email gateway or a standalone service) - final-stage landing page content, file hash, behavioral verdict.
- **DNS/passive DNS and domain registration data** - registration/creation date of the sending or linked domain (lookalike domains registered within days of the campaign are a strong signal).

## Key Fields to Inspect

**[ANALYST]**

| Field | Why it matters |
|---|---|
| AI/generative-content confidence score (vendor field) | Prioritization signal only - corroborate with infrastructure and intent evidence before treating as a verdict |
| `AuthenticationDetails` (SPF/DKIM/DMARC pass-fail) | AI-written content can be flawless; sending infrastructure usually still isn't - this is often the more reliable tell |
| Sender display name vs. `SenderFromAddress` | AI-generated BEC lures frequently spoof a plausible display name over a mismatched or freshly-registered domain |
| Subject-line/body semantic similarity across recipients | Confirms the "same pretext, different wording" fingerprint of templated LLM generation at volume |
| Personalization depth vs. plausible research effort | Correct title/project/recent-hire detail delivered at bulk-campaign speed is a stronger AI-tooling indicator than the prose quality itself |
| URL/attachment hash "first seen" status | Novel-every-time payloads are common when the attacker also automates variant generation, not just the text |
| Domain registration/creation date | Recently registered lookalike domains (days, not years, old) strongly support malicious intent regardless of how polished the copy reads |
| Click + subsequent sign-in correlation | The fact that actually decides whether this stays a phishing-attempt case or becomes an account-takeover case |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Legitimate vendor/marketing email drafted with AI-writing tools, sent from an established, authenticated domain with clean SPF/DKIM/DMARC | Fluent, well-personalized email from a domain registered in the last 1-2 weeks or from a display-name spoof of a known contact |
| Internal newsletter or HR communication that trips the AI-content classifier because it genuinely was AI-drafted for legitimate use | Same semantic pretext (urgent invoice, credential re-verification, "review this document") sent in dozens of textually distinct variants across the tenant in a tight time window |
| One-off translated correspondence from a non-native-English colleague/partner using an AI tool, matching known business context | Executive-impersonation payment request with correct name/title/reporting line details but arriving from an address that isn't the executive's real mailbox |
| Click on a link followed by no unusual downstream sign-in or mailbox change | Click followed within minutes by a sign-in from an unfamiliar ASN/country, or a new inbox forwarding rule appearing shortly after |

## Investigation Steps

1. Pull the flagged message(s) in full, including headers - confirm the vendor AI-content/generative-content confidence score and phishing verdict, and independently check SPF/DKIM/DMARC results and sending domain registration age.
2. Query the email gateway and/or UAL across the surrounding time window for other messages sharing the same pretext, sender infrastructure, or linked-URL domain (fuzzy/semantic match, not exact hash) to establish true campaign scope - AI-generated waves are almost never a single message.
3. Detonate any embedded URL or attachment in a sandbox; capture the final-stage landing page (credential form, OAuth-consent-phishing page, fake MFA prompt) or payload behavior, and hash it for internal/external threat-intel matching.
4. Check Safe Links/URL-click logs for every recipient in the campaign - determine who clicked, and for anyone who did, check identity provider sign-in logs for an unfamiliar sign-in shortly after.
5. For any account with a suspicious post-click sign-in, immediately check the UAL for new inbox rules (T1114.003), mailbox delegate additions (see the account-manipulation playbook), or MFA method changes - pivot to the account-takeover response track without waiting for the rest of this checklist.
6. Assess personalization depth against plausible manual-research effort - a bulk campaign referencing accurate, non-public project or org-chart detail across many recipients points to either a data breach feeding the campaign or heavy AI-assisted OSINT automation, both of which change your scoping.
7. Cross-check the sending infrastructure and content fingerprint against available threat-intel/ISAC sharing and, if you have an MSSP relationship, ask whether other tenants saw the same template that week - these campaigns are frequently reused with light AI-driven variation across many organizations in the same run.
8. Capture the specific linguistic and structural tells actually present in this sample (or the lack of the ones you'd normally coach on) and route them back to security-awareness content - "look for typos" is no longer sufficient guidance and your training material needs to reflect that.

## True Positive Indicators

- High AI-content/generative-content confidence score paired with a failed authentication result or freshly registered sending/linked domain.
- Sandbox detonation confirms an active credential-harvesting page, consent-phishing prompt, or malware payload behind the link/attachment.
- Multiple textually distinct but semantically identical messages hitting several mailboxes in a tight window - the templated-regeneration fingerprint.
- Personalization detail that exceeds what's plausible for the apparent research effort, especially in an executive-impersonation payment request.
- Confirmed click followed by an unfamiliar sign-in, new inbox rule, or delegate addition on the affected account.

## False Positive / Benign Positive Indicators

- Legitimate AI-drafted vendor, HR, or internal communication from an authenticated, established domain with a clean track record.
- Content classifier fired on a genuinely AI-assisted but legitimate translation of routine business correspondence, corroborated with the sender via a known relationship or out-of-band confirmation.
- "Too polished for its context" turns out to be an approved marketing/sales sequence tool that itself uses generative AI to draft outreach.
- No click activity, no authentication anomalies, and the sending domain/infrastructure has years of clean sending history.

## Escalation Criteria

- Escalate to **IR/Account-Takeover response** immediately if any recipient clicked and a suspicious post-click sign-in, inbox rule, or delegate addition is confirmed.
- Escalate to **Finance + IR jointly, time-critical**, if the pretext involves a payment/wire-transfer request under executive impersonation - these move fast and the financial window to intervene closes within hours.
- Escalate to **Security Awareness/Comms** for any confirmed multi-mailbox campaign, regardless of click outcome, so the org-wide notice reflects the actual pretext used rather than generic phishing advice.
- Escalate to the relevant **endpoint/malware playbook** if sandbox detonation confirms a malicious attachment payload rather than a credential-harvesting link.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Tenant-wide quarantine/purge of the campaign message | SOC Lead / email admin (standing authority) | Fastest lever; use as soon as campaign scope is confirmed |
| Block sender domain/URL infrastructure at the gateway | SOC analyst (standing authority) | Low risk, do immediately on confirmed malicious infrastructure |
| Force password reset + revoke active sessions for clicked/compromised accounts | IAM/Security Engineering on-call | Mandatory for any confirmed post-click sign-in anomaly |
| Remove attacker-added inbox rule or mailbox delegate | Security Engineering on-call | Time-sensitive - this is the attacker's persistence mechanism |
| External takedown request for a lookalike/spoofed domain | Legal/Brand-protection team | Longer timeline (days), doesn't stop the current wave but limits reuse |
| Org-wide notification naming the specific pretext used | Comms + CISO sign-off (for high-profile/executive-impersonation cases) | Keep specific enough to be useful, avoid tipping off the attacker to detection method |

## Example Query (Microsoft 365 Defender - Advanced Hunting KQL)

```kql
EmailEvents
| where Timestamp > ago(24h)
| where DetectionMethods has "AIGeneratedContent" or ThreatTypes has "Phish"
| join kind=inner (EmailUrlInfo) on NetworkMessageId
| summarize Recipients = dcount(RecipientEmailAddress), Subjects = dcount(Subject)
    by SenderFromDomain, UrlDomain
| where Recipients >= 5 and Subjects >= 3
| order by Recipients desc
```

## Closure Criteria

Close once: full campaign scope is mapped (every recipient identified, not just the reporting user), sandbox verdict on any link/attachment is recorded, every confirmed-click account has been checked for post-click sign-in/mailbox anomalies and remediated if compromised, and malicious infrastructure is blocked at the gateway. Classify as True Positive, Benign Positive, False Positive, or Insufficient Evidence based on corroborated infrastructure and click/sign-in evidence - never close solely on the vendor's AI-content confidence score, since that score describes authorship style, not malicious intent. Insufficient Evidence is a valid closure when the sending infrastructure has already gone dark and no recipient interaction can be confirmed either way.

**Example case-note line:**
`2026-09-15 09:47 UTC - Defender for Office 365 flagged 14 near-identical-but-reworded messages across Finance and Exec Assistant mailboxes, AI-generated-content confidence 0.91, pretext "urgent invoice review," sender domain example-billing-support.com registered 4 days prior via passive DNS. Sandbox confirmed a credential-harvesting page cloning the corporate SSO login. Two users clicked; c.nakamura@example.com had a subsequent sign-in from an unrecognized ASN 11 minutes later with a new inbox forwarding rule to an external address. Classified True Positive; pivoted to account-takeover response track. Password reset and session revocation completed, forwarding rule removed, domain blocked at gateway, remaining 12 recipients confirmed no-click via Safe Links logs. Comms sent org-wide notice naming the "urgent invoice review" pretext specifically.`
