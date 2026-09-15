# Playbook: QR-Code Phishing (Quishing)

## Playbook ID & Name

**EML-006 — QR-Code Phishing (Quishing) Detection and Response**

Category: Email. Applies to inbound mail where the phishing payload is delivered as a QR code — embedded as an inline image in the HTML body, attached as a standalone PNG/JPG, or rendered inside a PDF/Office document — rather than as a plain clickable hyperlink or a directly malicious attachment. The defining trait of this playbook is that the SEG, the URL rewrite/detonation pipeline, and any endpoint control never see the actual destination URL as text; a human has to decode an image first, almost always with a personal phone camera on a cellular connection, completely off the corporate network and off EDR. That's a different exposure surface than the sibling **Malicious Link** and **Malicious Attachment** playbooks in this section, so don't collapse this into either of those — cross-reference them once you're past the QR-specific delivery mechanics.

## Business Risk

**[STAKEHOLDER]** - Every other phishing control you've bought sits on the corporate network path or the managed endpoint — Safe Links rewriting, proxy category blocking, EDR on the click. A QR code routes around all of it by design: the user's phone camera decodes the image, opens a mobile browser, and lands on the credential page on a network and device the security stack never touches. It also benefits from a reputation problem that's genuinely our own doing — QR codes are now completely normal in business email (vendor invoices, conference badges, e-signature requests, printer scan-to-email notices), so staff have been trained by legitimate use to trust them, which pushes click-through rates on QR lures noticeably higher than a comparable plain-link phish. The realistic financial exposure is the same as any credential phish that lands — mailbox takeover, BEC-style fraud, downstream data exposure — but the detection gap is what makes this worth a dedicated playbook and a dedicated line item in the awareness budget rather than folding it into general phishing training.

## Severity / Priority Default

- **Default:** Medium at initial trigger (message flagged or reported, no confirmed click).
- **High** once telemetry confirms the decoded link was actually visited (a `UrlClickEvents` hit or proxy hit on the decoded domain).
- **Critical** if a sign-in event for the targeted user follows the click from an unfamiliar device or ASN, or if the targeted account is executive, finance, or otherwise privileged.

## MITRE ATT&CK Techniques

| ID | Technique | Where it fits |
|---|---|---|
| **T1566.001** | Phishing: Spearphishing Attachment | QR embedded inside a PDF/image file attachment rather than the message body |
| **T1566.002** | Phishing: Spearphishing Link | QR functions as the delivered link when embedded inline in the HTML body; also the redirect chain the QR ultimately unwraps to |
| **T1204** | User Execution | The scan itself, plus the credential-entry step on the landing page — no malware execution required for the dominant variant |
| **T1078.004** | Valid Accounts: Cloud Accounts | Post-phish reuse of harvested M365/Okta/Google Workspace credentials, or replay of a stolen session token from an AiTM kit |
| **T1114.003** | Email Collection: Email Forwarding Rule | Common post-compromise cleanup — attacker adds a rule to hide or exfiltrate future mail after the credential lands |
| **T1098.002** | Account Manipulation: Additional Email Delegate Permissions | Alternative to a forwarding rule for the same objective — quieter, doesn't show up in the mailbox's own rule list |
| **T1552.001** | Unsecured Credentials: Credentials In Files | Occasionally recovered during scoping — harvested creds staged in a text file on the phishing kit's backend, useful for confirming scope if the kit infrastructure is seized/analyzed |
| **T1567** | Exfiltration Over Web Service | Follow-on if the compromised mailbox/OneDrive is used to move data out via a legitimate cloud service |

A less common but growing variant skips credential harvesting and instead has the QR redirect to a fake "secure viewer" or document-update installer, pulling a second-stage binary (**T1105** Ingress Tool Transfer, frequently wrapped in **T1027** Obfuscated Files or Information). Treat any QR-phishing case where the landing page prompts a download rather than a login as this variant and pivot to the endpoint-execution playbooks in this book.

## Trigger / Detection Logic Summary

**[ENGINEERING]** The structural problem is that a QR code is just pixels until something decodes it. Modern SEGs and Microsoft Defender for Office 365 run an OCR/QR-decode pass against inline images and rendered PDF pages at ingest, extract whatever URL comes out, and then run that URL through the same reputation and detonation pipeline as any other link — but this is a heuristic add-on, not a guaranteed catch, and it has a real false-negative rate against low-contrast, tiled, or multi-layered QR images designed specifically to defeat automated decoding.

Alert on any of the following:

- Inbound message flagged by the mail platform with a detection method/campaign tag indicating QR-code phishing, where the decoded URL matches a newly registered domain, URL shortener, or known phishing-kit redirector.
- A `UrlClickEvents` (or equivalent SEG click-time) hit against a URL that only exists in the corpus because it was extracted from an image/PDF — no plain-text hyperlink for that destination appears anywhere in the message body.
- Heuristic fallback for messages the platform didn't auto-tag: an image or PDF attachment, **no other clickable hyperlink in the body**, and a subject line built around urgency/authority themes — voicemail notification, e-signature request, MFA/Authenticator re-enrollment, HR benefits enrollment, or a "scan to email" copier/scanner notice — from an external or first-contact sender.
- User-reported submissions (Report Message button, abuse mailbox) where the free-text description mentions scanning a code — these often arrive *before* the platform's own QR-decode heuristic fires, so don't treat a clean automated verdict as the end of the story if a human already flagged it.
- The single highest-fidelity chain: a QR-decoded URL click followed within minutes to hours by an Entra ID sign-in for that user from an unfamiliar device, browser, or ASN.

## Required Log Sources & Event IDs

| Source | Fields / Tables | Why |
|---|---|---|
| Microsoft 365 Defender Advanced Hunting — `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` | `NetworkMessageId`, `ThreatTypes`, `DetectionMethods`, decoded `Url`/`UrlDomain` | Core delivery and verdict data, including the platform's own QR-decode output where available |
| Microsoft Defender for Office 365 Safe Links — `UrlClickEvents` | `NetworkMessageId`, `Url`, `ActionType`, `IPAddress`, `IsClickedThroughMessage` | Confirms whether, when, and from where the decoded link was actually visited |
| Entra ID sign-in logs | `CorrelationId`, `IPAddress`, `DeviceDetail`, `ClientAppUsed`, `ConditionalAccessStatus`, `AuthenticationRequirement` | Confirms whether a click converted into an actual authentication, and whether MFA was satisfied normally or via a replayed token |
| Microsoft Purview Audit (Unified Audit Log, M365) | `New-InboxRule`, `Set-Mailbox` (forwarding), `Add-MailboxPermission`/`Add-RecipientPermission` | Post-compromise mailbox tampering — T1114.003 / T1098.002 |
| Mail flow / message trace | Sender IP, SPF/DKIM/DMARC result, delivery/quarantine action | Scoping and lure authentication check — a surprising number of QR lures pass SPF/DKIM because they ride a compromised low-reputation SaaS sender or a legitimate transactional mail relay |
| Corporate web proxy / SWG (if applicable) | Destination domain, user agent | Only relevant if the QR was scanned via a corp-managed device's camera app, or the user later re-opened the link from a desktop browser |
| Abuse mailbox / Report Message submissions | Ticket text, forwarded `.eml` | Frequently the first signal, given the SEG's QR-decode false-negative rate |

## Key Fields to Inspect

**[ANALYST]**

| Field | Source | What to check |
|---|---|---|
| `NetworkMessageId` | EmailEvents / EmailUrlInfo / UrlClickEvents | The join key across the whole investigation — pull every table by this ID, not by subject line (subjects get reused/templated across a campaign) |
| `SenderFromAddress` vs display name | EmailEvents | Spoofed display name ("IT Service Desk", "Scanner-02") over a mismatched or newly registered sending domain is the classic tell |
| Attachment `FileType` / SHA256 | EmailAttachmentInfo | PDF/PNG/JPG carrying the QR — the file itself is frequently clean on static AV/hash checks since the malicious content is a decoded URL, not code |
| `DetectionMethods` / `ThreatTypes` | EmailEvents | Should show `Phish`; check whether the detection method reflects QR-specific decoding versus a generic verdict — tells you if this was caught by design or by luck |
| Decoded `Url` / `UrlDomain` | EmailUrlInfo | Check domain age, registrar, and whether it's a direct landing page or a first hop through a URL shortener/open redirect on an otherwise-legitimate service |
| `ActionType` | UrlClickEvents | `ClickBlocked` vs `ClickAllowed` — an allowed click on a QR-sourced URL often means the destination was unknown-at-click-time rather than a control failure; don't assume Safe Links is broken without checking the verdict timeline |
| `ClientAppUsed` / `DeviceDetail` | Entra ID sign-in logs | Mobile browser, unfamiliar device model, or a device that's never authenticated for this user before is the strongest single indicator that the scan converted into credential entry |
| `AuthenticationRequirement` / satisfaction detail | Entra ID sign-in logs | Normal MFA challenge versus "requirement satisfied by claim in the token" — the latter is consistent with an adversary-in-the-middle kit replaying a stolen session rather than the user completing MFA live |
| `New-InboxRule` parameters | Unified Audit Log | Forwarding to an external address, or rules that silently mark-as-read/delete — the standard cleanup move once a mailbox is actually in hand |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| QR from a known vendor invoice, event badge, or internal printer scan-to-email notice, matching a known relay/asset | QR from an external, first-contact sender with no prior mail history to that recipient |
| Decoded URL lands directly on a known, long-established domain with no redirect chain | Decoded URL passes through a shortener or open redirect before landing on a fresh domain |
| No sign-in anomaly follows a click — user viewed a legitimate invoice or badge page | A sign-in from an unfamiliar device/ASN follows the click within minutes to hours |
| Subject line is transactional and specific (invoice number, event name) | Subject line is generic and urgency-driven (voicemail, e-signature, "your access will expire") |
| Attachment/image matches a pattern IT or a known vendor sends routinely, at predictable cadence | One-off image/PDF with no prior sending pattern from that sender, sent to a broad or oddly-specific recipient list |

## Investigation Steps

1. Pull the original message via message trace or the raw `.eml` — never work from a forwarded screenshot. Confirm where the QR actually lives (inline image, attached PNG/JPG, or rendered inside a PDF) and capture the `NetworkMessageId`.
2. Decode the QR yourself in an isolated environment (a sandboxed browser or a dedicated decode utility — not your personal phone) to recover the underlying URL and walk the full redirect chain before it lands on the real page.
3. Query `EmailUrlInfo` and `UrlClickEvents` for that `NetworkMessageId` to see whether the platform already decoded it, and whether any recipient clicked — get the timestamp, `ActionType`, and source IP for every click.
4. For each user who clicked, check Entra ID sign-in logs in the window immediately following for a sign-in from an unfamiliar device, browser, or ASN — this is the pivot that separates "saw the page" from "handed over credentials."
5. If a suspicious sign-in turns up, treat it as a confirmed account compromise: pull the Unified Audit Log for that account across the following 24–72 hours for new inbox rules, delegate/forwarding changes, and OAuth app consent grants.
6. Check sender authentication (SPF/DKIM/DMARC) and the originating infrastructure to determine whether this is opportunistic mass phishing or a targeted spear variant — small, personalized recipient lists with internal-sounding branding (a "scan-to-email" copier notice, for instance) usually mean targeted.
7. Scope the blast radius across the tenant by attachment SHA256, decoded domain, and sender — the person who reported it is rarely the only recipient.
8. Coordinate takedown/blocklisting of the decoded domain and any redirector, and force a password reset plus MFA re-registration for every account with a confirmed click-to-signin chain or credential submission.

## True Positive Indicators

- QR decodes to a newly registered domain, a URL shortener, or an open redirect on an otherwise-legitimate platform, landing on a page mimicking an M365/Okta/Google Workspace login.
- Sender is external/first-contact using urgency or authority themes with no prior relationship to the recipient.
- A confirmed click from a mobile user agent is followed by an Entra sign-in from an unfamiliar device/ASN for that same user.
- The same attachment hash or decoded domain hits multiple mailboxes in a tight window (mass campaign) or a very small, highly specific recipient set (finance/exec spear variant).
- Post-click account activity shows a new inbox rule, delegate permission, or OAuth consent grant appearing shortly after the suspicious sign-in.

## False Positive / Benign Positive Indicators

- Legitimate vendor invoice/payment QR, a conference or event badge QR, a restaurant/menu marketing QR, or a real carrier's package-tracking QR.
- Internal multifunction-printer "scan to email" notification containing a QR for print-job pickup, matching a known internal relay/asset.
- An IT-initiated, calendar-confirmed MFA re-enrollment or SSO onboarding campaign that deliberately uses a QR — verify against the change calendar before escalating.
- Decoded URL resolves to a well-established, reputable domain with no redirect chain and nothing resembling a credential page on detonation.
- QR delivered but never decoded or clicked by anyone (`UrlClickEvents` empty for that `NetworkMessageId`) — the lure existed, but no real exposure occurred.

## Escalation Criteria

Escalate to Tier 2/IR immediately if any confirmed click is followed by a sign-in from an unfamiliar device or ASN; if any post-click mailbox tampering (forwarding rule, delegate permission, OAuth consent grant) is found; if the targeted account is executive, finance, or otherwise privileged; or if the campaign reached more than a handful of recipients tenant-wide, regardless of whether anyone actually clicked — volume alone justifies moving fast on comms and takedown.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority | Notes |
|---|---|---|
| Purge remaining copies of the message tenant-wide | SOC Tier 2 (no external approval) | Standard first move once the message is confirmed malicious |
| Block decoded domain/redirector at mail gateway, proxy, and DNS | Security Engineering on-call | Do this even if no one clicked yet — cuts off the campaign for anyone still holding the message |
| Force password reset + MFA re-registration on clicked/compromised accounts | IAM Team Lead | Standard containment for any confirmed credential submission |
| Revoke active sessions/refresh tokens for a compromised account | IAM Team Lead or Incident Commander | Required specifically to kill a replayed AiTM session — a password reset alone does not always invalidate an already-stolen token |
| Remove malicious inbox rule, delegate grant, or OAuth consent | Messaging/IAM admin | Escalate to Incident Commander sign-off if BEC activity (fraud attempt, data exfil) is confirmed rather than just the credential theft |
| Org-wide awareness nudge on the specific lure theme | Security Awareness/Comms owner | Track as a follow-up action item, not same-shift containment |

## Example Query

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d) and FileType in ("pdf", "png", "jpg", "jpeg")
| join kind=inner EmailEvents on NetworkMessageId
| join kind=leftouter UrlClickEvents on NetworkMessageId
| where isnotempty(Url)
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, Url, ActionType, IPAddress
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the message is purged tenant-wide, the decoded domain is blocked, and every account with a confirmed click-to-signin chain has been reset, re-registered for MFA, and audited for post-compromise mailbox tampering with nothing found (or everything found removed). Close as **Benign Positive / Expected Activity** when the decoded URL/QR traces to a verified legitimate business use — vendor invoice, internal printer, a sanctioned IT campaign — confirmed directly with the business or IT owner. Close as **Insufficient Evidence** when the QR image can't be recovered or decoded (degraded image, message aged out of retention) and no click or sign-in evidence exists — put the sender/domain on a watchlist rather than dropping the case outright.

**Example case note:**
> 2026-09-15 09:47 UTC — Reported message to helpdesk@example.com contained a PDF titled "Voicemail_Notification.pdf" with an embedded QR; decoded in isolated sandbox to hxxps://bit.ly/3xk9Lq2 → hxxps://secure-0365-verify.example-cdn.net/login, a credential page cloning the M365 sign-in UI, domain registered 6 days prior. UrlClickEvents showed 3 clicks from mobile Safari user agents; one of the three (j.alvarez@northwindlogistics.example) had a matching Entra sign-in 11 minutes later from an unrecognized Android device on a residential ISP ASN, AuthenticationRequirement satisfied by claim in token. Confirmed new inbox rule "..." forwarding to an external Gmail address, created 4 minutes post-signin. Message purged tenant-wide (18 total recipients found via SHA256/domain sweep), decoded domain and shortener blocked at mail gateway, account password reset and MFA re-registered, forwarding rule removed, session revoked. Closed as True Positive; 2 other clicking recipients showed no follow-on sign-in and were confirmed unaffected.
