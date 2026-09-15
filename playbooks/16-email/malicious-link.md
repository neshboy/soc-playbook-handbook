# Malicious Link (Email)

## Playbook ID & Name

**EML-005 — Malicious Link (Phishing Link Click / Credential-Harvest or Payload Pivot)**

This one is the sibling of the Malicious Attachment playbook, but the evidence trail is shaped differently. There's no file hash to sandbox — the "payload" is a URL, and the URL you see in the alert is frequently not the URL the user's browser actually hit, because of redirect chains, URL shorteners, and the vendor's own click-time rewriting sitting in the middle. Most of the work here is reconstructing what actually happened between "message delivered" and "user clicked," and then deciding how far past that click the attacker got.

## Business Risk

**[STAKEHOLDER]** - A single link click can hand an attacker a working set of corporate credentials or a foothold on an endpoint in under thirty seconds, and unlike a malware attachment that AV might still catch on execution, a convincing fake login page usually sails past every control except the user's own judgment. The exposure isn't the click itself — it's whatever the attacker does with the account or device afterward: mailbox takeover, fraudulent wire approval, or a foothold used to move toward higher-value systems.

## Severity/Priority Default

**Medium** as the default for a reported or detected click with no confirmed credential entry or payload execution — this is the most common outcome and shouldn't auto-inflate. Escalate to **High** if the click-time verdict shows credential submission on a phishing kit page, or if EDR shows any process execution following the click. Escalate to **Critical** if the account involved has privileged access (Domain Admin, Global Admin, finance approval authority) or if the same URL/domain shows clicks from multiple users, suggesting a live campaign rather than an isolated event.

## MITRE ATT&CK Techniques

- **T1566.002** — Phishing: Link (the delivery mechanism itself)
- **T1204** — User Execution (the click/interaction that triggers the chain)
- **T1078.002 / .004** — Valid Accounts: Domain / Cloud Accounts (if harvested credentials are reused by the attacker)
- **T1114.003** — Email Collection: Email Forwarding Rule (common follow-on once a mailbox is actually compromised)
- **T1110.001 / .003** — Brute Force: Password Guessing / Spraying (if the same infrastructure is later seen targeting other accounts)
- **T1105** — Ingress Tool Transfer (if the link leads to a payload download rather than a credential page)
- **T1218.005 / .010 / .011** — System Binary Proxy Execution: Mshta / Regsvr32 / Rundll32 (common execution wrappers if the link drops a script-based loader)
- **T1059.001** — Command and Scripting Interpreter: PowerShell (follow-on execution stage)
- **T1027** — Obfuscated Files or Information (obfuscated redirect chains or downloaded script content)

## Trigger / Detection Logic Summary

Alerts fire from one of three places, and they rarely line up neatly with each other: the Secure Email Gateway (SEG) or native filter flags a URL as malicious at delivery or re-scans it post-delivery (zero-hour auto-purge); the click-time protection layer (e.g., Safe Links equivalent) logs a user actually clicking a rewritten link and returns a "malicious" or "blocked" verdict; or a downstream control — proxy, DNS, EDR — sees the actual network/process consequence of the click, independent of what the email layer thought at delivery time. A key operational reality: the delivery-time verdict and the click-time verdict can disagree, because attacker infrastructure frequently weaponizes a URL *after* it clears the initial scan (a blank or benign page at send time, swapped for a credential-harvest page hours later).

## Required Log Sources & Event IDs

| Source | Field/Operation | Why it matters |
|---|---|---|
| Secure Email Gateway / native filter (Defender for Office 365, Proofpoint, Mimecast) | Delivery verdict, URL reputation category, sandbox/detonation result | Tells you what was known about the link at send time — often stale |
| Click-time / URL rewrite service (Safe Links or equivalent) | Click timestamp, clicking user, source IP, verdict at time of click, rewritten vs. original URL | The actual moment of user interaction — this is your ground truth for "did anyone click" |
| Message trace / mail flow logs | Sender IP, envelope-from, recipient list, delivery status | Scoping — who else received the same message |
| Microsoft Purview Audit (Unified Audit Log; or equivalent identity audit) | Sign-in events, `New-InboxRule`, mailbox delegation changes, MFA challenge result for the affected account | Confirms whether the click led to actual account compromise, not just a page load |
| Proxy / secure web gateway logs | Destination domain, category, bytes transferred, user-agent | Confirms whether the endpoint actually reached the destination and what happened next |
| DNS logs | Query name/time for the malicious domain, resolving host | Corroborates a click even when proxy logging is incomplete (roaming laptops, split tunnel VPN) |
| EDR / endpoint process telemetry | Process creation following browser activity, child processes of the browser or a script host, network connections from non-browser processes | Confirms or rules out a technical payload beyond a static credential page |

## Key Fields to Inspect

**[ANALYST]**

- **Original vs. rewritten URL** — the message header or SEG log shows the true destination; the click-time log shows what the user's browser actually resolved. Don't assume they still point at the same thing hours later.
- **Click source IP and user-agent** — a click from a corporate egress IP on a managed laptop is a different story than a click logged from an unfamiliar ASN, which sometimes means the "click" was automated scanning/prefetching, not the human.
- **Time between delivery and click** — clicks within seconds to minutes of delivery, especially outside business hours, lean toward automated crawler or bot activity, not a distracted employee.
- **Post-click sign-in activity** — new sign-in for the same user shortly after the click, especially from a different country/ASN or a device never seen before, with MFA satisfied or MFA fatigue-style repeated prompts.
- **Mailbox rule/delegation changes** in the Unified Audit Log in the hours following the click — the single strongest indicator of a real account takeover following a credential-phish link.
- **Destination page content, if still live** — login page branding mismatch (wrong logo, wrong domain in the address bar, a Microsoft/Okta-style login form hosted on an unrelated free-tier hosting domain).
- **Redirect chain depth** — legitimate marketing/tracking links redirect once or twice through known platforms; phishing kits often chain through several disposable domains or URL shorteners before landing.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Link domain matches a known, previously-seen vendor/partner or internal tool | Domain registered in the last days-to-weeks, or a lookalike of a legitimate brand (`0ffice365-login.example.net`) |
| Single or short redirect chain to a recognized SaaS/tracking platform | Multiple chained redirects through disposable or free-hosting domains before landing on a login form |
| Click followed by normal browsing behavior, no credential entry logged | Click followed by credential submission on a form, or by a file download/executable request |
| Delivery and click-time verdicts agree (both benign) | Delivery verdict was benign but click-time verdict flags malicious — weaponized-after-delivery pattern |
| Sign-in activity for the user is unchanged after the click | New sign-in, new device, or new inbox rule within minutes to hours of the click |

## Investigation Steps

1. **Pull the click-time log entry**, not just the delivery-time SEG verdict — confirm the exact user, timestamp, source IP, and the verdict returned at the moment of the click, since this can differ from the send-time scan.
2. **Retrieve the original message** (.eml or full message trace, not a forwarded screenshot) and extract the true destination URL from the headers/body before any rewriting.
3. **Check scope** — run message trace across the organization for the same sender/URL/domain to identify every other recipient, since a single reported click is rarely the only delivery.
4. **Determine if the destination is still live** — if safe to do so from an isolated analysis environment (never from a production endpoint), check whether the page is a credential form, a benign redirect, or already taken down.
5. **Check the clicking user's identity activity** in the Unified Audit Log or equivalent — new sign-ins, MFA challenges/fatigue prompts, inbox rule creation, delegation changes, in the window following the click.
6. **Check endpoint telemetry** for the clicking user's device — any process spawned from the browser, script host activity, or outbound connections to the same or related infrastructure shortly after the click.
7. **Pivot on infrastructure** — check whether the domain, IP, or hosting provider appears in threat intel feeds or has been seen against other tenants/orgs; check passive DNS for sibling domains that may be part of the same kit.
8. **Decide on user credential status** — if there's any ambiguity about whether credentials were entered, treat the account as potentially compromised and move to containment rather than waiting for certainty.

## True Positive Indicators

- Click-time verdict confirms malicious, and the destination is a known or newly-identified phishing kit page (login form on non-corporate infrastructure).
- Credential submission is confirmed (either by the click-time platform, by network telemetry showing a POST to the phishing domain, or by user admission).
- Sign-in activity, new inbox rules, or delegation changes appear for the affected account shortly after the click.
- Endpoint telemetry shows process execution, script activity, or outbound connections tied to the link's domain following the click.
- The same URL/domain generated clicks or deliveries against multiple users in the organization within a short window.

## False Positive / Benign Positive Indicators

- The "click" was generated by automated link-crawling/prefetch behavior (some SEG products, chat clients, and mobile mail apps pre-fetch links for preview purposes) — check user-agent and timing against known crawler patterns before assuming a human clicked.
- Destination domain is a legitimate but newly-onboarded vendor or SaaS tool not yet in the reputation allowlist — verify with the business owner before escalating.
- URL shortener or tracking redirect belongs to a known legitimate marketing platform, and the final destination resolves to a benign page with no credential form.
- Security awareness training or an internal phishing simulation platform generated the alert — check the sender domain and campaign ID against the training vendor's known infrastructure first.
- Insufficient Evidence is the honest closure when click-time logging is incomplete (VPN split-tunnel, unmanaged personal device, third-party mail client bypassing the rewrite service) and no corroborating sign-in or endpoint signal exists either way.

## Escalation Criteria

Escalate immediately to IR/Tier 2 if credential submission is confirmed for a privileged or finance-approval account, if any post-click process execution or outbound C2-style connection is observed on the endpoint, if the same campaign is confirmed against multiple users, or if a new inbox rule, mailbox delegation, or unfamiliar sign-in appears for the affected account within the investigation window.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Needed | Notes |
|---|---|---|
| Block sender/domain/URL at SEG and web proxy | SOC analyst/Team Lead — act immediately once confirmed malicious | Low business impact, first move on confirmation |
| Force password reset + revoke active sessions for clicked/affected user | SOC Team Lead, notify user's manager | Standard when credential entry is confirmed or suspected |
| Remove malicious inbox rule / revoke delegation | SOC Team Lead + IT/Identity team | Required if account takeover indicators are present |
| Isolate endpoint via EDR | SOC Team Lead, notify asset owner | Applies when post-click execution telemetry is observed |
| Organization-wide purge of the message (zero-hour auto-purge or manual) | SOC Team Lead — can act immediately | Removes remaining copies from other mailboxes still holding the message |

SLA target: initial triage decision within 1 hour of report/alert for Medium severity, 30 minutes for High/Critical given the account-takeover risk window.

## Example Query (Microsoft Sentinel / Defender KQL)

```kql
UrlClickEvents
| where Timestamp > ago(24h)
| where ActionType in ("ClickBlocked", "ClickAllowed")
| where ThreatTypes has "Phish" or Url has_any ("login", "verify", "secure-")
| project Timestamp, AccountUpn, Url, IPAddress, ActionType, ThreatTypes
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(24h)
    | project SigninTime=TimeGenerated, UserPrincipalName, IPAddress, Location
) on $left.AccountUpn == $right.UserPrincipalName
| where SigninTime between (Timestamp .. Timestamp + 2h)
```

## Closure Criteria

Close as **True Positive** once the click chain is reconstructed, credential/account impact is confirmed one way or the other, and containment (block, reset, rule removal, purge as warranted) is verified effective. Close as **Benign Positive / Expected Activity** when the destination is confirmed legitimate (vendor, training simulation, tracking redirect) with supporting evidence attached. Close as **Insufficient Evidence** when click-time logging is incomplete and no corroborating identity or endpoint signal exists — add the user and domain to a short-term watchlist rather than closing silently.

**Example case note:** *"User jchen@example.com (WKS-SALES-014, 10.4.22.61) clicked a rewritten link in a message purporting to be a DocuSign request; click-time verdict returned malicious, destination resolved to secure-docusign-verify[.]example, a credential-harvest page registered 4 days prior. Network telemetry confirmed a POST request to the domain consistent with form submission. Unified Audit Log showed a new inbox rule ('Move to RSS Feeds', hiding replies) created 11 minutes later, plus a sign-in from an unfamiliar ASN in a different country with MFA satisfied via push. Password reset and session revocation completed, inbox rule removed, domain blocked at SEG and proxy, org-wide purge run — 3 other recipients identified via message trace, none clicked. Classified True Positive — T1566.002 / T1204 / T1078.004 / T1114.003."*
