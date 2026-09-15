# AI Browser-Agent Abuse

## Playbook ID & Name

**AI-022 — AI Browser-Agent Abuse (Hijacked or Weaponized Autonomous Browsing Agent)**

## Business Risk

**[STAKEHOLDER]** - Autonomous browser agents (Claude for Chrome / computer-use style agents, Copilot browsing extensions, "agentic" browser products marketed to knowledge workers) exist because they can drive a real, logged-in browser session the same way an employee would - click, type, fill forms, download - just faster and without getting suspicious of a weird page. That's also the exposure. The agent reads whatever content is on the page it's told to visit, and unlike a human it has no reliable instinct for "this text is content, not a command." When a page - or a compromised advertising script, or a rogue extension pretending to be a helpful AI copilot - manages to talk to the agent instead of just being read by it, the agent keeps acting, except now it's acting on the attacker's instructions while wearing the employee's actual authenticated session: webmail, cloud console, HR portal, banking site. Separately, the same convenience gets pointed the other way - someone (an insider, or malware that's found the agent's automation driver) aims a browsing agent at hundreds of login or account-recovery forms and lets it run unattended, turning a productivity feature into an unsupervised credential-stuffing or account-enumeration engine. Both directions produce the same headline: an authenticated session, or a fleet of them, did something at machine speed that no human approved and that looks - correctly - exactly like an insider-threat or account-takeover event to everyone downstream of the SOC.

## Severity/Priority Default

**High (P2)** by default - any confirmed deviation from the user's stated task involving a live authenticated session justifies this floor. **Critical (P1)** if the agent completed a financial transaction, submitted credentials/session data to an external domain, created mailbox/cloud persistence, or ran a mass login/form-submission pattern against third-party accounts. **Medium (P3)** only once triage confirms the deviation was caught by an approval gate or sandboxed profile before any real action executed.

## MITRE ATT&CK Technique(s)

- **T1204** User Execution - user (or the agent, acting on injected page content) triggers a malicious download/install
- **T1566.002** Phishing: Link - common delivery path for the poisoned page or the rogue "AI copilot" extension itself
- **T1027** Obfuscated Files or Information - injection payload hidden in the DOM (zero-width characters, white-on-white text, off-screen `<div>`, HTML comments) so it's invisible to the human but visible to the agent's page-read
- **T1552.001** Unsecured Credentials: Credentials In Files - agent instructed to surface saved passwords, autofill data, or a credentials file open in another tab
- **T1119** Automated Collection - agent enumerates/scrapes records or tabs at machine speed beyond the user's original ask
- **T1567** Exfiltration Over Web Service - agent's form-submit/paste action sends collected data to an attacker-controlled site or webhook
- **T1114.003** Email Collection: Email Forwarding Rule - agent, operating an authenticated webmail session, creates a forwarding rule under injected instruction
- **T1078.004** Valid Accounts: Cloud Accounts - downstream actions ride the user's already-authenticated cloud/SaaS session rather than any new credential
- **T1110.003** Brute Force: Password Spraying - weaponized-direction case: the agent is aimed at many login/recovery forms in an automated run

## Trigger / Detection Logic Summary

**[ENGINEERING]** Two distinct patterns, both correlated on the agent's own session/task ID:

**Pattern A - hijack via untrusted page content.** Fires when the agent's per-step action log shows a `navigate`/`read` step followed within a short window (seconds to a few minutes) by a `type`, `form_submit`, `download`, or `click` step whose target domain, form field, or file has no relationship to the original task text the user gave the agent. Weight this higher when the ingested page's captured DOM/screenshot contains directive language addressed to an assistant ("ignore your current task," "system:", instructions in hidden/off-screen elements) or when the destination of the deviating action is a newly-registered or never-seen-before domain.

**Pattern B - weaponized automation.** Fires on volume/velocity: one agent session or browser-automation profile generating a high count of `form_submit`/login actions across many distinct target domains or account identifiers in a short window - the signature of an agent being used as an unattended credential-stuffing or spray tool rather than completing a single user task.

Both patterns depend on the browser-agent product's action log carrying a stable session/task ID that can be joined to proxy/SWG and identity logs - without that join key you're triaging screenshots by hand, which doesn't scale past the first incident.

## Required Log Sources & Event IDs

No standard Windows/Sysmon Event ID applies to this layer - correlate on operation name, session ID, and domain, the same as other AI-agent telemetry in this book.

| Layer | Log Source | Key Fields / Operations |
|---|---|---|
| Agent product | Browser-agent action/task log (vendor console or self-hosted agent runtime) | `session_id`/`task_id`, original task text, per-step action (`navigate`, `click`, `type`, `download`, `form_submit`), current URL/domain at each step |
| Browser fleet management | Chrome Enterprise / Edge for Business admin reporting | Extension install/update events, requested host permissions (`<all_urls>`), publisher/ID, install source |
| Endpoint/EDR | Process-creation and network-connection telemetry for the browser process | Command line flags (`--remote-debugging-port`, `--headless`, webdriver markers), child processes spawned after a download, outbound connections |
| Proxy / SWG | Web proxy or secure web gateway logs | Destination domain/IP, user-agent string, request timing/interval pattern, bytes transferred, TLS SNI |
| Identity provider | Entra ID / Okta sign-in logs | Interactive sign-ins tied to the agent-controlled session/device, impossible travel, new device fingerprint |
| SaaS mailbox (if webmail in scope) | M365 Unified Audit Log | `New-InboxRule`, `Add-MailboxPermission`, `Set-Mailbox` |
| DLP | Endpoint or network DLP with form-field/keystroke coverage | Credential-pattern or PII typed into a web form by the automated session |

## Key Fields to Inspect

**[ANALYST]**

- Original task text the user gave the agent, verbatim, versus the actual sequence of actions taken
- Current URL/domain at the exact step where behavior deviates, plus the captured DOM/screenshot content for that page
- Time delta between page ingestion and the deviating action - seconds-to-minutes is the classic hijack signature; unrelated if hours later
- Destination domain of any download, form submission, or paste action, checked against threat intel and internal allow-lists
- Browser extension ID, publisher, install source, and requested permission scope (`<all_urls>` / "read and change all your data on all websites" is the red flag)
- Process command line for the browser - automation/webdriver flags, headless mode
- Volume and velocity of login/form-submit actions per minute and count of distinct target domains or account identifiers in one session
- What credentials, cookies, or autofill data existed in the profile the agent was operating under at the time

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Agent navigates and reads a page, then completes only the action the user requested | Agent reads a page, then types/submits/downloads on a domain unrelated to the stated task within seconds/minutes |
| Task text is user-authored, no external page content resembles a directive | Ingested page/DOM contains imperative language addressed to an assistant, often in hidden or off-screen elements |
| Extension permission scope matches an IT-reviewed, sanctioned AI browsing tool | Extension requests broad host permissions, installed via an unsolicited link/ad, unknown publisher |
| Login/form activity matches the user's normal single-site workflow and historical volume | High-velocity form submissions/logins across dozens of distinct domains or accounts in one session |
| Downloaded file matches the task and is scanned/executed only with normal user follow-through | Agent downloads and a child process executes it automatically, with no user action in between |

## Investigation Steps

1. Pull the full agent action log for the session - original task text and the complete step-by-step trace (navigate/click/type/download/submit) with timestamps and target domains.
2. Isolate the exact step where behavior deviates from the stated task, and preserve the page's DOM/screenshot content from that step as evidence - do not re-render the live page in a browser to check it.
3. Check the destination domain of any deviating action (form submit, download, paste) against threat intel and internal allow-lists; flag first-seen or newly-registered domains.
4. Pull browser fleet management data for any extension installed on that profile shortly before the anomaly - publisher, permission scope, install source - and EDR process data for automation/webdriver flags on the browser process.
5. If the session touched webmail or a cloud console, pull the Unified Audit Log / IdP sign-in log for the same window and check for a new forwarding rule, delegate grant, or credential change tied to that session.
6. If the pattern looks like weaponized automation rather than hijack, quantify login/form-submit volume and distinct target-domain/account count for the session, and check the source host's egress IP/ASN for signs it's also serving as infrastructure for something else.
7. Determine what was actually visible or reachable in that authenticated session (mailbox contents, saved cards, cloud resources) and whether any exfil call to an external destination actually completed, versus was attempted and blocked.
8. Interview the task owner to confirm intended scope, and check whether the agent product's approval-gate/guardrail for this action class (e.g., "confirm before submitting a form" or "confirm before download") existed, fired, and was bypassed or simply not configured.

## True Positive Indicators

- Confirmed action outside the stated task, immediately following ingestion of page content containing directive/hidden text
- Credentials, session data, or PII typed or transmitted to a domain with no relationship to the task
- Unsanctioned browser extension with broad host permissions installed shortly before the anomalous agent activity
- High-velocity login/form-submission activity across many distinct domains or accounts from a single agent session
- Mailbox forwarding rule, delegate grant, or new cloud credential created via a browser-agent session with no matching change ticket

## False Positive / Benign Positive Indicators

- Page contained instructional-looking prose meant for a human reader (a style guide, a template with placeholder commands) but the agent's action trace shows no deviating tool call followed
- Agent completed a legitimate multi-site task (price comparison, form-fill across several IT-sanctioned vendor portals) at a velocity consistent with the user's historical baseline
- Extension is an IT-approved AI browsing tool with a documented, previously-reviewed permission scope - simply not yet in the SOC's asset baseline
- Webdriver/remote-debugging flag traced to a QA or test-automation service account, not an AI agent product
- Deviating action was caught and blocked by the agent's own confirmation gate before anything executed - no actual exposure occurred

## Escalation Criteria

Escalate to Tier 2/IR immediately on any confirmed exfiltration of credentials, session data, or regulated data to an external domain; any mailbox or cloud persistence created via a hijacked browser-agent session; or any evidence the same injected page/payload affected multiple users or sessions (campaign, not an isolated fluke) - loop in the AI platform owner for the last case, since it's an upstream input-handling gap, not a one-off. Escalate weaponized-automation cases to IR and, if third-party accounts were targeted, to Legal - notification obligations to the affected external party may apply.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority Required |
|---|---|
| Sign out and revoke session tokens/cookies for the affected user profile | SOC Tier 2, immediate |
| Disable/uninstall the rogue extension fleet-wide via browser management console | Endpoint/browser admin, immediate on confirmed malicious extension |
| Suspend the browser-agent product's autonomous action capability tenant-wide (revert to read-only/confirm-every-step mode) | AI platform owner, immediate pending review |
| Block the destination domain(s) at proxy/firewall | SOC, immediate |
| Force credential reset for any account exposed to the session | IAM/helpdesk, immediate |
| Remove unauthorized mailbox rule/delegate grant | SOC Tier 2, immediate |
| Notify affected data owner and, for third-party targeted accounts, external party/Legal | CISO or Privacy/Legal, per severity |

SLA: confirmed hijack or exfil cases triaged within 15 minutes; session/token revocation and extension removal within 30 minutes of confirmation.

## Example Query (Splunk SPL)

```spl
index=browser_agent action IN ("form_submit","download","type")
| eval delta = tool_time - ingest_time
| where delta <= 300 AND task_domain != current_domain
| join type=left session_id
    [ search index=proxy sourcetype=swg_egress
      | stats count AS reqs, values(dest_domain) AS domains BY session_id ]
| where reqs > 20 OR mvcount(domains) > 10
| table _time, session_id, task_domain, current_domain, action, domains, reqs
```

## Closure Criteria

Close as **True Positive** once the session/token is revoked, any rogue extension is removed fleet-wide, destination domains are blocked, any created mailbox rule/credential is reversed, and root cause - hijack via injected page content, or weaponized automation - is documented with a corresponding guardrail change (confirm-before-submit gate, extension allow-listing) filed with the AI platform owner. Close as **Benign Positive** when the deviating step was blocked by an existing confirmation gate or the extension/domain is confirmed sanctioned. Close as **Insufficient Evidence** when the agent product didn't retain per-step DOM/screenshot data and the vendor's action log can't reconstruct what the agent actually saw at the time of the deviation.

**Example case note:** "Browser-agent session `bwa-77291` (user jortiz@example.com, profile on host WKS-FIN-014) was tasked at 09:14 UTC with 'check invoice status on vendor portal.' Action log shows navigation to `vendor-billing.example.com`, followed at 09:15 UTC by a form_submit of the saved autofill credentials to `vendr-billing-example.net` - a lookalike domain not requested in the task, reached via a redirect embedded in an off-screen `<div>` on the legitimate page. Credential fields captured by DLP before submit. Session tokens revoked 09:28 UTC, password reset forced, destination domain blocked at proxy 09:30 UTC. No confirmation gate existed for form_submit actions on domains outside task scope - change request filed with AI platform owner to add one. Closed True Positive; root cause: indirect prompt injection via lookalike-domain redirect."
