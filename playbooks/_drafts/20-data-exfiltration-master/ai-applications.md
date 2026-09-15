# Exfiltration via AI Applications — Prompt Input & File Upload

This channel gets missed constantly because it doesn't look like exfiltration to the person doing it. An analyst pastes a stack trace into ChatGPT to debug it. A finance user uploads a spreadsheet to Copilot to "summarize the variance." Nobody involved thinks they've moved data outside the company boundary — but depending on the AI tool's tier and data-handling terms, that content may now sit on a third-party provider's infrastructure indefinitely, potentially feeding a training pipeline. This section covers telemetry and indicators specific to narrowing an investigation down to "yes, this went out via an AI application" as opposed to email, cloud storage, USB, or a web service more broadly.

**[STAKEHOLDER]** - The risk here isn't usually a malicious insider stealing IP on purpose. It's well-meaning staff routing sensitive data (source code, customer PII, unreleased financials, credentials embedded in config files) through a consumer-grade AI account that has no enterprise data protection agreement. The business decision that matters: which AI tools are sanctioned (enterprise tenant, SSO-gated, contractual no-training clause) versus shadow AI (personal free-tier accounts). Legal/Compliance and IT Security jointly own that approved list, not the SOC.

## Telemetry Sources

| Source | What it shows | Common gap |
|---|---|---|
| Web proxy / SWG | Destination domain, URL path, method, bytes-out, user agent | TLS-inspected traffic only; many orgs don't decrypt AI domains |
| CASB / SSPM | Sanctioned vs. unsanctioned SaaS AI use, session identity (corp tenant vs. personal login) | Depends on API connectors or reverse-proxy mode being deployed for that app |
| DNS logs | First-seen/rare queries to AI domains from a host that never used them before | No visibility into what was actually sent post-resolution |
| Endpoint DLP / browser extension DLP | Content inspection on paste/upload events, pattern matches (PII, secrets, source code) | Clipboard monitoring often licensed separately; users can disable extensions with local admin |
| Enterprise AI gateway (if deployed) | Prompt/response logging for org-provisioned LLM access | Only covers traffic actually routed through the gateway — doesn't stop direct browser use |
| Windows Security 4688 | Browser process launch, command-line arguments if auditing enabled, parent process | No visibility into in-browser navigation or file picker selection |
| 4103 / 4104 (PowerShell) | Script block content revealing direct API calls (`Invoke-RestMethod` to `api.openai.com`, `api.anthropic.com`, hardcoded keys) | Scripted/API-based exfil, not browser paste-based |
| 4648 | Explicit-credential logon if a script or scheduled job runs under a service account to automate a data pull | Rare in this channel unless automation is involved |
| 4698 | Scheduled task created — relevant if someone automates "pull report → post to AI API" on a cadence | Task Content XML needed to see the actual command |

## Key Indicators

| Signal | Normal | Suspicious |
|---|---|---|
| Destination domain | Sanctioned enterprise AI tenant (e.g., `copilot.microsoft.com` under org SSO) | Personal-tier `chat.openai.com`, `claude.ai`, `gemini.google.com`, `poe.com`, `character.ai` login not tied to corp SSO |
| Upload volume/frequency | Occasional single-file uploads | Bulk sequential uploads, or one user uploading dozens of files in a short window |
| Session identity | Corporate SSO-federated session | Personal email login while on corp network/device (CASB identity mismatch) |
| Content pattern | General text | DLP hit on regex for source code headers, SSN/PAN patterns, API keys, "CONFIDENTIAL" markings in the outbound POST body |
| Encoding | Plain text paste | Base64 or otherwise encoded blob pasted just before the AI domain hit — possible attempt to dodge DLP pattern matching (T1027) |
| Prior file access | File opened, used, closed normally | File opened from a sensitive share seconds before a large POST to an AI upload endpoint |

**[ANALYST]** Evidence to pull: proxy full-URL log with bytes-out for the session window, CASB session detail (personal vs. corp identity), DLP alert with the actual matched content snippet, and — if EDR clipboard monitoring is licensed — the paste event tied to the browser process ID. Cross-reference 4688 for the browser process and its parent (was it launched normally, or by a script?). If the flow looks scripted rather than interactive (no mouse/keyboard telemetry, tight timing between file read and POST), pull 4104 for the host to check for direct API calls bypassing the browser entirely — this maps to T1048 (Exfiltration Over Alternative Protocol) rather than T1567.

**[ENGINEERING]** Detection logic, conceptually:

```
alert when:
  proxy.dest_domain IN (ai_app_watchlist)
  AND proxy.method == "POST"
  AND proxy.bytes_out > threshold
  AND casb.session_identity NOT IN (corp_sso_sessions)
```

Pair this with a DLP rule scoped specifically to the AI-domain watchlist (not general web egress) so precision stays high — broad web DLP on paste/upload events is a false-positive factory otherwise.

## Enrichment Steps to Confirm This Channel

1. Confirm destination against a maintained AI-app watchlist, split sanctioned/unsanctioned.
2. Check CASB/SSO logs for which identity (corp tenant vs. personal) was used in that session.
3. Pull the DLP match detail — what pattern fired, and does it correspond to genuinely sensitive content or a benign false match (e.g., a public code snippet).
4. Correlate file-access logs immediately preceding the web session to identify the source file/share.
5. Rule out overlap with other channels under investigation in the master playbook (email attachment, cloud storage share) before closing this as the confirmed vector — same data loss event can sometimes show attempts across multiple channels.

**[MANAGEMENT]** Most tickets on this channel close as **Expected Activity** (sanctioned enterprise AI tool, corp identity, DTA in place) or **Benign Positive** (personal account, but content was genuinely non-sensitive). Escalate to **Confirmed** only when DLP content match plus unsanctioned identity plus sensitive-data-classification align. Track monthly: shadow-AI session count, sanctioned-tool adoption rate, and DLP-block vs. DLP-alert-only mode for the AI watchlist — this is a policy/tooling maturity metric owned by IT Security governance, reviewed alongside the approved SaaS AI list on a quarterly cadence.
