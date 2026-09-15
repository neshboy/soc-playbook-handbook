# Unusual Token Consumption

## Playbook ID & Name
**AI-016 — Unusual Token Consumption: Anomalous LLM API/Token Volume or Cost**

**[STAKEHOLDER]** - Every call to a language model costs real money, billed by the token, and that cost scales with how much text goes in (the prompt) and how much comes out (the completion). A sudden multiplier on your normal AI spend is never "just a billing curiosity" - it's either a stolen API key being resold or abused by someone outside the company (an attacker running their own workload on your account, an increasingly common pattern known as LLMjacking), a runaway internal automation burning budget with no one watching, or - less alarmingly but still worth catching - a legitimate new use case that nobody told Finance about yet. The business decision on whether to keep a key alive during investigation sits with the app owner and FinOps/Security jointly, because cutting it off can break a production workflow just as easily as leaving it running can burn five figures overnight.

## Severity / Priority Default

**Medium** by default (cost/volume anomaly, cause not yet confirmed). Escalate to **High** if the responsible key traces to an unfamiliar ASN/hosting provider inconsistent with the legitimate app's known egress, if the key is found in a public leak (GitHub, paste site, secret-scanning alert), or if bulk sensitive/proprietary data is confirmed staged into prompt content.

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1552.001 Unsecured Credentials: Credentials in Files | Root cause in most LLMjacking cases - the abused API key was hardcoded in a repo, notebook, or CI config and scraped by an automated credential-harvesting bot |
| T1078.004 Valid Accounts: Cloud Accounts | The abusive traffic authenticates with a technically valid, stolen API key/service principal - no exploit needed, just a working credential |
| T1098.001 Additional Cloud Credentials | Attacker who gained access to the AI service account or key vault issues themselves a second, quieter key so rotating the originally-leaked one doesn't fully cut them off |
| T1090 Proxy | Stolen-key abuse frequently routes through commercial hosting/proxy infrastructure or bulletproof VPS ranges to spread requests and mask the true source |
| T1567 Exfiltration Over Web Service | Insider or compromised session stages bulk proprietary data into prompt bodies under cover of a normal "summarize/analyze this" request - the model API itself becomes the exfil channel |
| T1048 Exfiltration Over Alternative Protocol | Data sent directly to a provider's raw inference endpoint, bypassing the corporate proxy/DLP inspection path entirely |
| T1119 Automated Collection | A script sweeps an internal dataset (tickets, records, files) and feeds it through the model in bulk, driving the token spike as a side effect of collection, not the model use itself |

## Trigger / Detection Logic Summary

Three independent signals feed this playbook, and they point at different root causes:

1. **Billing/cost anomaly:** cloud cost-anomaly detection (Azure Cost Management, AWS Cost Anomaly Detection, provider usage dashboards) flags AI/model spend materially above the trailing 30-day baseline for a given subscription, project, or API key.
2. **Gateway/usage-metric anomaly:** the LLM gateway or provider usage API shows one key/service principal responsible for a disproportionate share of total tokens, sustained near-maximum completion lengths, or a sudden shift to a more expensive model tier.
3. **Concurrency/geo anomaly:** the same API key is used from an unusual number of concurrent sessions or from source IPs/ASNs that don't match the legitimate application's known deployment footprint - the strongest single indicator of a stolen, resold key.

## Required Log Sources & Fields

- **LLM gateway / API proxy logs** (internal gateway, Azure OpenAI diagnostic logs, Bedrock invocation logging, Anthropic/OpenAI usage-API exports) - `api_key_id`, `model_name`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `cost_usd`, `source_ip`, `timestamp`, `request_id`.
- **Cloud cost/billing anomaly alerts** - baseline vs. actual spend, service/project attribution, alert threshold crossed.
- **Cloud audit trail** (CloudTrail, Azure Activity Log, GCP Audit Logs) - API key/credential creation and rotation events for the AI service principal.
- **Identity provider logs** (Entra ID, Okta) - sign-in location and MFA status for any human-linked service account tied to the key.
- **Secret-scanning / DLP alerts** (GitHub secret scanning, GitGuardian, internal repo scanners) - whether the abused key ID appears in a public leak.
- **SaaS AI admin console** (OpenAI/Anthropic usage dashboard, Azure OpenAI metrics) - per-key breakdown of requests, tokens, and cost by day/hour.

## Key Fields to Inspect [ANALYST]

| Field | Why it matters |
|---|---|
| `api_key_id` / service principal | Isolates which specific credential is driving the spike - never work off the aggregate account-level alert alone |
| `prompt_tokens` vs `completion_tokens` split | Large prompt tokens suggest data being pushed *in* (possible staging/exfil); large completion tokens suggest content being generated *out* (possible bulk generation for resale, spam, or malicious content) |
| `model_name` / tier | A sudden switch to a pricier flagship model on a key that normally uses a cheap tier is a cost multiplier worth explaining on its own |
| `source_ip` / ASN | Traffic from an unfamiliar hosting/VPS ASN, especially concurrent with traffic from the legitimate app's known egress range, is the classic LLMjacking signature |
| Concurrent session count | Legitimate single-app keys rarely run dozens of simultaneous sessions; a stolen key resold to multiple downstream abusers often does |
| Key creation/rotation timestamp vs. abuse onset | A short gap between a leak-detection alert and the spike start strongly implicates theft over misconfiguration |
| Prompt content (where retained) | Confirms whether payloads are normal application inputs or bulk sweeps of unrelated internal data - many gateways only log metadata by default, so this field may simply be unavailable |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Daily token/cost volume tracks known app usage or headcount within a stable band | Volume jumps 3x-15x+ baseline with no corresponding business change |
| Single, consistent model tier matching the app's designed use case | Tier suddenly upgraded to the most expensive model available for that provider |
| Traffic from known corporate egress ranges or the app's documented cloud region | Traffic from unfamiliar ASNs, hosting providers, or countries never seen for this key |
| Prompt sizes consistent with normal document/ticket length for the use case | Prompt sizes far exceeding normal inputs, or repeated near-identical prompts sweeping a dataset |
| One application, one key, predictable concurrency | Same key active from many disparate sources simultaneously |

## Investigation Steps

1. Identify the specific key/service principal driving the anomaly from the gateway or provider usage dashboard - don't triage off the aggregate cost alert.
2. Pull a 30-90 day baseline for that key's normal daily tokens/cost; confirm the current volume is a genuine statistical outlier, not just a high-but-explainable day.
3. Check credential provenance - key creation date, last rotation, and whether it appears in any secret-scanning or public-leak alert; a short gap between leak detection and abuse onset points to theft.
4. Compare source IP/ASN/geo for the abnormal traffic against the legitimate app's documented deployment footprint - unfamiliar hosting-provider ranges are the strongest compromise signal.
5. Where prompt/response content is retained, review it for bulk data-staging patterns, off-topic content generation unrelated to the business, or a stuck agent loop repeating near-identical calls and hitting max output length every time.
6. Contact the application/service owner directly - confirm whether a recent feature launch, batch job, or known bug explains the volume before treating this as compromise.
7. If large prompt payloads contain internal data, trace that data back to its source system and confirm it against the data owner's classification and the requester's actual entitlement.
8. Check whether the same key or credential shows up in abuse against any other cloud service - a wider secrets-leak incident changes scope well beyond this one AI account.

## True Positive Indicators

- Same key used concurrently from multiple geographically dispersed, unfamiliar ASNs with no legitimate multi-region deployment to explain it.
- Key confirmed present in a public repo, gist, or paste site shortly before the spike began.
- Sustained maximum-length completions generating content unrelated to any business use case.
- Bulk proprietary/regulated data confirmed staged into prompts with no matching authorization.
- A second, undocumented key or credential appears on the same service principal shortly after the first anomaly (persistence attempt).

## False Positive / Benign Positive Indicators

- A confirmed feature launch, larger rollout, or approved batch/migration job explains the increase.
- A non-malicious bug in retry or loop logic explains repeated calls - routed to Engineering as a defect, not an incident.
- A newly onboarded team is using a shared key ahead of being added to the cost-governance tracking sheet.
- Model-tier change was a deliberate, approved decision for quality reasons.
- Large prompts are normal for the use case (e.g., a long-document summarization tool).

## Escalation Criteria

- **Security Engineering/IR** immediately if key theft is confirmed (unfamiliar ASN, public leak match) - treat and rotate as a credential-compromise event.
- **Finance/FinOps** if spend trajectory threatens a defined budget threshold before root cause is resolved.
- **Data Owner/Privacy** if bulk proprietary or regulated data is confirmed staged into prompts (cross-reference the LLM Data Leakage playbook for the exfil-specific workflow).
- **AI Governance board** if the responsible key/automation isn't a registered, approved application.

**SLA target:** confirmed key theft or LLMjacking is a "burning meter" incident, not a slow-moving one - apply a spend cap or rate limit within 1 hour of confirming the anomaly is not a known/approved change, even before root cause is fully nailed down, then revoke/rotate within 4 hours of confirmed compromise. Root-cause and cost-impact review within 24 hours, matching the AI API Key Compromise playbook's SLA where the two overlap.

## Containment Options & Approval Authority [MANAGEMENT]

| Action | Approval Authority | Notes |
|---|---|---|
| Revoke/rotate the abused API key | Security Engineering on-call | Immediate on confirmed compromise; coordinate redeploy to avoid breaking the legitimate app |
| Apply a hard spend cap or rate limit on the key | AI Platform/FinOps owner | Fast, low-risk; buys investigation time without full service cutoff |
| Suspend the service principal/app registration | IAM owner | Use if credential reuse across other services is suspected |
| Kill a runaway agent/automation job | Application owner | For confirmed non-malicious loops; coordinate to avoid dropping in-flight legitimate work |
| Block source IP/ASN at API gateway/WAF | SOC Lead | Tactical measure while rotation completes |

**[STAKEHOLDER] Briefing template for the app/FinOps owner asked to approve action above:**
- *What happened:* key/service [id] consumed [X]x its 30-day baseline token volume in [window], from [source IP/ASN — flag if unfamiliar].
- *Risk if untouched:* this is an open-ended cost exposure (real money, billed by the token, no lockout mechanism) and, if the traffic is a stolen key rather than a runaway job, a possible data-exposure risk depending on what the key can retrieve.
- *Evidence:* the baseline-vs-actual numbers, source IP/ASN mismatch, and any leak-detection hit (GitGuardian/secret scanner) tying the spike to theft rather than a legitimate change.
- *Decision needed:* approve a spend cap/rate limit now (buys investigation time, low disruption) vs. full key revocation (stops the bleed immediately but breaks the legitimate app until redeployed) vs. confirm this is a known, approved change and stand down.
- *GO (cap or revoke now):* either the spend/rate is bounded while we finish root-cause, or the legitimate integration goes down until redeployed with a new key — say which tradeoff you're accepting.
- *NO-GO (wait for full root-cause first):* spend keeps accruing at the current rate for however long root-cause takes — only acceptable if you're confident this is the approved batch job/feature launch, not theft.

## Example Query (Splunk SPL)

```spl
index=ai_gateway sourcetype=llm_usage earliest=-24h
| stats sum(total_tokens) as tokens_24h, sum(cost_usd) as cost_24h by api_key_id, model_name
| join api_key_id [ search index=ai_gateway sourcetype=llm_usage earliest=-30d latest=-1d
    | stats avg(total_tokens) as avg_daily_tokens by api_key_id ]
| eval ratio=round(tokens_24h/avg_daily_tokens,1)
| where ratio > 3
| sort - ratio
```

## Closure Criteria

Close when the responsible key/account and root cause are identified and classified (True Positive, Benign Positive, or Insufficient Evidence), any confirmed-compromised key is rotated, spend/rate controls are back to normal, and the app or data owner has signed off where applicable. Insufficient Evidence is a valid closure when the gateway only retained token-count metadata (not prompt content) and root cause can't be reconstructed beyond confirming and capping the anomaly.

**Example case-note line:**
`2026-09-15 03:10 UTC - Azure Cost Management anomaly alert: Azure OpenAI key svc-ai-summarizer-prod-01 consumed 4.8M tokens in the prior 24h vs. a 30-day average of 310K (15.5x baseline). Gateway logs show requests originating from AS-14061 (DigitalOcean); the legitimate app runs only from corporate Azure VNet egress 20.44.x.x. GitGuardian alert dated 2026-09-13 confirms the same key was posted in a public GitHub Gist two days before abuse onset. Classified True Positive (LLMjacking via leaked API key). Key revoked and rotated, Gist removed and repo owner notified, spend cap applied to the replacement key, IR ticket opened for a secrets-hygiene review of the summarizer service's CI pipeline.`
