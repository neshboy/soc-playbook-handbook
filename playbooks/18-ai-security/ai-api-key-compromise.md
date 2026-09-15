# Playbook: AI API Key Compromise

## Playbook ID & Name
**AI-005 — AI API Key Compromise (LLM Provider Credential Theft & Abuse)**

## Business Risk
**[STAKEHOLDER]** - An AI API key is a bearer credential with a billing meter attached. Whoever holds a valid OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, or Vertex AI key can spend the company's money, query whatever models and data sources that key is scoped to, and - if the key is wired into a Retrieval-Augmented Generation pipeline, a coding agent, or a customer-support bot - potentially pull back proprietary documents, source code, or customer PII through the model itself. Unlike a stolen password, there's often no MFA prompt to stop the abuse and no lockout after failed attempts, because the key alone *is* the authentication. The financial exposure is real (five- and six-figure inference bills are not hypothetical), but the bigger risk is almost always what the key can retrieve or exfiltrate, not what it costs to run.

## Severity/Priority Default
**High** by default on any confirmed live key exposure or usage anomaly. Escalate to **Critical** if the key has access to a RAG index or tool containing regulated/customer data, if unauthorized additional keys were created on the account (persistence), or if usage volume indicates bulk automated extraction rather than a single curious query. De-escalate to **Medium** only after confirming the key was already dead/rotated at time of exposure and no live calls succeeded.

## MITRE ATT&CK Technique(s)
- T1552.001 — Unsecured Credentials: Credentials In Files (primary vector - key committed to a git repo, left in a `.env`, CI/CD log, Jupyter notebook, or mobile app bundle)
- T1552.005 — Unsecured Credentials: Cloud Instance Metadata API (alternate vector - key or the secret store credential used to retrieve it stolen via SSRF against a cloud metadata endpoint)
- T1078.004 — Valid Accounts: Cloud Accounts (the key itself functions as a valid cloud/API identity once in attacker hands)
- T1098.001 — Account Manipulation: Additional Cloud Credentials - attacker mints a second key under the compromised account so revoking the original doesn't fully lock them out (not T1098.002 Additional Email Delegate Permissions, which doesn't apply to an API-key-only compromise with no mailbox access)
- T1538 — Cloud Service Dashboard (attacker checks usage/billing console to gauge remaining quota or scope before hitting it hard)
- T1567 — Exfiltration Over Web Service (the model API itself becomes the exfil channel - attacker pulls data out through completions rather than a traditional upload)
- T1530 — Data from Cloud Storage (where the key's RAG/tool scope reaches connected document stores)
- T1119 — Automated Collection (scripted, high-volume querying against the compromised key)
- T1090 — Proxy (calls routed through commercial VPN/residential proxy to mask origin - common when the key is being resold or tested by a third party)

## Trigger / Detection Logic Summary
Two independent trigger paths, and you want both wired in because they catch different failure modes. **Path one - exposure detection**: a secret-scanning tool (GitHub push protection, GitGuardian, TruffleHog, an internal CI linter) flags a string matching a known provider key format in a commit, log file, or build artifact. **Path two - usage anomaly**: the LLM gateway or provider's own usage telemetry shows a key's behavior diverging sharply from its own baseline - a spike in request rate or token consumption, a new source IP/ASN never associated with that key, calls at 03:00 local time for a key that's only ever called from a 9-to-5 batch job, or a sudden jump in spend against a normally flat billing curve. Neither path alone is reliable: exposure detection tells you a key *could* be compromised, not that it *was* used; usage-anomaly detection can fire on a legitimate new deployment region just as easily as on theft. Treat the two as complementary evidence, not separate verdicts.

## Required Log Sources & Event IDs
There are no Windows/Sysmon Event IDs for this scenario - the telemetry lives in provider and gateway logs, not the OS.

| Source | What to pull |
|---|---|
| LLM gateway / API proxy logs | Request ID, key ID/fingerprint (never the full key), model, token counts (prompt vs. completion), source IP, user-agent, timestamp |
| Provider usage/billing console (OpenAI, Anthropic, Azure OpenAI, AWS Bedrock) | Per-key spend, quota consumption, model access list, key creation/last-used timestamps |
| Cloud audit trail (AWS CloudTrail, Azure Activity Log, GCP Audit Logs) | Key/secret creation, retrieval, or scope-modification events tied to the IAM principal or service account that owns the key |
| Secret manager logs (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault) | Read/access events for the secret backing the key - who or what pulled it and from where |
| Source control secret scanning (GitHub, GitLab) | Commit hash, file path, repo visibility, exposure window (push timestamp to revocation/removal) |
| CI/CD pipeline logs | Whether the key was echoed into build logs, artifacts, or container images |

## Key Fields to Inspect
**[ANALYST]**
- **Key ID / fingerprint** (last 4-6 characters only) - correlates activity without ever handling the live secret
- **Source IP, ASN, geolocation** - flag hosting providers, VPN/proxy ranges, and any country with no legitimate business tie
- **Model invoked** - a key that normally calls a small embedding model suddenly calling a frontier chat model is a scope change worth questioning
- **Token counts** - completion tokens far exceeding prompt tokens across many calls suggests bulk content generation or data pull, not interactive chat
- **Request rate / timing regularity** - human interactive use is bursty and irregular; scripted abuse is often near-uniform interval, machine-fast
- **User-agent / client string** - `python-requests/2.31.0`, `curl/8.1.2`, or a bare SDK string where the legitimate app always sends a branded user-agent is a mismatch worth flagging
- **Key creation/last-rotated timestamp** vs. **first-abuse timestamp** - a key created 18 months ago and abused today points to a long-dormant leak, not a fresh mistake
- **New key/credential creation events** on the same account shortly after suspected exposure (persistence check)

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Calls originate from a known application server or CI runner IP range, consistently, day over day | Calls appear from a new ASN/country with no deployment or remote-work explanation |
| Token consumption tracks with known application load (ticket volume, user sessions) | Token consumption spikes 5-10x baseline with no corresponding business event |
| Request timing matches the app's actual usage pattern (business hours, batch windows) | Requests hit at 02:00-04:00 local time for a key that has never run outside 08:00-18:00 |
| One key, one owning application, stable model list | Same key suddenly calling models it has never used, or a second key appearing on the account unrequested |
| User-agent matches the known SDK/client the app uses | Generic script/library user-agent replacing the app's normal signature |

## Investigation Steps
1. Identify the trigger path (secret-scanner hit vs. usage anomaly vs. provider billing alert) and pull the specific key ID/fingerprint - never work from the full key value in a ticket or chat thread.
2. Pull gateway/provider logs for that key across the prior 30-90 days to establish a real baseline: normal source IPs/ASNs, models called, token volume, and calling application - don't assume you know the baseline, build it from data. Use the per-key baseline query in the Example Query section below (the detection query there is an aggregate sweep across all keys, not scoped to the one key you're triaging).
3. Compare the triggering activity against that baseline. Look specifically for new geography, new ASN (especially hosting/VPN ranges), token-volume spikes, off-hours timing, and any model the key has never called before.
4. If a secret scanner flagged the key, pull the commit or log where it appeared. Check repo visibility (public vs. private), how long the exposure window was open before remediation, and whether the repo shows unusual clone/fork activity during that window.
5. Check whether the key was hardcoded and shipped somewhere outside source control entirely - a compiled mobile app, a public-facing JS bundle, or a support ticket/Slack paste - because remediation differs (app store release cycle vs. a simple git history purge).
6. Pull cloud audit logs and secret manager access logs for the owning account: did anyone mint an additional API key, widen its scope, or raise its rate limit/quota shortly after the suspected exposure window (T1098.001 persistence pattern)?
7. Where the key has RAG or tool access, review what the actual calls returned - not just volume. Pull sample request/response pairs (subject to gateway retention) to check whether responses contained customer PII, source code, or internal documents (T1530/T1119).
8. Decide containment timing against operational impact: immediate revocation is the safe default, but if the key underpins a production integration, coordinate the cutover with the app owner rather than silently breaking a live service mid-incident.

## True Positive Indicators
- Usage spike from an unfamiliar country/ASN with no remote-work, vendor, or deployment explanation
- Key confirmed live (still returns 200s) in a public repo, paste site, decompiled mobile binary, or exposed CI log
- Spend/token consumption far exceeding historical baseline in a compressed window
- New key or elevated quota/scope created on the account that the owning team did not request
- Scripted, near-uniform call timing inconsistent with the application's normal interactive pattern
- Model responses in sampled logs show retrieval of data well outside the application's normal scope

## False Positive / Benign Positive Indicators
- Secret-scanner match against a test fixture, example/dummy key format, or a key already dead/revoked at exposure time with confirmed failed auth on replay
- New source IP explained by planned autoscaling, a new CDN edge region, or a documented infrastructure migration
- Volume spike traced to an approved batch job (nightly embeddings refresh, quarterly document reindex) that wasn't communicated to the SOC ahead of time - annoying, but not malicious; fix the communication gap, not the key
- A second key on the account traced to a sanctioned vendor onboarding or a developer's approved local-testing key

## Escalation Criteria
Escalate to IR immediately if the key has access to a RAG index, tool, or data store containing regulated or customer data; if additional keys/credentials were created without authorization (persistence); if usage indicates bulk automated extraction rather than isolated misuse; or if the key surfaces on a paste site or marketplace with evidence of resale. Treat confirmed live-key exposure in a **public** repository as high urgency regardless of usage volume yet observed - the absence of abuse so far doesn't mean it won't happen in the next hour.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Immediate revoke/rotate the key** - low approval bar, any engineer or analyst with provider console access can act, but must notify the owning application team first to avoid an unplanned production outage.
- **Vendor engagement** - open a support case with the provider (OpenAI, Anthropic, Microsoft, AWS, Google) for supplemental logs, revocation confirmation, and a billing dispute if fraudulent usage drove real spend; owned by the Cloud/Platform team.
- **Retroactive spend cap / quota lockdown** - Finance or Platform Engineering approval, applied while the incident is triaged to bound further financial exposure.
- **Repository remediation** - purge the key from git history, force-push, and rotate every other secret that shared the exposed commit/file; requires the engineering lead's sign-off and coordination with the dev team, since history rewrites affect every clone.
- **Legal/Privacy notification** - required if the key's scope reached regulated data; Legal/Privacy approval, timeline set by the breach-notification policy, not by the SOC.
- SLA target: revoke or rotate within 1 hour of confirmed live exposure; full root-cause and scope-of-access review within 24 hours.

**[STAKEHOLDER] Briefing template for the app owner whose production key is being revoked:**
- *What happened:* key [fingerprint only, never the full value] was exposed via [git leak / usage anomaly] and [is / is not] confirmed to have been called by someone other than your application.
- *Risk if untouched:* whoever holds this key can spend against our account and, if it has RAG/tool access, retrieve [name what the key's scope actually reaches] with no MFA gate to stop them.
- *Evidence:* baseline vs. abnormal usage (new ASN/geo, token spike, model-tier change) and, if applicable, the leak location (repo, paste site) and exposure window.
- *Decision needed:* approve immediate revoke/rotate now, which will break your integration until the replacement key is deployed — or accept the ongoing exposure window while we coordinate a scheduled cutover.
- *GO (revoke now):* your integration goes down until redeployed with the new key — tell us your expected redeploy time so we can track the gap.
- *NO-GO (delay for coordinated cutover):* integration stays up, but the exposure window stays open and financial/data exposure continues accruing every hour it's live — this is only acceptable for a short, explicitly time-boxed delay.

## Example Query (Microsoft Sentinel — KQL)

**Detection sweep** (flags any key crossing the threshold, all keys, rolling 1h bins):
```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| extend KeyId = tostring(properties_s.ApiKeyId), SourceIp = tostring(properties_s.CallerIpAddress)
| summarize Calls = count(),
            TotalTokens = sum(toint(properties_s.TotalTokens)),
            IPs = make_set(SourceIp)
    by KeyId, bin(TimeGenerated, 1h)
| where TotalTokens > 200000 or array_length(IPs) > 3
```

**Per-key 90-day baseline** (run this for the specific `KeyId` that triggered — this is what Investigation Step 2 needs before you can call anything in the detection sweep above "anomalous"):
```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where TimeGenerated > ago(90d)
| extend KeyId = tostring(properties_s.ApiKeyId), SourceIp = tostring(properties_s.CallerIpAddress),
         Model = tostring(properties_s.ModelName)
| where KeyId == "<key_id_from_alert>"
| summarize Calls = count(), TotalTokens = sum(toint(properties_s.TotalTokens)),
            IPs = make_set(SourceIp), Models = make_set(Model)
    by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

## Closure Criteria
Close as **True Positive** once the key is revoked/rotated, no further successful calls are observed against the old key during a defined watch window (24-48 hours), the leak vector is identified and remediated (removed from repo history, added to a blocking secret-scanner rule, mobile build re-issued if applicable), and financial impact is assessed - dispute filed with the provider if warranted. Close as **Benign Positive** when the anomaly maps to a documented, legitimate change (new infra region, approved batch job, sanctioned vendor key) with no unauthorized key or scope changes on the account. Close as **Insufficient Evidence** when provider log retention didn't cover the exposure window and no source-IP or call-content corroboration is available - rotate the key as a precaution regardless of verdict, since "we couldn't prove abuse" is not the same as "abuse didn't happen."

**Example case note:** *"GitGuardian flagged a live Anthropic key (fingerprint ...a91f) committed to public repo example-corp/support-bot at 09:14 UTC. Gateway logs show the key's baseline was 40-60 calls/day from 10.40.12.0/24 (CI runner range) calling claude-3.5-haiku only. From 09:20-10:05 UTC observed 1,140 calls from AS-206092 (known hosting provider, Netherlands) calling claude-opus-4, completion tokens averaging 8x baseline. No unauthorized additional keys found on the account via provider console audit. Key revoked 10:11 UTC, repo history purged 10:40 UTC, replacement key issued and rotated into Vault. Sampled response logs show no evidence the RAG-connected support KB was queried during the abuse window - tool scope for this key does not include KB retrieval. Provider billing dispute filed for the anomalous usage window. Closed True Positive."*
