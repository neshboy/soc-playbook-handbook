# Playbook: Automated API Scraping / Excessive Model Queries

## Playbook ID & Name
**AI-017 — Automated API Scraping / Excessive Model Queries**

## Business Risk
**[STAKEHOLDER]** - This is the AI-era version of a scraper hammering your website, except the thing being harvested is more expensive to produce and harder to replace than a web page. A model, and everything wired to it - your RAG index, your proprietary prompt engineering, your fine-tuning, your inference bill - is a business asset. Someone running thousands of scripted queries against your endpoint could be a competitor trying to reverse-engineer your model's behavior (model extraction), a data broker vacuuming up whatever your RAG-connected chatbot will disclose, or a low-effort abuser just burning your compute budget for fun or resale. None of those outcomes are good: extraction erodes competitive advantage, bulk querying against a RAG-backed assistant is a real path to leaking customer or internal data one answer at a time, and either way you're paying the token bill for someone else's project. The business decision here is usually rate-limiting and access control, not a court case - but Legal gets pulled in fast if the scraped output turns out to include regulated data or if the activity violates a customer-facing terms of service you now have to enforce.

## Severity/Priority Default
**Medium** by default - most hits are noisy automation, not a targeted attack. Escalate to **High** if the queried endpoint is RAG-connected to sensitive/regulated data, if the query pattern shows systematic coverage of the model's parameter space (classic extraction behavior), or if the source is confirmed to be using a stolen or shared API key. Escalate to **Critical** if sampled responses confirm sensitive data disclosure at volume, or if the same actor is simultaneously probing multiple AI endpoints across the org (coordinated recon).

## MITRE ATT&CK Technique(s)
- T1595 — Active Scanning (initial low-and-slow probing of the API surface, endpoint enumeration, parameter fuzzing before the bulk run starts)
- T1046 — Network Service Discovery (mapping which model endpoints, versions, and routes are exposed and reachable, often via `/v1/models` style discovery calls or brute-forced path guessing)
- T1119 — Automated Collection (the core of this playbook - scripted, repetitive querying at a volume and regularity no human interactive session produces)
- T1567 — Exfiltration Over Web Service (where the model API itself is the exfil channel - data leaves through completions/responses rather than a traditional upload or download)
- T1530 — Data from Cloud Storage (where the abused endpoint is RAG-connected and the attacker's queries are systematically pulling content out of the underlying document/vector store)
- T1078.004 — Valid Accounts: Cloud Accounts (where the scraping runs under a legitimate, currently-authorized API key or OAuth token rather than an anonymous/unauthenticated call)
- T1552.001 — Unsecured Credentials: Credentials In Files (common enabling vector - the key used for scraping was found leaked in a repo, mobile app, or public config rather than stolen through a live attack)

## Trigger / Detection Logic Summary
The signature to chase here is *volume plus regularity plus coverage* - no single metric on its own is reliable. A rate-based rule alone (e.g., >N requests/minute from one key) will catch obvious floods but misses a patient scraper doing 1 request every 3 seconds around the clock, which adds up to tens of thousands of calls a day while never tripping a burst threshold. What separates scripted scraping from a busy legitimate integration is the *shape* of the traffic: near-uniform inter-request timing (coefficient of variation close to zero - humans and even most legitimate batch jobs don't query at machine-perfect intervals), systematic parameter sweeps (temperature, top-p, or prompt templates cycling through a fixed set of values), sequential or alphabetically ordered query content (a sign of walking a list rather than answering organic user questions), and a request volume from a single key/IP/session that is an order of magnitude above that identity's own 30-90 day baseline. Layer detection at the gateway/WAF (request rate, source diversity, user-agent) and at the application/LLM-log level (prompt diversity, response content, token pattern) - each layer alone produces too many false positives to act on.

## Required Log Sources & Event IDs
There are no Windows/Sysmon Event IDs for this scenario - the telemetry lives in API gateway, WAF, and LLM application logs, not host OS logs.

| Source | What to pull |
|---|---|
| API Gateway / reverse proxy logs (AWS API Gateway, Azure API Management, Kong, Apigee, NGINX) | Client/API key ID, source IP, request path, HTTP status, request rate per minute, response size, user-agent |
| WAF logs (Cloudflare, AWS WAF, Azure Front Door WAF) | Rate-limit rule hits, bot-score/bot-management verdicts, geographic dispersion of source IPs |
| LLM gateway / provider invocation logs (Azure OpenAI diagnostic logs, AWS Bedrock invocation logging, OpenAI/Anthropic usage logs) | Model called, prompt/completion token counts, per-key call volume, timestamps at sub-second resolution |
| Cloud IAM / audit trail (CloudTrail, Azure Activity Log, GCP Audit Logs) | Key/token issuance, scope changes, and which principal owns the credential driving the traffic |
| CDN / bot-management platform | ASN reputation, known scraper/datacenter IP ranges, TLS fingerprint (JA3) clustering across "different" source IPs |
| RAG/vector store retrieval logs (where applicable) | Which documents/chunks were retrieved per query - critical for scoping actual data exposure, not just query volume |

## Key Fields to Inspect
**[ANALYST]**
- **API key ID / client ID / OAuth subject** - the identity driving the traffic; never assume one IP equals one identity or vice versa
- **Request timing intervals** - compute the standard deviation of inter-request gaps; a tight, near-constant interval is the single strongest scripted-automation signal
- **Source IP / ASN diversity** - a single key hitting from one IP is different from a single key rotating across dozens of IPs in a known residential-proxy or hosting range (evasion of IP-based rate limiting)
- **User-agent string** - `python-requests`, `curl`, `axios/1.x`, or a bare SDK default where the legitimate integration always sends a branded, versioned user-agent
- **Prompt/query content pattern** - sequential IDs, alphabetically walked terms, template-filled prompts with only one variable changing, or systematic parameter sweeps (temperature 0.1, 0.2, 0.3...)
- **Token volume and response size distribution** - scraping runs tend to produce a tight, repetitive response-size distribution; organic human use is far more variable
- **Endpoint/route coverage** - is the caller hitting one endpoint repeatedly, or systematically walking every model/route/version the gateway exposes (T1046 behavior)?
- **Retrieval logs (RAG-connected endpoints)** - which specific documents or chunks are being surfaced across the query set; a scraper often ends up retrieving a disproportionate share of the total corpus over time

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Request timing is bursty and irregular, tracking real user sessions or a known batch schedule | Request intervals are near-constant (low variance) around the clock, including 02:00-05:00 local time |
| Query content varies organically with user need | Query content is templated, sequential, or systematically sweeps parameters/IDs |
| Traffic from a small, stable set of IPs/ASNs tied to known app servers or user geography | Traffic rotates across many IPs in datacenter/residential-proxy ranges, all under one key |
| Volume tracks with known business activity (ticket load, active users) | Volume is flat-rate high regardless of business hours, weekends, or holidays |
| RAG retrieval hits are spread across the corpus proportional to real topic demand | Retrieval hits show systematic, near-exhaustive coverage of the document store over days/weeks |
| User-agent matches the app's documented SDK/client string | Generic script/library user-agent, or a user-agent that changes every request while the key stays constant |

## Investigation Steps
1. Identify the triggering key/IP/session and pull its 30-90 day baseline from gateway and LLM invocation logs - request rate, timing distribution, source IPs, endpoints called, and typical prompt/response token ranges. Don't assess the anomaly against a guess; build the baseline from data.
2. Compute inter-request timing variance for the flagged identity. Near-zero variance across a long window is the strongest single indicator of scripted automation versus a genuinely busy human or app.
3. Sample actual prompt/response content (subject to your gateway's retention and redaction policy) rather than relying on volume alone - look for templated prompts, sequential parameters, or systematic topic/document sweeps.
4. Check source IP/ASN reputation and diversity. Distinguish "one IP, high volume" (simple flood, easier to contain) from "many IPs, one key, coordinated timing" (proxy-rotated scraping, harder to contain by IP block alone).
5. If the endpoint is RAG-connected, pull retrieval logs and calculate what proportion of the underlying corpus has been touched by this identity's queries over the observation window - this is the number that actually matters for a data-exposure conversation with Legal/Privacy, not raw request count.
6. Trace the API key/credential back to its owning application or team. Confirm whether this is a known, sanctioned integration running an undocumented batch job (common and boring) versus a credential that was leaked, shared, or never provisioned for this use case.
7. Check for coordinated activity across other AI endpoints in the environment - the same key, ASN, or TLS fingerprint hitting multiple model APIs in the same window suggests reconnaissance across your AI surface, not an isolated integration issue.
8. Decide containment against business impact: rate-limiting or key revocation is the default move, but if the key is tied to a production customer-facing feature, coordinate the cutover with the owning team rather than silently breaking live traffic mid-investigation.

## True Positive Indicators
- Near-constant inter-request timing sustained over hours or days, inconsistent with any documented batch job or human session
- Systematic parameter sweeps, sequential ID walks, or templated prompts with only minor variable substitution
- Source IPs rotating across known proxy/hosting ranges while the API key/session identity stays constant
- RAG retrieval logs showing broad, near-exhaustive corpus coverage disproportionate to any single legitimate use case
- Confirmed leaked or shared credential (per T1552.001) driving the traffic, with no matching authorized integration on record
- Volume and token consumption an order of magnitude above the identity's own historical baseline with no corresponding business event

## False Positive / Benign Positive Indicators
- Traffic traced to a known, approved batch job or scheduled pipeline (nightly re-embedding run, QA regression suite, load test) that simply wasn't communicated to the SOC ahead of time
- A newly onboarded legitimate integration whose "baseline" doesn't exist yet because it's genuinely new - confirm with the owning team rather than assuming malice from novelty alone
- Rate-limit rule fired on a documented third-party partner integration with contractually agreed higher call volume
- Regular timing explained by a legitimate polling client (health-check, monitoring probe) hitting a low-sensitivity endpoint, not the model inference path itself

## Escalation Criteria
Escalate to IR immediately if sampled query/retrieval content confirms disclosure of regulated or customer data at volume, if the driving credential is confirmed compromised or leaked (link to the AI API Key Compromise playbook), if the pattern shows systematic model-extraction behavior (broad, structured coverage of input space consistent with training a shadow model on your outputs), or if the same actor/infrastructure is probing multiple AI endpoints across the org. Treat sustained scraping against a RAG-connected endpoint with unknown corpus content as high urgency by default - you often can't rule out sensitive-data exposure without the retrieval-log review in step 5, so don't wait for that review to complete before opening the case.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Rate-limit or throttle the offending key/IP** - low approval bar, SOC or Platform on-call can apply immediately at the gateway/WAF; least disruptive first move and reversible.
- **Revoke/rotate the API key** - requires notifying the owning application team first if it's a known integration; any engineer with gateway/provider console access can execute once notification is sent.
- **IP/ASN block at WAF or CDN** - Platform/Network team approval; effective against single-source floods, less effective against proxy-rotated scraping (pair with key-level action).
- **Temporary endpoint lockdown or auth-tier upgrade** (require stronger auth, add CAPTCHA/bot-management challenge on the exposed route) - Engineering lead approval, since it can affect legitimate users of a public-facing endpoint.
- **Legal/Privacy notification and possible external enforcement** (terms-of-service violation notice, cease-and-desist) - Legal-owned decision, triggered when confirmed data exposure or competitive extraction is in scope; timeline set by Legal, not the SOC.
- SLA target: rate-limit or block applied within 30-60 minutes of confirmed scripted abuse; full corpus-exposure assessment on RAG-connected endpoints within 24 hours.

## Example Query (Splunk SPL)
```spl
index=api_gateway sourcetype=llm_invocation
| sort 0 api_key_id src_ip _time
| streamstats current=f last(_time) as prev_time by api_key_id, src_ip
| eval req_gap = _time - prev_time
| bucket _time span=1m
| stats count as req_count, values(user_agent) as uas,
    stdev(req_gap) as timing_stdev
    by api_key_id, src_ip, _time
| where req_count > 200 AND timing_stdev < 0.5
```

## Closure Criteria
Close as **True Positive** once the key/IP is rate-limited or revoked, the timing/coverage pattern stops in subsequent monitoring windows, the corpus-exposure assessment (if RAG-connected) is complete, and the owning credential's provisioning is reviewed for how it was obtained. Close as **Benign Positive** when the pattern maps to a documented, approved job or integration with the volume simply uncommunicated to the SOC - fix the communication gap and add the identity to a known-automation allowlist so it doesn't keep re-triggering. Close as **Insufficient Evidence** when gateway retention didn't retain enough history to confirm timing regularity or corpus coverage; apply a precautionary rate limit anyway and flag the retention gap for the logging backlog.

**Example case note:** *"WAF alerted on API key fp-7c21 against endpoint api.example.com/v1/chat/completions - 14,600 calls over 6 hours from key normally averaging 300/day. Timing analysis showed inter-request stdev of 0.18s across the full window, consistent with scripted polling, not interactive use. Source IPs spanned 22 addresses across AS-40676 (known hosting range), all under the one key. Sampled prompts showed sequential product-SKU substitution in an otherwise fixed template - classic corpus-walk pattern. Endpoint is RAG-connected to the internal product-knowledge index; retrieval logs show 61% of the total document corpus was touched by this key's queries over the 6-hour window. Key traced to a partner integration account for Example Corp Reseller LLC, provisioned 14 months ago, no documented reason for this volume. Key rate-limited to 50 req/hr at 14:22 UTC pending partner contact; partner confirmed at 16:05 UTC an internal contractor had built an unauthorized bulk-lookup tool against the API without the reseller's knowledge. Key rotated, new key issued with hard rate cap. No evidence of data leaving the reseller's own environment beyond the retrieved product data already in scope of their existing agreement. Closed True Positive, no Legal escalation required per existing partner data-sharing agreement."*
