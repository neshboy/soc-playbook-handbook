# Model Endpoint Abuse

## Playbook ID & Name
**AI-015 — Model Endpoint Abuse: Unauthorized or Out-of-Policy Use of an AI Inference Endpoint**

## Business Risk
**[STAKEHOLDER]** - Every model we serve - whether it's a self-hosted inference server or a managed cloud AI service - is a metered, billable, and sometimes internet-reachable door. If that door is left unlocked or its keys leak, someone else runs their workload on our budget, our infrastructure, or our reputation: unexplained six-figure cloud AI bills, our endpoint used to generate content we'd never approve, or - worse - the serving host itself becoming a foothold into the rest of the network. This isn't a hypothetical; stolen cloud credentials being resold specifically to invoke paid LLM APIs ("LLMJacking") is an active criminal business model right now.

## Severity/Priority Default
**High (P2)** at detection. Escalate to **Critical (P1)** the moment there is confirmed unauthorized invocation at volume, evidence of remote code execution on the host serving the model, or a credential compromise that reaches beyond the AI endpoint itself.

## MITRE ATT&CK Technique(s)

| Role in the attack | Technique |
|---|---|
| Finding the endpoint | T1595 Active Scanning, T1046 Network Service Discovery |
| Getting in | T1190 Exploit Public-Facing Application (unauthenticated/vulnerable model-serving stack), T1078.004 Valid Accounts: Cloud Accounts (stolen/leaked API key or IAM credential) |
| Credential sourcing | T1552.005 Unsecured Credentials: Cloud Instance Metadata API (SSRF against the instance metadata service to lift the serving host's IAM role) |
| What they do with access | T1090 Proxy (laundering third-party traffic through our paid model access), T1572 Protocol Tunneling |
| If host compromise follows | T1059.001/.003 Command and Scripting Interpreter, T1105 Ingress Tool Transfer, T1027 Obfuscated Files or Information, T1562.001 Impair Defenses: Disable or Modify Tools |

## Trigger / Detection Logic Summary
Fires on any of:
1. Sustained or spiking inference request volume from a single API key/IAM principal/source IP that breaks its own historical baseline (requests/minute, tokens returned, or cloud AI cost).
2. Successful invocation from a source IP, ASN, or geography that has never called this endpoint/key before, especially outside business hours for that identity's normal usage pattern.
3. A self-hosted model-serving port (e.g., a Triton, Ray Serve, TorchServe, vLLM, or Ollama listener) receives traffic from the internet or an unexpected internal subnet, or its unauthenticated model-list/health endpoint is enumerated repeatedly.
4. A managed cloud AI service invocation log (Bedrock, Azure OpenAI, Vertex AI) shows a model ID or region this identity has never used, paired with jailbreak-style or content-policy-adjacent prompt patterns - a classic LLMJacking tell.
5. EDR alert on the host running the inference service: unexpected child process off the serving daemon, new outbound connection, or a request to the instance metadata address (169.254.169.254 or cloud-provider equivalent) from a process that has no business calling it.

## Required Log Sources
There's no Windows/Sysmon Event ID for "someone called an inference endpoint" - don't force one. The signal lives in:
- API gateway / WAF / reverse-proxy access logs in front of the endpoint (source IP, path, status code, client ID, request/response size)
- Cloud AI service invocation and billing logs (AWS CloudTrail `InvokeModel`/`InvokeModelWithResponseStream`, Azure OpenAI diagnostic logs, GCP Vertex AI request logs) - identity/principal, model ID, region, token counts
- IAM/identity provider logs for the credential in use - issuance date, last legitimate use, MFA status, any breach/leak-feed match
- Model-serving application logs (Triton, Ray Serve, TorchServe, vLLM, Ollama, TGI) - request path, model name, client IP
- Host EDR/process telemetry for the VM or container running the model server
- Cloud cost/usage anomaly reports from the billing console or FinOps tooling - often the first place this actually surfaces
- Threat intel feeds on credential leaks and known LLM-proxy/reseller infrastructure

## Key Fields to Inspect
**[ANALYST]**

| Field | Why it matters |
|---|---|
| `client_id` / `api_key_id` / IAM principal ARN | The credential doing the calling - is it valid, current, and being used consistent with its normal pattern? |
| `model_id` / `model_arn` | Attackers invoking a model this identity has never touched is a strong tell |
| `source_ip`, ASN, geolocation | Baseline mismatch against the credential's known calling infrastructure |
| `request_count` per minute/hour per key | Volume anomaly - flat, low-and-slow abuse is common to stay under simple rate alarms |
| `http_status_code` distribution | A wall of 401/403 followed by a 200 suggests brute-forced or guessed key; a wall of 200s at high volume suggests successful ongoing abuse |
| prompt/response content (where logged) | Jailbreak framing, disallowed-content generation, or content wholly unrelated to our business use case |
| token counts / response size | Cost driver - correlates directly to the billing anomaly |
| host process tree on the serving VM/container | Whether abuse stayed at the API layer or escalated into host compromise |

## Normal vs Suspicious

| Normal | Suspicious |
|---|---|
| Requests originate from known application service accounts / corporate egress ranges | Requests from unfamiliar ASNs, VPN/proxy exit nodes, or countries the identity has never operated from |
| Model selection matches the application's documented use case | Sudden calls to a different, often more capable or less-restricted model |
| Request volume tracks with product usage / business hours | Flat 24/7 high-volume traffic, or a sharp step-change with no corresponding release or campaign |
| Model-serving management ports bound to localhost or internal-only interfaces | Health/model-list endpoint reachable from the public internet, enumerated repeatedly |
| Billing trend flat or grows in line with forecast | Unexplained cost spike tied to a single key/principal |

## Investigation Steps
1. Identify the specific endpoint (self-hosted server vs. managed cloud AI service), its exposure (public/internal/VPC-only), and its auth model (API key, IAM role, none).
2. Pull invocation logs for the alert window: identity/key, source IP, model ID, request volume, status codes, token counts.
3. Verify the credential's legitimacy - issuance record, last known good use, owning team, and check it against breach/leak-feed data.
4. If self-hosted, pull host EDR and process telemetry for the serving VM/container - look for unexpected child processes, new listeners, or metadata-service calls.
5. Correlate source IP/ASN/geography against threat intel for known scanning or LLM-proxy/reseller infrastructure.
6. Pull the cloud billing/usage anomaly report for the same identity - confirm the cost impact and window match the log evidence.
7. Determine blast radius: does this credential reach other endpoints or resources beyond the model API? Any lateral movement path from the host?
8. If provider-side confirmation is needed (managed cloud AI service abuse from a shared-tenancy angle), open a case with the cloud provider's abuse/support team and preserve logs before they roll off retention.

## True Positive Indicators
- Confirmed invocation from a credential that was leaked, rotated for cause, or never legitimately provisioned to the calling identity/IP.
- Model or region selection inconsistent with the application's documented use, paired with jailbreak/content-policy-adjacent prompt patterns.
- Cost/usage spike that maps directly to the anomalous log window and identity.
- Host-level compromise indicators on the model-serving VM/container (unexpected process execution, outbound C2-like traffic, metadata API abuse).

## False Positive / Benign Positive Indicators
- Legitimate load test, chaos-engineering exercise, or internal vulnerability scan against the endpoint - check the approved testing calendar first.
- A new internal team or partner integration onboarded onto a shared key without notifying the SOC.
- Cost spike explained by a legitimate feature launch, marketing campaign, or seasonal demand.
- Geographic anomaly explained by a corporate VPN exit-node change or a remote employee traveling.

## Escalation Criteria
- Any confirmed remote code execution on infrastructure hosting the model - escalate immediately as a host-compromise incident, not just an AI-usage issue.
- Credential confirmed leaked/sold and reused elsewhere (other cloud services, other endpoints) - escalate to IAM/cloud security for org-wide credential audit.
- Sustained unauthorized invocation with material cost impact or generation of policy-violating content traceable to our infrastructure - escalate to legal/compliance and the cloud provider's abuse team.
- Evidence the endpoint was used as a relay/proxy for a third party's unrelated malicious traffic - escalate to threat intel for campaign tracking.

## Containment Options & Approval Authority
**[MANAGEMENT]**

| Action | Approval Authority |
|---|---|
| Rate-limit or temporarily block the offending source IP/ASN at the WAF/gateway | On-call security engineer, no prior approval needed |
| Revoke/rotate the abused API key or IAM credential | IAM/cloud platform team, expedited given active abuse |
| Take the self-hosted model-serving endpoint offline or restrict to internal-only ingress | Platform/infrastructure owner + security engineering sign-off |
| Isolate the compromised host from the network for forensic capture | IR lead, standard emergency-isolation authority |
| Engage cloud provider abuse/support team for provider-side blocking | AI platform owner or CISO delegate |
| Full endpoint decommission pending redesign | CISO or incident commander - confirmed campaign-level abuse or repeat compromise |

## Example Query (Splunk SPL)
```spl
index=ai_gateway sourcetype=inference_access
| bin _time span=5m
| stats count AS requests, sum(tokens_returned) AS tokens,
        values(model_id) AS models, values(src_ip) AS src_ips
        BY client_id, _time
| where requests > 500 OR mvcount(src_ips) > 5
| sort - requests
```

## Closure Criteria
Invocation logs, credential provenance, and (where applicable) host EDR telemetry fully reviewed; abused credential rotated or confirmed authorized; cost/usage anomaly explained and closed with FinOps; any host-level compromise remediated and re-imaged if warranted; provider abuse case opened/closed as needed; disposition set to True Positive, Benign Positive, Expected Activity, or Insufficient Evidence with rationale recorded.

**Example case note:** "2026-09-15 09:47 UTC - API key `svc-inference-prod-04` showed a 40x request-volume spike over 30 minutes, sourced from an AWS ASN we've never seen call this key, invoking a model ID outside the application's documented use case. Cost anomaly of ~$1,900 confirmed in billing console for the same window. Key traced to a service account whose credential was embedded in a public GitHub repo by a contractor eight days prior. Key revoked and rotated, gateway rule added to block the source ASN, contractor's repo access reviewed. Disposition: True Positive (credential compromise, LLMjacking pattern); no host-level compromise found. IAM audit ticket IAM-3391 opened for org-wide secret-scanning coverage gap."
