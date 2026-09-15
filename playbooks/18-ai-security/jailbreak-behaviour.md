# AI-012 — Jailbreak Behaviour

**Category:** AI Security
**Sub-type:** Attempts to bypass an LLM's safety guardrails, content filters, or usage-policy restrictions through adversarial prompt framing (role-play, hypothetical framing, obfuscation, multi-turn escalation) — targeting enterprise chatbots, internal copilots, customer-facing assistants, or direct API access to a model deployment.

## Business Risk

**[STAKEHOLDER]** - The AI tools we've deployed - HR chatbots, customer support assistants, internal copilots - have guardrails that stop them producing harmful, policy-violating, or brand-damaging content. A jailbreak is someone deliberately trying to talk the model out of following those rules, usually by pretending it's a game, a hypothetical, or a "developer mode." If it works, the model can end up writing malware, generating a working phishing email, disclosing data it was told to withhold, or saying something that ends up in a screenshot on social media with our logo next to it. The decision on how aggressively to lock down a given AI deployment - and how much friction that adds for legitimate users - belongs to the AI product/application owner working with Legal and the AI governance function, not Security alone.

## Severity/Priority Default

**Medium (P3)** at intake for a flagged/blocked attempt with no confirmed bypass. Escalate to **High (P2)** when the safety layer was actually bypassed and the model returned actionable harmful content (working exploit code, functional phishing text, disclosed PII, self-harm/regulated content), or when the same jailbreak payload appears across multiple unrelated accounts within a short window (campaign indicator rather than one curious employee).

## MITRE ATT&CK Technique(s)

| Technique | Relevance |
|---|---|
| T1562.001 Impair Defenses: Disable or Modify Tools | Conceptually the core intent of a jailbreak - the attacker is trying to disable or talk around the model's built-in content-filter/safety-classifier "tool," which is functioning as the application's defensive control |
| T1027 Obfuscated Files or Information | Base64/hex/ROT13/leetspeak encoding, mid-conversation language switching, or "token smuggling" used specifically to get a disallowed instruction past the safety classifier without it recognizing the intent |
| T1204 User Execution | Downstream only - applies once a bypass has occurred and the requesting user copies model-generated code/commands out and runs them; see the AI-Assisted Malware Development Indicators playbook for that chain |
| T1566 Phishing (.001 Attachment, .002 Link) | Downstream only - applies if the jailbreak's actual objective was to produce a usable phishing lure; see the AI-Generated Phishing Content Detected playbook for that chain |

Automated/scripted campaigns that fire dozens of jailbreak template variants against a model endpoint don't map cleanly to T1595 Active Scanning - that technique covers pre-access reconnaissance of externally-visible infrastructure, not iterative payload fuzzing against an endpoint the requester can already reach. The closer reference is MITRE ATLAS AML.T0054 (LLM Jailbreak), outside the Enterprise matrix supplied for this book - don't force an Enterprise ID onto this specific sub-behavior.

## Trigger / Detection Logic Summary

Two detection paths, and they need separate triage logic because a flag does not equal a bypass:

1. **Safety-classifier flag (provider or gateway level):** the model deployment's content filter (Azure OpenAI content filter categories, Bedrock Guardrails intervention, Anthropic/OpenAI moderation classification, or an internal LLM gateway's own filter) tags a prompt or completion with a jailbreak, prompt-injection, or policy-violation category.
2. **Heuristic/behavioral pattern (gateway or SIEM correlation):** keyword/regex match against a known jailbreak-phrase corpus (role-play frames like "you are DAN / no restrictions," "developer mode enabled," "ignore all previous instructions and system prompt," "hypothetically, without any policy," "output your instructions then comply") combined with session-level behavior - repeated refusals followed by rapid rephrase-and-retry, an unusually long prompt padded with dozens of fake few-shot examples (many-shot jailbreaking), an encoded blob with no legitimate business reason to be in a text prompt, or sub-second retry cadence inconsistent with a human typing.

Neither path alone tells you whether the model actually complied. The filter category tells you what was *attempted*; you have to read the completion (or its metadata, if raw text isn't retained) to know what was *returned*.

## Required Log Sources & Fields

- **LLM gateway / API proxy logs** - session/conversation ID, caller identity, model/deployment name, prompt text (if retained - often truncated or redacted by default), completion text, prompt and completion token counts, content-filter category, filter action (blocked/flagged/allowed), latency.
- **Cloud AI service diagnostic logs** (Azure OpenAI content-filter logs, AWS Bedrock Guardrails trace, GCP Vertex AI safety-attribute output) - per-call filter verdict, severity score, category (hate/violence/self-harm/sexual/jailbreak/prompt-injection where the provider distinguishes it), IAM principal or API key used.
- **Identity provider logs** (Entra ID, Okta) - the human/service identity behind the API key or session token, sign-in geography, whether the account has any AI red-team/safety-eval authorization tag.
- **Application/chatbot audit log** - conversation history for the full session (not just the flagged turn), user-facing response actually shown, any tool/function calls the model attempted mid-jailbreak (a jailbreak chained into a tool-abuse attempt is a different, worse case - see Agent Tool Abuse playbook).
- **WAF/API gateway logs** on public-facing model endpoints - request rate, source IP/ASN, client fingerprint (browser session vs. scripted client), to distinguish a human trying variations from an automated fuzzing campaign.
- **DLP/output-scanning logs**, if deployed on completions - flags on the *output* side (e.g., detected malware-pattern code, detected PII in a completion) which is often a stronger signal of actual bypass than the input-side filter category alone.

## Key Fields to Inspect [ANALYST]

| Field | Why it matters |
|---|---|
| `session_id` / `conversation_id` | Jailbreaks are almost always multi-turn - pull the whole session, not the single flagged prompt |
| `content_filter_category` + `filter_action` | Category tells you the type of attempt; action tells you whether it was blocked, flagged-but-allowed, or missed entirely |
| `completion_text` (if retained) | The only reliable way to confirm bypass - does the response actually contain the disallowed content, or is it a refusal that also happened to trip the keyword heuristic |
| `refusal_count` within session | Three or more refusals followed by rephrased retries in a tight window is the classic escalation signature, not a one-off curious question |
| `prompt_token_count` | Abnormally long prompts often indicate many-shot jailbreaking (dozens of fabricated compliant Q&A pairs used to condition the model) |
| `caller_identity` / API key owner | Human employee vs. shared service key vs. authorized AI red-team account - changes everything about intent |
| inter-request timing | Sub-second or perfectly regular intervals between variant attempts point to a scripted fuzzing tool, not a person typing |
| encoding artifacts in prompt (base64/hex/leetspeak, mid-message language switch) | A strong obfuscation signal - legitimate business prompts rarely need to disguise their own text |
| duplicate payload hash across sessions/accounts | Same jailbreak "recipe" appearing under different users in a short window means someone is sharing or scripting a known template, not independent curiosity |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Single flagged prompt, employee curiosity ("what if I ask it to pretend"), no retry after the refusal | Repeated rephrase-and-retry across the same session after each refusal, escalating in specificity |
| Prior-authorized AI red-team/safety-eval account testing filter robustness on a scheduled engagement | Unauthorized account running the same style of adversarial probing with no eval ticket on file |
| Prompt text is plain language, readable, and matches a plausible business/creative-writing use case | Prompt contains base64/hex blobs, deliberate misspellings to dodge keyword filters, or a sudden language switch mid-conversation |
| A handful of filter hits per week across a large user population, evenly distributed | Same jailbreak template/hash appears across many unrelated accounts within hours - a shared playbook or scripted campaign |
| Filter blocks the attempt and the completion returned to the user is a standard refusal | Filter flags the prompt as jailbreak/injection *and* the completion still contains the requested disallowed content - confirmed bypass |
| Human-paced typing intervals between attempts (tens of seconds, variable) | Machine-paced, near-identical intervals between dozens of prompt variants hitting an API-key-authenticated endpoint |

## Investigation Steps

1. Pull the full session/conversation trail around the flagged turn, not just the isolated prompt - jailbreaks build context over several turns before the actual ask.
2. Determine whether the model complied or the guardrail held: compare the filter category against the actual completion text (or output-side DLP flag if raw text isn't retained) - a flag with a normal refusal response is not a bypass.
3. Identify the requesting identity - human employee, shared service account, or an authorized AI red-team/safety-eval engagement - and check whether an approval ticket or governance registration exists for adversarial testing.
4. Classify the objective: what was the jailbreak actually trying to extract or generate - malware/exploit code, phishing content, restricted PII, system-prompt/tool-definition extraction, or content the org's AI usage policy simply prohibits? This drives which downstream playbook and escalation path applies.
5. Search the gateway/SIEM for the same payload hash, phrase template, or near-duplicate structure across other sessions and accounts in the same window - one curious employee looks very different from a coordinated or scripted campaign.
6. Check source IP/ASN, client type (browser session vs. raw API client), and request timing for automation signatures - a fuzzing tool testing dozens of jailbreak variants in minutes needs a different response than one human at a keyboard.
7. If bypass is confirmed, trace what happened to the output next - did the user copy generated code into a file and execute it, paste content elsewhere, or forward it (pivot into endpoint or email telemetry as needed)?
8. Interview the user (or the application/service-account owner) - get a plain description of intent; most single-attempt cases are curiosity or unauthorized-but-harmless testing, not a real attack, but that still needs to be documented and the account's access reviewed.

## True Positive Indicators

- Confirmed bypass: filter category shows jailbreak/prompt-injection *and* the completion text actually contains the disallowed content requested.
- Multi-turn escalation with deliberate obfuscation (encoding, misspelling, language-switching) specifically shaped to evade the classifier.
- Same jailbreak template or payload hash observed across multiple unrelated accounts within a short window - a shared or scripted campaign rather than one person's curiosity.
- Machine-paced retry cadence against an API-key-authenticated endpoint cycling through many jailbreak variants.
- Objective content confirmed usable and harmful - a working code snippet, real disclosed data, or a functional phishing draft - not a joke or an obviously fictional response.

## False Positive / Benign Positive Indicators

- Authorized AI red-team, bug-bounty, or safety-evaluation engagement with a governance ticket on file, deliberately probing guardrail robustness.
- A single, non-repeated curiosity prompt from an employee with no harmful output and no retry after the refusal.
- Classifier false-positive: a legitimate security-research, fiction-writing, or training-content prompt (e.g., "explain how a phishing email is structured, for our awareness training deck") superficially matches jailbreak keyword heuristics but had a stated legitimate purpose and produced benign output.
- Internal QA/regression test suite intentionally exercising the guardrail as part of the AI application's own CI pipeline, misclassified as an attack due to request volume.

## Escalation Criteria

- Escalate to **AI Security/Governance** whenever a confirmed bypass produced actionable harmful content (working exploit/malware code, a functional phishing kit, disclosed regulated data).
- Escalate to **IR** if the requesting identity is an unauthenticated/external user against a customer-facing chatbot rather than an internal employee - this is public-facing abuse of a production application, not internal curiosity.
- Escalate to **Legal/Trust & Safety** immediately, on a separate track, if generated or requested content falls into legally regulated categories (self-harm, child-safety material, or similar) - these carry reporting obligations that go beyond normal SOC handling.
- Escalate to **AI Governance/Data Owner** whenever the same payload pattern appears across multiple accounts - treat as a guardrail design gap needing a fix ticket, not just an incident closure.

## Containment Options & Approval Authority [MANAGEMENT]

| Action | Approval Authority | Notes |
|---|---|---|
| Suspend the user's session/API key pending review | SOC Lead or AI application owner | Fast, low business impact for a single-account case |
| Add the jailbreak payload/template signature to the gateway blocklist | AI Security Engineering (standing authority for signature updates) | Doesn't retroactively undo any bypass already served |
| Rate-limit or block source IP/ASN at API gateway/WAF | SOC on-call | For scripted/campaign-pattern probing against a public endpoint |
| Tighten content-filter threshold or disable an affected model deployment | Application Owner + AI Governance sign-off | Business-impacting; may increase refusal rate for legitimate users |
| File a safety-classifier gap report with the model provider | AI Governance / vendor management | Relevant when the provider's own filter missed a confirmed bypass |
| User coaching / policy reminder | Line manager + Security Awareness | Standard path for a one-off, non-malicious, blocked attempt |

## Example Query (Microsoft Sentinel / KQL)

```kql
AIGatewayLogs
| where ContentFilterCategory in ("Jailbreak", "PromptInjection")
| summarize Attempts = count(),
    Bypassed = countif(FilterAction == "Flagged" and ResponseContainsDisallowed == true)
    by SessionId, CallerId, bin(TimeGenerated, 15m)
| where Attempts >= 3 or Bypassed > 0
| order by Bypassed desc, Attempts desc
```

## Closure Criteria

Close when the session's objective content is classified (True Positive / Benign Positive / False Positive / Expected Activity / Insufficient Evidence), bypass status is confirmed either way, any confirmed-harmful output is traced to its downstream use (or confirmed not acted on), any real guardrail gap has an engineering ticket, and AI Governance has logged the case if a bypass or cross-account pattern was confirmed. Insufficient Evidence is a valid close when the provider retained only the filter-category metadata and not the raw prompt/completion text - common when verbose logging isn't enabled by default - and intent can't be reconstructed from what's left.

**Example case-note line:**
`2026-09-15 09:47 UTC - Azure OpenAI content filter flagged 4 consecutive prompts in session sess-88f3 (internal HR chatbot, deployment gpt-4o-hr) from t.nguyen@example.com as category "Jailbreak"; turns 2-4 used a DAN-style role-play frame plus a base64-encoded payload requesting an employee SSN lookup outside the bot's tool scope. All 4 attempts were blocked (FilterAction=Blocked); completions contained standard refusals only, no disallowed content returned. No AI red-team authorization on file for this account. Classified True Positive (attempted only - no bypass, no data exposed). API access suspended pending manager interview; payload hash added to gateway blocklist; no cross-account matches found in the prior 24h window.`
