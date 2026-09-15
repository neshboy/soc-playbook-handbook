# Category 18: AI Security

## What Ties These Alerts Together

Every playbook in this category is really about the same underlying fact: your organization now has a class of "users" that talk to sensitive systems in natural language, act on the results without a human clicking confirm every time, and produce logs that most SOCs have never had to read before. Whether the trigger is a jailbreak attempt, a poisoned document in a RAG index, or an agent that just deleted files it wasn't supposed to touch, the common thread is a boundary problem: input (a prompt, a document, a tool response) and instruction (what the model is told to do) collapse into the same channel. Classic security controls assume you can separate "data" from "code." Large language models don't respect that assumption, and neither do the agents built on top of them.

A second thing these alerts share: severity is rarely obvious from the alert alone. A single flagged prompt might be a curious employee, a red-team exercise nobody told you about, or the opening move of a genuine exfiltration attempt. You will spend a lot of time in this category on triage that ends in **Benign Positive** or **Expected Activity** - and that's fine. The job is to be able to tell the difference quickly, and to know which handful of cases actually warrant escalation.

Third: this is a young detection surface. Unlike Windows auth or endpoint telemetry, there isn't 15 years of community tuning behind these signatures. Expect noisier baselines, expect vendor detections to change under you as providers ship new safety classifiers, and expect this category to get rewritten more often than most others in this handbook.

## Log Sources and Tooling That Matter Here

**[ENGINEERING]** - Detection coverage for this category depends on stitching together sources that usually live in different teams' hands:

| Source | What it gives you |
|---|---|
| LLM gateway / API proxy logs (e.g., internal gateway in front of OpenAI, Anthropic, Azure OpenAI, Bedrock) | Prompt/response pairs, token counts, model name, calling user/service, latency, truncation/refusal flags |
| Cloud provider AI service logs (Azure OpenAI diagnostic logs, AWS Bedrock invocation logging, GCP Vertex AI request logs) | Per-call metadata, IAM principal, region, content-filter verdicts |
| Identity provider (Entra ID, Okta) sign-in and app-consent logs | Account takeover indicators, OAuth grants to AI tools/plugins, anomalous sign-in geography |
| CASB / SSE / SWG (e.g., Netskope, Zscaler) | Shadow-AI discovery - unsanctioned ChatGPT/Gemini/Claude web use, file uploads to consumer AI tools |
| DLP tooling (endpoint and network) | Sensitive-data patterns (PII, source code, credentials) in outbound prompt bodies |
| Agent/orchestration framework logs (LangChain, Semantic Kernel, custom agent runtimes, MCP server logs) | Tool-call sequences, function arguments, which tool an agent invoked and with what parameters |
| RAG/vector store audit logs (Pinecone, Weaviate, Azure AI Search, internal embedding pipelines) | Document ingestion events, embedding source, retrieval hit logs |
| EDR/endpoint logs on developer and analyst workstations | Coding-agent file writes, command execution spawned by an AI assistant, browser-agent driven activity |
| Application/API WAF logs on model endpoints | Query volume, request shape, scraping patterns against exposed inference endpoints |
| SaaS AI admin consoles (Copilot, Glean, internal chatbot admin panels) | Usage-per-user, blocked-prompt counters, plugin/connector inventories |

If your org has no LLM gateway and everyone is hitting provider APIs directly with personal keys, say so in your findings - that's a visibility gap, not a clean bill of health. A lot of this category's maturity work is really "get the logging in place" before "tune the detection."

## Friction You Will Actually Hit

Prompt and response bodies are frequently truncated, redacted, or simply not retained by default - many gateway and provider logs cap at a few hundred tokens or store only metadata unless verbose logging is explicitly enabled, so the "smoking gun" text you want for evidence may not exist by the time you go looking. Attribution is messier than it looks: shared service accounts, API keys embedded in CI pipelines, and multi-tenant SaaS chatbots mean the "user" field in a log line often maps to an application, not a person, and you'll burn time chasing the wrong owner. Agent frameworks add another layer - a single user-visible action can trigger a chain of tool calls across multiple systems, each logged separately with its own timestamp and no shared correlation ID unless someone built one in. And because model behavior and safety filtering change on provider updates outside your control, a detection that was reliable last month can go silent or start flooding you with false positives with zero change on your end - always check the model/provider changelog before assuming your rule broke.

## Playbooks In This Category

| # | Playbook |
|---|---|
| 1 | Prompt Injection |
| 2 | Indirect Prompt Injection |
| 3 | LLM Data Leakage |
| 4 | Sensitive Information Submitted to a Public/Unsanctioned AI Tool |
| 5 | AI API Key Compromise |
| 6 | AI Account Takeover |
| 7 | AI Agent Performing an Unauthorised Action |
| 8 | Agent Tool Abuse |
| 9 | RAG Poisoning |
| 10 | Knowledge Base Poisoning |
| 11 | System Prompt Extraction / Prompt Leakage |
| 12 | Jailbreak Behaviour |
| 13 | AI-Generated Phishing Content Detected |
| 14 | AI-Assisted Malware Development Indicators |
| 15 | Model Endpoint Abuse |
| 16 | Unusual Token Consumption |
| 17 | Automated API Scraping / Excessive Model Queries |
| 18 | Data Exfiltration Attempted Through Prompts |
| 19 | AI-Generated Command Execution via an Agent |
| 20 | Model-Connected Tool Misuse |
| 21 | MCP Server Abuse |
| 22 | AI Browser-Agent Abuse |
| 23 | AI Coding-Agent Modifying Sensitive Files Unexpectedly |
| 24 | Agent Privilege Abuse |
