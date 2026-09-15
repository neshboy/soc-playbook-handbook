# Decision Matrix and Containment Paths — Malicious File Uploaded Into an AI System

## Why this section exists

Most SOC file-upload playbooks are written for the pre-LLM world: file lands, AV/sandbox scores it, you contain a host. An AI application breaks that model because the "victim" isn't just a filesystem — it's a reasoning agent with a context window, and possibly tool access, browsing, code execution, and API credentials of its own. The same malicious PDF can produce nine completely different blast radii depending on what the AI *did* with it after ingestion. Containment that assumes "file uploaded = endpoint compromise" either overreacts (isolating a chat session that only rendered text) or catastrophically underreacts (leaving an agent's live API session open after it already exfiltrated a customer record). The decision matrix below exists to force that branching decision at triage, before containment actions are chosen, not after.

The governing question for every case: **what is the last confirmed action the AI system took**, not what the file was capable of. Capability drives severity scoring; confirmed action drives containment path.

## Decision matrix

| # | Confirmed outcome (from session/tool logs) | Evidence to confirm | Primary risk | ATT&CK mapping | Containment path |
|---|---|---|---|---|---|
| 1 | File only parsed/rendered (text extraction, OCR, preview) | Ingestion log shows parser invocation, no tool-call events, no outbound request logged | Low — content sits in context window only | T1566.001 (delivery only) | **Path A** |
| 2 | AI followed embedded instructions (prompt injection acted on) | Model output/reasoning trace references instructions not present in the user's own prompt; system prompt override detected | Medium-High — integrity of agent behavior compromised | T1204 | **Path B** |
| 3 | AI accessed an external resource (URL fetch, image pull, DNS lookup) triggered by file content | Outbound HTTP/DNS log correlated to timestamp of file processing | Medium — beaconing/tracking, possible SSRF | T1071.004, T1105 | **Path C** |
| 4 | AI invoked a connected tool/plugin/function (retrieval, calculator, code sandbox, browser tool) | Tool-call log entry with parameters sourced from file content | Medium-High — depends on tool's blast radius | T1059.001/.003 (if tool = shell/interpreter) | **Path D** |
| 5 | AI revealed sensitive data in its response (secrets, PII, internal docs pulled into context) | Output transcript diff against DLP pattern match; RAG retrieval log | High — direct disclosure | T1552.001 | **Path E** |
| 6 | AI executed code (sandboxed interpreter, generated script that ran) | Code-execution sandbox log, stdout/stderr capture | High | T1059.001, T1027 (if obfuscated payload decoded first) | **Path F** |
| 7 | AI modified data (wrote to a document, database, ticket, repo, memory store) | Write-operation audit log on the downstream system, diff of before/after state | High — persistence/integrity | Data-destruction/impact-class technique (name only, no ID confirmed for this specific case) | **Path G** |
| 8 | AI sent a message on the user's/org's behalf (email, Slack, ticket comment, webhook) | Outbound message log, recipient list, content hash | Critical — reputational + potential further phishing pivot | T1567 (if content left the trust boundary) | **Path H** |
| 9 | AI performed an authenticated API call (CRM, cloud storage, ticketing, payment) using stored credentials/tokens | API gateway log, token/session ID used, endpoint called | Critical — credential and scope compromise | T1530, T1098.001 | **Path I** |

Multiple rows frequently apply in sequence — injection (row 2) is very often the trigger that leads to rows 3-9. Document the full chain, but contain at the highest-numbered confirmed row; lower-numbered containment is redundant once a higher-impact action is confirmed.

## Containment paths

**Path A — Parse only.** No agent/session action required. Quarantine the file in storage, hash it, submit to sandbox for out-of-band verification, close as **Benign Positive** or **Insufficient Evidence** if sandbox disagrees with the static verdict. No user/session lockout.

**Path B — Followed embedded instructions.** Freeze the session (do not let it continue producing output), snapshot the full context window and reasoning trace before any auto-purge/rotation policy overwrites it, and treat every subsequent row (C-I) as suspect until logs prove otherwise.

**Path C — Accessed external resource.** Block the destination domain/IP at the egress proxy, pull DNS/HTTP proxy logs for beaconing pattern (interval, repeated user-agent), and check whether the resource returned a second-stage payload — if so, escalate to Path F.

**Path D — Invoked a tool.** Identify the specific tool/plugin and its permission scope. If the tool has write/execute capability, suspend the tool's credentials or API key immediately, not just the chat session — the session can be closed while the token stays live.

**Path E — Revealed sensitive data.** Standard data-exposure containment: identify every party who saw the output (single user vs. shared workspace vs. logged to a third-party observability tool), and notify per data-classification policy.

**Path F — Executed code.** Isolate the sandbox/container instance (do not just kill the process — preserve the container image and filesystem diff for forensics), rotate any credentials the sandbox had environment access to, and check the sandbox's network egress logs for lateral reach beyond the intended isolation boundary.

**[STAKEHOLDER]** - a sandbox escape or unrestricted network egress from an AI code-execution feature is the scenario that turns a "chatbot incident" into a full breach; this is why sandbox network isolation is a design prerequisite, not a nice-to-have.

**Path G — Modified data.** Freeze the downstream system (repo, ticket queue, document store) from further automated writes, diff against last-known-good backup, and route through change-control before any rollback — a rollback executed mid-investigation can destroy evidence of what else changed.

**Path H — Sent a message.** Recall/delete where the platform supports it, notify recipients if recall isn't possible, and revoke the messaging integration's token. Treat every recipient as a potential secondary phishing target if the message contained a link or attachment the AI itself generated or forwarded.

**Path I — API call with stored credentials.** Highest-priority containment: revoke/rotate the credential or OAuth token at the identity provider immediately, pull the API gateway's full call history for that token (not just the flagged call — assume the session token was reused), and coordinate with the third-party service owner if the API belongs to an external SaaS platform.

**[MANAGEMENT]** - containment path selection (rows/paths above) should be logged as its own field in case documentation, separate from severity; two incidents with identical file hashes can require entirely different approval chains if one only parsed and the other called a payments API. Any Path F/G/H/I containment action requires sign-off per the standard high-impact containment approval matrix, not analyst-level authority alone.
