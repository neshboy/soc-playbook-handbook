# Indirect Prompt Injection

## Playbook ID & Name
**AI-002 — Indirect Prompt Injection: Untrusted Content Hijacking an AI Agent/Copilot**

## Business Risk
**[STAKEHOLDER]** - Any AI assistant that reads external content (a web page, PDF, email, ticket, or search result) to help staff can be silently redirected by hidden instructions embedded in that content. Because the assistant runs with its own service identity and tool permissions - mailbox access, file search, web browsing, ticketing - a successful injection can exfiltrate data or take unauthorized actions using a trusted account nobody thinks to watch. The business impact mirrors an insider-threat or compromised-service-account event, except the "insider" is an automated agent that did exactly what a document told it to do.

## Severity/Priority Default
**High (P2)** by default. Escalate to **Critical (P1)** if the agent holds mailbox-send, financial-system write, or production code-execution permissions, or if confirmed data left the tenant.

## MITRE ATT&CK Technique(s)
There is no dedicated ATT&CK ID for prompt injection itself (MITRE tracks that separately under ATLAS); this playbook maps the observed *downstream behavior* of a hijacked agent to the closest supplied enterprise techniques:

- **T1566.001/.002** Phishing (Attachment/Link) - common delivery vector for the poisoned content
- **T1114.003** Email Collection: Email Forwarding Rule - agent creates a forwarding rule under attacker instruction
- **T1098.002** Account Manipulation: Additional Email Delegate Permissions - agent grants mailbox delegate access
- **T1552.001** Unsecured Credentials: Credentials In Files - agent is directed to surface secrets from a file share/knowledge base
- **T1530** Data from Cloud Storage - agent pulls files from SharePoint/cloud storage beyond the user's original ask
- **T1119** Automated Collection - agent enumerates/collects records at machine speed on attacker instruction
- **T1567** Exfiltration Over Web Service / **T1048** Exfiltration Over Alternative Protocol - agent's tool call posts data to an external endpoint
- **T1098.001** Additional Cloud Credentials - follow-on persistence if the agent's service principal is used to add credentials

## Trigger / Detection Logic Summary
**[ENGINEERING]** Alert fires on the correlation of two events within a short window on the same agent session: (1) ingestion of untrusted/external content (web fetch, attachment parse, inbound email processed by the agent), and (2) a sensitive tool-call or action by that same session - mailbox rule creation, external send, bulk file retrieval, or an outbound call to a domain the tenant has never seen. Secondary trigger: the agent's own request/response log (prompt or retrieved-context field) contains injection markers - "ignore previous instructions," "system:", "you are now," hidden HTML comments, zero-width/white-on-white text, or base64 blobs immediately preceding a tool invocation that wasn't part of the user's stated intent.

## Required Log Sources & Event IDs
No standard Windows/Sysmon Event IDs apply here - telemetry is application and cloud-audit layer:

| Source | What to pull |
|---|---|
| LLM/agent gateway logs (Azure OpenAI diagnostic logs, agent framework trace, custom app log) | Prompt, retrieved RAG context, tool-call name/params/response, completion text |
| Microsoft Purview Audit (Unified Audit Log) | `CopilotInteraction` records, `New-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission` |
| Exchange Online message trace | Forwarding/send events tied to the agent mailbox |
| Entra ID / Azure AD audit log | App consent grants, service-principal permission changes |
| SharePoint/OneDrive audit log | `FileAccessed`, `FileDownloaded` by the agent identity |
| Proxy / egress firewall logs | Destination domain, first-seen indicator, bytes out |

## Key Fields to Inspect
**[ANALYST]**
- `session_id`/`conversation_id`, agent or plugin identity (app ID/service principal)
- Source URL or document hash of the ingested content
- `retrieved_context` snippet - does it contain directive language?
- `tool_name`, `tool_parameters`, `tool_response`
- Time delta between content ingestion and the suspicious action (seconds-to-minutes is the classic signature; hours-later actions are usually unrelated)
- Destination domain/IP for any outbound call, recipient list on any email action
- Forwarding rule conditions and forward-to address
- Volume of data read/transferred vs. the user's original request scope

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Agent summarizes a fetched webpage/document, no new tool calls beyond what the user asked | Agent fetches content, then immediately calls mailbox/file/webhook tools not requested by the user |
| Retrieved context is prose relevant to the task | Retrieved context contains imperative instructions addressed to "the assistant"/"AI" |
| Forwarding rules created by known helpdesk workflows with ticket reference | Forwarding rule created by the agent identity with no matching ticket, forwarding to an external domain |
| File retrieval matches the scope of the user's question | Bulk retrieval of files/records unrelated to the stated task, right after reading an external doc |

## Investigation Steps
1. Pull the full session transcript for the agent: original user prompt, every retrieved-context chunk, every tool call and response.
2. Isolate the specific content chunk (webpage/attachment/email body) that immediately precedes the suspicious tool call; extract and preserve it as evidence - do not re-render it in a live browser/agent.
3. Confirm whether the tool call executed successfully (rule created, mail sent, file downloaded, webhook reached) or was blocked by an existing guardrail/allow-list.
4. Check the destination (domain, recipient, mailbox rule target) against threat intel and internal allow-lists; flag first-seen external domains.
5. Determine what data was in scope of the action - specific files, mailbox content, records - and whether it left the tenant boundary.
6. Check Entra ID/app-consent logs for any permission or credential changes on the agent's service principal in the same timeframe (possible persistence, T1098.001).
7. Identify the ingestion path: who/what caused the agent to process this content (user-initiated fetch, scheduled crawl, inbound email triage) - this determines whether other users/sessions were exposed to the same payload.
8. If forwarding rule, delegate permission, or external send occurred, remediate immediately (Containment) before continuing root-cause analysis.

## True Positive Indicators
- Retrieved content contains directive language explicitly targeting an AI/assistant.
- Tool call executed was outside the user's stated request and followed content ingestion within seconds/minutes.
- Destination domain/mailbox is external, unfamiliar, and unrelated to the business task.
- Same payload found in content processed by other agent sessions (campaign, not isolated fluke).

## False Positive / Benign Positive Indicators
- Document legitimately contains instructional text meant for a *human* reader (style guide, template) that superficially resembles a directive but the agent didn't act on it.
- Tool call was within normal scope of a legitimate workflow (e.g., an approved auto-forwarding integration).
- Retrieved chunk flagged by keyword heuristics ("ignore," "system") but is ordinary prose, no anomalous action followed.
- Time delta between ingestion and action is long/unrelated to the flagged content (agent acted on a different, later instruction).

## Escalation Criteria
Escalate to IR lead and AI platform owner if: data confirmed to leave the tenant; the agent's service principal permissions were altered; the same payload appears across multiple sessions/users (campaign); or the agent has write/send/financial permissions and any unauthorized action executed successfully.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **SOC-authorized immediately (IR runbook standing authority):** remove any unauthorized mailbox rule/delegate grant; quarantine the malicious source document/URL; block the destination domain at proxy/firewall.
- **Requires AI platform owner sign-off:** disabling the agent's plugin/tool-use capability tenant-wide, or revoking/rotating the agent's service-principal credentials, since this affects all users of that assistant.
- **Requires data owner + Legal/Privacy notification:** confirmed exfiltration of PII/regulated data, per breach-notification policy.
- **Change Advisory Board:** any permanent change to the agent's system prompt, allow-listed domains, or tool permission scope as a hardening measure.

## Example Query (Microsoft Sentinel - KQL)
```kql
AppTraceLogs
| where AppName == "MeridianCopilot"
| where Message has_any ("ignore previous", "system:", "you are now")
| project TimeGenerated, SessionId, IngestedSource, RetrievedContent
| join kind=inner (
    AppToolCallLogs
    | where ToolName in ("SendMail","CreateInboxRule","WebhookPost","FileBulkDownload")
) on SessionId
| where (ToolCallTime - TimeGenerated) between (0s .. 5m)
| project TimeGenerated, SessionId, IngestedSource, ToolName, Destination
```

## Closure Criteria
Close when the ingested payload is confirmed benign/malicious, any executed action is reversed or confirmed within scope, destination indicators are actioned (blocked/allow-listed), and, for confirmed positives, the source content and agent-permission scope have been reviewed with the AI platform owner.

**Example case-note line:** *"Confirmed indirect prompt injection via vendor invoice PDF ingested by MeridianCopilot at 14:02 UTC; agent created inbox forwarding rule to attacker-relay.example.net at 14:03 UTC; rule removed, domain blocked, service-principal token rotated; no evidence of prior successful exfil in mail trace - closed as True Positive, contained."*
