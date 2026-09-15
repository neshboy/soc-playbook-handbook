# AI-003 — LLM Data Leakage

**Category:** AI Security
**Sub-type:** Sensitive data disclosure via prompt input, model output, or LLM-application logic (SaaS chat tools, enterprise Copilot/Assistant deployments, and internal RAG applications)

## Business Risk

**[STAKEHOLDER]** - Staff and applications routinely send data into large language models to get work done faster; the risk isn't the model "stealing" anything, it's that source code, customer PII, M&A terms, or credentials pasted into a prompt (or pulled into a prompt by a retrieval pipeline) can end up stored, logged, or surfaced to the wrong person, and once it's left the tenant boundary you can't recall it - the decision on tool approval and data-retention terms sits with Legal, Procurement, and the data owner, not with IT alone.

## Severity / Priority Default

**Medium** by default (unsanctioned tool use, unconfirmed sensitivity). Escalate to **High** if DLP confirms regulated data categories (PCI, PHI, PII at volume) or live credentials/API keys were transmitted, or if a RAG application served one tenant's/customer's documents to another tenant's session.

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1567 Exfiltration Over Web Service | Sensitive data pasted or uploaded into a public LLM chat UI (chat.openai.com, gemini.google.com, claude.ai) - functionally identical to exfil to any other SaaS web service |
| T1048 Exfiltration Over Alternative Protocol | Data sent directly to a model provider's API endpoint (api.openai.com, api.anthropic.com) via script or plugin, bypassing the corporate web proxy/CASB inspection path |
| T1552.001 Unsecured Credentials in Files | API keys, connection strings, or hardcoded passwords pasted into a prompt for "debug this code" style requests |
| T1530 Data from Cloud Storage | RAG/knowledge-base pipeline retrieves documents from cloud storage (SharePoint, S3, blob) without honoring source-document ACLs, then surfaces them in a chatbot answer to an unauthorized user |
| T1119 Automated Collection | Bulk/scripted scraping of internal wikis, ticket systems, or repos to build embeddings/context for an LLM app, sweeping up data the requester was never scoped to hold in aggregate |

## Trigger / Detection Logic Summary

Two distinct detection paths feed this playbook - triage them separately, they rarely overlap:

1. **User-driven leakage (SaaS LLM tools):** Secure Web Gateway/CASB flags a POST to a generative-AI domain category with an unusually large upload/paste body, a file attachment, or a DLP content match (source code fingerprint, PII pattern, secret pattern) in the request payload.
2. **Application-driven leakage (internal LLM/RAG deployment):** The LLM application's own gateway or audit log shows a response containing document IDs, chunks, or citations that fall outside the requesting user's entitlement group, or shows a service account/API key making retrieval calls against a document store it isn't scoped for, or logs show full prompt/completion text (including sensitive fields) being written to a log sink with broader read access than the source data itself.

## Required Log Sources & Fields

- **Secure Web Gateway / Proxy** (Zscaler, Netskope, Palo Alto, Forcepoint) - destination domain/category = "AI/Generative AI" or "Uncategorized AI", HTTP method, bytes sent, MIME type of upload, user/device.
- **CASB** (Microsoft Defender for Cloud Apps, Netskope) - app instance, activity = "Upload"/"Message posted", DLP policy match, browser session risk score.
- **DLP (endpoint + network)** - policy name triggered, matched content classifier (credit card, national ID, source-code regex, API-key regex), action taken (block/alert/allow-with-justification), user justification text if the tool allows override.
- **Identity provider logs** (Entra ID sign-in/audit, Okta) - service principal or app registration consent grants for AI plugins/connectors, especially OAuth scopes touching Mail, Files, or Sites.
- **Internal LLM app gateway / API management logs** (Azure API Management, Bedrock invocation logs, internal reverse proxy) - caller identity, model/deployment name, prompt token count, completion token count, retrieved-document IDs, latency/size outliers.
- **RAG orchestration/application logs** - retrieval query, returned chunk source path, ACL check result (allow/deny/bypass), tenant or workspace ID on both the requester and the retrieved document.
- **Cloud audit trail** (CloudTrail, Azure Activity Log) for API keys tied to the LLM service - unusual source IP, new key creation, key used from a region/ASN never seen before.

## Key Fields to Inspect [ANALYST]

| Field | Why it matters |
|---|---|
| `dest_domain` / `app_name` | Confirms this is a genuinely unsanctioned or unapproved AI endpoint, not an approved enterprise Copilot tenant |
| `http_method` + `bytes_out` | Large POST bodies on a chat domain almost always mean paste-in or file upload, not casual browsing |
| `dlp_policy_name` / `classifier_hit` | Tells you *what kind* of data tripped the alert - source code vs. PII vs. secrets each route differently |
| `user_justification` | Many DLP tools let the user click through with a typed reason - read it, it's often an honest admission ("just formatting this JSON") |
| `caller_identity` (internal app logs) | Human user vs. service account vs. shared API key - shared/service keys need owner identification before you can even open a ticket with the right person |
| `retrieved_doc_id` vs `requester_entitlement` | The core signal for RAG cross-boundary leakage - a mismatch here is the whole incident |
| `prompt_token_count` / `response_size` | Sudden spikes suggest bulk extraction ("summarize all customer records") rather than a normal single-question interaction |
| `oauth_scope` on AI plugin consent | Scopes like `Mail.Read`, `Files.Read.All` granted to a third-party AI plugin quietly turn "chatting with an LLM" into "an app reading your whole mailbox" |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Employee uses company-approved Copilot/enterprise ChatGPT tenant with data-retention opt-out contractually in place | Employee uses personal/consumer account on the same domain, or a completely unapproved AI tool |
| Small prompt bodies (a few KB), text only, occasional short code snippet | Multi-MB uploads, attached spreadsheets/CSVs/PDFs, or paste events matching a DLP PII/secrets classifier |
| RAG app returns chunks that all trace back to documents the requesting user's group already has read access to | RAG app returns a chunk sourced from a folder/workspace tagged to a different customer, business unit, or classification tier |
| Internal API key used consistently from known corporate egress IPs during business hours | Same API key suddenly called from an unfamiliar cloud ASN or after being rotated/exposed elsewhere |
| Prompt/completion logging redacted or hashed for regulated fields per data-handling policy | Full unredacted PII/PHI persisted in plaintext logs readable by a broad support/engineering group |

## Investigation Steps

1. Identify which detection path triggered - proxy/CASB/DLP (user-driven) or LLM app/RAG gateway (application-driven) - the evidence trail and containment owner differ sharply.
2. For user-driven cases: pull the actual DLP match context (not just the alert) to confirm the classifier fired on real sensitive content and wasn't a benign lookalike (test data, lorem-ipsum SSNs, sample code with placeholder keys).
3. Identify the destination: is it a company-contracted enterprise AI tenant with a signed data-processing agreement and no-training clause, or a consumer-tier/free account with no such protections? This single fact changes the entire severity calculation.
4. For application-driven cases: trace the retrieval query and returned document IDs against the requesting user's actual entitlement group in the source system (SharePoint/S3/Confluence ACL, not the app's own cache) - confirm whether this is a genuine ACL bypass in the RAG pipeline or a stale/misconfigured permission sync.
5. Check whether an AI browser plugin or connector was granted OAuth scopes beyond what the use case needs, and whether that consent was approved through the normal app-governance process or self-granted by the user.
6. Interview the user (or the app owner for a service account) - get a plain description of what they were trying to do; most of these are workflow shortcuts, not malicious exfiltration, but the data still left the boundary and that has to be documented regardless of intent.
7. Determine data volume and sensitivity class actually exposed (single record vs. bulk export; public vs. confidential vs. regulated) - this drives whether Legal/Privacy needs to be looped in for breach-notification assessment.
8. Check the destination provider's data-retention and training-use terms (or confirm via architecture/data-flow diagrams already on file) to establish whether the data is recoverable/deletable or effectively permanent once ingested.

## True Positive Indicators

- DLP/CASB confirms real regulated data (PII, PHI, PCI) or live secrets in the transmitted content, sent to a consumer-tier AI tool with no enterprise agreement.
- RAG application confirmed to have returned another tenant's, customer's, or business unit's restricted documents to a user without matching entitlement.
- Bulk/scripted extraction pattern (abnormally large token counts, repeated near-identical retrieval queries, off-hours automation) pointed at an internal knowledge base via an LLM interface.
- Shared or service-account API key used from an unrecognized network location shortly after being used normally from a corporate egress IP.
- AI plugin/connector granted broad mailbox or file-store OAuth scope without a documented business approval.

## False Positive / Benign Positive Indicators

- Content matches a DLP PII/secret pattern but is synthetic test data, documentation examples, or already-public information (marketing copy, published API docs).
- Upload/paste went to the company's own contracted enterprise AI tenant with a valid no-training / no-retention clause already on file with Legal.
- RAG "cross-boundary" hit turns out to be a shared, intentionally-public internal resource (style guide, glossary) that was over-classified rather than a genuine ACL failure.
- Large token count traced to a legitimate batch/automation job already registered with the AI governance board.
- User justification and manager confirmation both check out as routine work, and the destination tool is on the approved list.

## Escalation Criteria

- Escalate to **Privacy/Legal** whenever DLP confirms regulated personal data left the environment to a non-contracted destination - this may trigger breach-notification analysis regardless of whether it was accidental.
- Escalate to **AI Governance/Data Owner** for any confirmed RAG ACL bypass - this is a design defect, not a one-off user error, and needs a fix ticket in addition to the incident.
- Escalate to **IR/Security Engineering** if live production credentials or API keys were exposed in a prompt - treat as a credential-compromise event and rotate immediately (see credential-exposure playbook for rotation steps).
- Escalate to **executive/Board-notification track** only if volume and sensitivity meet the org's defined material-incident threshold (check with Legal/Compliance for the current numeric/regulatory trigger).

## Containment Options & Approval Authority [MANAGEMENT]

| Action | Approval Authority | Notes |
|---|---|---|
| Block destination domain/category at proxy/CASB | SOC Lead (standing authority for unapproved AI tools) | Fast, low-risk; doesn't undo data already sent |
| Disable/rotate exposed API key or credential | Security Engineering on-call | Immediate if live secret confirmed in a prompt |
| Suspend AI plugin OAuth consent | IAM/App Governance owner | Requires confirming no dependent legitimate workflow breaks |
| Disable RAG retrieval path or take app offline | Application Owner + CISO sign-off | Business-impacting; needs downtime approval given user reliance on the tool |
| Contact AI vendor for data deletion/opt-out enforcement | Legal/Privacy, via existing vendor contract clause | Deletion is contractual, not guaranteed technically instant |
| User acceptable-use coaching / policy reminder | Line manager + Security Awareness | Standard path for a one-off, non-malicious, low-sensitivity case |

## Example Query (Microsoft Sentinel / KQL)

```kql
CloudAppEvents
| where ActionType in ("FileUploaded","MessagePosted")
| where Application in ("ChatGPT","Google Gemini","Claude","Generic AI Service")
| extend Bytes = tolong(RawEventData.FileSize)
| where Bytes > 500000 or isnotempty(RawEventData.DlpMatch)
| project Timestamp, AccountDisplayName, Application, ActionType, Bytes, IPAddress
| order by Timestamp desc
```

## Closure Criteria

Close when: destination and data category are confirmed and classified (True Positive, Benign Positive, or False Positive), any exposed credentials are rotated, any confirmed RAG ACL defect has a tracked engineering fix ticket, and Legal/Privacy has signed off if regulated data volume met their review threshold. Insufficient Evidence closures are valid when proxy/DLP logs expired before triage (log retention gaps are common on high-EPS proxy stacks) or when the actual pasted content can't be reconstructed from metadata alone.

**Example case-note line:**
`2026-09-15 14:22 UTC - CASB alert on j.alvarez@example.com uploading a 2.1MB CSV to chat.openai.com (consumer tier) from host MER-FIN-WKS0231 (10.44.12.7); DLP classifier matched "PII-SSN-bulk". User confirmed via interview it was a customer export for "formatting help," an accidental rather than malicious paste; file contained 340 live customer SSNs regardless of intent. Classified True Positive. Domain blocked at proxy, user coached, Privacy notified for breach-threshold review per data volume; RAG systems not involved.`
