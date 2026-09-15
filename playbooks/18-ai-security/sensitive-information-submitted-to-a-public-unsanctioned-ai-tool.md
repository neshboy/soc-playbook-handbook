# Sensitive Information Submitted to a Public/Unsanctioned AI Tool

## Playbook ID & Name
**AI-004** — Sensitive Information Submitted to a Public/Unsanctioned AI Tool (Shadow AI / Generative AI Data Leakage)

## Business Risk
**[STAKEHOLDER]** - Employees pasting source code, customer records, contracts, or credentials into consumer-tier AI chatbots hands that data to a third party outside our contracts, retention terms, and jurisdiction — once it's in a prompt history you don't control, you can't un-send it, and depending on the tool's terms of service it may be used to train future models or be discoverable by that vendor's own staff.

## Severity/Priority Default
**Medium (P3)** at intake. Escalates to **High (P2)** when the matched content is regulated data (PII/PCI/PHI) at volume, live credentials, unreleased financial/M&A material, or confirmed source code with IP value.

## MITRE ATT&CK Technique(s)
- **T1567** Exfiltration Over Web Service — primary technique; the AI tool's chat/upload interface is the exfiltration channel.
- **T1048** Exfiltration Over Alternative Protocol — where content is pushed via the AI vendor's API/SDK rather than the browser UI, often bypassing browser-based DLP.
- **T1552.001** Unsecured Credentials in Files — common category of the actual content pasted (config snippets, `.env` files, connection strings).
- **T1530** Data from Cloud Storage — frequently the upstream source of the sensitive file the user copied from before pasting.
- **T1071** Application Layer Protocol — the underlying HTTPS traffic pattern used for correlation, not the intent itself.

## Trigger / Detection Logic Summary
Alert fires when outbound web traffic to a domain categorized as "Generative AI" / unsanctioned SaaS carries a DLP-classified payload: a POST/upload event, a browser paste event captured by an endpoint DLP agent, or a CASB inline/API event tagged with a sensitive-information-type match (PII pattern, PAN, secret/API-key regex, source-code fingerprint, or classification label like "Confidential" / "Internal Use Only"). Separately, CASB shadow-IT discovery reporting a spike in "Generative AI" category usage by a user or department, or a Data Protection API (Microsoft Purview, Google DLP) sensitivity-label match traveling toward a non-tenant AI endpoint, will also seed this playbook.

**[ENGINEERING]** - Build this as two correlated rules, not one: (1) a proxy/CASB rule on `url_category=Generative AI AND http_method=POST AND bytes_out > threshold`, and (2) a DLP-engine rule on policy match against that same destination category. Alerting only on category+POST without the DLP match drowns the queue in benign one-line prompts; alerting only on DLP match without destination context misses tools your proxy hasn't categorized yet (new AI startups get spun up weekly).

## Required Log Sources & Event IDs
No Windows/Sysmon Event IDs are relevant as primary telemetry for this scenario — detection lives in web/cloud control-plane logs, not host event logs:

| Source | What to pull |
|---|---|
| Secure Web Gateway / Proxy (Zscaler, Netskope, Palo Alto Prisma) | URL category, domain, HTTP method, bytes uploaded, TLS inspection status |
| CASB (Netskope, Microsoft Defender for Cloud Apps) | Cloud app instance, activity type (login/upload/post), account type (personal vs. managed) |
| DLP engine (Microsoft Purview DLP, Symantec/Broadcom DLP, Forcepoint) | Policy name, sensitive info type, match count, action (audit/warn/block/override) |
| Endpoint DLP / browser extension | Clipboard-to-browser paste event, file-upload-via-browser event |
| Identity provider (Entra ID, Okta) | OAuth consent grants to third-party AI plugins against Microsoft 365/Google Workspace |
| EDR/Sysmon network+process telemetry | Browser process and destination correlation, used only to rule out automation/RMM, not as a numbered-event-ID source |

## Key Fields to Inspect
**[ANALYST]** - `user`, `source_ip`, `dest_domain` / `dest_ip`, `url_category`, `http_method`, `uploaded_bytes`, `dlp_policy_name`, `sensitive_info_type`, `match_count`, `file_name` (if a file was attached rather than pasted text), `account_type` (personal Gmail/consumer login vs. corporate SSO), `action_taken` (block/allow/user-override), `override_justification_text`, `browser_process`, `device_compliance_state`, and the timestamp of any prior access to the source document (SharePoint/S3/repo download) to establish a data lineage.

## Normal vs Suspicious Pattern
**Normal:** occasional short, generic prompt to an AI tool (syntax help, drafting a paragraph), no DLP match, or usage entirely inside a **sanctioned** tenant-bound tool (e.g., Microsoft 365 Copilot, an enterprise ChatGPT Team seat under contract) where data stays within the org boundary.

**Suspicious:** a DLP match on regulated data or secrets, submitted to a consumer-tier AI tool signed in with a personal account; a large text blob or file upload rather than a short question; the paste happens within minutes of downloading a sensitive document; the user clicks through a DLP warning banner with a justification that doesn't match the classification; repeated matches across sessions or across multiple sensitive-info categories from the same user.

## Investigation Steps
1. Confirm the DLP match is real content, not a template, quoted policy text, or placeholder/test data — request a redacted match preview from the DLP console.
2. Identify the destination AI tool, whether it's sanctioned or not, and the account type used (personal login vs. corporate SSO/managed tenant).
3. Pull the full DLP match detail: sensitive info type(s), match count, byte size, and whether a file was uploaded alongside the pasted text.
4. Trace the content back to its source — which document, database export, or repo the user had open or downloaded shortly before, and confirm they had legitimate access to it.
5. Check the user's role against the data type — a developer debugging a code snippet is a different risk profile than a contractor pasting a customer list with no job-related need.
6. Review the DLP action taken (blocked outright, warned-then-overridden, or logged only) and read the override justification if one was captured.
7. Classify the data's regulatory scope (PII/PCI/PHI, source code, financial/M&A) to determine downstream escalation path.
8. Check the user's history for repeat behavior — one-off mistake vs. an established pattern across time or data categories.

## True Positive Indicators
Confirmed regulated data (real SSNs/PANs/health records), live credentials or API keys, unreleased financial results, or source code with proprietary markers submitted to an unsanctioned/personal-tier AI account; repeated submissions across categories; deliberate workaround of a block (personal device, mobile hotspot, forwarding to personal email first).

## False Positive / Benign Positive Indicators
Matched content was dummy/test data, documentation examples, or already-public information; the tool was actually a sanctioned enterprise AI product misclassified by the proxy as "unsanctioned"; the DLP regex over-fired on a non-sensitive numeric string (an internal ticket ID matching a card-number pattern is a classic one); a pre-approved, documented use case (security team testing the tool with sanitized sample data).

## Escalation Criteria
Escalate to Privacy/Legal and the DPO for confirmed regulated data at volume; escalate to Legal/IP protection and engineering leadership for confirmed source code or trade secrets; trigger immediate credential rotation with the Identity/Cloud team for exposed secrets; escalate to HR/People for repeat or willful DLP bypass; escalate to formal incident response if volume/type crosses a regulatory notification threshold.

## Containment Options & Approval Authority
**[MANAGEMENT]** - Block the domain/category at the proxy or CASB (Security Engineering, no approval needed for clearly non-business consumer AI SaaS). Revoke any OAuth grant a third-party AI plugin holds against Microsoft 365/Google Workspace (Identity team, notify the user's manager). Rotate or revoke exposed credentials immediately as standard incident procedure (Cloud/IAM team, no approval required). Force sign-out or require step-up authentication pending review (SOC lead approval). Formal disciplinary action sits with People/HR and Legal, not the SOC — it requires manager and HR sign-off. A legal hold or breach-notification determination for regulated data requires Legal/Privacy and executive sign-off.

## Example Query (Splunk SPL)
```spl
index=proxy dest_category="Generative AI" http_method=POST
| join type=inner user
  [ search index=dlp sensitive_info_type=* earliest=-15m
    | table user sensitive_info_type match_count action_taken ]
| where uploaded_bytes > 2000 AND account_type="personal"
| table _time user dest_domain sensitive_info_type match_count action_taken uploaded_bytes
```

## Closure Criteria
Close as **Benign Positive/Expected Activity** when the tool is sanctioned or the matched content is confirmed non-sensitive, documenting the justification. Close as **True Positive** only after remediation is complete — coaching/awareness note for low-severity misuse, or credential rotation and Legal notification for regulated-data exposure, linked to the incident record. Close as **Insufficient Evidence** when TLS inspection couldn't decrypt the payload and only metadata was available — note the visibility gap and file a tooling improvement request rather than guessing at content.

**Example case note:**
`2026-09-15 14:22 UTC — User j.martinez (Finance) submitted a 4.3KB text block to chat.openai.com (personal login, unsanctioned tool) matching DLP policy "Financial-Draft-Statements"; source traced to Q3 earnings draft downloaded from SharePoint 6 minutes prior. Confirmed True Positive. Escalated to Legal as IR-2026-0091; user's access to Generative AI category blocked pending review; manager notified.`
