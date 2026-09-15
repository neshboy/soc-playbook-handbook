# Knowledge Base Poisoning

**Playbook ID & Name:** AI-010 — Knowledge Base Poisoning (Internal Wiki / ITSM Knowledge Article / SharePoint-Confluence-ServiceNow-Backed AI Assistant Content)

**[STAKEHOLDER]** - Every helpdesk chatbot, internal Copilot deployment, and SOC-facing virtual assistant is only as trustworthy as the documents it was told to treat as authoritative. This playbook covers what happens when someone with write access to that source material - a wiki page, a ServiceNow knowledge article, a SharePoint runbook, a Confluence space - edits it to say something false, malicious, or dangerous, and the AI assistant then repeats that content to every employee, analyst, or customer who asks a related question. Unlike a single phishing email that one person might report, a poisoned knowledge article gets served, verbatim and with an implied stamp of authority, to hundreds of people over weeks before anyone notices the source was wrong. The business risk is not "a document was edited" - it's "our automated advice-giving system is now a distribution channel for an attacker's instructions," and the decision on how fast to pull the article and re-verify the whole KB is one leadership needs to own, not IT alone.

**Related Playbooks:** See Playbook AI-009 (RAG Poisoning) for the sibling pattern where the retrieval index/embedding store itself is tampered post-ingestion rather than the source wiki/ITSM/SharePoint article being edited pre-ingestion — the two get confused at intake constantly.

**Severity/Priority default:** High. Escalates to **Critical** if the poisoned article instructs execution of code/commands, targets a security runbook used to suppress or dismiss real detections, or has already been served by the AI assistant to a measurable number of users/analysts.

**MITRE ATT&CK Techniques:** T1078.002 (Valid Accounts: Domain Accounts) / T1078.004 (Cloud Accounts) - most KB poisoning starts with a legitimate, compromised editor account, not a novel exploit; T1190 (Exploit Public-Facing Application) - where the KB platform itself (externally reachable Confluence, ServiceNow portal) is the entry point; T1136 (Create Account) and T1098 (Account Manipulation) - attacker provisions or self-grants persistent edit/admin rights on the KB space; T1566.001/.002 (Phishing: Attachment/Link) - common initial-access route into the compromised editor's mailbox; T1204 (User Execution) - the downstream victim (analyst, helpdesk tech, end user) follows the poisoned "fix"; T1059.001/.003 (PowerShell / Windows Command Shell), T1218.005/.010/.011 (Mshta / Regsvr32 / Rundll32), T1105 (Ingress Tool Transfer), and T1027 (Obfuscated Files or Information) - the actual payload embedded in the article's "remediation steps"; T1562.001 (Impair Defenses: Disable or Modify Tools) - when a poisoned security runbook tells an analyst or automation to disable a control as a "known issue" fix; T1552.001 (Unsecured Credentials In Files) - applies when the "remediation steps" point the reader/assistant to credentials or secrets already sitting in an adjacent file/config the AI can retrieve, not to the credential-phishing case (a fake "reset your password here" step): that's a social-engineering lure with no dedicated Enterprise technique of its own, closest in spirit to the Phishing entry above.

## Trigger / Detection Logic Summary

Fires on anomalous edit activity to knowledge-base content that an AI assistant, RAG pipeline, or virtual agent consumes as a retrieval source, combined with signals that the edit is not routine content maintenance. Two distinct trigger families matter here. First, **platform-side**: an edit to a high-traffic or high-authority article (password reset, VPN setup, "known false positive" SOC runbook, incident-response playbook) made by an account with no prior edit history on that space, from an unusual location, outside change-approval process, or introducing an external link/script/attachment where none existed before. Second, **AI-side**: the assistant's retrieval/citation log shows a spike in a single document being surfaced as the top-ranked source across many unrelated queries, or a user/analyst reports that the bot gave advice that contradicts the known-good runbook. Either signal alone can be noise; both together on the same article within a short window is a strong trigger.

**[ENGINEERING]** - This is a content-integrity detection problem layered on top of an identity/access problem, not a model-security problem - the LLM itself is behaving correctly by trusting its configured source. Build detection at the ingestion boundary: diff every KB article version against its prior version at ingestion/re-index time, hash and baseline "stable" articles (ones that rarely change), and flag any diff that adds a URL, a code block, a command, or an attachment to an article that historically had none. Pair this with retrieval-log anomaly scoring - if one document's citation frequency in the RAG/assistant logs jumps sharply relative to its historical baseline without a corresponding spike in genuinely relevant queries, that document is worth a manual pull regardless of what the diff shows.

## Required Log Sources & Event IDs

There are no Windows/Sysmon Event IDs for this scenario - match on platform audit records and application-layer log fields, not a numeric ID list.

| Source | What it gives you |
|---|---|
| Confluence / MediaWiki / Notion audit log | Page edit history, editor account, IP, prior vs. new content diff, permission-group changes on the space |
| SharePoint / Purview audit log | `FileModified`, `PagePermissionChanged`, version history on the document library backing the assistant's index |
| ServiceNow (`sys_audit`, KB article revision table) | Knowledge article `sys_updated_by`, workflow/approval state, published-vs-draft transitions |
| RAG/vector store ingestion & retrieval logs | Document re-embed events, per-document citation/retrieval-hit frequency over time |
| AI gateway / assistant conversation logs | Which source document was cited in a given response, user query text, response text served |
| Identity provider (Entra ID, Okta) sign-in logs | Auth context for the editor account at time of edit - new device, unfamiliar geography, MFA method downgrade |
| EDR / proxy logs on any workstation that acted on the article's instructions | Process execution, script content, outbound connections matching a URL embedded in the poisoned article |
| Change management (ServiceNow CR, Jira) | Whether the edit maps to an approved, ticketed content change |

## Key Fields to Inspect

**[ANALYST]**

| Field | What to check |
|---|---|
| Editor account (`sys_updated_by`, Confluence `by.accountId`) | Does this account normally edit this space/article? First-time editor on a stable, high-traffic page is a strong signal |
| Diff content | What changed - added link, added code block/command, changed a phone number or URL, altered a "safe/expected" IOC list, changed a severity classification |
| Publish workflow state | Did the article skip a review/approval step that this space normally enforces, or was it force-published |
| Source IP / device of the edit | Consistent with the editor's normal location/device, or a new ASN/device fingerprint |
| Retrieval citation frequency (per document, over time) | Sudden spike in how often the AI assistant cites this specific document across unrelated queries |
| Downstream user reports | Helpdesk tickets or analyst chatter saying "the bot told me to do X and it didn't work" or "that's not our usual guidance" |
| Article category | Is this a customer-facing FAQ (lower blast radius, still reputational risk) or an internal SOC/IT runbook (direct operational risk) |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| KB owner edits their own article, through the normal review workflow, with a ticket reference in the edit comment | Article edited by an account with zero prior history on that space, no ticket reference, edit comment blank or generic |
| Edit updates a screenshot, fixes a typo, or updates a contact name | Edit adds a new external URL, a PowerShell/cmd snippet, or an attachment to an article that never had one |
| A "known false positive" SOC runbook entry is updated by the detection engineering lead after a documented tuning exercise | Same type of entry updated by an account outside the detection engineering group, instructing analysts to suppress or auto-close a specific alert/IOC |
| Assistant citation frequency for an article rises gradually alongside a real product change or seasonal support volume | Citation frequency for one article spikes sharply within hours with no corresponding change in query topic mix |
| Helpdesk article "VPN not connecting" points to the sanctioned client download page | Same article now points to a lookalike domain (e.g., `vpn-update[.]example-corp-support.com`) or instructs disabling the endpoint agent as a "fix" |

## Investigation Steps

1. Pull the full revision history for the flagged article: every editor, timestamp, source IP/device, and a content diff for each revision - not just the most recent one, since poisoning is sometimes staged across several small edits to avoid a single obvious diff.
2. Confirm whether the editing account's access to the KB space is legitimate and current - check group/role membership, recent permission changes (new grant to the space, new admin role), and cross-reference against the identity provider's sign-in log for that session (MFA method, device, geography).
3. Determine what the AI assistant actually served: pull assistant conversation logs filtered to citations of this document and read a sample of the responses generated from it - what instructions, links, or claims did real users actually receive, and how many distinct users/sessions were affected.
4. If the article contains executable instructions (a script, a command line, a "run this to fix it" step), treat any workstation known to have followed it as a potential compromise and pull EDR telemetry for process execution and outbound connections matching the article's content.
5. Check change management for a matching, approved CR - a legitimate edit to a sensitive runbook should have a ticket; absence of one is not proof of malice but raises the priority of every other check.
6. If the poisoned content is a security-specific runbook (e.g., "alert X is a known false positive, suppress it," or "disable real-time protection to resolve this"), audit whether any analyst or automation actually acted on that guidance during the exposure window - this is the scenario with the highest downstream risk since it can mask an unrelated real incident.
7. Revert the article to the last known-good revision, re-index/re-embed it in the RAG pipeline, and confirm the assistant is now citing the corrected content on a repeat test query.
8. Expand scope: check whether the same editor account touched any other articles in the exposure window, and whether the initial compromise (if the editor account itself was compromised) has a broader footprint - mailbox rules, other SaaS sessions, other KB spaces.

## True Positive Indicators

- First-time or out-of-pattern editor on a stable, high-authority article, with no matching change ticket, introducing a new link, command, or attachment
- Poisoned content specifically targets security detection/response guidance (false-positive suppression lists, "safe" IOC exemptions, control-disablement steps)
- Retrieval citation spike for the document correlates with the edit timestamp, confirming the assistant actively served the changed content to users
- Embedded instructions resolve to attacker-controlled infrastructure (lookalike domain, unlisted download source) or, when followed, produce confirmed malicious process execution on a workstation
- Editor account shows other compromise indicators in the same window (anomalous sign-in, mailbox rule creation, other unauthorized edits)

## False Positive / Benign Positive Indicators

- Edit performed by the verified content owner with a matching, approved change ticket and consistent device/location
- Content change reflects a genuine, documented product or process update (new VPN client version, updated phone number, corrected screenshot) with no added executable content
- Citation-frequency spike explained by a real, correlated increase in relevant support queries (e.g., a known outage driving traffic to the exact article that legitimately addresses it)
- Detection engineering confirms the "known false positive" runbook update matches an actual tuning decision made through the normal review process

## Escalation Criteria

Escalate immediately to IR if the poisoned article contains executable instructions that any user has already followed, if it targets SOC alert-suppression or control-disablement guidance, or if the editor account shows independent signs of compromise. Escalate to the content/platform owner and AI product owner regardless of verdict whenever a security- or IT-operations-facing runbook is involved - even a benign-looking edit to that category of content warrants a second reviewer given how directly it can steer analyst behavior.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority Required |
|---|---|
| Unpublish/roll back the flagged article to last known-good version | KB space owner or Tier 2, immediate |
| Suspend the editor account pending investigation | Security lead approval; account owner notified same shift |
| Force re-index/re-embed of the KB corpus after rollback | AI platform owner, immediate once rollback confirmed |
| Notify all users/analysts who received the poisoned content during exposure window | Communications/IT ops lead approval |
| Temporarily disable the AI assistant's citation of the affected KB space pending full audit | CISO or AI platform owner approval only |

SLA: triage within 30 minutes of trigger given the potential for automated, wide-scale distribution of bad guidance; confirmed poisoning of a security-operations runbook requires containment (rollback + suppression review) within 1 hour.

## Example Query

```kql
// Detect anomalous first-time editors adding links/commands to stable KB articles
KBAuditLogs
| where TimeGenerated > ago(24h)
| where ContentDiff has_any ("http://", "https://", "powershell", "cmd.exe", "<script")
| join kind=leftanti (
    KBAuditLogs
    | where TimeGenerated between (ago(180d) .. ago(24h))
    | summarize by ArticleId, EditorId
  ) on ArticleId, EditorId
| project TimeGenerated, ArticleId, EditorId, SourceIp, ContentDiff
```

## Closure Criteria

Close as **True Positive** once the article is rolled back and re-indexed, the editor account is confirmed compromised or malicious and remediated, affected users/analysts are notified, and any downstream execution is fully scoped and remediated. Close as **Benign Positive** when the edit maps to a verified content owner and approved change record with no added executable content. Close as **Insufficient Evidence** only after confirming full revision history and assistant citation logs were actually retrievable for the exposure window - many KB platforms retain only a limited number of prior revisions by default, and that gap should be documented, not assumed away.

**Example case note:** "ServiceNow KB article KB0041207 ('VPN Client Connection Issues - Known Fix') edited 2026-09-14 22:11 UTC by account `j.alvarez` (help desk tier 1, no prior edit history on this article, no matching CR). Diff added a link to `vpn-update.example-corp-support.net` and a 'quick fix' PowerShell one-liner. Assistant citation log shows this article was served in 11 distinct chatbot sessions between 22:30 UTC and 06:00 UTC the following day. EDR confirmed one workstation (host WKS-00417) executed the referenced script; process spawned `powershell.exe -enc <base64>` resolving to the same domain - contained and reimaged. `j.alvarez` account showed an unfamiliar-device sign-in 40 minutes prior to the edit with legacy-auth fallback; account suspended, password reset, MFA re-enrolled. Article rolled back to prior revision and re-indexed at 07:15 UTC; assistant re-tested and confirmed serving corrected content. Escalated to IR for credential-compromise workstream; affected chatbot users notified via IT ops broadcast."
