# AI-006: AI Account Takeover

**Category:** AI Security

## Playbook ID & Name

**AI-006 — AI Account Takeover** (human or service identity with access to an enterprise AI platform — Copilot/M365, ChatGPT Enterprise, Claude for Work/Enterprise, Gemini for Workspace, an internal LLM gateway admin console, or a cloud IAM principal fronting Azure OpenAI / Bedrock / Vertex AI).

This is distinct from **AI API Key Compromise** (a leaked secret used directly, no identity session involved) and from **Agent Privilege Abuse** (an already-authorized agent overstepping its own scope). Here, the attacker has taken over the *account* — password, session, or SSO trust — and is now sitting inside the AI platform as that person or service.

## Business Risk

**[STAKEHOLDER]** - An AI seat is rarely "just a chat window" anymore. It usually carries connectors into email, file storage, ticketing, source repos, and internal knowledge bases, plus the ability to mint its own API keys. An attacker who takes over one of these accounts inherits all of that reach at once, and can use the tool's own retrieval features to pull sensitive content out through a channel most DLP tooling wasn't built to inspect. The decision to kill sessions and rotate keys on a live account sits with the SOC shift lead under standing authority — this is not a "wait for the change window" situation.

## Severity/Priority Default

- **High** on any confirmed unauthorized sign-in to an account holding AI-platform access, pending scope confirmation.
- **Critical** if the account holds admin/owner rights on the AI platform or gateway, if a new API key or service account was created post-compromise, if any connected data source (mailbox, storage, repo) shows access/download activity in the compromise window, or if the legitimate owner has been locked out.

## MITRE ATT&CK Techniques

- **T1078.004** Valid Accounts: Cloud Accounts — the technique this playbook is built around; the AI seat is a cloud-hosted identity regardless of which vendor sits behind it.
- Common precursors: **T1110.001/.003** Brute Force / Password Spraying, **T1566.001/.002** Phishing (Attachment/Link — often a credential page cloned to look like the SSO front door for the AI tool), **T1552.001** Unsecured Credentials in Files (a console password or SSO cookie sitting in a leaked repo or paste).
- Common follow-on activity once inside: **T1538** Cloud Service Dashboard (surveying the admin console), **T1087** Account Discovery and **T1069** Permission Groups Discovery (mapping who else has access and what roles exist), **T1098.001** Additional Cloud Credentials (minting a new API key for persistence), **T1136** Create Account (adding a new seat/member), **T1098.002** Additional Email Delegate Permissions and **T1114.003** Email Forwarding Rule (if the AI assistant has mailbox integration), **T1530** Data from Cloud Storage and **T1119** Automated Collection (using the agent's own connectors to pull bulk content), **T1567** Exfiltration Over Web Service (the chat interface or a connected consumer service becomes the exfil path), and in the worst cases **T1531** Account Access Removal (attacker locks the real owner out to buy time).

## Trigger / Detection Logic Summary

This alert usually fires from one of two directions, and the strongest cases show both:

1. **Identity side** — the IdP flags a risky sign-in (impossible travel, anonymized/known-bad IP, leaked-credential risk, atypical device) for an identity that is a member of a group or role granting AI-platform access (e.g., `AI-Platform-Admins`, `Copilot-Users`, an Anthropic Console owner role, a Bedrock-scoped IAM role).
2. **Platform side** — the AI admin console's own audit trail shows an anomaly with no matching change ticket: a new API key created, a new member/seat invited, a payment/billing method changed, a data connector enabled to an unfamiliar destination, a bulk conversation/history export, or per-account token/usage consumption that breaks the account's established baseline.

Correlation rule: risky sign-in event for a principal with AI-platform entitlement, followed within a short window (recommend 30-60 minutes as a starting threshold, tune per environment) by any privileged action inside the AI platform's own audit log.

## Required Log Sources & Event IDs

No Windows/Sysmon event IDs apply directly to this scenario — this is a SaaS/cloud identity and AI-platform-audit problem, not an endpoint one, unless the account is federated back to on-prem AD (in which case pull the corresponding on-prem sign-in success/logon events for the same window, described by name rather than number since local numbering varies by environment).

| Source | What to Pull | Purpose |
|---|---|---|
| IdP sign-in/risk logs (Entra ID Identity Protection, Okta System Log) | Risk detection type, IP, ASN, device, MFA method/result, `correlationId` | Confirms whether the session itself was hijacked |
| AI SaaS admin console audit log (Copilot admin center, Anthropic Console audit log, OpenAI org audit log, Gemini for Workspace admin log) | Actor, action type (key created, member invited, connector enabled, role changed, billing changed), timestamp, source IP | The direct evidence of what the attacker did once inside |
| LLM gateway / internal API proxy logs | Calling identity, model invoked, token volume, source IP/ASN, per-key usage | Detects abuse routed through an internal proxy rather than the vendor console directly |
| Cloud provider AI service diagnostic logs (Azure OpenAI, Bedrock invocation logging, Vertex AI request logs) | IAM principal, region, request volume, content-filter verdicts | Confirms whether the underlying model resource was actually invoked, not just the console browsed |
| Mailbox/Unified Audit Log (if the AI tool has mailbox delegate/connector access) | New forwarding rule, delegate grant, mail read/export activity | Catches the classic BEC-style follow-on when the AI seat is mailbox-integrated |
| CASB/SSE and DLP | File uploads/downloads through the AI tool, sensitive-data pattern matches in prompt/response bodies | Surfaces exfil attempted through the chat interface itself |

## Key Fields to Inspect

**[ANALYST]** -

- Risk sign-in: `userPrincipalName`/account, resolved ASN/owner of IP (not just city), device trust/compliance state, `isInteractive`, MFA method and whether it was satisfied or just password.
- AI platform audit entries for the account: action type (`apikey.created`, `member.invited`, `connector.enabled`, `role.changed`, `billing.updated`), actor identity, source IP, and whether the action lines up with any open change ticket.
- Token/usage volume for the account and any API keys tied to it, compared against its 30-day baseline — a service account that normally runs a nightly batch and suddenly shows continuous daytime traffic from a new ASN is the tell, not the raw volume number alone.
- Connector/plugin inventory before and after the suspect window — anything pointed at a destination (storage bucket, external webhook, unfamiliar SaaS tenant) that wasn't there previously.
- Conversation/history export events and their size — a handful of exports during normal use looks nothing like a single bulk export of the full history.
- If mailbox-integrated: new forwarding rules or delegate grants timestamped inside the compromise window.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Same device/geo the account always signs in from, API key rotation matches the documented rotation schedule | New device/geo matching a flagged risky sign-in, followed by a new API key minted minutes later |
| Admin enables a connector with a linked change ticket and a named business reason | Connector enabled to an unfamiliar cloud storage tenant or personal email domain, no ticket |
| Gradual usage growth tied to a known project ramp-up | Sudden token/usage spike outside the account's normal working hours, from an unfamiliar ASN |
| Occasional single conversation export by the account owner | One bulk export of full conversation/history shortly after a risky sign-in |
| Mailbox connector behaving as configured, no new rules | New forwarding rule or delegate grant appears on a mailbox the AI tool has access to |

## Investigation Steps

1. Correlate the flagged risky sign-in with the AI platform's own audit log for the same identity across the same time window — don't stop at the IdP risk score, go get the platform-side evidence.
2. Run the standard account-takeover verification: resolve IP/ASN and device on the anomalous sign-in, check MFA method and whether it was satisfied, and reach the user out-of-band (phone, not email) to confirm or deny.
3. Pull the full AI-platform audit trail for the account: every key created/rotated/deleted, membership/role change, connector/plugin change, and billing change, cross-referenced against open change tickets.
4. Compare token/usage volume for the account and any keys tied to it against its established baseline; flag anomalies by both volume and by time-of-day/source-ASN shift, not volume alone.
5. If the account or tool has mailbox, storage, or ticketing connector access, pull the downstream system's own audit log for the same window — forwarding rules, delegate grants, bulk downloads, mass ticket reads.
6. Enumerate what this identity's AI access actually reaches — connected RAG index, internal knowledge base, source repo, shared drive — and scope the blast radius before assuming it's contained to the chat interface.
7. Check whether any API key, service account, or new member created during the suspect window is still active. If yes, that persistence mechanism must be revoked regardless of what happens with the original password/session.
8. Build the full timeline — likely initial-access vector, actions taken inside the platform, downstream systems touched, containment applied — and record the disposition before closing.

## True Positive Indicators

- User denies the flagged sign-in, or confirms they did not perform the platform action in question.
- New API key, service account, or member created shortly after an unverified/risky sign-in, from an unfamiliar source.
- Bulk conversation/history export, or a data connector pointed at a destination with no legitimate business tie.
- Usage/token volume spike inconsistent with the account's role and normal schedule.
- Mailbox forwarding rule or delegate grant appears on an AI-integrated mailbox with no matching help-desk request.
- Legitimate owner reports being locked out or seeing unfamiliar activity in their own history/audit view first.

## False Positive / Benign Positive Indicators

- Sign-in anomaly already explained by confirmed travel, a new corporate device enrollment, or a VPN/SASE egress change.
- API key rotation or connector change matches an approved, ticketed maintenance window.
- Usage spike explained by a legitimate batch job, data migration, or a new project onboarding that wasn't communicated to the SOC ahead of time.
- Authorized penetration test or red-team exercise against the AI platform, confirmed against the test schedule.
- Export or download activity performed by the actual account owner, confirmed directly with them.

## Escalation Criteria

Escalate to Incident Response immediately when: an admin/owner-level AI account is confirmed compromised; any new API key, service account, or member persists past initial discovery; any downstream connected system (mailbox, storage, repo) shows access or exfil activity in the compromise window; the legitimate owner has been locked out; or the same credential-harvesting page/source IP is tied to more than one affected account, indicating a broader campaign rather than an isolated hit.

## Containment Options & Approval Authority

**[MANAGEMENT]** -

| Action | Who Can Approve | Notes |
|---|---|---|
| Revoke active sessions/tokens for the account | SOC Analyst (standing authority) | Immediate first move on any confirmed or high-confidence suspected takeover |
| Force password reset + MFA re-registration | SOC lead | Notify user out-of-band, not via the potentially compromised inbox |
| Revoke/rotate all API keys tied to the account | IAM + AI platform owner (joint) | Includes any key minted during the suspect window, even if it looks legitimate |
| Remove rogue connector, member, or service account created during the incident | AI platform admin, IR sign-off | Do this before closing regardless of how the original session was restored |
| Disable AI platform access pending investigation | Platform owner / IR lead | Weigh business disruption for admin/exec accounts, but active exfil overrides that |
| Notify owners of downstream connected systems touched | IR lead coordinates | Mailbox, storage, or repo owners need their own scoped review, not just a heads-up |

## Example Query (Splunk SPL)

```spl
index=identity sourcetype=aad:signin RiskLevel=high
| eval risk_time=_time, user=UserPrincipalName
| join user
    [ search index=ai_platform sourcetype=ai:console:audit
      action IN ("apikey.created","member.invited","connector.enabled")
    | eval user=ActorEmail, action_time=_time ]
| where action_time > risk_time AND action_time < risk_time + 3600
| table risk_time, action_time, user, action, IPAddress, RiskEventType
```

## Closure Criteria

Close as **True Positive** only after session/token revocation, full API-key and connector audit, and downstream-system review are complete and documented, with confirmed containment applied. Close as **Benign Positive** when the sign-in and platform action are both independently explained (confirmed travel/device, ticketed change) and no persistence artifact remains. Close as **Insufficient Evidence** when the user cannot be reached and no persistence or downstream access is found in the window — flag the account for a short-term watchlist rather than forcing a verdict.

**Example case-note line:** *"2026-09-15 11:20 UTC — Entra ID flagged unlikelyTravel risk sign-in for m.oyelaran@example.com (member of AI-Platform-Admins), IP 203.0.113.77 (unrecognized VPN exit node), MFA satisfied via push. 22 minutes later, Anthropic Console audit log shows apikey.created by the same account from the same IP, no matching change ticket. User confirmed by phone she did not approve the push or create a key. Key revoked, session/tokens revoked, password reset + MFA re-registration forced, connector inventory checked (clean). Disposition: True Positive (T1078.004 → T1098.001), IAM and AI platform owner notified, account placed on 14-day monitoring watchlist."*
