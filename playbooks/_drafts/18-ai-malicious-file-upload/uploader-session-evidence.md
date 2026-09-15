# Evidence to Gather: Uploader Identity and Session Context

This fragment feeds the **Evidence Collection** and **Investigation** sections of the master playbook *Malicious File Uploaded Into an AI System*. Before an analyst opens the file itself, the case needs a solid identity and session skeleton around it — who uploaded it, from where, on what device, under what privilege, and whether the session that carried it out even belongs to the person it claims to. Skip this and you end up analyzing a payload with no idea whether it arrived via a phished contractor account, a compromised service token, or a curious employee testing a "will it detect this" theory. All three need very different responses.

## Uploader Identity

Pull the identity record from the AI application's own audit log first — this is the authoritative source for `user_id`, `tenant_id`, `upload_id`, and `session_id`. Then cross-reference against the identity provider:

- Internal AD/Kerberos-backed SSO: correlate the app-reported username against **4768** (TGT requested) and **4769** (service ticket requested) around the upload timestamp, using Account Name and Client Address to confirm the account was actually active and network-located where claimed.
- Federated/SaaS identity (Entra ID, Okta, etc.): pull the corresponding sign-in log entry for the same time window — MFA method used, conditional access policy result, and whether the sign-in was flagged risky. Reference these logs generically; they don't carry Windows Security Event IDs.
- Confirm account type: standard user, shared/service account, contractor/guest, or break-glass admin. Service accounts uploading files into an AI tool is unusual enough on its own to warrant a note even before the file is examined.

**[ANALYST]** - If the AI app authenticates through a local Windows session (e.g., an internal RAG tool with Windows auth), check for a **4648** (explicit credential logon) preceding the upload — that's a strong indicator someone is using alternate credentials, consistent with **T1550** lateral-movement tradecraft, rather than uploading under their own identity.

## Upload Timestamp

Record both the AI application's timestamp (usually UTC, app-server clock) and the timestamp from any correlated authentication event. Normalize everything to UTC before comparing — timezone mismatch between app logs, IdP logs, and endpoint logs is one of the most common false-lead generators in this kind of case. Note ingestion delay separately from event time; SIEM arrival time is not evidence of when the upload happened.

## Source IP and Network Path

Capture the source IP as reported by the application (behind any load balancer — get the `X-Forwarded-For` chain, not just the last hop), then check it against:

- Known corporate egress ranges vs. unexpected geography
- VPN/proxy exit-node lists — a lot of "suspicious" IPs turn out to be the corporate proxy, which is a benign positive, not a finding
- TOR/anonymization feeds and recent threat-intel reputation

**[ENGINEERING]** - Where the AI platform sits behind on-prem infrastructure, join the app's source IP/port against **4624** Source Network Address/Source Port for the corresponding Logon ID, to anchor the upload to a specific authenticated network session rather than just an application-layer claim.

## Device and Endpoint Context

Collect device ID/MDM enrollment state, compliance status, EDR agent presence, OS build, and browser user-agent/TLS fingerprint. An upload from a compliant, EDR-covered corporate laptop carries very different risk than one from an unmanaged personal device or a session with no device attestation at all — this materially changes containment options later (device isolation only works if EDR is actually present).

## Session Metadata and Privilege Level

Pull the session/JWT token issuance time, expiry, concurrent-session count, and whether any other session exists for the same identity from a different geography in an overlapping window (impossible travel). Then determine privilege:

| Evidence | Source | What it tells you |
|---|---|---|
| Logon Type, Authentication Package | 4624 | Interactive vs. network vs. RDP-originated session |
| Special privileges assigned | 4672 | Session token carries admin-equivalent rights |
| Ticket encryption type | 4769 | Anomalous RC4 use worth flagging alongside privilege review |
| App-level role/scope claims | AI app audit log / IdP token | Whether the uploader has elevated app permissions (admin console, bulk ingestion) |

**[STAKEHOLDER]** - The reason this matters commercially: a malicious file uploaded by a low-privilege session is a contained incident; the same file uploaded by a session holding admin-equivalent rights over the AI platform (per **4672**, or an app-role claim of Global Admin/tenant-admin) changes blast radius and who needs to be on the call.

**[MANAGEMENT]** - Session and privilege evidence should be captured and time-stamped in the case record within the first triage window; SLA for this enrichment step sits ahead of file-analysis SLA, since privilege level directly drives escalation routing and containment approval authority.

Relevant technique context: unauthorized use of a legitimate session maps to **T1078** (.002 Domain Accounts, .004 Cloud Accounts); the upload act itself, if socially engineered, maps to **T1204** User Execution and, if delivered as an email attachment redirected into the AI tool, **T1566.001**.
