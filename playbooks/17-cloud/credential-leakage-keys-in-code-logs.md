# Credential Leakage (Keys in Code/Logs)

**Playbook ID & Name:** CLD-018 — Credential Leakage: Cloud Keys and Secrets Exposed in Code, Config, or Logs (AWS Access Keys, Azure/Entra ID App Secrets & Connection Strings, GCP Service Account Keys, M365/Graph API Tokens)

**[STAKEHOLDER]** - A developer hardcoded a live AWS key in a script, or an application logged a connection string at debug level, and it ended up somewhere it shouldn't be - a public GitHub repo, a fork of one, a log aggregator with broad read access, a CI build artifact, a support ticket attachment. The moment that happens, the credential should be treated as compromised whether or not anyone has used it yet, because scanners (both defensive and criminal) actively crawl public code hosting for exactly this pattern, typically within minutes. This playbook is about speed of rotation and scope containment, not about proving intent - by the time intent is provable, the damage is usually already priced in.

**Severity/Priority default:** High, auto-escalates to Critical if the exposed credential carries administrative/broad-write scope (e.g., AWS `AdministratorAccess`, Azure `Owner`/`Contributor` at subscription scope, a GCP service account with `roles/editor` or `roles/owner`), was exposed on a public/internet-indexed location, or confirmed API activity exists on the key from an unrecognized source.

**MITRE ATT&CK Techniques:** T1552.001 (Unsecured Credentials: Credentials In Files) - primary, the exposure itself; T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) - common source of the leaked value when an app logs its IMDS-fetched session token; T1078.004 (Valid Accounts: Cloud Accounts) - use of the leaked credential to authenticate; T1098.001 (Additional Cloud Credentials) - attacker mints a second key/secret off the compromised identity to outlive rotation of the first; T1580 (Cloud Infrastructure Discovery) and T1538 (Cloud Service Dashboard) - post-access recon/console browsing; T1530 (Data from Cloud Storage) and T1567 (Exfiltration Over Web Service) - impact if the key is actually used for data theft.

## Trigger / Detection Logic Summary

Fires from one of three directions, and you need all three wired up because none of them alone catches everything:

1. **Exposure-side detection** - a secret-scanning system (GitHub secret scanning / push protection, GitGuardian, TruffleHog in CI, Defender for Cloud's agentless secret scanning, or the cloud provider's own partner-feed integration with GitHub) flags a pattern matching a known credential format in a commit, log file, container image layer, or public paste site.
2. **Usage-side detection** - GuardDuty (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`, `Recon:IAMUser/MaliciousIPCaller`), Microsoft Defender for Cloud, or GCP Security Command Center fires because the credential is actively being used from infrastructure or a pattern inconsistent with its owner.
3. **Provider-initiated notice** - AWS, Azure, and GCP all participate in GitHub's secret scanning partner program and will proactively notify (and for AWS, often auto-quarantine via an attached deny policy) an account when one of their key formats is found exposed on public GitHub, regardless of whether your own scanning caught it first.

**[ENGINEERING]** - Treat exposure-side and usage-side detections as two stages of the *same* case, not two alerts. The correlation key is the credential identifier itself (AWS access key ID, Entra app/client ID + secret ID, GCP service account key ID) - pivot from the secret-scanning alert straight into the audit/management-plane logs for that exact key ID, not just the owning identity, since the owning identity may have other valid keys still in legitimate use.

## Required Log Sources & Event IDs

| Platform | Log Source | Event / Operation Name |
|---|---|---|
| GitHub / source control | Audit log, secret scanning API | `secret_scanning_alert.created`, `secret_scanning_alert.resolve`, push-protection bypass events |
| AWS | CloudTrail (management + data events) | `eventName=GetCallerIdentity`, `CreateAccessKey`, `ListUsers`, any data-plane call using the flagged `accessKeyId`; GuardDuty findings referencing `InstanceCredentialExfiltration` |
| AWS | Support Center / Health Dashboard | AWS-initiated "exposed credentials" case, often paired with automatic `AWSCompromisedKeyQuarantineV2` policy attachment |
| Azure / Entra ID | Entra ID Sign-in Logs, Audit Logs, Key Vault diagnostic logs | Non-interactive sign-in via client credentials flow for the flagged app ID; Identity Protection risk detection "Leaked Credentials"; Key Vault `SecretGet` |
| M365 | Unified Audit Log (Purview) | Graph API calls authenticated via the exposed app secret/certificate |
| GCP | Cloud Audit Logs (Admin Activity + Data Access) | `google.iam.admin.v1.ListServiceAccountKeys`, `GenerateAccessToken`, subsequent API calls under the flagged service account; Security Command Center "Leaked Service Account Key" finding |
| CI/CD | Build system logs (Jenkins, GitHub Actions, GitLab CI) | Build/job logs that may themselves be the leak source (echoed env vars, verbose debug output) |

Retention trap worth flagging every time this comes up: application debug logs are frequently the leak vector but are the *least* likely telemetry to have decent retention - by the time someone notices a key in a log line, the log aggregator may have already rolled it off after 7-14 days, so you're reconstructing exposure duration from the code-commit timestamp or CI build history instead.

## Key Fields to Inspect

**[ANALYST]**

| Field | What to check |
|---|---|
| Credential identifier (access key ID, client/app ID, service account key ID) | The exact value flagged - track this specific ID forward, not the whole identity's activity |
| Exposure location and visibility | Public repo vs. private-but-broadly-shared, fork count, whether the commit is still reachable in history even after a "fix" commit, whether it hit a CI log or artifact store with wide read access |
| Exposure duration | Time between commit/log-write and detection/rotation - minutes matter here |
| `sourceIPAddress` / `callerIpAddress` on any activity using the key | Corporate/CI range vs. unrecognized ASN, VPS hosting, anonymizing proxy |
| `userAgent` on activity using the key | Consistent with the owning application/service, or a generic scripting client/SDK nobody on the team uses |
| Scope/permissions attached to the exposed identity | IAM policy, role bindings, app registration API permissions - this defines blast radius, not just "was it used" |
| First-use timestamp relative to exposure | Near-zero gap from unfamiliar infrastructure is close to a guaranteed compromise signal |
| Downstream actions taken with the key | Discovery calls (`GetCallerIdentity`, `ListUsers`, `ListBuckets`), credential creation, data reads/downloads, resource creation (cryptomining instances are a very common quick monetization path) |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| A dummy/placeholder key committed in example documentation (recognizable non-functional pattern, e.g. an obviously fake AKIA-format string used purely for illustration) | A live, functional key format matching production account ID/tenant patterns |
| Push-protection blocks the commit before it ever reaches the remote; no exposure occurred | Secret lands in a commit that's already been pushed, or worse, merged and released in a tagged version |
| Key flagged in a private-and-appropriately-scoped internal repo, resolved by rotation within the standard SLA | Key flagged in a public repo, a public fork, or indexed by a search engine/scanner already |
| No API activity on the flagged key outside the CI runner's known IP range before rotation completes | API activity from an unfamiliar IP/ASN appears within minutes of the exposure window opening |
| Debug-level log line containing a secret, caught by internal log-hygiene scanning before the log ever left the environment | Secret-bearing log shipped to a third-party SaaS log aggregator, support vendor, or included in a shared troubleshooting export |

## Investigation Steps

1. Identify the exact leaked credential, its identifier, and every permission/role attached to the identity it belongs to - this defines blast radius before anything else.
2. Determine the exposure surface and duration: where did it land (public repo, fork, log sink, build artifact), how long was it reachable, and is it still reachable via cached search results, forks, or CI artifact retention even after the source is fixed.
3. Query the relevant audit/management-plane log for every API call made using that specific credential identifier across the full exposure window plus a lookback buffer, and separate known-good usage (your own CI runner, application) from anything unaccounted for.
4. Cross-check for provider-side signals - a GuardDuty/Defender/Security Command Center finding, an AWS auto-quarantine action, or a Health Dashboard notice - which often arrive independently and can confirm or contradict what your own logs show.
5. Rotate/revoke the credential immediately; this is not gated on finishing the investigation - do it in parallel, since every minute of delay is additional exposure window.
6. If usage from unrecognized infrastructure is confirmed, scope the incident further: what did the attacker touch, was anything created (new keys, new users, compute instances, storage exports), and was data actually read or downloaded.
7. Find and fix the root cause at the source - purge the secret from version-control history (not just a follow-up commit, which leaves it in history), scrub build artifacts/log lines, and confirm the sink that carried it (log aggregator, ticketing system, chat export) doesn't still hold a copy.
8. Document the exposure timeline, confirm closure, and feed the root cause back to engineering (missing pre-commit hook, verbose logging left on in production, missing push protection) as a preventive-control gap, not just an incident to close.

## True Positive Indicators

- Live, functional credential confirmed in a location reachable outside the intended trust boundary (public repo, indexed cache, broadly-shared log sink).
- API activity on the flagged credential from infrastructure inconsistent with its owner's known footprint.
- Exposed identity carries meaningful permissions (data read/write, IAM management, compute creation) rather than a fully scoped-down, single-purpose token.
- Additional credentials, users, or resources created off the exposed identity after the exposure window opened.
- Provider-side quarantine or abuse notice independently confirms the exposure.

## False Positive / Benign Positive Indicators

- Flagged string is a documented placeholder/example value, not a live credential (verify against the actual account/tenant - don't just trust that it "looks fake").
- Secret was already rotated/expired before the exposure occurred, so the exposed value is dead on arrival.
- Push protection blocked the commit before it reached the remote repository - no external exposure occurred at all.
- Credential scoped to a fully isolated, non-production sandbox with no path to sensitive data or lateral movement, and confirmed unused.
- Internal-only exposure (private repo, access-controlled log sink) with no evidence the credential left the intended trust boundary, and rotation completed inside SLA with zero recorded usage from unexpected sources.

## Escalation Criteria

Escalate to Incident Response immediately if: confirmed unauthorized API activity exists on the credential; the exposed identity has administrative or broad data-access scope; the exposure occurred on a public, internet-indexed location; resources were created that weren't authorized (new IAM principals, compute instances, storage exfil); or the credential provides a path to customer data, triggering a parallel legal/privacy notification assessment. Escalate to the engineering/platform team without full IR when the exposure is confirmed contained (private, unused, rotated inside SLA) but reveals a systemic gap - e.g., no push protection enabled, verbose logging enabled in production - since that's a control-gap finding regardless of this specific incident's outcome.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Rotate/revoke the exposed credential | SOC Analyst/Engineering has standing pre-approved authority to act immediately on any confirmed leaked cloud credential - this is a time-critical action that should never wait on a change ticket |
| Attach a deny/quarantine policy to the identity pending investigation | SOC Tier 2, immediate, especially where the provider has already auto-quarantined (formalize, don't reverse, without platform team sign-off) |
| Disable the owning IAM user/service principal/service account entirely | Cloud platform owner or IAM team lead; notify the application owner first if it's customer-facing production |
| Purge secret from version-control history (history rewrite, force-push cleanup) | Repo owner/engineering lead, coordinated with SOC to preserve evidence (commit hash, timestamp, diff) before rewriting history |
| Notify GitHub/hosting provider for cache/search-index removal | SOC or engineering lead, no additional approval needed - time-sensitive |
| Customer/legal notification if data confirmed accessed | CISO/Privacy/Legal, standard breach-notification assessment process |

Target SLA: rotate within 15 minutes of confirmed exposure, full blast-radius scoping within 4 hours, root-cause fix (history purge, logging change, pre-commit hook) tracked to closure within 5 business days.

## Example Query (Splunk SPL - Correlating GitHub Secret Scanning with AWS CloudTrail)

```spl
index=github sourcetype="github:secret_scanning_alert" secret_type="aws_access_key_id"
| rename secret_value AS access_key_id
| join type=left access_key_id
    [ search index=cloudtrail sourcetype="aws:cloudtrail" earliest=-24h
      | rename userIdentity.accessKeyId AS access_key_id
      | table _time access_key_id sourceIPAddress eventName userAgent ]
| table _time repository access_key_id sourceIPAddress eventName userAgent
| sort - _time
```

## Closure Criteria

Close as **True Positive - Contained** once the credential is rotated, confirmed dead (no further successful calls in audit logs for 24-48 hours post-rotation), any unauthorized-created resources/credentials are removed, and the exposure source is purged/fixed. Close as **Benign Positive - Exposure Without Use** when the credential was live but no unauthorized usage is found in the full exposure window and rotation completed inside SLA. Close as **Insufficient Evidence** when the log source that would confirm usage (application debug log, short-retention CI log) had already rolled off before the investigation started - document the gap and flag it as a retention finding rather than guessing at a verdict.

**Example case note:** *"AWS access key AKIA********Q7XZ for IAM user svc-billing-sync flagged by GitHub secret scanning in a public fork of api-integrations, exposed ~40 minutes before push-protection alert fired (fork predates protection rollout on that repo). CloudTrail shows zero calls using this key outside the origin CI runner IP 10.20.4.15 in the 24h window surrounding exposure. Key deactivated at 14:32 UTC, IAM user's remaining keys rotated, repo history rewritten to remove the commit, GitHub cache-purge request submitted. Classified Benign Positive - Exposure Without Use; opened a separate engineering ticket to enable push protection org-wide given this repo predated the rollout."*
