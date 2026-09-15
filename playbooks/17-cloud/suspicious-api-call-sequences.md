# Suspicious API Call Sequences

**Playbook ID & Name:** CLD-015 — Suspicious API Call Sequences (AWS CloudTrail / Azure & Entra ID Activity Logs / M365 Unified Audit Log / GCP Cloud Audit Logs)

**[STAKEHOLDER]** - Almost nothing an attacker does in a cloud environment is illegal to do in isolation. Listing users, describing instances, reading a bucket's policy, assuming a role - every one of those is a normal, permitted action that happens thousands of times a day in a live account. What gives an intruder away is the *order* and *speed* they do them in: enumerate who you are, enumerate what you can reach, grab a durable credential, quiet the alarms, then take the data. This playbook is not about any single API call being bad - it's about a chain of individually-boring calls that, stitched together on one identity in a short window, spells out an attack in progress. Catching the sequence early is usually the difference between "we revoked a session" and "we're doing breach notification."

**Severity/Priority default:** High. Sequence-based detections are, by design, already correlated across multiple weak signals - by the time this fires, at least two and usually three ATT&CK stages have already lit up on the same principal. Escalates to **Critical** if the sequence includes logging/monitoring tampering or reaches a collection/exfiltration API within the window.

**MITRE ATT&CK Techniques:** T1078.004 (Valid Accounts: Cloud Accounts) - the identity riding the whole chain; T1580 (Cloud Infrastructure Discovery); T1087 (Account Discovery); T1069 (Permission Groups Discovery); T1538 (Cloud Service Dashboard); T1552.005 (Unsecured Credentials: Cloud Instance Metadata API); T1098.001 (Additional Cloud Credentials); T1562.001 (Impair Defenses: Disable or Modify Tools); T1119 (Automated Collection); T1530 (Data from Cloud Storage); T1567 (Exfiltration Over Web Service); T1090 (Proxy) - when the calls route through anonymizing infrastructure.

## Trigger / Detection Logic Summary

Fires when a single principal (user, role, access key, service principal, or service account) generates a sequence of API calls across two or more ATT&CK-mapped stages within a bounded time window - typically 5-30 minutes for scripted/automated activity, up to a few hours for a slower manual actor. A canonical malicious sequence looks like: **discovery** (`GetCallerIdentity`, `ListUsers`, `ListRoles`, `DescribeInstances`, `ListBuckets`) → **permission enumeration** (`ListAttachedUserPolicies`, `GetPolicyVersion`, `SimulatePrincipalPolicy`) → **credential/persistence action** (`CreateAccessKey`, `CreateLoginProfile`, "Add application password") → **defense evasion** (`StopLogging`, `DeleteTrail`, `PutEventSelectors` narrowing scope, disabling GuardDuty/Defender for Cloud) → **collection/exfiltration** (`GetObject` at volume, `ListObjectsV2` fan-out, `Export-Mailbox`, mass `Get-MgUser` via Graph). Not every stage needs to be present - three consecutive stages from an unfamiliar actor is enough to trigger; all five is close to a confirmed compromise. This is inherently a correlation-rule/UEBA problem, not a single-event alert - see the Engineering note below.

**[ENGINEERING]** - Build this as a sessionized, sliding-window aggregation keyed on actor identity (ARN / `userPrincipalName` / service account email), not on any individual `eventName`. Tag each observed API call with its ATT&CK stage via a lookup table, then alert when a session accumulates calls spanning ≥2 distinct stages (weighted higher for evasion and collection stages) inside the window. Native tooling gets you partway there: AWS GuardDuty's "Discovery," "PrivilegeEscalation," "PersistenceIAMUser," and "Exfiltration" finding families already do internal sequence correlation; Microsoft Sentinel's Fusion detections and anomaly-based analytics do the same for Entra ID/M365; GCP's Event Threat Detection covers the AWS-equivalent set. Where this playbook adds value over out-of-the-box detections is stitching *cross-service* sequences (e.g., an Entra ID sign-in anomaly followed by unusual Graph API mailbox export calls) that a single vendor's built-in correlation won't span.

## Required Log Sources & Event IDs

| Platform | Log Source | Representative API Calls / Operations by Stage |
|---|---|---|
| AWS | CloudTrail (management + data events) | Discovery: `GetCallerIdentity`, `ListUsers`, `ListBuckets`, `DescribeInstances`, `DescribeSecurityGroups`. Enum: `ListAttachedUserPolicies`, `GetPolicyVersion`. Persistence: `CreateAccessKey`, `CreateLoginProfile`, `AttachUserPolicy`. Evasion: `StopLogging`, `DeleteTrail`, `UpdateDetector` (GuardDuty disable). Collection/Exfil: `GetObject`, `ListObjectsV2`, `PutBucketPolicy` (making public) |
| Azure / Entra ID | Entra ID Sign-in + Audit Logs, Azure Activity Log, Microsoft Graph activity logs | Discovery: `Get-MgUser`, `Get-MgDirectoryRole`, "List service principals". Enum: "List app role assignments". Persistence: "Add service principal credentials", "Add owner to application". Evasion: "Update conditional access policy", disabling Defender for Cloud plans. Collection: `Export-Mailbox`, `New-InboxRule`, mass `Get-MgUser`/`Get-MgGroup` via Graph |
| M365 | Unified Audit Log (Purview) | `Set-Mailbox` (forwarding), `New-InboxRule`, `Add-MailboxPermission`, `Search-Mailbox` -Export, `FileDownloaded`/`FileSyncDownloadedFull` (SharePoint/OneDrive) |
| GCP | Cloud Audit Logs (Admin Activity + Data Access), Event Threat Detection | Discovery: `google.iam.admin.v1.ListServiceAccounts`, `compute.instances.list`. Persistence: `google.iam.admin.v1.CreateServiceAccountKey`. Evasion: disabling Cloud Audit Logs sinks, `logging.sinks.delete`. Collection: `storage.objects.get` at volume |

Note: these are control-plane audit events, not Windows/Sysmon Event IDs; there is no numeric equivalent in this category - match on operation/API name and correlate on identity, not on a fixed ID list.

## Key Fields to Inspect

**[ANALYST]**

| Field | What to check |
|---|---|
| Actor identity (`userIdentity.arn`, `userPrincipalName`, `principalEmail`) | Is this a human, a CI/CD service principal, or a long-lived static key? Does *this* identity normally run *this* mix of API calls? |
| `sourceIPAddress` / `callerIpAddress` across the whole session | Same IP throughout, or does it hop between calls - a common sign of proxy/VPN chaining or session-token replay from a different host than the original login |
| `userAgent` per call | Native console vs AWS CLI/boto3/PowerShell/`curl` - a sequence that starts in the console and switches to a raw SDK mid-session is worth a second look |
| Call cadence (timestamps between consecutive API calls) | Sub-second intervals across dozens of calls indicate a script, not a human clicking through a console |
| `errorCode` / `errorMessage` on enumeration calls | Repeated `AccessDenied`/`Client.UnauthorizedOperation` responses mid-sequence mean the actor is probing for what they *can* reach - itself a signal, even if every subsequent call fails |
| Session token origin | Was the session established via a fresh interactive sign-in, an assumed role, a federated SSO token, or a stolen/replayed session (`sts:AssumeRoleWithWebIdentity`, refresh token reuse)? |
| Stage coverage and order | How many distinct ATT&CK stages appear, and do they follow the discovery → persistence → evasion → collection order, or land out of sequence (which can indicate a scripted playbook running unattended) |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| A developer runs `ListBuckets`/`DescribeInstances` a few times while debugging, then stops | Dozens of discovery calls (`ListUsers`, `ListRoles`, `ListBuckets`, `DescribeInstances`) fired within seconds, in alphabetical/scripted order, from an identity with no prior discovery-call history |
| A CI/CD pipeline creates an access key and immediately uses it for a deploy under a known service account | An interactively-authenticated human identity creates an access key, then that key is used minutes later from a different IP/ASN than the console session |
| Security team disables a specific GuardDuty finding type as a documented tuning change (with a ticket) | `StopLogging`/`DeleteTrail`/disabling threat-detection service occurs immediately after a privilege-enumeration burst, with no change ticket |
| A backup job lists and reads a known set of S3 objects on a schedule | `ListObjectsV2` fan-out across many buckets never touched by this identity before, followed by high-volume `GetObject` calls outside the backup window |
| Analyst runs `SimulatePrincipalPolicy` while auditing least privilege | Same call run by a newly created or dormant identity, immediately preceded by `GetCallerIdentity` (classic "who am I, what can I do" opener for a stolen key) |

## Investigation Steps

1. Pull every API call for the flagged identity within the full correlation window (extend ±1 hour beyond the alert window - sequences often start before the scoring threshold trips) and build a chronological timeline: `eventTime`, `eventName`/operation, source IP, `userAgent`, result code.
2. Tag each call to its ATT&CK stage (discovery, enumeration, persistence, evasion, collection/exfil) and confirm the sequence and cadence - is this a human working through a task, or a scripted burst?
3. Establish whether the source IP(s)/ASN(s) match this identity's known baseline (VPN egress range, office IP, CI/CD runner). Check for mid-session IP changes or use of hosting-provider/anonymizing-proxy ranges.
4. Trace the session back to its authentication event - interactive sign-in with MFA, federated SSO assertion, or a long-lived static credential with no recent auth event at all (a strong compromise indicator for that key).
5. If a persistence action occurred (new access key, new app secret, new login profile), determine whether it has been used since creation, and from where.
6. If a defense-evasion call occurred (`StopLogging`, `DeleteTrail`, disabling GuardDuty/Defender/Event Threat Detection, narrowing an `EventSelector`), treat this as a near-automatic escalation trigger regardless of what precedes or follows it - this is rarely legitimate outside a documented change window.
7. If collection/exfil-stage calls are present, quantify scope: which buckets/mailboxes/objects, how much data, and whether any resource was made public or shared externally as part of the sequence (`PutBucketPolicy`, `PutBucketAcl`, new sharing link, forwarding rule).
8. Cross-reference the identity against change management, on-call schedules, and known automation inventory before concluding malicious intent - then determine blast radius: what does this identity/role have access to that it has *not yet* touched.

## True Positive Indicators

- Discovery → persistence → evasion → collection stages all present on one identity within a tight window, especially with sub-second call cadence indicating scripting
- New access key or app credential created and used from an IP/ASN inconsistent with the identity's baseline, immediately following an enumeration burst
- Audit logging or threat-detection service disabled mid-sequence with no matching change ticket
- Storage or mailbox objects accessed/exported at a volume or scope with no precedent for that identity, especially followed by a public-sharing or forwarding-rule change
- Sequence originates from a session established via an already-flagged compromise indicator (impossible travel, MFA fatigue push, legacy-auth fallback)

## False Positive / Benign Positive Indicators

- Sequence matches a documented security assessment, penetration test, or CSPM/CIEM tool performing scheduled least-privilege auditing (`SimulatePrincipalPolicy`, mass `ListAttachedUserPolicies` runs)
- Actor is a verified IaC pipeline (Terraform/CloudFormation/Bicep/Deployment Manager) whose normal apply run legitimately spans discovery, creation, and policy calls in sequence
- New-hire or newly-onboarded automation account naturally triggers a discovery burst while a human or script initializes tooling for the first time - confirm against HR/onboarding record or service catalog
- Backup, DR, or data-lifecycle jobs producing a high-volume storage-read pattern that matches a known, scheduled job definition
- Duplicate/overlapping alerts from multi-region CloudTrail replication or multiple correlation rules scoring the same underlying session

## Escalation Criteria

Escalate immediately to IR if: the sequence includes a confirmed unauthorized persistence action (new credential in use from an unrecognized location) combined with any defense-evasion call, or if collection/exfiltration-stage calls touched regulated or crown-jewel data. Escalate to the identity/platform owner regardless of verdict when the flagged identity is privileged (admin, break-glass, or has broad cross-account/cross-tenant reach) - a benign-looking sequence on a high-privilege identity still warrants a second reviewer.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority Required |
|---|---|
| Revoke active session tokens / force re-authentication for the identity | SOC Tier 2, immediate, no prior approval needed if evasion or collection stage confirmed |
| Disable or rotate the identity's credentials (access key, app secret, service account key) | Security lead approval; account/platform owner notified same shift |
| Re-enable any disabled logging/threat-detection service and preserve prior state for forensics | SOC Tier 2, immediate |
| Quarantine identity via explicit deny policy or Conditional Access block pending investigation | Security lead approval |
| Cross-account/tenant-wide credential freeze or forced re-authentication campaign | CISO or Cloud Platform Lead approval only |

SLA: sequence-based alerts must be triaged within 15 minutes given the correlation already spans multiple stages; confirmed active exfiltration-stage activity requires containment action within 30 minutes of confirmation.

## Example Query

```kql
// Sentinel/Log Analytics - simple sequence scoring, primarily AWS CloudTrail
// (ingested here into the AWSCloudTrail table, not a generically-named
// "CloudTrailLogs"). Entra ID AuditLogs uses OperationName, not EventName, so
// unioning it in as-is will just fall through to "Other" below and get
// filtered out - stitching true cross-platform sequences needs a separate
// staging step per source (normalize both to a common Stage column) before
// the union, not a single shared case() over mismatched schemas.
let window = 30m;
AWSCloudTrail
| union AuditLogs
| extend Stage = case(
    EventName in ("GetCallerIdentity","ListUsers","ListBuckets","DescribeInstances"), "Discovery",
    EventName in ("ListAttachedUserPolicies","GetPolicyVersion"), "Enum",
    EventName in ("CreateAccessKey","CreateLoginProfile"), "Persistence",
    EventName in ("StopLogging","DeleteTrail"), "Evasion",
    EventName in ("GetObject","ListObjectsV2"), "Collection", "Other")
| where Stage != "Other"
| summarize Stages = make_set(Stage), Calls = count() by Actor = tostring(UserIdentityArn), bin(TimeGenerated, window)
| where array_length(Stages) >= 2
```

## Closure Criteria

Close as **True Positive** (contained) once the identity's credentials are rotated/revoked, any tampered logging/detection service is restored, exfiltrated data scope is documented, and root cause (phished credential, leaked static key, insider action) is recorded. Close as **Benign Positive** when the sequence maps to a verified pentest, CSPM audit, or IaC pipeline run with matching change record. Close as **Insufficient Evidence** only after confirming the full session's logs (management and data events) were actually available for the correlation window - a partial-telemetry window is not the same as a clean sequence.

**Example case note:** "Identity `arn:aws:iam::111122223333:user/svc-reporting` generated `GetCallerIdentity` → `ListUsers` → `ListAttachedUserPolicies` → `CreateAccessKey` → `StopLogging` within 4 minutes on 2026-09-14, all from source IP 198.51.100.77 (unrecognized hosting-provider ASN, no prior activity for this identity). No matching CR in ServiceNow; account owner confirms no pipeline run at that time. New access key used 6 minutes later from the same IP to call `ListObjectsV2`/`GetObject` against `s3://acme-reports-prod` (47 objects, ~2.3 GB). CloudTrail logging stop confirmed unauthorized; access key deactivated, logging re-enabled at 14:52 UTC, bucket access reviewed for public exposure (none found), escalated to IR for credential-compromise workstream and customer-data exposure assessment."
