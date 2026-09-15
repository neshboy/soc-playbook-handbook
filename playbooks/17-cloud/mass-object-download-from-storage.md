# Mass Object Download from Storage

## Playbook ID & Name

**CLD-013 — Mass Object Download from Cloud Storage (AWS S3 / Azure Blob & Files / GCP Cloud Storage / SharePoint & OneDrive)**

Covers a single identity (human, service principal, or role session) reading an abnormally large number of objects/files, or an abnormally large volume of bytes, from a storage account/bucket/site in a short window — distinct from the "storage made public" and "storage-based exfiltration over an unusual protocol" playbooks elsewhere in this section, though all three frequently show up together in the same incident.

## Business Risk

**[STAKEHOLDER]** - Storage buckets and SharePoint/OneDrive sites are where the actual data lives — claims records, source code, contracts, HR files, customer PII. A compromised account or an over-permissioned service credential doesn't need to be clever to cause damage here; it just needs to call "get object" a few thousand times in a row. This is the pattern behind a large share of real breach notifications: not a dramatic hack, but a quiet, high-volume read of files that nobody noticed until the data showed up somewhere it shouldn't. The business question this playbook answers is simple and expensive to get wrong: did someone just copy our data, and if so, whose and how much?

## Severity/Priority Default

**High** as the default posture for any statistically significant spike in object/file reads by a single identity, pending scope confirmation. **Critical** if the objects touched include a known sensitive-data bucket/library (tagged PII, PCI, PHI, or "confidential" in DLP/classification), if the identity is a service account whose credentials show signs of prior compromise, or if the download volume correlates with an immediately preceding privilege change or new access grant. **Medium** only after the analyst has confirmed the actor and business justification but volume still exceeds baseline enough to warrant a documented note (e.g., an approved bulk migration that wasn't pre-registered with SOC).

## MITRE ATT&CK Techniques

- T1530 Data from Cloud Storage
- T1119 Automated Collection
- T1078.004 Valid Accounts: Cloud Accounts
- T1098.001 Additional Cloud Credentials
- T1552.005 Unsecured Credentials: Cloud Instance Metadata API
- T1580 Cloud Infrastructure Discovery
- T1567 Exfiltration Over Web Service (if objects leave via a SaaS sync/share mechanism)
- T1048 Exfiltration Over Alternative Protocol (if objects leave via `rclone`/`azcopy`/CLI direct to an external endpoint)

## Trigger / Detection Logic Summary

Alert fires when a single principal's object/file-read event count, or cumulative bytes transferred, for a given bucket/container/site exceeds a rolling baseline threshold (commonly expressed as N standard deviations above that principal's 14/30-day average, or a hard floor like >500 distinct objects or >5 GB within a 15-60 minute window — tune per environment, don't ship the vendor default unchanged). Detection logic should require **both** a volume anomaly and at least one context factor to avoid drowning in noise from legitimate batch jobs: unfamiliar source IP/ASN for that identity, first-time access to that particular bucket/library by that identity, access via CLI/SDK/sync-tool user agent where the identity normally only uses the web console, or a preceding `ListObjectsV2`/`ListBucket`/enumeration burst immediately before the mass GET pattern (list-then-grab is the signature of someone who doesn't already know the object naming scheme, i.e., not the normal application/service pattern for that bucket).

## Required Log Sources & Event IDs

| Platform | Log Source | Key API Calls / Operations |
|---|---|---|
| AWS | S3 Server Access Logs, CloudTrail data events (must be explicitly enabled per bucket) | `GetObject`, `ListObjectsV2`/`ListBucket`, `HeadObject`, `SelectObjectContent`, `GetObjectVersion` |
| Azure | Storage Account Diagnostic Logs / Storage Analytics logs | `GetBlob`, `ListBlobs`, `GetFile` (Azure Files), operation `Read` in resource-level logs |
| GCP | Cloud Audit Logs — Data Access (must be explicitly enabled; disabled by default for most services) | `storage.objects.get`, `storage.objects.list` |
| M365 (SharePoint/OneDrive) | Unified Audit Log (Purview) | `FileDownloaded`, `FileSyncDownloadedFull`, `FileAccessed` at volume, `AnonymousLinkCreated`/`SharingSet` if paired with external share |
| Identity provider (context) | Entra ID / AWS IAM / GCP IAM sign-in and STS logs | Correlate the storage read session back to `AssumeRole`, `GetSessionToken`, federated sign-in event |

Note: this is a control-plane/data-plane audit event category, not Windows/Sysmon Event IDs — there are no numeric equivalents here. AWS S3 data events and GCP Data Access audit logs are the two most commonly *missing* prerequisites in this playbook; if either isn't enabled, the mass download may be entirely invisible to the SIEM and you're investigating blind from bandwidth/billing metrics only.

## Key Fields to Inspect

**[ANALYST]**

- Actor identity: `userIdentity.arn`/`principalId` (AWS), `identity.claims` on Storage logs (Azure — often just shows the SAS token or account key, not a person), `protoPayload.authenticationInfo.principalEmail` (GCP), `UserId` (M365 UAL)
- Object/key/blob path pattern — sequential (`invoice_0001.pdf`...`invoice_9999.pdf`), single prefix, or scattered across unrelated folders (scattered is more consistent with someone who found broad access and is grabbing everything, not a targeted pull)
- Object count and cumulative `bytesTransferredOut`/`ResponseBodySize` for the session — raw request count alone can hide a "10,000 tiny thumbnail" false positive vs. a genuinely large data pull
- Source IP/ASN, and whether it matches that identity's normal egress range or a VPN/hosting provider/Tor exit never seen for this identity before
- `userAgent` / client string — `aws-cli/`, `azcopy/`, `rclone/`, `python-requests/`, `Boto3/` where the identity normally only shows `S3Console/` or a specific internal app's SDK signature
- Authentication method for the session token: long-lived static access key vs. short-lived STS/AssumeRole vs. SAS token with an expiry far in the future (an over-generous SAS token is a very common root cause here)
- Whether a `ListObjectsV2`/`ListBlobs` enumeration burst precedes the GET burst, and the time delta between list and first GET (near-zero delta suggests scripted automation, not a human browsing)
- Destination, if determinable: does the session correlate with an outbound transfer to an external IP, a personal cloud storage endpoint, or a webhook/SaaS connector shortly after the reads (hands this off cleanly to the storage-based exfiltration playbook if confirmed)

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Nightly ETL/backup job pulls a known, consistent object count from a known bucket at a known time, using a tagged service role | Same-looking volume but from a role/identity that has never touched this bucket before, or at a time outside the job's schedule |
| Employee downloads a handful of files (typically single digits to low tens) from a SharePoint library they work in daily | Same employee account pulls hundreds to thousands of files across multiple unrelated libraries within minutes, especially right after a role change or right before a resignation date |
| Data migration/bulk export tied to an approved change ticket, source IP is the known migration jump host | Bulk read with no ticket, from a residential ISP or hosting-provider IP, using `rclone`/`azcopy`/CLI tooling never associated with that identity |
| Access pattern matches expected application read behavior (targeted key lookups matching a request pattern) | List-then-sequential-GET across the entire bucket/container — enumeration followed by wholesale collection |

## Investigation Steps

1. Pull the full session for the alerting identity across the detection window — every `GetObject`/`GetBlob`/`FileDownloaded` event, not just the ones that crossed the threshold, plus any preceding `List*` calls.
2. Confirm the actor: human user, service principal, or assumed role — and whether the credential type is a static long-lived key, a short-lived STS/PIM session, or a SAS/pre-signed URL, and how that credential was originally issued.
3. Establish scope: total distinct object count, cumulative bytes, and — critically — what's actually in that bucket/container/library. Cross-reference against data classification/DLP tags to know if this is a sensitive-data bucket before treating severity as routine. If no DLP/classification tags exist for this bucket/container (very common — don't assume tagging coverage is universal), pull a representative sample of the actual object keys/paths (10-20, spread across different prefixes/folders rather than just the first page of results) and open a handful directly to manually assess sensitivity. Record in the case note that classification was manually sampled rather than tag-derived, so the next analyst or auditor doesn't mistake it for an automated determination.
4. Check source IP/ASN and user agent against this identity's historical baseline. Pivot to identity provider logs (Entra sign-in, AWS SSO, IAM Identity Center) to trace the authentication chain if the IP is unfamiliar.
5. Look immediately backward and forward in time from the download burst for related events: new access key/SAS token issued, permission/role grant added, prior failed access attempts on the same bucket (suggests probing before a successful pull), and — forward — any outbound transfer, external share link creation, or sync-tool activity that would indicate the data actually left the environment.
6. Validate against change management: is there an approved migration, backup run, audit request, or e-discovery export tied to this timestamp and this identity?
7. If the actor is a human, and no ticket exists, involve HR/legal-aware channels early if this maps to a departing-employee or insider-risk scenario — handle evidence collection accordingly before confronting the user.
8. Document whether retention/log gaps limit your ability to say "no data left" vs. "no evidence data left" — these are not the same finding, and the case note needs to say which one you're closing on.

## True Positive Indicators

- Bulk read confirmed unauthorized: no ticket, no business justification, actor denies or can't explain the activity
- Credential shows independent compromise indicators (impossible travel, new MFA device, concurrent password-spray success against the same identity)
- Enumeration-then-mass-GET pattern from a tool/user agent never associated with that identity, from an unfamiliar IP/ASN
- Objects touched include tagged sensitive/regulated data and downloads correlate with a subsequent external transfer, share, or sync event
- Timing correlates with insider-risk context: resignation notice on file, recent HR action, access review flags on the account

## False Positive / Benign Positive Indicators

- Confirmed scheduled backup, ETL, indexing, or DR replication job running under its normal service identity, at its normal schedule, against its normal target
- Approved bulk migration or e-discovery/legal-hold export with a matching change ticket or legal request reference
- Security tooling itself (DLP scanner, CASB, backup/AV agent) performing a full-bucket crawl as part of its normal operation — check the vendor's documented service account list before treating as suspicious
- Duplicate alert caused by multi-region log replication or a retry storm from a client-side SDK timeout/backoff loop re-requesting the same objects

## Escalation Criteria

Escalate to IR immediately if: the identity shows independent signs of compromise, the volume/scope includes regulated data categories (PHI/PCI/PII) that would trigger breach-notification obligations if confiscated data actually left the tenant, or a subsequent external transfer/share event is confirmed. Escalate to HR/Legal (via the insider-risk process, not a standard IR ticket) if the actor is an employee with no compromise indicators but no legitimate business reason for the access — this is a people-process problem, not a technical containment problem, and needs to be routed accordingly from the first triage note. Notify the data/application owner regardless of final verdict whenever a sensitive-data bucket or library is touched at this volume.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Authority Required |
|---|---|
| Revoke active session/rotate access keys or SAS token for the identity | SOC Tier 2, immediate, for confirmed unauthorized/compromised credential |
| Suspend the identity (disable account/service principal) pending investigation | Security lead approval; notify account/service owner |
| Apply an explicit deny/quarantine policy on the specific bucket/container rather than suspending the whole identity | SOC Tier 2 with security lead sign-off, when the identity has other legitimate uses |
| Revoke SAS tokens / pre-signed URLs at the storage-account level (invalidates all outstanding tokens, breaks other consumers too) | Cloud platform owner approval — high blast-radius action |
| Engage HR/Legal insider-risk process, preserve evidence under legal hold | Security lead initiates, Legal/HR owns the process from there |

SLA: initial scope assessment (object count, sensitivity tier, actor identification) within 30 minutes of alert; containment action on confirmed unauthorized access within 60 minutes.

## Example Query

```kql
// Azure Storage - abnormal blob read volume by a single identity
StorageBlobLogs
| where TimeGenerated > ago(1h)
| where OperationName == "GetBlob"
| summarize ObjectCount = count(), Bytes = sum(ResponseBodySize) by AuthenticationHash, CallerIpAddress, AccountName
| where ObjectCount > 500 or Bytes > 5000000000
| order by Bytes desc
```

## Closure Criteria

Close as **True Positive - Contained** once the credential is rotated/revoked, scope of accessed data is documented (bucket, object count, classification tier), and root cause (phished credential, over-permissioned service account, insider action) is recorded, with breach-notification assessment completed for any regulated data involved. Close as **Benign Positive** when the activity maps to a verified scheduled job, approved migration, or legitimate security-tooling crawl. Close as **Insufficient Evidence** when data-event logging wasn't enabled on the bucket prior to the alert, or retention expired before the investigation could pull the full session — and say explicitly in the note that this is a visibility gap, not a cleared identity.

**Example case note:** "S3 data events show `GetObject` called 4,812 times against bucket `contoso-claims-docs` between 2026-09-14 22:03-22:11 UTC by role `svc-reporting-readonly` from source IP 198.51.100.27 (hosting-provider ASN, never seen for this identity in 90-day baseline). Preceding `ListObjectsV2` burst at 22:02 UTC, near-zero delay before first GET. User agent `rclone/1.65.0` — this identity's baseline shows only `Boto3/` from internal CI runners. No matching change ticket. Bucket contains PHI-tagged claims documents. Escalated to IR as confirmed unauthorized access; access key deactivated 22:34 UTC, bucket policy updated to deny the source ASN, breach-notification assessment opened with Legal, application owner (m.tran@example.com) notified."
