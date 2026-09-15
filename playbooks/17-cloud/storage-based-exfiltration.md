# Playbook: Storage-Based Exfiltration

**Playbook ID:** CLD-014
**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)
**Primary platform in this write-up:** AWS S3, with Azure Blob Storage, M365 SharePoint/OneDrive, and GCP Cloud Storage deltas called out inline. This playbook assumes the storage resource is **not** publicly exposed - see the separate Public Storage Bucket Exposure playbook for the misconfiguration path. Here the attacker (or a misused legitimate identity) already has valid credentials and is pulling data out through normal, authenticated read paths - which is exactly why it's harder to catch.

## Business Risk

**[STAKEHOLDER]** - This is the "quiet" exfiltration path: no malware, no exploit, just someone with valid access reading (and copying out) more than they should. It's what a departing employee does the week before resigning, what a compromised service account does after a phished admin session, and what a third-party integration does when its API key leaks. Because the read operations are individually legitimate, this rarely trips a hard block - it gets caught on volume, pattern, and context, or it doesn't get caught at all until the data shows up somewhere it shouldn't. The business question this playbook answers: did someone with legitimate access take data they weren't supposed to have, and how much.

## Severity / Priority Default

**High (P2)** at trigger, based on volume/anomaly alone. Escalates to **Critical (P1)** when the identity involved is confirmed compromised (not just anomalous), when the data set includes regulated or contractually-restricted information, or when there's evidence of a completed transfer to an external destination (not just a read).

## MITRE ATT&CK Techniques

- T1530 - Data from Cloud Storage (the core action - objects/blobs/files actually read or copied)
- T1119 - Automated Collection (scripted/bulk enumeration and pull, as opposed to a human clicking through a UI)
- T1567 - Exfiltration Over Web Service (data pushed out via a SaaS API, personal cloud storage, or paste/file-sharing service as the egress channel)
- T1078.004 - Valid Accounts: Cloud Accounts (the access itself is legitimate credentials, compromised or misused)
- T1098.001 - Additional Cloud Credentials (attacker mints a new access key/SAS token/app secret to keep pulling data after the original session ends)
- T1538 - Cloud Service Dashboard (attacker uses the console/portal directly to browse and download rather than the API - common with less-technical insiders)
- T1580 - Cloud Infrastructure Discovery (enumerating buckets/containers/sites/drives before deciding what to pull - the recon phase that usually precedes the bulk read)
- T1552.005 - Unsecured Credentials: Cloud Instance Metadata API (a compromised workload pulls its own IAM role credentials from the metadata service, then uses them to read storage it wasn't meant to touch directly)

## Trigger / Detection Logic Summary

Three trigger patterns feed this playbook, and they often chain together in a single case:

1. **Volumetric anomaly** - a single identity (user, role, service principal, or app registration) reads/downloads a number of objects or a byte volume that's a significant multiple of its own 14/30-day baseline, within a short window.
2. **Access-pattern anomaly** - `ListObjects`/`ListBlobs`/`GetObject` sequences that sweep an entire bucket/container/site rather than the handful of keys a normal workflow touches, especially combined with a new source IP, new user agent, or off-hours timing.
3. **Credential/permission-expansion precursor** - a new access key, SAS token, presigned URL, or sharing link is generated shortly before the read spike (T1098.001), or an identity that normally has no business reading this data set suddenly has the permission to (recent IAM/RBAC change).

Native cloud detections that commonly feed this: AWS GuardDuty `Exfiltration:S3/ObjectRead.Unusual` and `Discovery:S3/AnomalousBehavior`; Microsoft Defender for Cloud/Defender for Cloud Apps anomalous file download and mass-download alerts against SharePoint/OneDrive; GCP Security Command Center anomalous IAM/storage access findings. Don't rely on these alone - they under-fire on slow, low-and-slow pulls spread over days specifically to stay under volumetric thresholds.

## Required Log Sources & Event IDs

| Source | Platform | Key event names / fields |
|---|---|---|
| CloudTrail (data events - must be explicitly enabled) | AWS | `GetObject`, `ListObjects`/`ListObjectsV2`, `CopyObject`, `GetObjectTorrent` |
| CloudTrail (management events) | AWS | `CreateAccessKey`, `PutBucketReplication`, `PutObjectAcl`, `AssumeRole` chains |
| S3 Server Access Logs | AWS | `Requester`, `Operation`, `Key`, `Bytes Sent`, `Remote IP`, `User-Agent` |
| GuardDuty findings | AWS | `Exfiltration:S3/ObjectRead.Unusual`, `Discovery:S3/AnomalousBehavior`, `Exfiltration:S3/AnomalousBehavior.NetworkPermissions` |
| Storage Account diagnostic logs (`StorageBlobLogs`) | Azure | `GetBlob`, `ListBlobs`, operation `PutBlob`/`CopyBlob`, `AuthenticationType`, `RequesterObjectId` |
| Azure Activity Log | Azure | `ListAccountSas`, `ListServiceSas`, `Microsoft.Storage/storageAccounts/listkeys/action` |
| Entra ID Sign-in logs | Entra ID | Sign-in result, IP, location, device, session risk, tied to the identity used against storage |
| Unified Audit Log | M365 | `FileDownloaded`, `FileSyncDownloadedFull`, `FileAccessed`, `AnonymousLinkCreated`, `SharingSet`, `FileCopied` |
| Cloud Audit Logs (Data Access) | GCP | `storage.objects.get`, `storage.objects.list`, `storage.objects.copy`, `storage.setIamPolicy` |
| DLP / CASB / proxy logs | Cross-platform | Outbound transfer volume, destination domain, MIME/file-type classification hits |

**Known blind spot worth stating plainly:** S3 presigned URL *creation* is a client-side signing operation and generates no CloudTrail event by itself - only the resulting `GetObject` call (via the URL) shows up, often attributed to whatever principal's credentials signed it, with the actual downloader's IP as the caller. Same gap exists for Azure SAS tokens generated via SDK rather than the `ListAccountSas` API. Don't assume the absence of a "token created" event means nothing was issued.

## Key Fields to Inspect

**[ANALYST]**

- CloudTrail data events: `eventName`, `userIdentity.arn`/`userIdentity.principalId`, `userIdentity.sessionContext.sourceIdentity` (if set), `sourceIPAddress`, `userAgent`, `requestParameters.bucketName`, `requestParameters.key`, `additionalEventData.bytesTransferredOut`, `errorCode`.
- S3 server access logs: `Requester`, `Key` (watch for sequential/alphabetical sweeps), `Bytes Sent` summed per requester per hour, `Referrer` (blank/`-` often means direct API/script rather than console).
- Azure `StorageBlobLogs`: `CallerIpAddress`, `RequesterObjectId`, `AuthenticationType` (SAS vs AAD vs Account Key - account-key auth bypasses per-user attribution entirely), `OperationName`, `ResponseBodySize`.
- M365 Unified Audit Log: `UserId`, `ClientIP`, `Workload` (SharePoint/OneDrive), `SiteUrl`, `SourceFileName`, `SourceRelativeUrl`, `ItemType`, `EventSource` (SharePoint vs SecurityComplianceCenter for eDiscovery-driven bulk pulls).
- GCP audit logs: `protoPayload.authenticationInfo.principalEmail`, `resourceName`, `methodName`, `callerIp`, `numResponseItems`.

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Volume per identity | Consistent with known job function (e.g., reporting service reads ~200 objects/day) | 10-100x the identity's own baseline in a single session, or a human account suddenly behaving like a batch job |
| Source IP/ASN | Known corporate egress, VPN pool, documented CI/CD runner range | Residential/hosting-provider ASN, unfamiliar country, or a cloud IP range with no matching internal service |
| Object/key pattern | Targeted reads matching an app's known access pattern (specific prefixes, recent files) | Full `ListObjects` sweep followed by sequential `GetObject` across the entire bucket/container/site, including old/archived items nobody touches |
| Auth type | AAD/IAM-role identity, MFA-satisfied session | Storage account key or long-lived static key used directly, bypassing per-user logging; or a SAS token with an unusually long expiry (30+ days) |
| Timing | Business hours, matches on-call/change schedule | Off-hours, especially immediately following a permission change or a suspicious sign-in |
| Destination | Internal network, known backup/replication target, approved third-party integration | Personal cloud storage domain, unfamiliar external IP, paste-site or file-sharing service, or a spike in outbound bytes on a proxy/CASB log with no corresponding business ticket |

## Investigation Steps

1. **Confirm the volume and scope.** Pull exact object/byte counts, time window, and full list of keys/files touched for the flagged identity - don't work off the alert summary alone, pull the raw log slice.
2. **Establish identity context.** Human user, service principal, IAM role, or app registration? Check recent sign-in risk (Entra ID), recent credential creation (`CreateAccessKey`, `ListAccountSas`, new app secret - T1098.001), and whether this identity's normal job function has any reason to touch this data set.
3. **Check for a preceding permission or access change.** New IAM policy attachment, RBAC role assignment, SharePoint sharing link, or bucket policy edit in the hours/days before the read spike - this is often the actual root cause, with the bulk read as the symptom.
4. **Classify the data.** Bucket/container/site naming, tags, sensitivity labels (MIP/AIP for M365, resource tags for AWS/Azure/GCP). Sample a handful of the actual objects if feasible - "customer-exports" and "test-fixtures" get very different escalation treatment.
5. **Trace the egress path.** Was this read-only within the platform (e.g., copied to another bucket you own), or did bytes leave the environment? Check DLP/CASB/proxy logs for a correlated outbound transfer to an external destination around the same timestamps.
6. **Correlate authentication anomalies.** Impossible travel, new device, legacy/basic auth, MFA fatigue-push approval, or a recently reported phishing click tied to this identity - this is where the case either becomes "compromised account" (T1078.004) or "insider/authorized-but-excessive."
7. **Check for a repeatable pattern, not just one spike.** Query the same identity's activity over the prior 30-60 days - a "one-time large export" and "steady low-and-slow pull every night for three weeks" get very different responses.
8. **Determine current exposure state.** Is a SAS token/presigned URL/sharing link still active and usable by anyone who has it? Time-bound tokens that haven't expired yet are an open door, not a historical event.

## True Positive Indicators

- Bulk read/download volume with no matching change ticket, business justification, or historical pattern for that identity.
- Read spike immediately preceded by a permission grant, new credential, or sharing-link creation that itself has no justification.
- Confirmed egress to an external, non-approved destination (personal storage, unfamiliar domain) corroborated by proxy/CASB logs.
- Authentication anomaly on the identity (impossible travel, new device + no MFA, session token replay) coinciding with the storage access.
- Object/key sweep pattern (full enumeration, sequential retrieval) inconsistent with any known application behavior.

## False Positive / Benign Positive Indicators

- Known backup, replication, ETL, or DLP-classification job running from an IP range that recently changed after an infra migration - flagged as "new" purely because the source IP wasn't in the baseline yet.
- Legitimate bulk data migration or platform decommission with a documented change record.
- User re-imaging a laptop and OneDrive/SharePoint re-syncing their entire library from scratch (`FileSyncDownloadedFull` volume spike is expected in this case) - Expected Activity.
- Security tooling (CASB, DLP scanner, backup vendor) performing a full-content classification pass that touches every object at least once.
- SAS token/presigned URL usage from a known partner integration whose IP range simply wasn't documented anywhere the analyst could find it - close as Benign Positive but file a ticket to document it.

## Escalation Criteria

- Confirmed or strongly suspected account compromise (not just anomalous behavior) behind the access.
- Regulated or contractually restricted data (PII, PCI, PHI, source code with embedded secrets, M&A/legal-hold material) confirmed among the accessed objects.
- Evidence of completed transfer to an external, attacker-controlled, or otherwise unapproved destination.
- Active, unexpired SAS token, presigned URL, or sharing link discovered during the investigation that is still exploitable - this needs immediate containment regardless of whether the original access was malicious.
- Pattern suggests insider activity (departing employee, HR case already open) - route to HR/Legal in parallel with standard IR, per your organization's insider-threat handling process.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority | Notes |
|---|---|---|
| Revoke/expire active SAS tokens, presigned URLs, or sharing links | SOC Tier 2 / Cloud platform on-call, no prior approval needed | Rotating the storage account key or bucket key invalidates all outstanding SAS/presigned URLs signed with it - broad blast radius, use deliberately |
| Disable or suspend the identity (IAM user/role, Entra account, app registration) | IR lead approval | Coordinate with app/service owners first if it's a service principal - can break production |
| Revoke active sessions and rotate credentials/keys | IR lead, expedited | Applies to both the compromised identity and any new keys it minted (T1098.001) |
| Revert the permission/policy change that enabled the excess access | Resource owner + Cloud Platform team | Emergency change, documented after the fact rather than blocked on CAB |
| Block destination IP/domain at proxy or CASB | Network/security engineering | Only meaningful if egress is still ongoing |
| Legal/HR engagement for suspected insider activity | Legal / HR / CISO | Run in parallel, not sequentially after IR - evidence handling requirements differ |

## Example Query (Splunk SPL - AWS CloudTrail Data Events)

```spl
index=cloudtrail eventSource="s3.amazonaws.com" eventName="GetObject"
| bucket _time span=1h
| stats count AS get_count, dc(requestParameters.key) AS unique_keys,
    values(sourceIPAddress) AS src_ips
    BY _time, userIdentity.arn, requestParameters.bucketName
| where unique_keys > 200
| sort - unique_keys
```

Note: CloudTrail data events for `GetObject` carry the object key, not a bytes-transferred field, so this query scores on object-count/fan-out, not volume. To get actual byte volume, join this result against S3 server access logs (`Bytes Sent`) or Azure `StorageBlobLogs.ResponseBodySize` for the same identity/time window - summing the length of the key *string* is not a proxy for data volume and should not be used as one.

## Closure Criteria

Case closes when: (a) the scope of accessed/downloaded objects is fully enumerated with a documented byte/object count, (b) the identity's compromise status is determined (compromised / misused-but-legitimate / expected activity), (c) any active tokens or links found during the investigation have been revoked, (d) data sensitivity has been assessed and routed to Legal/Privacy if regulated data is involved, and (e) a corrective control (SAS max-expiry policy, alerting threshold tune, access review) is ticketed if a gap enabled the access.

Valid dispositions are **True Positive** (confirmed exfiltration, or excessive access with no confirmed external transfer - note which in the case record), **Benign Positive** (expected bulk operation), and **Insufficient Evidence** (data-event logging wasn't enabled at the time, or retention had already rolled off the relevant window - document this as a logging gap, not a guessed verdict).

**Example case note:**
`2026-09-15 09:47 UTC - Investigated GuardDuty finding Exfiltration:S3/ObjectRead.Unusual for role arn:aws:iam::442100xxxxxx:role/svc-reporting-prod. CloudTrail data events show 3,412 GetObject calls against s3://solace-financial-customer-exports between 2026-09-14 22:10-23:05 UTC (baseline for this role: ~150/day), source IP 203.0.113.77 (unrecognized ASN, not in known CI/CD or VPN ranges). Preceding event at 21:58 UTC: new access key created for this role via CreateAccessKey by IAM user jsmith (no change ticket). Entra sign-in logs show jsmith's session flagged medium risk 3 hours earlier from an unfamiliar device, no MFA challenge completed (legacy auth). CASB logs show 1.2GB outbound to a personal Dropbox-style domain in the same window. Access key deactivated, jsmith account suspended pending IR review, Legal notified re: customer PII in export set. Disposition: True Positive (confirmed exfiltration), escalated to IR-2026-0914.`
