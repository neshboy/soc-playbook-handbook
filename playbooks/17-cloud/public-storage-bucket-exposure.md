# Playbook: Public Storage Bucket Exposure

**Playbook ID:** CLD-004
**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)
**Primary platform in this write-up:** AWS S3 (Azure Blob Storage and GCS deltas called out inline — same investigative logic, different log field names)

## Business Risk

**[STAKEHOLDER]** - An internet-reachable storage bucket with sensitive data in it is functionally a leaked hard drive: no exploit needed, no phishing needed, just an anonymous HTTP GET. This is one of the most common ways companies end up in a breach headline, and the exposure window is often measured in weeks or months before anyone internal notices it. The decision this playbook feeds is simple - was anything sensitive actually readable, and if so, for how long and by whom.

## Severity / Priority Default

**High (P2)** at trigger. Escalates to **Critical (P1)** the moment confirmed regulated data (PII, PCI, credentials, source code with embedded secrets) is shown to have been retrieved by an external, unrecognized identity.

## MITRE ATT&CK Techniques

- T1538 - Cloud Service Dashboard (attacker or misconfigured pipeline uses console/API to change bucket permissions)
- T1580 - Cloud Infrastructure Discovery (enumerating buckets/objects once inside, or via automated scanners)
- T1595 - Active Scanning (external actors mass-scanning for open buckets by predictable naming patterns)
- T1530 - Data from Cloud Storage (objects actually read/listed)
- T1567 - Exfiltration Over Web Service (bucket used as a staging/exfil point, or data pulled out over the same public HTTP(S) endpoint)
- T1078.004 - Valid Accounts: Cloud Accounts (legitimate but misused identity made the change)
- T1098.001 - Additional Cloud Credentials (attacker adds access keys/IAM users after gaining bucket-level or account-level access)

## Trigger / Detection Logic Summary

Two distinct trigger paths feed this playbook and both matter:

1. **Configuration-drift trigger** - a bucket ACL or policy change grants read/list/write to `AllUsers` (S3), `AllAuthenticatedUsers`, `anonymous` role (Azure Blob public access level = Blob/Container), or `allUsers`/`allAuthenticatedUsers` (GCS IAM binding). Fired by CSPM (AWS Config, Microsoft Defender for Cloud, Security Command Center) or a native finding (GuardDuty `Policy:S3/BucketPublicAccessGranted`).
2. **Post-exposure activity trigger** - GuardDuty/Defender/SCC surfaces anomalous read volume or an unrecognized external caller against a bucket that is (or recently was) public - e.g. `UnauthorizedAccess:S3/MaliciousIPCaller.Custom`, `Exfiltration:S3/ObjectRead.Unusual`, `Discovery:S3/MaliciousIPCaller`.

Either trigger opens the same case; the config-drift trigger is the earlier, cheaper catch.

## Required Log Sources & Event IDs

| Source | Platform | Key event names / IDs |
|---|---|---|
| CloudTrail (management events) | AWS | `PutBucketAcl`, `PutBucketPolicy`, `PutBucketPublicAccessBlock`, `DeleteBucketPolicy`, `PutAccountPublicAccessBlock` |
| CloudTrail (data events, if enabled) | AWS | `GetObject`, `ListObjects`/`ListObjectsV2`, `HeadObject` |
| S3 Server Access Logs | AWS | Fields, not "event IDs" - see below |
| GuardDuty findings | AWS | `Policy:S3/BucketPublicAccessGranted`, `Exfiltration:S3/ObjectRead.Unusual`, `UnauthorizedAccess:S3/MaliciousIPCaller.Custom` |
| AWS Config | AWS | Rule `s3-bucket-public-read-prohibited` / `s3-bucket-public-write-prohibited` NON_COMPLIANT |
| Azure Activity Log | Azure | `Microsoft.Storage/storageAccounts/write`, `Microsoft.Storage/storageAccounts/blobServices/containers/write` |
| Storage Analytics / Diagnostic Logs | Azure | Anonymous `GetBlob`/`ListBlobs` operations, `AuthenticationType = Anonymous` |
| Microsoft Defender for Cloud | Azure | "Storage account with public access to blob containers should be restricted" alert class |
| Cloud Audit Logs (Admin Activity) | GCP | `storage.setIamPermissions`, `storage.buckets.update` |
| Security Command Center | GCP | Finding category `PUBLIC_BUCKET_ACL` |

## Key Fields to Inspect

**[ANALYST]**

- CloudTrail: `eventName`, `userIdentity.arn`, `userIdentity.type` (IAMUser / AssumedRole / Root), `sourceIPAddress`, `userAgent`, `requestParameters.AccessControlList.Grants[].Grantee.URI` (look for `groups/global/AllUsers` or `AuthenticatedUsers`), `requestParameters.bucketPolicy` (`Principal: "*"`), `errorCode` (blank = succeeded).
- S3 server access logs: `Requester` (`-` means anonymous/unauthenticated), `Operation`, `Key` (object path), `HTTP status`, `Bytes Sent`, `Remote IP`, `Referrer`, `User-Agent`.
- Azure diagnostic logs: `identity` block, `authenticationType`, `callerIpAddress`, `objectKey`, `statusCode`.
- CSPM/GuardDuty finding payload: `resource.s3BucketDetails[].publicAccess`, `severity`, `count` (repeat occurrences).

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Public grant present | Bucket is a known static-website/CDN-origin bucket, tagged `public=true`, matches architecture docs | Bucket holds app data, backups, logs, or Terraform state and is not tagged/expected to be public |
| Who made the change | CI/CD service role deploying an approved IaC diff, matches change ticket | IAM user/root making an ad-hoc console change with no ticket, or an unfamiliar assumed role |
| Requester in access logs | Authenticated principal, or anonymous hitting only `/index.html`, `/assets/*` on a website bucket | Anonymous (`-`) requester pulling `.env`, `.sql`, `.zip`, `.tfstate`, `.pem`, or a wide range of `Key` prefixes suggesting a directory crawl |
| Source of reads | Known CDN edge IPs, internal ranges, expected partner ASN | Diverse residential/hosting-provider ASNs, Tor exit nodes, known scanner IP ranges (Shodan/Censys/GrayNoise style ASNs) |
| Volume/timing | Steady low-volume reads matching normal traffic pattern | Sudden burst of `ListObjectsV2` immediately followed by sequential `GetObject` across many keys - classic scrape pattern |

## Investigation Steps

1. **Confirm the exposure is real, not a stale finding.** Check current bucket ACL/policy and account/bucket-level Block Public Access settings; a CSPM finding can be hours old and already remediated by another team.
2. **Establish the exposure window.** Find the earliest `PutBucketAcl`/`PutBucketPolicy` (or equivalent) event that introduced the public grant, and confirm whether it's still open. Note CloudTrail management-event lookback limits - pull from the long-term log archive/SIEM if the console's 90-day window isn't enough.
3. **Identify who/what made the change.** `userIdentity.arn`, `sourceIPAddress`, and `userAgent` - was this a Terraform/CloudFormation apply, a console click by a human, or an API call from an unrecognized key? Cross-reference against change tickets or IaC commit history.
4. **Inventory what's actually in the bucket.** List key prefixes, check for tagging/classification, and sample a few objects. Look specifically for secrets, PII, backups, and IaC state files.
5. **Check for external access during the exposure window.** Pull S3 server access logs (or diagnostic logs for Azure/GCS) filtered to anonymous/unauthenticated requesters; enumerate unique remote IPs, ASNs, objects touched, and bytes transferred.
6. **Scope the blast radius.** Count distinct external callers, correlate IPs against threat intel and known scanner ranges, and separate "one scanner hit index.html and left" from "six IPs pulled 40GB over three days."
7. **Look for follow-on compromise indicators.** If credentials, API keys, or `.tfstate` were exposed, pivot to check for their use elsewhere (new IAM users/keys via `CreateAccessKey`, unfamiliar logins, new roles) - this is where T1098.001 shows up.
8. **Contain, remediate, and route data-sensitivity findings to Legal/Privacy** if regulated data confirmed accessible.

## True Positive Indicators

- Public grant (`AllUsers`/`AllAuthenticatedUsers`/`allUsers`) present on a bucket not designed to be public.
- Anonymous `GetObject`/`ListObjects` from external IPs/ASNs with no legitimate business reason to be there.
- Sequential or bulk object retrieval pattern consistent with scraping/enumeration.
- Sensitive file types (`.env`, `.pem`, `.sql`, `.tfstate`, database dumps, PII exports) confirmed present and confirmed retrieved.
- GuardDuty/Defender/SCC exfiltration or public-access finding correlates with an unexplained IAM/config change (not a known deploy).

## False Positive / Benign Positive Indicators

- Bucket is intentionally public (static site hosting, public downloads, package mirror, CDN origin) and the grant matches documented architecture and an approved IaC change.
- "Access" in logs is entirely CDN edge nodes, internal scanners, or the org's own CSPM tool doing a compliance probe.
- `AuthenticatedUsers`/scoped cross-account grant to a specific, known partner AWS account ID - reviewed and approved, just poorly labeled.
- Short-lived public window from an IaC pipeline apply-then-rollback with zero external reads logged in that window.
- Finding based on a bucket policy `Principal` referencing a specific account/service (not `"*"`), misclassified as fully public by the scanning tool.

## Escalation Criteria

- Confirmed anonymous external retrieval of non-public, sensitive, or regulated data.
- Exposure duration unknown or exceeds 24 hours with no compensating evidence of zero access (log gaps count against you here, not for you).
- Evidence the bucket contents were used to pivot further (harvested credentials, new IAM keys, lateral movement).
- Exposure discovered externally first (bug bounty report, researcher tweet, journalist inquiry) rather than internally.
- Multiple buckets across the account exposed simultaneously, suggesting a compromised IaC pipeline, root credential misuse, or a bad account-wide Block Public Access change.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority | Notes |
|---|---|---|
| Re-enable Block Public Access / strip the offending ACL grant or policy statement | SOC Tier 2 / Cloud engineering on-call, no prior approval needed | Treated as emergency revert-to-known-good, not a normal change |
| Account-wide enforcement of Block Public Access via SCP/Org policy | Cloud Platform team + CAB | Can break legitimate public assets elsewhere - needs review |
| Rotate credentials/keys for the identity that made the change | IAM/Identity team, expedited | Especially if `userIdentity` doesn't match any known deploy pipeline |
| Legal/regulatory breach-notification assessment | Data Protection Officer / Legal | Triggered by confirmed sensitive data + confirmed external retrieval |
| Preserve evidence (server access logs, CloudTrail extract, object list) before any lifecycle deletion | SOC case owner | Object lifecycle rules can quietly delete evidence during the investigation |

## Example Query (Splunk SPL - AWS CloudTrail)

```spl
index=cloudtrail eventSource="s3.amazonaws.com"
    (eventName="PutBucketAcl" OR eventName="PutBucketPolicy")
| search requestParameters="*AllUsers*" OR requestParameters="*AuthenticatedUsers*" OR requestParameters="*\"Principal\":\"*\"*"
| table _time, eventName, userIdentity.arn, sourceIPAddress, requestParameters.bucketName
| sort - _time
```

## Closure Criteria

Case closes when: (a) the public grant is confirmed removed and Block Public Access is enforced going forward, (b) the exposure window has been reviewed against access logs with a documented conclusion on external access (none found / found and scoped), (c) any confirmed sensitive-data access has been routed to Legal/Privacy, and (d) root cause is identified and a corrective control (IaC guardrail, SCP, CSPM rule) is ticketed.

Valid dispositions are **True Positive** (data exposure confirmed), **Benign Positive** (intended public asset), and **Insufficient Evidence** (log retention or missing data-event logging prevented a definitive read on external access - this happens more than anyone likes and should be documented as a gap, not guessed around).

**Example case note:**
`2026-09-15 14:02 UTC - Confirmed s3://acme-prod-reports ACL modified 2026-09-12 03:11 UTC by IAM user svc-terraform-ci (source 10.40.2.18, internal NAT), granting READ to AllUsers. Server access logs show 214 anonymous GetObject calls from 6 external IPs (AS-14618, AS-16509) between 2026-09-12 03:15 and 2026-09-14 22:40 UTC; objects retrieved were quarterly-sales-summary PDFs (Confidential, no PII). Block Public Access re-enabled 2026-09-15 13:40 UTC. Legal notified out of caution, no notification obligation determined. Root cause: Terraform module default missing explicit private ACL - ticket TF-4471 opened for guardrail. Disposition: True Positive (data exposure confirmed, low sensitivity impact).`
