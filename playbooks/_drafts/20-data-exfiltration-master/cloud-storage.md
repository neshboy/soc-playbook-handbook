# Exfiltration via Cloud Storage (Personal Drives, Unsanctioned Buckets) — Deep Dive

## Where this fits in the channel-narrowing workflow

By the time an analyst is reading this section, the trigger is usually one of: a DLP alert on a web upload, a departing-employee review, an unexplained egress spike on the proxy, or a CASB alert flagging OAuth consent to a personal account. The job here isn't "is data leaving the org" — that's already assumed from the parent playbook's triage step. The job is confirming **cloud storage specifically** as the channel, as opposed to email attachment, USB, DNS tunneling, or a C2 exfil protocol. The tell for this channel is almost always the destination: a small, known set of SaaS storage domains or a cloud object-storage endpoint, reached over HTTPS/443, often with a sync client or CLI tool doing the work rather than a one-off manual transfer.

Relevant ATT&CK coverage: T1567 (Exfiltration Over Web Service), T1048 (Exfiltration Over Alternative Protocol — API-based tools bypassing the browser), T1530 (Data from Cloud Storage — attacker pulling data out of the org's own cloud storage before pushing it elsewhere), T1538 (Cloud Service Dashboard — recon on quota/usage before a bulk move), T1580 (Cloud Infrastructure Discovery — enumerating buckets/containers), T1098.001 (Additional Cloud Credentials — adding a personal API key or external identity), T1552.001 (Credentials in Files — hardcoded keys found during collection staging), and T1119 (Automated Collection — scripted staging of files ahead of upload).

## Endpoint telemetry

| Source | What to pull | Normal | Suspicious |
|---|---|---|---|
| Windows Security 4688 | New Process Name, Command Line, Parent Process | `OneDrive.exe` launched at logon under the user's own corporate profile | `rclone.exe`, `megacmd.exe`, `s3cmd`, `aws s3 cp`, `gsutil cp` with a `--config`/profile pointing to a non-corporate remote; command line referencing an unapproved bucket name or personal Dropbox app key |
| Sysmon (if deployed) / EDR | Network connections tied to process, file-open volume | Sync client with steady low-volume deltas | Browser or PowerShell process making sustained large outbound POST/PUT to storage-provider IPs shortly after a burst of file reads across many directories |
| 4104/4103 (PowerShell logging) | Script block content | — | `Invoke-RestMethod`/`Invoke-WebRequest` against `content.dropboxapi.com`, `www.googleapis.com/upload/drive`, or an S3/Blob endpoint, especially with base64-encoded body or `-Headers @{Authorization=...}` carrying a bearer token not issued by corporate IdP |
| 4697 / 7045 (service install) | Service Name, Image Path, Account | — | Sync client (MEGAsync, Dropbox, Box Drive) installed as a service or scheduled via 4698 to run unattended on a shared or server-class host where no business case exists |

## Network and DNS telemetry

**[ANALYST]** - Proxy and firewall logs are the fastest way to confirm this channel. Pull SNI/Host header, bytes-in vs bytes-out, and connection duration for the suspect window. Personal cloud storage traffic has a distinctive shape: normal browsing is bursty with roughly symmetric small requests; exfiltration via sync or manual upload shows a heavy upload-to-download byte ratio inversion (PUT/POST dominating), often sustained over minutes rather than seconds. DNS logs showing repeated resolution of `*.dropboxusercontent.com`, `drive.google.com`, `docs.google.com`, `mega.nz`, `we.tl`/`wetransfer.com`, `pcloud.com`, `*.s3.amazonaws.com`, `*.blob.core.windows.net`, or `*.storage.googleapis.com` immediately before or during the byte-ratio anomaly is corroborating, not conclusive — plenty of legitimate SaaS integrations touch these same domains.

**[ENGINEERING]** - A first-pass proxy query to narrow the channel:

```sql
-- Splunk-style, proxy/firewall index
index=proxy dest_domain IN ("*.dropboxusercontent.com","drive.google.com","*.googleapis.com",
  "mega.nz","*.s3.amazonaws.com","*.blob.core.windows.net","wetransfer.com","pcloud.com")
| stats sum(bytes_out) as up, sum(bytes_in) as down, count by src_ip, user, dest_domain
| eval ratio = up / (down + 1)
| where up > 50000000 AND ratio > 3
| sort - up
```

Adjust the byte threshold to your baseline — a 50MB/session floor filters out routine link-preview and small-file sync noise but keeps bulk pulls visible.

## Cloud provider / SaaS audit telemetry

| Source | What to pull | Suspicious pattern |
|---|---|---|
| Microsoft 365 / Entra sign-in & audit logs | Tenant ID, application, consent scope | Corporate identity signing into a **foreign/consumer tenant** OneDrive, or a new third-party app granted `Files.ReadWrite.All`/`offline_access` scope shortly before bulk downloads |
| Google Workspace audit log | Drive file access, external sharing events | Bulk `download`/`copy` events on files the user hasn't touched in months, followed by "shared externally" to a non-corporate Gmail address |
| AWS CloudTrail | `PutObject`, `PutBucketPolicy`, `CreateBucket`, `AssumeRole` | `PutObject` volume spike to a bucket not in the approved CMDB list; `PutBucketPolicy` making a bucket public; `AssumeRole` into an external account ID |
| CASB | OAuth grants, unsanctioned app usage, upload category | "Shadow IT" storage app usage rated high-risk, uploads flagging as sensitive by content inspection |

## Distinguishing indicators worth flagging in the case notes

- Sync-client continuous small deltas vs. a single large manual burst — the former often means an approved backup/collaboration tool, the latter often precedes departure or a one-time leak.
- Personal-tenant sign-in on a corporate device is a stronger indicator than mere domain visitation — plenty of business units legitimately use Dropbox Business or a corporate Google Workspace instance under the *same* domain names.
- API-key/CLI tooling (rclone, s3cmd, gsutil) is a stronger signal of intent than a browser upload, since it implies pre-planning and usually bypasses proxy content inspection.

**[MANAGEMENT]** - Don't close this line of investigation as confirmed exfiltration on domain-match alone; require at least two corroborating data points (byte-ratio anomaly + foreign tenant sign-in, or CLI tool execution + DLP content match) before escalating past Insufficient Evidence. Legitimate causes — approved SaaS backup jobs, a contractor using a personally-licensed Box account for an authorized handoff, or a migration project — close a large share of these as Benign Positive or Expected Activity, and that should be tracked as a normal outcome, not a miss.
