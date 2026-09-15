# Exfiltration via File-Sharing Services and Messaging Applications

## Why This Channel Is Different to Chase

File-sharing and chat platforms sit in a blind spot between "sanctioned SaaS" and "unmonitored personal app." Slack, Teams, WhatsApp Desktop, Dropbox, and consumer transfer sites (WeTransfer, MEGA, Send Anywhere) all ride outbound HTTPS on standard ports, often to CDN-fronted domains your firewall already allow-lists for business reasons. The exfil doesn't look like malware traffic - it looks like someone doing their job, badly or maliciously. That's the whole problem, and it's why this channel needs its own telemetry checklist rather than a generic "check the proxy logs" note.

## Telemetry Sources to Pull First

| Source | What it gives you | Common gap |
|---|---|---|
| SaaS audit logs (Slack Enterprise Grid, Microsoft 365 Unified Audit Log/Teams, Google Workspace) | File uploads, external share creation, guest invites, app installs | Free/Standard tier plans often lack the audit API entirely |
| CASB / proxy (Zscaler, Netskope, Forcepoint) | Domain/app category (`file-sharing`, `instant-messaging`), upload byte counts, sanctioned-vs-unsanctioned tagging | Decrypted-TLS inspection frequently exempted for these categories by policy |
| Firewall/NGFW flow logs | Destination IP/domain, bytes-out, session duration | NAT'd egress collapses multiple users to one IP |
| Endpoint (EDR/Sysmon-equivalent, Windows 4688) | Process creation for `Teams.exe`, `Slack.exe`, `WhatsApp.exe`, browser-spawned uploads | Command-line auditing frequently disabled for GUI apps, so 4688 gives you the process but not the argument |
| DLP (native M365/Google DLP, endpoint DLP agent) | Content-aware match on the actual file (regex, fingerprint, exact-data-match) | Coverage gaps on personal Dropbox/Slack workspaces not enrolled in tenant DLP |

**[ANALYST]** - When a case lands on your desk tagged "possible file-sharing exfil," your first move is establishing *which* platform actually carries the payload, because each has a different evidentiary trail. Don't assume Teams because the alert fired on `teams.microsoft.com` traffic - that domain also carries call signaling and presence pings that generate huge baseline volume unrelated to file transfer.

## Indicators by Platform Family

**Cloud file-sharing (OneDrive/SharePoint, Google Drive, Dropbox, Box):**
- M365 UAL operations `FileUploaded`, `SharingSet`, `AnonymousLinkCreated`, `AddedToSecureLink` - the combination of a bulk `FileUploaded` burst followed by `AnonymousLinkCreated` on the same object within minutes is the classic "stage then share externally" pattern (T1567 Exfiltration Over Web Service, T1530 Data from Cloud Storage).
- Google Workspace equivalent: `drive` audit event `change_document_visibility` to `people_with_link` or `public_on_the_web`.
- Guest account creation right before a large share event correlates with T1098.001 Additional Cloud Credentials being used to hand off access to an external tenant.

**Messaging apps (Slack, Teams, Discord):**
- Slack Enterprise Grid audit event `file_upload` paired with `file_public_link_created` or a DM to an external/guest workspace member.
- Teams chat with an external tenant (federation enabled) showing a `MessageSent` action carrying a SharePoint attachment link rather than an inline file - Teams stores attachments in the sender's OneDrive and shares a link, so the *real* exfil record is the SharePoint `AnonymousLinkCreated` event, not the chat log itself. This is the single most missed pivot in Teams-based cases.
- WhatsApp Desktop/Web has essentially no enterprise audit trail - your evidence is endpoint-side: process creation for `WhatsApp.exe` or the browser process hosting `web.whatsapp.com`, plus proxy bytes-out to WhatsApp CDN ranges. Treat WhatsApp findings as circumstantial unless corroborated by DLP content match or a network capture.

**[ENGINEERING]** - Baseline query pattern for narrowing the channel once "SaaS-flavored exfil" is suspected but the specific app isn't confirmed:

```kql
// Sentinel/M365 Defender - external sharing burst correlated with prior mass download
let lookback = 1h;
CloudAppEvents
| where ActionType in ("FileUploaded","AnonymousLinkCreated","SharingSet","ChangeDocumentVisibility")
| where AccountDisplayName == "jsmith@northwind.example.com"
| summarize Actions=make_set(ActionType), Objects=make_set(ObjectName), Count=count()
    by bin(Timestamp, 15m), Application
| where Count > 5
```

```text
# Proxy log grep - consumer transfer/file-sharing domains not on the sanctioned list
grep -Ei '(wetransfer\.com|mega\.nz|send-anywhere\.com|gofile\.io|transfer\.sh)' proxy.log \
  | awk '{print $3, $7, $10}'   # src_ip, dest_domain, bytes_out
```

**[ENGINEERING]** - On the endpoint, a 4688 for `Teams.exe`/`Slack.exe`/browser process with a parent of `explorer.exe` immediately preceding a large outbound flow (per NetFlow or Sysmon-equivalent network event) to the app's known CDN range is weak alone but strong when stacked with a DLP content hit on the same file within the same session window.

## Narrowing the Channel - What Confirms vs Rules Out

- **Confirms file-sharing/messaging channel**: DLP content match tied to a specific `FileUploaded`/`file_upload` event, with an `AnonymousLinkCreated` or external-guest-share action on the same object, and no corresponding legitimate business ticket (T1567, T1048).
- **Rules out / redirects investigation**: bytes-out to the app domain but no matching audit-log upload event (likely just chat/presence traffic); or a share event to a *known* partner domain already whitelisted in the vendor-access register - closes as Expected Activity.
- **Insufficient Evidence**: WhatsApp/Signal-style apps with no server-side audit API and no endpoint DLP coverage - document what you *can't* see and escalate the log-retention gap to Management rather than guessing at intent.

**[MANAGEMENT]** - Tenant-level audit logging for Slack/Teams/Drive file-sharing operations, plus CASB app-category tagging, should be a hard prerequisite before this channel is marked "covered" in the exfil playbook's coverage matrix. Review the sanctioned-vs-shadow file-sharing app list quarterly with IT and Legal; unsanctioned app usage found mid-investigation should trigger a scoped retroactive audit-log pull, not just a one-off block.
