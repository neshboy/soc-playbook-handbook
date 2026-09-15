# Exfiltration Channel Deep-Dive: HTTP/HTTPS

*Module scope: this section assumes the master playbook's channel-narrowing triage has already pointed at web traffic as the probable exfil path (large outbound transfer, DLP web-upload alert, or a proxy block with unusual context). The job here is to confirm or rule out HTTP/S specifically, using the telemetry below — not to re-explain what exfiltration is.*

Relevant technique mapping: **T1567** Exfiltration Over Web Service (legitimate cloud/web platforms used as the drop point), **T1071** Application Layer Protocol (HTTP/S carrying data or C2 disguised as normal web traffic), **T1048** Exfiltration Over Alternative Protocol (HTTP substituted after a primary channel gets blocked), **T1090** Proxy and **T1572** Protocol Tunneling (destination or transport concealment).

## Primary Telemetry Sources

- **Forward/web proxy or SWG logs** (Zscaler, Palo Alto Prisma Access, Blue Coat/Symantec ProxySG, Squid) — the single richest source if it exists. Full URL, method, bytes in/out, category, User-Agent.
- **NGFW flow + App-ID logs** — useful when proxy coverage is partial (unmanaged devices, cloud workloads egressing directly).
- **TLS decryption / SNI logs** — only where SSL inspection is actually deployed. Without it you're working from SNI + cert metadata only, no URI or body.
- **NetFlow/IPFIX** — volumetric fallback when nothing else is logging payload-level detail.
- **Endpoint telemetry**: Windows Event ID **4688** (process creation, command line if auditing is on) and PowerShell **4103**/**4104** (module logging / script block logging) to catch the client-side tooling issuing the requests.

## Key Fields to Pull

| Field | Typical source | What it tells you |
|---|---|---|
| `bytes_out` / `cs-bytes` | proxy, NGFW | volume asymmetry — exfil is bytes_out-heavy, browsing is bytes_in-heavy |
| HTTP method | proxy | GET-only host suddenly issuing large POST/PUT |
| Content-Length, chunked encoding | proxy | large or streamed uploads |
| Destination host / SNI | proxy, TLS logs | pivots into reputation/enrichment |
| User-Agent | proxy | scripted clients (`python-requests`, `curl/7.x`, bare `Microsoft-Delivery-Optimization` on wrong host, blank UA) vs real browser strings |
| URI path | proxy (needs decryption) | repeated POST to the same path with growing size = staged upload |
| Category / first-seen flag | SWG | newly observed or "uncategorized" destinations |
| TLS cert CN/issuer, cert age | TLS logs | mismatched CN vs SNI, self-signed, freshly issued cert |
| Client source IP + logged-on user | proxy, 4688 | ties traffic back to a host/identity for endpoint pivot |

## Suspicious POST Volume — What "Suspicious" Actually Looks Like

Don't alert on POST volume in isolation — legitimate SaaS apps POST constantly. Baseline **per host/user, per destination**, then flag deviation:

- Outbound bytes to a single destination exceeding the host's 30-day P95 by a wide margin, especially off-hours or outside the user's normal working window.
- POST-to-GET ratio inverting for a host that's normally GET-dominant (i.e., it stops "browsing" and starts "uploading").
- Single destination absorbing a disproportionate share of a host's total egress in a short window (destination concentration).
- Repeated POSTs to the same URI with monotonically increasing Content-Length — classic chunked staged upload from a script.
- POST with no preceding GET/navigation on that domain — a scripted client hitting an API endpoint directly, not a user browsing to a page and submitting a form.
- Volume from a server or service account that has no legitimate reason to originate outbound web traffic at all.

## Unusual Destinations — Enrichment Angles

- **First-seen-in-environment** domain/IP, or domain registered/cert-issued in the last 30 days.
- Dynamic DNS providers, raw IP-literal HTTPS destinations, or non-standard ports carrying HTTP (8080/8443) dressed up as web traffic.
- Legitimate platforms abused as a dead drop (T1567): Discord CDN/webhook endpoints, Telegram Bot API, Pastebin-style paste sites, `transfer.sh`, `webhook.site`, or a personal (non-tenant-sanctioned) cloud storage account.
- SNI/Host header/cert CN mismatch — a domain-fronting or CDN-abuse tell (T1572/T1090).
- ASN or hosting provider with a bulletproof/low-reputation footprint; geolocation with no plausible business relationship to the org.

## Endpoint Corroboration

Pull **4688** command lines for the source host around the transfer window: `curl.exe -F`, `certutil.exe -urlcache`, or PowerShell invoking `System.Net.WebClient.UploadFile` / `System.Net.Http.HttpClient` `PostAsync`. Cross-reference **4104** script block content for the actual body-construction logic (often base64 or archive staging just before the POST) and **4103** for the module/parameter trail if the script is obfuscated (T1027).

**[ANALYST]** - Pull the proxy session, the matching 4688/4104 on the source host, and DLP/CASB logs for the same window before calling it. Confirm whether the destination is sanctioned SaaS (Benign Positive / Expected Activity — e.g., a dev pushing a build artifact to an approved bucket) versus genuinely unrecognized. Don't assume a large POST is malicious just because it's large; don't assume it's fine just because the domain resolves to a "known" cloud provider — attackers ride those too.

**[ENGINEERING]** - Build the baseline as a rolling per-host/per-destination bytes_out model, not a flat threshold; a flat MB threshold either floods you with false positives from backup/sync jobs or misses low-and-slow exfil entirely. Join proxy logs to endpoint process telemetry on source IP + timestamp window (allow for NAT and proxy log ingestion delay — SWG logs commonly lag 5-15 minutes) to get process-level attribution.

**[MANAGEMENT]** - Track SSL-inspection coverage percentage and proxy log retention window as standing metrics; both directly gate how far back and how deep this investigation path can go. Review newly-observed-destination alert volume monthly — this rule decays fast as the org adopts new SaaS.

## Illustrative Detection Logic (proxy log table)

```kql
ProxyLog
| where TimeGenerated > ago(7d)
| where isnotempty(DestinationDomain)
| summarize TotalBytesOut = sum(BytesOut), PostCount = countif(HttpMethod == "POST"),
            TotalRequests = count()
          by SourceHost, DestinationDomain, bin(TimeGenerated, 1h)
| where TotalBytesOut > 50000000  // tune against host baseline, not a global constant
| where PostCount > (TotalRequests * 0.7)
| join kind=leftouter (
    ProxyLog
    | summarize FirstSeen = min(TimeGenerated) by DestinationDomain
  ) on DestinationDomain
| where FirstSeen > ago(30d)
```

This flags hosts pushing large, POST-dominant volume to domains the environment has only seen in the last month — a reasonable first pass, not a verdict. Route survivors into the master playbook's evidence-collection step: source host identity, logged-on user (4624/Logon ID chain), destination enrichment, and endpoint process trail, before deciding between Confirmed Malicious, Insufficient Evidence, or Benign Positive.
