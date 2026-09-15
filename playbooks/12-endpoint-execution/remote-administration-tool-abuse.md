# Remote Administration Tool Abuse

**Category:** Endpoint - Execution & LOLBins
**Playbook ID:** EP-016

## Playbook Overview

RMM/RAT abuse is the one that keeps analysts up at night because the tooling is *legitimate*. AnyDesk, TeamViewer, ScreenConnect (ConnectWise Control), Atera, Splashtop, LogMeIn - every one of these has a real business use, real vendor signing certs, and a real reason to be sitting in your allowlist. The problem is that initial access brokers and ransomware affiliates use the exact same binaries for the exact same reason IT does: fast, reliable, encrypted remote access that most EDR products under-flag by default because "it's not malware." This playbook is not about detecting a bad hash - it's about detecting an unauthorized *instance* of a good hash, or an authorized tool being used outside its normal pattern of life.

**[STAKEHOLDER]** - This is one of the highest-consequence detections in the endpoint category because it's frequently the last thing seen before ransomware deployment. An unapproved remote-access tool on a workstation means someone other than your IT team may currently have hands-on-keyboard access to that machine. Business risk isn't "malware infection," it's "an outsider has the same access level as your helpdesk." Decision authority for isolating the host sits with the SOC on-call; decision authority for account/network-wide response sits with the IR lead.

**Severity/Priority default:** High (P2), escalates to Critical (P1) on privileged account involvement, server/DC execution, or confirmed follow-on activity.

**MITRE ATT&CK Techniques:** T1219 (Remote Access Tools) / T1219.002 (Remote Desktop Software) - the primary technique for this whole playbook; ATT&CK's own procedure examples for T1219 name AnyDesk, TeamViewer, ScreenConnect, Splashtop, and Atera specifically, which is exactly the tooling this detection watches. Also: T1105 (Ingress Tool Transfer), T1543.003 (Create or Modify System Process: Windows Service), T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys), T1021.001/.002 (Remote Services: RDP / SMB-Windows Admin Shares), T1090 (Proxy), T1572 (Protocol Tunneling), T1562.001 (Impair Defenses: Disable or Modify Tools), T1204 (User Execution), T1566.001/.002 (Phishing: Attachment/Link), T1059.001/.003 (PowerShell / Windows Command Shell), T1027 (Obfuscated Files or Information).

## Trigger / Detection Logic Summary

**[ENGINEERING]** Three independent trigger paths, any of which should open a case:

1. **Binary/hash allowlist mismatch** - a known RMM executable (by filename, hash, or Authenticode signer) runs on a host, but the hash or install path doesn't match your organization's approved RMM baseline (i.e., you run Atera org-wide, and AnyDesk shows up).
2. **Delivery-path anomaly** - an RMM installer executes from a user-writable, non-IT-managed location (`Downloads`, `AppData\Local\Temp`, browser cache) rather than from a software deployment share or MDM package path.
3. **Behavioral anomaly on an *approved* tool** - the sanctioned RMM tool is used, but from an account or at a time inconsistent with helpdesk activity (e.g., a finance user's session spawning cmd.exe through the RMM's remote shell feature at 02:00 local time).

## Required Log Sources & Event IDs

| Source | Event IDs | Purpose |
|---|---|---|
| Sysmon | 1, 3, 11, 13, 22 | Process creation/lineage, network connections, dropped installer, Run-key persistence, DNS resolution to vendor relay infra |
| Windows Security | 4688, 4648, 4624, 4672, 4103, 4104 | Process creation (if 4688 CLI auditing enabled), explicit-credential logons, session context, privileged token, PowerShell install scripts |
| Windows Security/SCM | 4697 | Service installation via Security log (RMM installed as a persistent service) |
| Windows System (SCM) | 7045 | Corroborating service install from the System log - useful when Security log auditing is thin |
| Proxy/Firewall/DNS | n/a (vendor log format) | Confirms whether traffic terminates at the org's licensed RMM tenant/relay or an unfamiliar one |
| EDR/AV | n/a | Detonation/behavioral verdict, and whether defenses were disabled (T1562.001) immediately before or after install |

## Key Fields to Inspect

**[ANALYST]**

| Field | Where | Why it matters |
|---|---|---|
| `Image` / `CommandLine` | Sysmon 1 | Confirms actual binary path and install switches (`/silent`, `--install`, `-quiet`) |
| `ParentImage` / `ParentCommandLine` | Sysmon 1 | Was this launched by outlook.exe, a browser, an archive tool, or a legit deployment agent? |
| `Hashes` | Sysmon 1 | Compare against known-good RMM release hashes and against threat intel |
| `IntegrityLevel` | Sysmon 1 | RMM services often run as SYSTEM/High - unexpected on a standard user session |
| `ServiceFileName` / `Account` | 4697 / 7045 | Service path and run-as account for the installed agent |
| `DestinationIp` / `DestinationPort` | Sysmon 3 | Where the tool phones home - compare against your licensed tenant's known relay ranges |
| `QueryName` | Sysmon 22 | Vendor relay domain (e.g., `*.anydesk.com`, `*.screenconnect.com`) vs unfamiliar reseller domain |
| Logon Type | 4624 | Type 10 (RemoteInteractive) around the same timestamp can indicate a concurrent interactive session riding the same access |
| `ScriptBlockText` | 4104 | Silent-install one-liners, often base64 or flag-obfuscated (T1027) |

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Binary/hash | Matches approved vendor baseline | Different vendor, renamed binary, or hash not in baseline |
| Install path | Program Files, pushed via RMM/MDM/GPO | Downloads, Temp, AppData, email attachment cache |
| Trigger process | Deployment agent, SCCM/Intune process | outlook.exe, chrome.exe, msedge.exe, winrar.exe |
| Ticket correlation | Matching helpdesk/PSA ticket or change record | No ticket, or ticket references unrelated work |
| Session timing | Business hours, matches on-call schedule | Off-hours, weekend, immediately after a phishing click |
| Coexistence | One sanctioned RMM tool per fleet | A second, different RMM tool appears alongside the sanctioned one (classic "backup access" TTP) |
| Network destination | Known relay ASN/domain for your paid tenant | Free-tier relay, unfamiliar reseller domain, or direct IP with no DNS lookup |

## Investigation Steps

1. Identify the binary precisely - filename, SHA256, Authenticode signer, install path - and diff against the organization's approved RMM baseline/CMDB entry.
2. Pull the Sysmon Event ID 1 process tree back to the originating parent (browser, mail client, archive utility, or legitimate deployment agent) to establish delivery vector.
3. Check for persistence: Sysmon 11 (dropped files), Sysmon 13 (Run key), 4697/7045 (service install) - note service display name, since attackers sometimes rename RMM services to blend in (e.g., `WindowsUpdateHelper`).
4. Review network telemetry (Sysmon 3/22, proxy logs) for destination domain/IP and compare to the org's licensed relay infrastructure; check connection duration and data volume for signs of an active hands-on-keyboard session versus a quick beacon.
5. Correlate identity and session context: who was logged on (4624 logon type, 4672 privileged token), and check for any 4648 explicit-credential logon indicating the RMM session was used to pivot with different credentials.
6. Check the PSA/ticketing system and directly confirm with IT/helpdesk whether this session was sanctioned - don't assume the tool is hostile just because it isn't your primary vendor; some business units legitimately run a second tool for vendor support.
7. Hunt for follow-on activity from the same host and account: additional tool downloads (T1105), credential access attempts, lateral movement over T1021.001/.002, EDR/AV tampering (T1562.001), or new scheduled tasks/services.
8. Scope across the fleet - search EDR/SIEM for the same hash, service name, or destination domain on other hosts within the same time window; a single isolated instance and a ten-host cluster are two very different incidents.

## True Positive Indicators

- Unapproved or renamed RMM binary launched from a user-writable path, no matching ticket, immediately followed by tool download or lateral movement.
- Identical hash/service name appearing on multiple hosts within a short window with no deployment record.
- RMM install occurring seconds to minutes after AV/EDR was disabled or a protection product's tamper-protection event fired.
- RMM's built-in remote-shell/file-transfer feature used to drop or execute additional tooling.

## False Positive / Benign Positive Indicators

- Hash and path match the approved vendor baseline; process launched by the org's deployment agent, not a user-facing app.
- Session ties to an open helpdesk/PSA ticket and a known IT or MSP account.
- Destination domain/ASN matches the organization's paid tenant relay, consistent with historical baseline.
- Contractor/MSP performing scheduled maintenance that lines up with the change calendar - annoying to chase down every time, but a legitimate and frequent closure.

## Escalation Criteria

Escalate to IR lead / activate the incident bridge when: the tool appears on more than one host, a privileged or service account is involved, execution occurs on a domain controller or crown-jewel server, there is evidence of credential access (T1003) or lateral movement (T1021) following install, or defenses were tampered with (T1562.001) around the same timestamp. Also escalate any case where the binary cannot be attributed to any known vendor and shows beacon-like connection intervals.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who can approve | Notes |
|---|---|---|
| Network-isolate host via EDR | SOC on-call, per standing authority | Fastest, reversible, no business sign-off needed for a single endpoint |
| Kill process / quarantine binary | SOC analyst with EDR console access | Standard first move once confirmed unapproved |
| Block destination domain/IP at proxy/firewall | Network team, notify SOC lead | Coordinate - blocking a shared relay domain can affect legitimate sessions elsewhere |
| Disable/reset account credentials | Identity/IAM team, IR lead sign-off | Required if the RMM session appears tied to a compromised account rather than just a rogue install |
| Force logoff / disable AD account fleet-wide | IR lead approval | Reserve for confirmed lateral movement, since it disrupts active business sessions |
| Org-wide removal/blocklist of unauthorized RMM tool | Change record required if pushed via GPO/EDR policy at scale | Coordinate with IT to avoid breaking a legitimately-in-use secondary tool |

SLA target: triage start within 15 minutes of alert given the High default severity, containment decision within 30 minutes; treat any privileged-account or server/DC involvement as an immediate page to IR, not a queued ticket.

## Example Query (Microsoft Defender/Sentinel - KQL)

```kql
DeviceProcessEvents
| where FileName in~ ("AnyDesk.exe","ScreenConnect.ClientSetup.exe",
                       "TeamViewer.exe","Splashtop_Streamer.exe","AteraAgent.exe")
| where FolderPath has_any (@"\Temp\", @"\Downloads\", @"\AppData\Local\")
| where InitiatingProcessFileName in~ ("outlook.exe","chrome.exe","msedge.exe","winword.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          InitiatingProcessFileName, SHA256
```

## Closure Criteria

Close as **Benign Positive / Expected Activity** when the hash and install path match the approved RMM baseline and a change or helpdesk ticket confirms sanctioned use, with no unexpected persistence or off-baseline network destination. Close as **Insufficient Evidence** when command-line auditing or proxy logs weren't available and the tool's origin can't be confirmed either way after reasonable effort - flag the host for enhanced logging going forward rather than force a verdict. Close as **True Positive** when the tool is tied to unattributed infrastructure, an unapproved delivery path, or confirmed follow-on activity such as lateral movement or credential access.

**Example case note:**
`2026-09-15 14:12 UTC - WKS-FIN-014 (user jsmith, Meridian Logistics): unapproved AnyDesk_x64.exe (SHA256 3f2a9c...) launched from C:\Users\jsmith\Downloads\invoice_9214.exe, spawned by OUTLOOK.EXE; no PSA ticket on file; outbound connection to relay.anydesk-mirror-example.com not matching licensed tenant. Host isolated via EDR, hash blocked org-wide, escalated to IR-2026-0091 for lateral-movement scoping.`
