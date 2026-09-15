# Lateral Movement

Ransomware crews don't win at the point of encryption — they win in the hours or days before it, quietly moving from patient-zero to domain controllers, backup servers and file shares. If you catch lateral movement, you're doing incident response. If you miss it, you're doing disaster recovery. This section covers the four telemetry clusters that matter most at this stage: RDP sessions, SMB/admin-share activity, credential-theft-enabled logons (Pass the Hash / Pass the Ticket), and PsExec-style remote execution.

## RDP - Logon Type 10

Interactive remote desktop logons register as **Logon Type 10** in Event ID 4624 (contrast with Type 2 console, Type 3 network, Type 7 unlock). RDP is attractive to ransomware operators because it's already whitelisted on most corporate networks and it looks like normal admin behavior if nobody's watching the pattern.

| Event | Signal |
|---|---|
| 4624, Logon Type 10 | Successful interactive remote session. Check Source Network Address, Workstation Name, Account Name. |
| 4625, Logon Type 10 | Failed RDP attempts — bursts against multiple accounts from one source is password spraying (T1110.003) ahead of the eventual successful hop. |
| 4648 | Explicit-credential logon preceding an RDP connection launched via `mstsc /admin` with alternate creds, or scripted RDP from a jump box. |
| 4672 | Fires alongside 4624 if the RDP session token carries admin-equivalent privileges — flags a domain admin or local admin RDP'ing somewhere it doesn't belong. |
| Sysmon 3 | Outbound/inbound connection on TCP/3389 tying the network hop to `mstsc.exe`, `svchost.exe` (Terminal Services), or — red flag — a non-standard process brokering the connection. |

**[ANALYST]** - Baseline RDP first: which hosts are legitimate jump boxes, which accounts RDP daily, and what hours. Suspicious pattern: a workstation account (not a service or admin account) making a Type 10 logon to a server it's never touched, at 2am, followed within minutes by 4688/Sysmon 1 process creation for `net.exe`, `whoami.exe`, or `nltest.exe`. Don't assume RDP from an internal IP is safe — internal pivoting after an initial VPN or phishing foothold is the norm here, not the exception.

**[ENGINEERING]** - Correlate 4624 Type 10 with a subsequent 4672 on the same Logon ID, then chain forward to 4688 process creation events carrying that same Logon ID in the Subject fields. A useful hunt: RDP logons where Source Network Address is an internal RFC1918 range (e.g., `10.10.40.0/24`) that has never appeared as a source for that destination host in the prior 30 days — new-edge detection on the logon graph beats static thresholding. Maps to **T1021.001 – Remote Services: Remote Desktop Protocol**.

## SMB / Admin Shares - Logon Type 3

**Logon Type 3** (network logon) covers SMB connections to `C$`, `ADMIN$`, `IPC$`. This is the plumbing behind PsExec, `net use`, manual file copies, and most "living off the land" lateral movement. It's also enormously noisy — every domain controller replication, every backup agent, every legitimate file share touch generates Type 3 logons, so filtering matters more here than almost anywhere else in the playbook.

| Event | Signal |
|---|---|
| 4624, Logon Type 3 | Successful network logon. Cross-reference Account Name against expected service accounts for that host. |
| 4625, Logon Type 3 | Failed SMB auth — repeated failures against `ADMIN$` from one source is a credential-testing sweep. |
| Sysmon 3 | SMB traffic on TCP/445 attributed to the initiating process. |
| Sysmon 17/18 | Named pipe creation/connection — PsExec-family tools and several C2 frameworks ride named pipes over the SMB session for command relay. |

**[ANALYST]** - Normal: backup jobs, patch management (SCCM/WSUS), monitoring agents authenticating as service accounts to `C$` on a predictable schedule. Suspicious: a *user* account (never a service account before) authenticating to `ADMIN$` on a file server, a domain controller, or a hypervisor host it has no business reason to touch — especially if it happened within the same 10-minute window as an RDP hop from a different box. Evidence to pull: the account's normal logon footprint over 30-90 days, and whether the destination host is a backup or recovery-relevant asset (attackers deliberately walk toward backup infrastructure before detonating).

Maps to **T1021.002 – Remote Services: SMB/Windows Admin Shares**.

## Pass the Hash / Pass the Ticket

**[ENGINEERING]** - Pass the Hash (**T1550.002**) replays a captured NTLM hash without ever knowing the plaintext password. The telltale is an NTLM-authenticated Type 3 logon (4624, Authentication Package = NTLM) between two domain-joined hosts where Kerberos should have been the default authentication path — Kerberos failing back to NTLM inside a healthy domain, on a repeatable pattern, is the anomaly to hunt. If the target is a domain controller, the same behavior surfaces as **4776** with a benign-looking Error Code of `0x0` — success — which is exactly why it's dangerous; nothing fails, it just shouldn't be NTLM in the first place.

Pass the Ticket (**T1550.003**) reuses a stolen or forged Kerberos ticket rather than the hash. Two gaps are diagnostic:

- A **4769** (service ticket request) at the DC with no corresponding **4768** (TGT request) from that same client address in the session window — the ticket was imported (e.g., via Rubeus/Mimikatz `sekurlsa::tickets`), not legitimately requested.
- A **Golden Ticket (T1558.001)** shows as a 4768 with an abnormal lifetime far exceeding domain Kerberos policy, sometimes for an account that no longer resolves cleanly in AD (the krbtgt hash was used to forge a ticket for a deleted or nonexistent principal).
- A **Silver Ticket (T1558.002)** never touches the DC at all — you'll see the 4624 logon land on the target service host with zero matching 4769 upstream. That absence is the evidence.

Both PTH and PTT are almost always downstream of credential theft off a compromised box — check for **Sysmon Event ID 10 (ProcessAccess)** with a target image of `lsass.exe`, which is the operational fingerprint of **T1003.001 – OS Credential Dumping: LSASS Memory**. A sudden spike in 4769 requests using RC4 encryption (`0x17`) from one workstation against many service accounts also warrants a look — that's the Kerberoasting flavor of T1558.003, frequently run in the same window as lateral movement to harvest more tickets for reuse. If you see replication-style traffic paired with unexpected 4624 Type 3 logons to a domain controller from a non-DC host, escalate immediately — that combination is consistent with **T1003.006 – DCSync**.

## PsExec-Style Remote Execution

Classic PsExec (and lookalikes — Impacket's `psexec.py`, CrackMapExec modules) drops a service, executes, and cleans up.

| Event | Signal |
|---|---|
| 4697 (Security) / 7045 (System) | Service installation — watch for Service Name patterns like `PSEXESVC`, random 8-character names, or Service File Name pointing at `\Windows\Temp` or a UNC path. |
| 4688 / Sysmon 1 | Process creation for the dropped service binary; Sysmon 1 gives you the parent chain — `services.exe` spawning a cmd/PowerShell child is the normal PsExec shape. |
| Sysmon 17/18 | Named pipe `\PIPE\psexecsvc` (or renamed equivalents) — tools that rebrand the binary still often leave the pipe naming convention intact. |
| 4689 | Process exit — short-lived service processes that install, execute one command, and terminate within seconds fit the PsExec pattern. |

**[ANALYST]** - IT operations legitimately uses PsExec for patching, software pushes and troubleshooting — that's the friction. Before calling this malicious, check for a change ticket, confirm the source host is a known admin workstation or RMM/patch server, and verify the target list matches an approved maintenance window. Absent that context, a PsExec-pattern service install fanning out across a dozen hosts in a few minutes is a strong lateral-movement/pre-encryption-staging indicator, not a coincidence.

**[ENGINEERING]** - Correlate the 4697/7045 Service Name and Service File Name hash (via Sysmon 1) across hosts — attackers frequently reuse the exact same binary and service name domain-wide, which is a fast pivot for scoping how many machines are already touched. Scheduled tasks are the other common delivery mechanism for the same goal: **4698 (Task Created)** with Task Content XML pointing to a similarly staged payload path maps to **T1053.005 – Scheduled Task**, and shows up alongside PsExec activity when operators diversify their execution methods to survive one detection getting tuned out. WMI-based remote execution is another lateral-movement mechanism worth watching for in the same telemetry (process creation chains rooted in `WmiPrvSE.exe`), though no MITRE ID for it is confirmed for use in this book.

## Building the Pivot Chain

The single most useful analyst discipline at this stage is treating **Logon ID** as a join key, not a throwaway field. Every 4624 mints a Logon ID; every subsequent 4688 on that host carries it in the Subject. Chain hop-to-hop:

```text
Host A: 4624 (Type 10, RDP) -> Logon ID 0x3A9F1C
Host A: 4688 under 0x3A9F1C -> net.exe / whoami.exe / mstsc.exe to Host B
Host B: 4624 (Type 3, SMB/NTLM) from Host A -> new Logon ID 0x4B2E07
Host B: 4697/7045 service install under 0x4B2E07
Host B: 4688 spawned by services.exe -> payload execution
```

**[MANAGEMENT]** - Lateral-movement alerts (new-edge RDP, admin-share logons from non-service accounts, PsExec-pattern service installs) should carry a tighter SLA than routine alerts — 15 minutes to analyst eyes-on is a reasonable target once ransomware is suspected anywhere in the environment, because dwell time at this stage is measured in minutes, not hours. Ownership sits with the SOC for detection and initial triage; the decision to isolate a host or disable an account needs a named on-call approver (IT ops or IR lead) so analysts aren't stuck waiting on a change-control meeting mid-incident. Track mean-time-to-contain from first lateral-movement indicator, and review closure codes monthly — a healthy program will show a mix of Confirmed Malicious, Benign Positive (legitimate admin tooling), and Insufficient Evidence, not 100% escalation. If everything closes "malicious," your baseline is wrong; if nothing does, your detections probably are.
