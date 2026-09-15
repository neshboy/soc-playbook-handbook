# Initial Access

Every ransomware case starts the same way in the after-action report: "attacker gained initial access via..." and then one of four sentences follows almost every time. Phishing, exposed RDP, an unpatched edge device, or a credential that was never really the attacker's to begin with. The frustrating part for the SOC is that the earliest signature of each of these is usually sitting in a log nobody was watching that day, or it fired as a low-severity alert three weeks before the encryption event and got triaged as noise. This section covers the four dominant entry paths and what to look for in the first hour of telemetry, before there's any indication this is going to be a ransomware case at all.

## 1. Phishing (T1566.001 Attachment, T1566.002 Link, T1204 User Execution)

Still the highest-volume vector for initial access, particularly for opportunistic ransomware affiliates using commodity loaders. The earliest reliable signature is rarely in Windows Security logs at all — it's in the mail gateway or M365/Google Workspace audit trail (message trace, delivery verdict override, mailbox rule creation). On the endpoint, the tell is a process lineage that should never exist: `winword.exe` or `outlook.exe` spawning `cmd.exe`, `powershell.exe`, or `mshta.exe` (T1218.005).

**[ANALYST]** - Pull Sysmon Event ID 1 (Process Creation) filtered on parent image `WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE` with a child of `powershell.exe`, `cmd.exe`, `wscript.exe`, or `mshta.exe`. Cross-reference Event ID 4104 (PowerShell script block logging) for base64 or heavily concatenated strings — a real user's macro-driven document rarely produces script blocks that look deliberately mangled. Check Event ID 4688 command line (if command-line auditing is on) for the same parent/child pair as corroboration. Don't assume a clean AV verdict means the attachment was benign; most loaders in 2025-2026 campaigns are unsigned but not flagged on first contact.

**[ENGINEERING]** - Correlation logic: `Sysmon EID1 WHERE ParentImage IN (office_binaries) AND Image IN (LOLBins) AND CommandLine CONTAINS ('-enc','-nop','-w hidden','IEX')`, joined within 60 seconds to Sysmon EID3/EID22 showing an outbound connection or DNS query from that same child process. This is the moment to also check Event ID 15 (FileCreateStreamHash) — a downloaded attachment carrying the Mark-of-the-Web zone identifier is a useful corroborating artifact for "this file arrived from the internet."

**[STAKEHOLDER]** - This is why every awareness campaign and every mail-filtering investment gets justified — phishing remains the cheapest way in, and the cost of missing the first fifteen minutes is measured in the difference between an isolated laptop and a domain-wide encryption event two weeks later.

## 2. Exposed RDP (T1021.001 Remote Services: RDP, T1110 Brute Force)

Internet-facing RDP (3389, or a NAT'd/forwarded alternate port) is still found in a surprising number of environments post-incident, usually "temporarily" opened for a vendor and never closed. The earliest signature is a 4625 failure storm against a single account or a small rotating account list, source IP external, followed eventually by a 4624 Logon Type 10 (RemoteInteractive) success.

**[ANALYST]** - Baseline normal Logon Type 10 sources (helpdesk jump boxes, known VPN ranges). A 4624 Type 10 with a Source Network Address outside that baseline, especially immediately following a cluster of 4625 events with Sub Status 0xC000006A against the same account, is the classic RDP-brute pattern. Check 4740 (account lockout) — Caller Computer Name often reveals the true attacking host if there's an intermediary jump server muddying the picture. Also check 4776 if the box is domain-joined and NTLM was used instead of Kerberos — a spike in 4776 failures from one workstation source is the same pattern seen from the DC's perspective.

**[ENGINEERING]** - Alert on: count(4625, SubStatus=0xC000006A OR 0xC0000064) by source IP, target account > threshold in 5 minutes, followed by 4624 LogonType=10 same source within 30 minutes. Layer with Sysmon EID3 showing inbound TCP/3389 from a non-RFC1918 address hitting a host that has no business accepting external RDP.

## 3. Exploited public-facing application (T1190)

VPN appliances, file-transfer gateways, and public web apps are the vector when there's no phishing alert, no brute-force pattern, and the first sign of trouble is a webshell or a service process doing something a service process never does.

**[ANALYST]** - Look for Sysmon Event ID 11 (FileCreate) dropping a `.aspx`, `.jsp`, or `.php` file into a web root outside a deployment window, immediately followed by Sysmon EID1 showing `w3wp.exe`, `httpd.exe`, or `tomcat.exe` as parent of `cmd.exe` or `powershell.exe`. Correlate against the application's own access logs for anomalous POST requests to newly created paths and check patch/CVE status of the exposed appliance — this is where "we were two versions behind" gets confirmed or ruled out.

**[ENGINEERING]** - `Sysmon EID1 WHERE ParentImage matches web_server_process_list AND Image IN (cmd.exe, powershell.exe, whoami.exe, certutil.exe)`. Certutil or PowerShell download cradles immediately after this pattern indicate T1105 Ingress Tool Transfer staging the next-stage loader.

## 4. Valid accounts, bought or reused (T1078, T1078.004)

No malware, no exploit, no brute-force noise — because the attacker already has a working password or session token, often purchased from an initial-access broker or an infostealer log. This is the hardest to catch early because the logon *looks* legitimate.

**[ANALYST]** - The tell is context, not the event itself: 4624 Type 3 or Type 10 from an ASN/geolocation the account has never used, at an hour outside the account's pattern, with no corresponding MFA challenge in the identity provider's sign-in log (Azure AD / Okta — outside Windows Event ID scope but essential). 4768/4769 for a service account authenticating from an interactive-looking source is a strong secondary indicator, since service accounts shouldn't originate RDP-style sessions.

**[MANAGEMENT]** - This vector is the strongest argument for MFA-everywhere and conditional access policies, because detection here leans on identity telemetry the SOC may not own; establish which team reviews impossible-travel and new-device sign-in alerts, and at what SLA, before the incident — not during it.

| Vector | ATT&CK ID | Earliest signature | Primary log source |
|---|---|---|---|
| Phishing | T1566.001/.002, T1204 | Office app spawns shell/LOLBin, obfuscated 4104 script block | Mail gateway, Sysmon 1/3/22, 4104 |
| Exposed RDP | T1021.001, T1110 | 4625 storm → 4624 Type 10 success from unbaselined source | Security log 4625/4624/4740/4776 |
| Public-facing app exploit | T1190 | Webshell drop (Sysmon 11) → web process spawns shell (Sysmon 1) | Sysmon 1/11, app access logs |
| Valid account reuse | T1078, T1078.004 | Anomalous geo/ASN logon, no MFA challenge | IdP sign-in log, 4624/4768/4769 |
