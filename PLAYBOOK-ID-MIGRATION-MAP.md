# Playbook ID Migration Map

Produced by the Cross-Reference & Playbook-ID System pass described in `TERMINOLOGY-STANDARD.md`. Scheme applied: `<DOMAIN>-<NNN>`, domains `IAM` (Identity/AD — Account & Authentication + Kerberos & Advanced Attacks), `EP` (Endpoint — Execution/LOLBins + Persistence/Impact), `NW` (Network), `WEB` (Web), `EML` (Email), `CLD` (Cloud), `AI` (AI Security, including the AI master playbook), `INS` (Insider Threat), `EXF`/`RAN`/`MAL` (the three non-AI master playbooks). Numbering is sequential within each domain, in the order the playbook already appears in `BOOK-INDEX.md`.

This map was produced by reading each playbook file's actual ID field/title line — not just the parenthetical ID shown in `BOOK-INDEX.md` link text, which in a number of cases (noted below) did not match, or omitted, the ID actually printed inside the file.

**Old IDs marked "— (none found)" had no Playbook ID field or ID-bearing title anywhere in the file; a new canonical ID is being assigned for the first time.**

## Identity & Active Directory — Account & Authentication (IAM, category 10)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| IAM-AUTH-001 | IAM-001 | Repeated Login Failures | playbooks/10-identity-ad-account/repeated-login-failures.md |
| IAM-AUTH-04 | IAM-002 | Brute Force / Password Guessing & Spraying | playbooks/10-identity-ad-account/brute-force.md |
| IAA-AUTH-04 | IAM-003 | Password Spraying | playbooks/10-identity-ad-account/password-spraying.md |
| IAM-AUTH-004 | IAM-004 | Successful Login After Failures | playbooks/10-identity-ad-account/successful-login-after-failures.md |
| IAM-AUTH-05 | IAM-005 | Account Lockouts | playbooks/10-identity-ad-account/account-lockouts.md |
| IAM-AUTH-002 | IAM-006 | Privileged Account Login | playbooks/10-identity-ad-account/privileged-account-login.md |
| IAM-AUTH-07 | IAM-007 | Admin Group Membership Change | playbooks/10-identity-ad-account/admin-group-membership-change.md |
| ID-AD-01 | IAM-008 | New Account Creation | playbooks/10-identity-ad-account/new-account-creation.md |
| AD-ACC-06 | IAM-009 | User Account Deletion | playbooks/10-identity-ad-account/user-account-deletion.md |
| IAM-AUTH-010 | IAM-010 | Unexpected Password Reset | playbooks/10-identity-ad-account/unexpected-password-reset.md |
| IAM-AUTH-003 | IAM-011 | Service Account Misuse | playbooks/10-identity-ad-account/service-account-misuse.md |
| IAM-AUTH-12 | IAM-012 | Domain Policy Change | playbooks/10-identity-ad-account/domain-policy-change.md |
| AD-GPO-07 | IAM-013 | GPO Changes | playbooks/10-identity-ad-account/gpo-changes.md |
| IAM-AD-014 | IAM-014 | Domain Admin Group Modification | playbooks/10-identity-ad-account/domain-admin-group-modification.md |

## Identity & Active Directory — Kerberos & Advanced Attacks (IAM, category 11)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| PB-IAM-KRB-01 | IAM-015 | Kerberos Anomalies (General) | playbooks/11-identity-ad-kerberos/kerberos-anomalies-general.md |
| IAM-KRB-04 | IAM-016 | Golden Ticket Indicators | playbooks/11-identity-ad-kerberos/golden-ticket-indicators.md |
| PB-IAM-KRB-07 | IAM-017 | Silver Ticket Indicators | playbooks/11-identity-ad-kerberos/silver-ticket-indicators.md |
| AD-KRB-003 | IAM-018 | Kerberoasting Detection & Response | playbooks/11-identity-ad-kerberos/kerberoasting.md |
| PB-AD-KRB-04 | IAM-019 | AS-REP Roasting Detection & Response | playbooks/11-identity-ad-kerberos/as-rep-roasting.md |
| PB-IAM-KRB-06 | IAM-020 | DCSync (Domain Replication Credential Theft) | playbooks/11-identity-ad-kerberos/dcsync.md |
| PB-IAM-KRB-08 | IAM-021 | DCShadow (Rogue Domain Controller Replication Attack) | playbooks/11-identity-ad-kerberos/dcshadow.md |
| IDN-KRB-11 | IAM-022 | Pass the Hash | playbooks/11-identity-ad-kerberos/pass-the-hash.md |
| PB-IAM-014 | IAM-023 | Pass the Ticket | playbooks/11-identity-ad-kerberos/pass-the-ticket.md |
| PB-IAM-KRB-10 | IAM-024 | NTLM Abuse | playbooks/11-identity-ad-kerberos/ntlm-abuse.md |
| AD-KRB-011 | IAM-025 | Suspicious LDAP Enumeration | playbooks/11-identity-ad-kerberos/suspicious-ldap-enumeration.md |

## Endpoint — Execution & LOLBins (EP, category 12)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| EP-EXE-01 | EP-001 | Malware Detection (Generic AV/EDR Alert) | playbooks/12-endpoint-execution/malware-detection-generic-av-edr-alert.md |
| PB-END-EXE-001 | EP-002 | Suspicious Process (Generic) | playbooks/12-endpoint-execution/suspicious-process-generic.md |
| PB-EXEC-014 | EP-003 | Encoded/Obfuscated PowerShell Execution | playbooks/12-endpoint-execution/encoded-obfuscated-powershell.md |
| EP-EXEC-004 | EP-004 | PowerShell Download Cradle | playbooks/12-endpoint-execution/powershell-download-cradle.md |
| EP-EXE-014 | EP-005 | cmd.exe Spawned by an Office Application | playbooks/12-endpoint-execution/cmd-exe-spawned-by-an-office-application.md |
| EXEC-LOL-014 | EP-006 | PowerShell Spawned by an Office Application | playbooks/12-endpoint-execution/powershell-spawned-by-an-office-application.md |
| PB-EXE-011 | EP-007 | Suspicious rundll32 Usage | playbooks/12-endpoint-execution/suspicious-rundll32-usage.md |
| PB-END-EXE-008 | EP-008 | regsvr32 Abuse | playbooks/12-endpoint-execution/regsvr32-abuse.md |
| EP-EXEC-009 | EP-009 | mshta Abuse | playbooks/12-endpoint-execution/mshta-abuse.md |
| PB-END-EXE-010 | EP-010 | certutil Abuse (Download/Decode) | playbooks/12-endpoint-execution/certutil-abuse-download-decode.md |
| PB-END-EXE-011 | EP-011 | bitsadmin Abuse | playbooks/12-endpoint-execution/bitsadmin-abuse.md |
| EP-EXEC-012 | EP-012 | WScript/CScript Abuse | playbooks/12-endpoint-execution/wscript-cscript-abuse.md |
| PB-END-EXE-013 | EP-013 | Unknown / Unrecognised Executable Execution | playbooks/12-endpoint-execution/unknown-unrecognised-executable-execution.md |
| PB-EXE-014 | EP-014 | Unsigned Binary Execution | playbooks/12-endpoint-execution/unsigned-binary-execution.md |
| EP-EXEC-015 | EP-015 | USB-Triggered Execution | playbooks/12-endpoint-execution/usb-triggered-execution.md |
| END-EXE-014 | EP-016 | Remote Administration Tool Abuse | playbooks/12-endpoint-execution/remote-administration-tool-abuse.md |

## Endpoint — Persistence & Impact (EP, category 13)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| PB-PER-001 | EP-017 | New Service Creation | playbooks/13-endpoint-persistence/new-service-creation.md |
| PB-EP-13.2 | EP-018 | Scheduled Task Persistence | playbooks/13-endpoint-persistence/scheduled-task-persistence.md |
| EP-13-01 | EP-019 | Registry Run Key / RunOnce Persistence | playbooks/13-endpoint-persistence/registry-run-key-persistence.md |
| END-13.04 | EP-020 | Credential Dumping / LSASS Access / Mimikatz Indicators | playbooks/13-endpoint-persistence/credential-dumping-lsass-access-mimikatz-indicators.md |
| PB-13.05 | EP-021 | Process Injection | playbooks/13-endpoint-persistence/process-injection.md |
| EP-PERS-006 | EP-022 | Mass File Modification (Ransomware-Adjacent) | playbooks/13-endpoint-persistence/mass-file-modification-ransomware-adjacent.md |
| PB-EP-13.7 | EP-023 | Shadow Copy (VSS) Deletion | playbooks/13-endpoint-persistence/shadow-copy-vss-deletion.md |
| EP-13.04 | EP-024 | Security Tool Tampering / EDR Disabled | playbooks/13-endpoint-persistence/security-tool-tampering-edr-disabled.md |

## Network (NW, category 14)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| NET-14-01 | NW-001 | Network Port Scanning | playbooks/14-network/port-scanning.md |
| NET-14-03 | NW-002 | Internal Network Reconnaissance | playbooks/14-network/internal-network-reconnaissance.md |
| NET-14.01 | NW-003 | External Reconnaissance | playbooks/14-network/external-reconnaissance.md |
| — (none found) | NW-004 | C2 Communication | playbooks/14-network/c2-communication.md |
| PB-NET-04 | NW-005 | Beaconing (C2 Periodic Callback Activity) | playbooks/14-network/beaconing.md |
| NET-14-07 | NW-006 | DNS Tunnelling | playbooks/14-network/dns-tunnelling.md |
| PB-NET-04 | NW-007 | Large Outbound Data Transfer | playbooks/14-network/large-outbound-data-transfer.md |
| PB-NET-07 | NW-008 | Suspicious TLS | playbooks/14-network/suspicious-tls.md |
| PB-NET-01 | NW-009 | Known Malicious IP Hit | playbooks/14-network/known-malicious-ip-hit.md |
| PB-NET-10 | NW-010 | Known Malicious Domain Hit | playbooks/14-network/known-malicious-domain-hit.md |
| PB-NET-11 | NW-011 | Tor Activity | playbooks/14-network/tor-activity.md |
| NET-PXY-014 | NW-012 | Proxy Avoidance / Anonymizer Tooling Usage | playbooks/14-network/proxy-avoidance-tooling.md |
| NET-14-13 | NW-013 | Firewall Deny Spike | playbooks/14-network/firewall-deny-spike.md |
| NET-07 | NW-014 | Unusual Destination Country | playbooks/14-network/unusual-destination-country.md |
| NET-14-15 | NW-015 | Unexpected Inbound Service Exposure | playbooks/14-network/unexpected-inbound-service-exposure.md |
| NET-14-16 | NW-016 | Lateral Movement (Network View) | playbooks/14-network/lateral-movement-network-view.md |
| NET-14-17 | NW-017 | SMB Scanning | playbooks/14-network/smb-scanning.md |
| NET-014 | NW-018 | RDP Scanning | playbooks/14-network/rdp-scanning.md |
| NET-14-19 | NW-019 | SSH Attacks | playbooks/14-network/ssh-attacks.md |

*Note: `beaconing.md` and `large-outbound-data-transfer.md` both carried the identical old ID `PB-NET-04` — a real collision, not a typo. `port-scanning.md` (`NET-14-01`) and `external-reconnaissance.md` (`NET-14.01`) also collided under dash/dot notation. Both are resolved by this migration.*

## Web (WEB, category 15)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| WEB-15-003 | WEB-001 | SQL Injection | playbooks/15-web/sql-injection.md |
| WEB-XSS-01 | WEB-002 | XSS — Cross-Site Scripting Exploitation | playbooks/15-web/xss.md |
| WEB-15-004 | WEB-003 | Command Injection Detection and Response | playbooks/15-web/command-injection.md |
| WEB-15-004 | WEB-004 | Path Traversal (Directory Traversal) Detection and Response | playbooks/15-web/path-traversal.md |
| WEB-LFI-05 | WEB-005 | Local File Inclusion (LFI) Exploitation Attempt | playbooks/15-web/lfi.md |
| WEB-RFI-01 | WEB-006 | RFI — Remote File Inclusion Exploitation | playbooks/15-web/rfi.md |
| WEB-04 | WEB-007 | Web Shell Detection | playbooks/15-web/web-shell-detection.md |
| WEB-15-008 | WEB-008 | Credential Stuffing | playbooks/15-web/credential-stuffing.md |
| PB-15.1 | WEB-009 | Password Spraying (Web-Facing Authentication) | playbooks/15-web/password-spraying-web-facing.md |
| WEB-15-010 | WEB-010 | Admin Panel Scanning | playbooks/15-web/admin-panel-scanning.md |
| WEB-MFU-01 | WEB-011 | Malicious File Upload | playbooks/15-web/malicious-file-upload.md |
| WEB-RCE-01 | WEB-012 | Remote Code Execution (RCE) | playbooks/15-web/rce.md |
| WEB-15-013 | WEB-013 | API Abuse | playbooks/15-web/api-abuse.md |
| WEB-15-014 | WEB-014 | Enumeration | playbooks/15-web/enumeration.md |
| PB-15.15 | WEB-015 | Authentication Bypass | playbooks/15-web/authentication-bypass.md |
| WEB-SH-01 | WEB-016 | Session Hijacking | playbooks/15-web/session-hijacking.md |
| PB-15.17 | WEB-017 | Bot Traffic / Web Scraping | playbooks/15-web/bot-traffic-web-scraping.md |
| PB-WEB-04 | WEB-018 | Suspicious User-Agent | playbooks/15-web/suspicious-user-agent.md |

*Note: `command-injection.md` and `path-traversal.md` both carried the identical old ID `WEB-15-004` — another real collision resolved by this migration.*

## Email (EML, category 16)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| EML-PHISH-01 | EML-001 | Phishing | playbooks/16-email/phishing.md |
| PB-EMAIL-002 | EML-002 | Spear Phishing | playbooks/16-email/spear-phishing.md |
| EML-BEC-01 | EML-003 | Business Email Compromise | playbooks/16-email/bec.md |
| PB-EMAIL-004 | EML-004 | Malicious Attachment | playbooks/16-email/malicious-attachment.md |
| EML-16-05 | EML-005 | Malicious Link (Email) | playbooks/16-email/malicious-link.md |
| EML-16-006 | EML-006 | QR-Code Phishing (Quishing) | playbooks/16-email/qr-code-phishing.md |
| PB-EML-04 | EML-007 | Credential Phishing (Email) | playbooks/16-email/credential-phishing.md |
| EML-ACCT-08 | EML-008 | Internal (Compromised-Account) Phishing | playbooks/16-email/internal-compromised-account-phishing.md |
| PB-EMAIL-009 | EML-009 | Mailbox Forwarding Rule Abuse | playbooks/16-email/mailbox-forwarding-rule-abuse.md |
| PB-EMAIL-010 | EML-010 | Suspicious Inbox Rule Creation | playbooks/16-email/suspicious-inbox-rule-creation.md |
| PB-EMAIL-011 | EML-011 | OAuth App Abuse / Consent Phishing | playbooks/16-email/oauth-app-abuse-consent-phishing.md |
| PB-EML-004 | EML-012 | Impossible Travel (Mailbox Access) | playbooks/16-email/impossible-travel-mailbox-access.md |
| EMAIL-ATO-01 | EML-013 | Account Takeover (Email / M365 / Entra ID) | playbooks/16-email/account-takeover.md |
| PB-EMAIL-014 | EML-014 | Mass Outbound Email from Compromised Mailbox | playbooks/16-email/mass-outbound-email-from-compromised-mailbox.md |
| EML-EXEC-15 | EML-015 | Executive Impersonation | playbooks/16-email/executive-impersonation.md |
| EML-VEND-01 | EML-016 | Vendor Impersonation | playbooks/16-email/vendor-impersonation.md |

*Note: `impossible-travel-mailbox-access.md` (old `PB-EML-004`) and `malicious-attachment.md` (old `PB-EMAIL-004`) were one character apart under the old scheme — a near-collision, resolved by this migration.*

## Cloud (CLD, category 17)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| PB-CLD-11 | CLD-001 | Root / Global-Admin Account Usage | playbooks/17-cloud/root-global-admin-account-usage.md |
| CLD-17.04 | CLD-002 | New Access Key Creation | playbooks/17-cloud/new-access-key-creation.md |
| CLD-IAM-04 | CLD-003 | Suspicious IAM Policy Changes | playbooks/17-cloud/suspicious-iam-policy-changes.md |
| CLD-17-EXP-STOR-01 | CLD-004 | Public Storage Bucket Exposure | playbooks/17-cloud/public-storage-bucket-exposure.md |
| CLOUD-SG-01 | CLD-005 | Security Group Opened to the Internet | playbooks/17-cloud/security-group-opened-to-the-internet.md |
| PB-CLD-06 | CLD-006 | MFA Disabled on an Account | playbooks/17-cloud/mfa-disabled-on-an-account.md |
| PB-CLD-07 | CLD-007 | Impossible Travel (Cloud Sign-In) | playbooks/17-cloud/impossible-travel-cloud-sign-in.md |
| CLD-OAUTH-08 | CLD-008 | New OAuth Application Registered/Consented | playbooks/17-cloud/new-oauth-application-registered-consented.md |
| PB-CLD-09 | CLD-009 | Privilege Escalation via Role/Policy Chaining | playbooks/17-cloud/privilege-escalation-via-role-policy-chaining.md |
| CLD-AUD-01 | CLD-010 | Cloud Audit Logging Disabled | playbooks/17-cloud/cloud-audit-logging-disabled.md |
| PB-CLD-19 | CLD-011 | New Admin/Global-Admin Granted | playbooks/17-cloud/new-admin-global-admin-granted.md |
| PB-CLD-12 | CLD-012 | Access from Unusual Geography | playbooks/17-cloud/access-from-unusual-geography.md |
| CLD-STOR-13 | CLD-013 | Mass Object Download from Cloud Storage | playbooks/17-cloud/mass-object-download-from-storage.md |
| CLD-17-EXFIL-STOR-01 | CLD-014 | Storage-Based Exfiltration (Cloud) | playbooks/17-cloud/storage-based-exfiltration.md |
| CLD-17.15 | CLD-015 | Suspicious API Call Sequences | playbooks/17-cloud/suspicious-api-call-sequences.md |
| PB-CLD-17-06 | CLD-016 | Cloud Shell Abuse | playbooks/17-cloud/cloud-shell-abuse.md |
| CLD-17.17 | CLD-017 | Instance / VM Compromise Indicators | playbooks/17-cloud/instance-vm-compromise-indicators.md |
| CLD-17.18 | CLD-018 | Credential Leakage (Keys in Code/Logs) | playbooks/17-cloud/credential-leakage-keys-in-code-logs.md |

## AI Security (AI, category 18 + AI master)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| PB-AISEC-01 | AI-001 | Prompt Injection (Direct & Indirect) | playbooks/18-ai-security/prompt-injection.md |
| AISEC-03 | AI-002 | Indirect Prompt Injection | playbooks/18-ai-security/indirect-prompt-injection.md |
| AISEC-03 | AI-003 | LLM Data Leakage | playbooks/18-ai-security/llm-data-leakage.md |
| AI-SEC-01 | AI-004 | Sensitive Information Submitted to a Public/Unsanctioned AI Tool | playbooks/18-ai-security/sensitive-information-submitted-to-a-public-unsanctioned-ai-tool.md |
| AI-SEC-005 | AI-005 | AI API Key Compromise | playbooks/18-ai-security/ai-api-key-compromise.md |
| PB-AI-06 | AI-006 | AI Account Takeover | playbooks/18-ai-security/ai-account-takeover.md |
| AIS-AGT-07 | AI-007 | AI Agent Performing an Unauthorised Action | playbooks/18-ai-security/ai-agent-performing-an-unauthorised-action.md |
| PB-AI-18-08 | AI-008 | Agent Tool Abuse | playbooks/18-ai-security/agent-tool-abuse.md |
| AI-SEC-04 | AI-009 | RAG Poisoning | playbooks/18-ai-security/rag-poisoning.md |
| AI-18.10 | AI-010 | Knowledge Base Poisoning | playbooks/18-ai-security/knowledge-base-poisoning.md |
| AISEC-11 | AI-011 | System Prompt Extraction / Prompt Leakage | playbooks/18-ai-security/system-prompt-extraction-prompt-leakage.md |
| AISEC-12 | AI-012 | Jailbreak Behaviour | playbooks/18-ai-security/jailbreak-behaviour.md |
| AISEC-13 | AI-013 | AI-Generated Phishing Content Detected | playbooks/18-ai-security/ai-generated-phishing-content-detected.md |
| PB-AISEC-14 | AI-014 | AI-Assisted Malware Development Indicators | playbooks/18-ai-security/ai-assisted-malware-development-indicators.md |
| AISEC-15 | AI-015 | Model Endpoint Abuse | playbooks/18-ai-security/model-endpoint-abuse.md |
| AISEC-16 | AI-016 | Unusual Token Consumption | playbooks/18-ai-security/unusual-token-consumption.md |
| AI-SEC-017 | AI-017 | Automated API Scraping / Excessive Model Queries | playbooks/18-ai-security/automated-api-scraping-excessive-model-queries.md |
| PB-AI-18-18 | AI-018 | Data Exfiltration Attempted Through Prompts | playbooks/18-ai-security/data-exfiltration-attempted-through-prompts.md |
| PB-AI-18-19 | AI-019 | AI-Generated Command Execution via an Agent | playbooks/18-ai-security/ai-generated-command-execution-via-an-agent.md |
| PB-AI-18-20 | AI-020 | Model-Connected Tool Misuse | playbooks/18-ai-security/model-connected-tool-misuse.md |
| PB-AI-18-21 | AI-021 | MCP Server Abuse | playbooks/18-ai-security/mcp-server-abuse.md |
| AISEC-22 | AI-022 | AI Browser-Agent Abuse | playbooks/18-ai-security/ai-browser-agent-abuse.md |
| PB-AI-18-23 | AI-023 | AI Coding-Agent Modifying Sensitive Files Unexpectedly | playbooks/18-ai-security/ai-coding-agent-modifying-sensitive-files-unexpectedly.md |
| AIS-PRIV-24 | AI-024 | Agent Privilege Abuse | playbooks/18-ai-security/agent-privilege-abuse.md |
| PB-AISEC-24 | AI-025 | Malicious File Uploaded Into an AI System (Full Playbook — AI Master Playbook) | playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md |

*Note: `indirect-prompt-injection.md` and `llm-data-leakage.md` both carried the identical old ID `AISEC-03` — flagged directly in `TERMINOLOGY-STANDARD.md`'s own inconsistency writeup, and resolved here. `agent-privilege-abuse.md` (`AIS-PRIV-24`) and the AI master playbook (`PB-AISEC-24`) also coincidentally shared the number "24" under two different prefixes — not a true collision (different prefix), but a reminder of how fragile the old three-scheme mix was.*

## Insider Threat (INS, category 19)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| INSIDER-01 | INS-001 | Mass File Access | playbooks/19-insider/mass-file-access.md |
| INSIDER-07 | INS-002 | Large Download | playbooks/19-insider/large-download.md |
| INS-EXFIL-003 | INS-003 | USB Copying | playbooks/19-insider/usb-copying.md |
| INS-19-04 | INS-004 | Cloud Storage Upload of Sensitive Data | playbooks/19-insider/cloud-storage-upload-of-sensitive-data.md |
| INS-19-05 | INS-005 | Personal Email Transfer of Company Data | playbooks/19-insider/personal-email-transfer-of-company-data.md |
| INS-19-06 | INS-006 | Sensitive Repository Cloning | playbooks/19-insider/sensitive-repository-cloning.md |
| INS-07 | INS-007 | Printing of Sensitive Files | playbooks/19-insider/printing-of-sensitive-files.md |
| INSIDER-08 | INS-008 | Unusual Database Access | playbooks/19-insider/unusual-database-access.md |
| IT-19-002 | INS-009 | Departing-Employee Activity | playbooks/19-insider/departing-employee-activity.md |
| INSIDER-10 | INS-010 | Privileged Access Misuse | playbooks/19-insider/privileged-access-misuse.md |
| INSIDER-11 | INS-011 | Access Outside Job Role / Need-to-Know | playbooks/19-insider/access-outside-job-role-need-to-know.md |
| INSIDER-12 | INS-012 | Bulk Deletion of Data | playbooks/19-insider/bulk-deletion-of-data.md |

*Note: `printing-of-sensitive-files.md` (old `INS-07`) and `large-download.md`/`INSIDER-07` were a near-collision under the old scheme (`INS-07` vs `INSIDER-07`); resolved by this migration.*

## Master Playbooks (multi-stage, synthesised)

| Old ID | New ID | Playbook Title | File Path |
|---|---|---|---|
| PB-EXFIL-MASTER-001 | EXF-001 | Data Exfiltration Master Playbook | playbooks/20-data-exfiltration-master-playbook.md |
| RAN-MASTER-21 | RAN-001 | Ransomware Master Playbook | playbooks/21-ransomware-master-playbook.md |
| PB-MAL-MASTER-001 | MAL-001 | Malware Master Playbook | playbooks/22-malware-master-playbook.md |
| PB-AISEC-24 | AI-025 | Malicious File Uploaded Into an AI System (AI Master Playbook) | playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md |

---

**Total playbooks re-IDed: 160** (156 category playbooks across 10 categories + 4 master playbooks). The AI master playbook is listed both under AI Security (as it keeps an `AI-` id per the assigned scheme) and under Master Playbooks (its structural home in `BOOK-INDEX.md`), matching the "the AI master playbook keeps an `AI-` id" instruction in `TERMINOLOGY-STANDARD.md` — it is one playbook, one new ID (`AI-025`), counted once in the total.
