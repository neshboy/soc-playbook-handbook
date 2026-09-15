# SIGNAL TO ACTION: The Complete SOC Playbook Handbook

### A Practitioner's Guide to Designing, Operating and Governing Modern SOC Playbooks

---

## How This Book Is Organised

This handbook moves from concept to practice to reference. **Front Matter** sets up who the book is for and how to read it. **Foundations** explains what a playbook actually is, why playbooks exist, how stakeholders read them differently from analysts, and how to build one from a bare detection rule, closing with a fully worked master-template example. **Technical Reference** is the evidence layer underneath every playbook — the Windows, Sysmon, and Linux log sources analysts pull from during an investigation. The **Playbook Library** is the operational core: category-organised, per-alert playbooks covering Identity, Endpoint, Network, Web, Email, Cloud, AI Security, and Insider Threat, plus four synthesised master playbooks for the multi-stage scenarios (ransomware, data exfiltration, malware triage, and AI malicious file upload) that don't fit a single-alert template. **Operations & Governance** covers the cross-cutting disciplines that make a playbook program actually work in production — SIEM query translation, correlation thinking, false-positive engineering, client approval workflows, escalation quality, stakeholder communication, severity scoring, automation/SOAR gating, AI-assisted SOC operations, metrics, governance, testing, and documented failure patterns — each as a core chapter paired with a worked case-studies companion. **Appendices** close the book with quick-reference tables, reusable templates and checklists, a maturity model, and source references.

---

## Front Matter

- [Front Matter — Title Page, Preface, Foreword, Who This Book Is For, How to Use This Book, Depth Markers](00-frontmatter.md)

---

## Foundations

- [Chapter 1: What Exactly Is a SOC Playbook?](01-what-is-a-soc-playbook.md)
- [Part 2: Why Playbooks Exist](02-why-playbooks-exist.md)
- [Part 3: The Stakeholder View of a Playbook](03-stakeholder-view.md)
- [Part 4A: The Master Playbook Template](04a-master-template-fields.md)
- [Part 4B: Fully Worked Example — Brute Force Authentication Followed by Successful Logon (PB-IAM-BF-001)](04b-master-template-filled-example.md)
- [Part 5: The Playbook Decision Tree](05-decision-tree.md)
- [Part 6: Building a Playbook from a Detection Rule](06-building-from-detection-rule.md)

---

## Technical Reference: Windows, Sysmon & Linux Log Sources

- [Windows Event ID Reference: Logon & Session Events](07a-windows-events-logon-session.md)
- [Windows Event IDs: Process & Service Lifecycle Events](07b-windows-events-process-service.md)
- [Windows Event IDs: Account & Group Management Events](07c-windows-events-account-group.md)
- [Windows Event IDs: Lockout, Kerberos & NTLM Events](07d-windows-events-lockout-kerberos-ntlm.md)
- [Windows Event ID Reference Cluster: High-Signal & PowerShell Events (1102, 4103, 4104)](07e-windows-events-high-signal-powershell.md)
- [Windows Logon Types Reference](07f-windows-logon-types.md)
- [Sysmon — Process, Network & Image Events (Event IDs 1, 3, 6, 7, 8, 10)](08a-sysmon-process-network-image.md)
- [Sysmon Event ID Reference Cluster: File, Registry, Pipe & DNS Events](08b-sysmon-file-registry-pipe-dns.md)
- [Linux Log Reference — Authentication & SSH Evidence](09a-linux-auth-ssh-evidence.md)
- [Linux Log Reference: Persistence & Execution Evidence](09b-linux-persistence-execution-evidence.md)

---

## Playbook Library

Each category below has its own index page followed by its individual playbooks, in the order they appear in that category's table of contents.

### 10 — Identity & Active Directory: Account & Authentication

- [Category Index](playbooks/10-identity-ad-account/00-index.md)
- [Repeated Login Failures (IAM-001)](playbooks/10-identity-ad-account/repeated-login-failures.md)
- [Brute Force / Password Guessing & Spraying (IAM-002)](playbooks/10-identity-ad-account/brute-force.md)
- [Password Spraying (IAM-003)](playbooks/10-identity-ad-account/password-spraying.md)
- [Successful Login After Failures (IAM-004)](playbooks/10-identity-ad-account/successful-login-after-failures.md)
- [Account Lockouts (IAM-005)](playbooks/10-identity-ad-account/account-lockouts.md)
- [Privileged Account Login (IAM-006)](playbooks/10-identity-ad-account/privileged-account-login.md)
- [Admin Group Membership Change (IAM-007)](playbooks/10-identity-ad-account/admin-group-membership-change.md)
- [New Account Creation (IAM-008)](playbooks/10-identity-ad-account/new-account-creation.md)
- [User Account Deletion (IAM-009)](playbooks/10-identity-ad-account/user-account-deletion.md)
- [Unexpected Password Reset (IAM-010)](playbooks/10-identity-ad-account/unexpected-password-reset.md)
- [Service Account Misuse (IAM-011)](playbooks/10-identity-ad-account/service-account-misuse.md)
- [Domain Policy Change (IAM-012)](playbooks/10-identity-ad-account/domain-policy-change.md)
- [GPO Changes (IAM-013)](playbooks/10-identity-ad-account/gpo-changes.md)
- [Domain Admin Group Modification (IAM-014)](playbooks/10-identity-ad-account/domain-admin-group-modification.md)

### 11 — Identity & Active Directory: Kerberos & Advanced Attacks

- [Category Index](playbooks/11-identity-ad-kerberos/00-index.md)
- [Kerberos Anomalies (General) (IAM-015)](playbooks/11-identity-ad-kerberos/kerberos-anomalies-general.md)
- [Golden Ticket Indicators (IAM-016)](playbooks/11-identity-ad-kerberos/golden-ticket-indicators.md)
- [Silver Ticket Indicators (IAM-017)](playbooks/11-identity-ad-kerberos/silver-ticket-indicators.md)
- [Kerberoasting Detection & Response (IAM-018)](playbooks/11-identity-ad-kerberos/kerberoasting.md)
- [AS-REP Roasting Detection & Response (IAM-019)](playbooks/11-identity-ad-kerberos/as-rep-roasting.md)
- [DCSync (Domain Replication Credential Theft) (IAM-020)](playbooks/11-identity-ad-kerberos/dcsync.md)
- [DCShadow (Rogue Domain Controller Replication Attack) (IAM-021)](playbooks/11-identity-ad-kerberos/dcshadow.md)
- [Pass the Hash (IAM-022)](playbooks/11-identity-ad-kerberos/pass-the-hash.md)
- [Pass the Ticket (Kerberos Ticket Theft & Reuse) (IAM-023)](playbooks/11-identity-ad-kerberos/pass-the-ticket.md)
- [NTLM Abuse (Downgrade, Relay Follow-On, Brute Force & Pass the Hash) (IAM-024)](playbooks/11-identity-ad-kerberos/ntlm-abuse.md)
- [Suspicious LDAP Enumeration (AD Object, Group & Trust Discovery) (IAM-025)](playbooks/11-identity-ad-kerberos/suspicious-ldap-enumeration.md)

### 12 — Endpoint: Execution & LOLBins

- [Category Index](playbooks/12-endpoint-execution/00-index.md)
- [Malware Detection (Generic AV/EDR Alert) (EP-001)](playbooks/12-endpoint-execution/malware-detection-generic-av-edr-alert.md)
- [Suspicious Process (Generic) (EP-002)](playbooks/12-endpoint-execution/suspicious-process-generic.md)
- [Encoded/Obfuscated PowerShell Execution (EP-003)](playbooks/12-endpoint-execution/encoded-obfuscated-powershell.md)
- [PowerShell Download Cradle (EP-004)](playbooks/12-endpoint-execution/powershell-download-cradle.md)
- [cmd.exe Spawned by an Office Application (EP-005)](playbooks/12-endpoint-execution/cmd-exe-spawned-by-an-office-application.md)
- [PowerShell Spawned by an Office Application (EP-006)](playbooks/12-endpoint-execution/powershell-spawned-by-an-office-application.md)
- [Suspicious rundll32 Usage (EP-007)](playbooks/12-endpoint-execution/suspicious-rundll32-usage.md)
- [regsvr32 Abuse (EP-008)](playbooks/12-endpoint-execution/regsvr32-abuse.md)
- [mshta Abuse (EP-009)](playbooks/12-endpoint-execution/mshta-abuse.md)
- [certutil Abuse (Download/Decode) (EP-010)](playbooks/12-endpoint-execution/certutil-abuse-download-decode.md)
- [bitsadmin Abuse (EP-011)](playbooks/12-endpoint-execution/bitsadmin-abuse.md)
- [WScript/CScript Abuse (EP-012)](playbooks/12-endpoint-execution/wscript-cscript-abuse.md)
- [Unknown / Unrecognised Executable Execution (EP-013)](playbooks/12-endpoint-execution/unknown-unrecognised-executable-execution.md)
- [Unsigned Binary Execution (EP-014)](playbooks/12-endpoint-execution/unsigned-binary-execution.md)
- [USB-Triggered Execution (EP-015)](playbooks/12-endpoint-execution/usb-triggered-execution.md)
- [Remote Administration Tool Abuse (EP-016)](playbooks/12-endpoint-execution/remote-administration-tool-abuse.md)

### 13 — Endpoint: Persistence & Impact

- [Category Index](playbooks/13-endpoint-persistence/00-index.md)
- [New Service Creation (EP-017)](playbooks/13-endpoint-persistence/new-service-creation.md)
- [Scheduled Task Persistence (EP-018)](playbooks/13-endpoint-persistence/scheduled-task-persistence.md)
- [Registry Run Key / RunOnce Persistence (EP-019)](playbooks/13-endpoint-persistence/registry-run-key-persistence.md)
- [Credential Dumping / LSASS Access / Mimikatz Indicators (EP-020)](playbooks/13-endpoint-persistence/credential-dumping-lsass-access-mimikatz-indicators.md)
- [Process Injection (EP-021)](playbooks/13-endpoint-persistence/process-injection.md)
- [Mass File Modification (Ransomware-Adjacent) (EP-022)](playbooks/13-endpoint-persistence/mass-file-modification-ransomware-adjacent.md)
- [Shadow Copy (VSS) Deletion (EP-023)](playbooks/13-endpoint-persistence/shadow-copy-vss-deletion.md)
- [Security Tool Tampering / EDR Disabled (EP-024)](playbooks/13-endpoint-persistence/security-tool-tampering-edr-disabled.md)

### 14 — Network

- [Category Index](playbooks/14-network/00-index.md)
- [Network Port Scanning (NW-001)](playbooks/14-network/port-scanning.md)
- [Internal Network Reconnaissance (NW-002)](playbooks/14-network/internal-network-reconnaissance.md)
- [External Reconnaissance (Pre-Compromise Scanning & Enumeration) (NW-003)](playbooks/14-network/external-reconnaissance.md)
- [C2 Communication (NW-004)](playbooks/14-network/c2-communication.md)
- [Beaconing (C2 Periodic Callback Activity) (NW-005)](playbooks/14-network/beaconing.md)
- [DNS Tunnelling / Covert C2 or Exfiltration over DNS (NW-006)](playbooks/14-network/dns-tunnelling.md)
- [Large Outbound Data Transfer (NW-007)](playbooks/14-network/large-outbound-data-transfer.md)
- [Suspicious TLS (NW-008)](playbooks/14-network/suspicious-tls.md)
- [Known Malicious IP Hit (NW-009)](playbooks/14-network/known-malicious-ip-hit.md)
- [Known Malicious Domain Hit (NW-010)](playbooks/14-network/known-malicious-domain-hit.md)
- [Tor Activity (NW-011)](playbooks/14-network/tor-activity.md)
- [Proxy Avoidance / Anonymizer Tooling Usage (NW-012)](playbooks/14-network/proxy-avoidance-tooling.md)
- [Firewall Deny Spike (NW-013)](playbooks/14-network/firewall-deny-spike.md)
- [Unusual Destination Country (Outbound Network Traffic) (NW-014)](playbooks/14-network/unusual-destination-country.md)
- [Unexpected Inbound Service Exposure (NW-015)](playbooks/14-network/unexpected-inbound-service-exposure.md)
- [Lateral Movement (Network View) (NW-016)](playbooks/14-network/lateral-movement-network-view.md)
- [SMB Scanning (NW-017)](playbooks/14-network/smb-scanning.md)
- [RDP Scanning (NW-018)](playbooks/14-network/rdp-scanning.md)
- [SSH Attacks (NW-019)](playbooks/14-network/ssh-attacks.md)

### 15 — Web

- [Category Index](playbooks/15-web/00-index.md)
- [SQL Injection (WEB-001)](playbooks/15-web/sql-injection.md)
- [XSS — Cross-Site Scripting Exploitation (WEB-002)](playbooks/15-web/xss.md)
- [Command Injection Detection and Response (WEB-003)](playbooks/15-web/command-injection.md)
- [Path Traversal (Directory Traversal) Detection and Response (WEB-004)](playbooks/15-web/path-traversal.md)
- [Local File Inclusion (LFI) Exploitation Attempt (WEB-005)](playbooks/15-web/lfi.md)
- [RFI — Remote File Inclusion Exploitation (WEB-006)](playbooks/15-web/rfi.md)
- [Web Shell Detection (WEB-007)](playbooks/15-web/web-shell-detection.md)
- [Credential Stuffing (WEB-008)](playbooks/15-web/credential-stuffing.md)
- [Password Spraying (Web-Facing Authentication) (WEB-009)](playbooks/15-web/password-spraying-web-facing.md)
- [Admin Panel Scanning (WEB-010)](playbooks/15-web/admin-panel-scanning.md)
- [Malicious File Upload (WEB-011)](playbooks/15-web/malicious-file-upload.md)
- [Remote Code Execution (RCE) (WEB-012)](playbooks/15-web/rce.md)
- [API Abuse (BOLA, Key Theft, Excessive Data Access, Rate-Limit Evasion) (WEB-013)](playbooks/15-web/api-abuse.md)
- [Enumeration (Reconnaissance Against Web Applications and APIs) (WEB-014)](playbooks/15-web/enumeration.md)
- [Authentication Bypass (WEB-015)](playbooks/15-web/authentication-bypass.md)
- [Session Hijacking — Web/Cloud Session Token Theft and Replay (WEB-016)](playbooks/15-web/session-hijacking.md)
- [Bot Traffic / Web Scraping (WEB-017)](playbooks/15-web/bot-traffic-web-scraping.md)
- [Suspicious User-Agent (WEB-018)](playbooks/15-web/suspicious-user-agent.md)

### 16 — Email

- [Category Index](playbooks/16-email/00-index.md)
- [Phishing (EML-001 — General / Commodity Email-Borne Initial Access)](playbooks/16-email/phishing.md)
- [Spear Phishing (EML-002)](playbooks/16-email/spear-phishing.md)
- [Business Email Compromise (Cloud Mailbox Takeover & Financial Fraud) (EML-003)](playbooks/16-email/bec.md)
- [Malicious Attachment (EML-004)](playbooks/16-email/malicious-attachment.md)
- [Malicious Link (Email) (EML-005)](playbooks/16-email/malicious-link.md)
- [QR-Code Phishing (Quishing) Detection and Response (EML-006)](playbooks/16-email/qr-code-phishing.md)
- [Credential Phishing (Email) (EML-007)](playbooks/16-email/credential-phishing.md)
- [Internal (Compromised-Account) Phishing — Lateral Spread from a Trusted Mailbox (EML-008)](playbooks/16-email/internal-compromised-account-phishing.md)
- [Mailbox Forwarding Rule Abuse (EML-009)](playbooks/16-email/mailbox-forwarding-rule-abuse.md)
- [Suspicious Inbox Rule Creation (EML-010)](playbooks/16-email/suspicious-inbox-rule-creation.md)
- [OAuth App Abuse / Consent Phishing (EML-011)](playbooks/16-email/oauth-app-abuse-consent-phishing.md)
- [Impossible Travel (Mailbox Access) (EML-012)](playbooks/16-email/impossible-travel-mailbox-access.md)
- [Account Takeover (Email / M365 / Entra ID) (EML-013)](playbooks/16-email/account-takeover.md)
- [Mass Outbound Email from Compromised Mailbox (EML-014)](playbooks/16-email/mass-outbound-email-from-compromised-mailbox.md)
- [Executive Impersonation (CEO/CFO Fraud, External Spoof or Lookalike Domain) (EML-015)](playbooks/16-email/executive-impersonation.md)
- [Vendor Impersonation (Supplier/Invoice Fraud) (EML-016)](playbooks/16-email/vendor-impersonation.md)

### 17 — Cloud (AWS / Azure / M365 / Entra ID / GCP)

- [Category Index](playbooks/17-cloud/00-index.md)
- [Root / Global-Admin Account Usage (CLD-001)](playbooks/17-cloud/root-global-admin-account-usage.md)
- [New Access Key Creation (CLD-002)](playbooks/17-cloud/new-access-key-creation.md)
- [Suspicious IAM Policy Changes (CLD-003)](playbooks/17-cloud/suspicious-iam-policy-changes.md)
- [Public Storage Bucket Exposure (CLD-004)](playbooks/17-cloud/public-storage-bucket-exposure.md)
- [Security Group Opened to the Internet (CLD-005)](playbooks/17-cloud/security-group-opened-to-the-internet.md)
- [MFA Disabled on an Account (CLD-006)](playbooks/17-cloud/mfa-disabled-on-an-account.md)
- [Impossible Travel (Cloud Sign-In) (CLD-007)](playbooks/17-cloud/impossible-travel-cloud-sign-in.md)
- [New OAuth Application Registered/Consented (CLD-008)](playbooks/17-cloud/new-oauth-application-registered-consented.md)
- [Privilege Escalation via Role/Policy Chaining (CLD-009)](playbooks/17-cloud/privilege-escalation-via-role-policy-chaining.md)
- [Cloud Audit Logging Disabled (CLD-010)](playbooks/17-cloud/cloud-audit-logging-disabled.md)
- [New Admin/Global-Admin Granted (CLD-011)](playbooks/17-cloud/new-admin-global-admin-granted.md)
- [Access from Unusual Geography (CLD-012)](playbooks/17-cloud/access-from-unusual-geography.md)
- [Mass Object Download from Cloud Storage (CLD-013)](playbooks/17-cloud/mass-object-download-from-storage.md)
- [Storage-Based Exfiltration (Cloud) (CLD-014)](playbooks/17-cloud/storage-based-exfiltration.md)
- [Suspicious API Call Sequences (CLD-015)](playbooks/17-cloud/suspicious-api-call-sequences.md)
- [Cloud Shell Abuse (CLD-016)](playbooks/17-cloud/cloud-shell-abuse.md)
- [Instance / VM Compromise Indicators (CLD-017)](playbooks/17-cloud/instance-vm-compromise-indicators.md)
- [Credential Leakage (Keys in Code/Logs) (CLD-018)](playbooks/17-cloud/credential-leakage-keys-in-code-logs.md)

### 18 — AI Security

- [Category Index](playbooks/18-ai-security/00-index.md)
- [Prompt Injection (Direct & Indirect) Against LLM-Integrated Applications (AI-001)](playbooks/18-ai-security/prompt-injection.md)
- [Indirect Prompt Injection: Untrusted Content Hijacking an AI Agent/Copilot (AI-002)](playbooks/18-ai-security/indirect-prompt-injection.md)
- [LLM Data Leakage (AI-003)](playbooks/18-ai-security/llm-data-leakage.md)
- [Sensitive Information Submitted to a Public/Unsanctioned AI Tool (AI-004)](playbooks/18-ai-security/sensitive-information-submitted-to-a-public-unsanctioned-ai-tool.md)
- [AI API Key Compromise (AI-005)](playbooks/18-ai-security/ai-api-key-compromise.md)
- [AI Account Takeover (AI-006)](playbooks/18-ai-security/ai-account-takeover.md)
- [AI Agent Performing an Unauthorised Action (AI-007)](playbooks/18-ai-security/ai-agent-performing-an-unauthorised-action.md)
- [Agent Tool Abuse (AI-008)](playbooks/18-ai-security/agent-tool-abuse.md)
- [RAG Poisoning (Knowledge Base / Retrieval Corpus Injection) (AI-009)](playbooks/18-ai-security/rag-poisoning.md)
- [Knowledge Base Poisoning (AI-010)](playbooks/18-ai-security/knowledge-base-poisoning.md)
- [System Prompt Extraction / Prompt Leakage (AI-011)](playbooks/18-ai-security/system-prompt-extraction-prompt-leakage.md)
- [Jailbreak Behaviour (AI-012)](playbooks/18-ai-security/jailbreak-behaviour.md)
- [AI-Generated Phishing Content Detected (AI-013)](playbooks/18-ai-security/ai-generated-phishing-content-detected.md)
- [AI-Assisted Malware Development Indicators (AI-014)](playbooks/18-ai-security/ai-assisted-malware-development-indicators.md)
- [Model Endpoint Abuse (AI-015)](playbooks/18-ai-security/model-endpoint-abuse.md)
- [Unusual Token Consumption (AI-016)](playbooks/18-ai-security/unusual-token-consumption.md)
- [Automated API Scraping / Excessive Model Queries (AI-017)](playbooks/18-ai-security/automated-api-scraping-excessive-model-queries.md)
- [Data Exfiltration Attempted Through Prompts (AI-018)](playbooks/18-ai-security/data-exfiltration-attempted-through-prompts.md)
- [AI-Generated Command Execution via an Agent (AI-019)](playbooks/18-ai-security/ai-generated-command-execution-via-an-agent.md)
- [Model-Connected Tool Misuse (Confused-Deputy / Authorization-Boundary Bypass) (AI-020)](playbooks/18-ai-security/model-connected-tool-misuse.md)
- [MCP Server Abuse (AI-021)](playbooks/18-ai-security/mcp-server-abuse.md)
- [AI Browser-Agent Abuse (AI-022)](playbooks/18-ai-security/ai-browser-agent-abuse.md)
- [AI Coding-Agent Modifying Sensitive Files Unexpectedly (AI-023)](playbooks/18-ai-security/ai-coding-agent-modifying-sensitive-files-unexpectedly.md)
- [Agent Privilege Abuse (AI-024)](playbooks/18-ai-security/agent-privilege-abuse.md)
- *Malicious File Uploaded Into an AI System (AI-025) — see [Master Playbooks](#master-playbooks-multi-stage-synthesised) below; the file lives in this same folder.*

### 19 — Insider Threat

- [Category Index](playbooks/19-insider/00-index.md)
- [Mass File Access (Anomalous Bulk File/Object Access) (INS-001)](playbooks/19-insider/mass-file-access.md)
- [Large Download (Anomalous Bulk Data Access & Local Staging) (INS-002)](playbooks/19-insider/large-download.md)
- [USB Copying (Removable Media Exfiltration) (INS-003)](playbooks/19-insider/usb-copying.md)
- [Cloud Storage Upload of Sensitive Data (INS-004)](playbooks/19-insider/cloud-storage-upload-of-sensitive-data.md)
- [Personal Email Transfer of Company Data (INS-005)](playbooks/19-insider/personal-email-transfer-of-company-data.md)
- [Sensitive Repository Cloning (INS-006)](playbooks/19-insider/sensitive-repository-cloning.md)
- [Printing of Sensitive Files (Insider Threat) (INS-007)](playbooks/19-insider/printing-of-sensitive-files.md)
- [Unusual Database Access (Anomalous Query, Table, or Volume Pattern) (INS-008)](playbooks/19-insider/unusual-database-access.md)
- [Departing-Employee Activity (Insider Threat) (INS-009)](playbooks/19-insider/departing-employee-activity.md)
- [Privileged Access Misuse (Authorized-Access Abuse by Privileged Accounts) (INS-010)](playbooks/19-insider/privileged-access-misuse.md)
- [Access Outside Job Role / Need-to-Know (INS-011)](playbooks/19-insider/access-outside-job-role-need-to-know.md)
- [Bulk Deletion of Data (Anomalous Mass Deletion / Data Destruction) (INS-012)](playbooks/19-insider/bulk-deletion-of-data.md)

### Master Playbooks (Multi-Stage, Synthesised)

These four playbooks cover attack patterns that span many stages and channels rather than a single alert. Each is the finished, synthesised document — the working notes that fed into them live in `playbooks/_drafts/` and are not part of the reading path (see closing note below).

- [Data Exfiltration Master Playbook — Multi-Channel Detection, Investigation, and Response (EXF-001)](playbooks/20-data-exfiltration-master-playbook.md)
- [Ransomware Master Playbook (RAN-001) — Full Attack Lifecycle & Incident Command Field Guide](playbooks/21-ransomware-master-playbook.md)
- [Malware Master Playbook — Generic Malware Triage, End to End (MAL-001)](playbooks/22-malware-master-playbook.md)
- [Malicious File Uploaded Into an AI System (Full Playbook) (AI-025)](playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md)

---

## Operations & Governance

Each topic below is a core chapter paired with a companion case-studies file.

**23 — SIEM Queries Across Platforms**
- [Core: Playbook Queries Across SIEM Platforms](23-siem-queries-core.md)
- [Case Studies: Playbook Queries Across SIEM Platforms](23-siem-queries-case-studies.md)

**24 — Correlation Thinking**
- [Core: Correlation Thinking — Why the Chain Matters More Than Any Single Link](24-correlation-thinking-core.md)
- [Case Studies: Correlation Thinking](24-correlation-thinking-case-studies.md)

**25 — False Positive Engineering**
- [Core: False Positive Engineering](25-false-positive-engineering-core.md)
- [Case Studies: False Positive Engineering](25-false-positive-engineering-case-studies.md)

**26 — Client Approval and GO/NO GO Decisions**
- [Core: Client Approval and GO/NO GO Decisions](26-client-approval-go-nogo-core.md)
- [Case Studies: Client Approval and GO/NO GO Decisions](26-client-approval-go-nogo-case-studies.md)

**27 — Escalation Quality**
- [Core: Escalation Quality — What Tier 2 Actually Needs From You](27-escalation-quality-core.md)
- [Case Studies: Escalation Quality](27-escalation-quality-case-studies.md)

**28 — SOC-to-Stakeholder Communication**
- [Core: SOC to Stakeholder Communication](28-stakeholder-communication-core.md)
- [Case Studies: Stakeholder Communication](28-stakeholder-communication-case-studies.md)

**29 — Playbook Severity Model**
- [Core: Playbook Severity Model](29-severity-model-core.md)
- [Case Studies: Playbook Severity Model](29-severity-model-case-studies.md)

**30 — Automation and SOAR**
- [Core: Automation and SOAR — What to Automate, What to Gate](30-automation-and-soar-core.md)
- [Case Studies: Automation and SOAR](30-automation-and-soar-case-studies.md)

**31 — AI-Assisted SOC Operations**
- [Core: AI-Assisted SOC Operations](31-ai-assisted-soc-core.md)
- [Case Studies: AI-Assisted SOC Operations](31-ai-assisted-soc-case-studies.md)

**32 — Metrics**
- [Core: Metrics — Making the Numbers Tell the Truth](32-metrics-core.md)
- [Case Studies: SOC Metrics](32-metrics-case-studies.md)

**33 — Governance**
- [Core: Governance — The Header Nobody Reads Until an Auditor Does](33-governance-core.md)
- [Case Studies: Playbook Governance](33-governance-case-studies.md)

**34 — Playbook Testing**
- [Core: Playbook Testing](34-playbook-testing-core.md)
- [Case Studies: Playbook Testing](34-playbook-testing-case-studies.md)

**35 — Playbook Failure Examples**
- [Core: Playbook Failure Examples](35-playbook-failure-examples-core.md)
- [Case Studies: Playbook Failure Examples](35-playbook-failure-examples-case-studies.md)

---

## Appendices

- [Appendices — Index](appendices/00-appendices-index.md)
- [Appendix 36A: Quick Reference — Windows Event IDs, Logon Types & PowerShell Logging](appendices/36a-quickref-windows-powershell.md)
- [Appendix 36B: Quick Reference — Sysmon Event IDs & MITRE ATT&CK Technique Index](appendices/36b-quickref-sysmon-mitre.md)
- [Appendix 36C: Quick Reference — Linux Auth Logs, Cloud/M365 Log Sources, Email Headers & Network Investigation Fields](appendices/36c-quickref-linux-cloud-email.md)
- [Appendix 36D: Quick Reference — IOC Types, LOLBins, Persistence Locations & Process Lineage](appendices/36d-quickref-iocs-lolbins-processes.md)
- [Appendix 37A: Templates Cluster A — Master Playbook, Stakeholder Summary, Investigation, Escalation](appendices/37a-templates-core.md)
- [Appendix 37B: Templates & Process, Cluster B](appendices/37b-templates-process.md)
- [Appendix 37C: Playbook Review, QA, and Testing Checklists, and the Approval Matrix](appendices/37c-checklists-and-approval-matrix.md)
- [Playbook Maturity Model](appendices/38a-maturity-model.md)
- [References](appendices/38b-references.md)

---

## Note on `playbooks/_drafts/`

The `playbooks/_drafts/` folder (subfolders `20-data-exfiltration-master/`, `21-ransomware-master/`, `22-malware-master/`, and `18-ai-malicious-file-upload/`) contains only the working stage-by-stage and section-by-section material that was drafted while building the four master playbooks listed above. Every piece of it has already been folded into the finished, synthesised master playbooks (`playbooks/20-data-exfiltration-master-playbook.md`, `playbooks/21-ransomware-master-playbook.md`, `playbooks/22-malware-master-playbook.md`, and `playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md`). It is retained as source material only and is **not** part of this book's reading path.
