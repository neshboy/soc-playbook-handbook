# References

This appendix lists the source categories that ground the technical claims in *SIGNAL TO ACTION: The Complete SOC Playbook Handbook*. Event IDs, ATT&CK technique IDs, log field names and query syntax referenced throughout the book are drawn from the vendor and standards documentation below. Where a specific detail could not be verified against these source types, it was deliberately described in prose without attaching an ID, rather than guessed. Treat this list as a starting point for your own validation, not a substitute for it — vendor schemas change between product versions, and an event ID or field name that was accurate at time of writing can be deprecated, renamed, or reshaped by a platform update. Analysts building or maintaining playbooks against this book should re-check field names in their own tenant/version before shipping a detection.

## Vendor and Platform Documentation

**Microsoft Learn / Microsoft Security documentation** — grounds every Windows Security Event ID (logon types, account management, process creation auditing), Sysmon event schema and field definitions, Entra ID (formerly Azure AD) sign-in and audit log structure, and Microsoft 365 / Defender-family alerting and unified audit log behavior referenced in the detection engineering and Windows-focused investigation chapters. This is also the primary source for Active Directory authentication mechanics (Kerberos, NTLM) discussed in identity-based playbooks. Note that Microsoft's current product name for this capability is "Microsoft Purview Audit" (Standard/Premium tiers, managed from the Microsoft Purview portal); "unified audit log" persists at the technical layer (the `Search-UnifiedAuditLog` cmdlet, the `UnifiedAuditLogIngestionEnabled` setting) but is no longer the primary marketing name, so "Unified Audit Log" references elsewhere in this book mean the same underlying Purview Audit product.

**Sysmon documentation (Microsoft Sysinternals)** — grounds the Sysmon-specific event ID table, field naming (`Image`, `ParentImage`, `CommandLine`, `Hashes`, `TargetFilename`, etc.) and configuration schema used in endpoint detection examples throughout the engineering-depth sections.

**MITRE ATT&CK framework** — grounds every tactic, technique and sub-technique ID cited in the book's threat-mapping tables, playbook headers, and detection-to-technique cross-references. ATT&CK is also the structural basis for the book's own playbook categorization (initial access through impact) and for the adversary-emulation notes in the purple-team chapters.

**NIST guidance** — grounds the incident response lifecycle terminology (preparation, detection and analysis, containment/eradication/recovery, post-incident activity) drawn from NIST SP 800-61 Revision 2, and underpins risk-language and control-mapping references drawn from the NIST Cybersecurity Framework and SP 800-53 control families used in governance and audit-readiness sections. NIST SP 800-61 Revision 3 (April 2025) supersedes Revision 2 and reorganizes incident response guidance around the NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) instead of leading with the four-phase lifecycle cited above; that four-phase vocabulary is still widely used industry-wide and is retained here for continuity, but a reader building a new IR program from scratch should work from Revision 3 directly.

**CISA advisories** — grounds real-world campaign references, known-exploited-vulnerability framing, and the sector-notification and coordinated-disclosure conventions described in the escalation and external-reporting chapters.

**SANS materials** — grounds incident-handling methodology, the digital-forensics evidence-handling conventions (chain of custody, order of volatility), and several of the tabletop-exercise and IR-maturity assessment patterns referenced in the management-depth sections.

**AWS documentation** — grounds CloudTrail event structure, GuardDuty finding types, IAM policy evaluation logic, and VPC Flow Log field definitions used in the cloud-detection chapters covering AWS workloads.

**Google Cloud documentation** — grounds Cloud Audit Logs (Admin Activity and Data Access log categories), IAM binding and policy troubleshooting mechanics, and Google Cloud's native detection tooling referenced in the multi-cloud detection chapters.

**Elastic documentation** — grounds Elastic Common Schema (ECS) field naming conventions, Elastic Security detection rule syntax, and both Kibana Query Language (KQL) and ES|QL (Elasticsearch Query Language, the newer piped query language used in this book's Elastic worked examples) syntax used across engineering-depth query blocks written for the Elastic Stack. Elastic's KQL (Kibana Query Language) and Microsoft's KQL (Kusto Query Language, used elsewhere in this book for Sentinel and Defender Advanced Hunting) are unrelated languages that happen to share an acronym — confirm which platform a given "KQL" reference means before reusing a query.

**Splunk documentation** — grounds SPL (Search Processing Language) syntax, Common Information Model (CIM) field mapping, and Splunk Enterprise Security notable-event and correlation-search conventions used in the Splunk-flavored query examples throughout the book. Splunk was acquired by Cisco (deal closed March 2024) and now operates as "Splunk, a Cisco company"; the product, brand, and SPL syntax are unchanged by the acquisition.

**IBM QRadar documentation** — grounds QRadar's rule-building logic, offense-chaining behavior, and AQL (Ariel Query Language) syntax referenced in the QRadar-specific detection examples and the SIEM-comparison notes in the platform-selection chapter. These references apply to QRadar as an IBM-retained, on-premises/self-managed SIEM. In 2024, IBM transferred its QRadar SaaS/cloud customer base to Palo Alto Networks, which migrated those customers to Cortex XSIAM — a reader researching "QRadar cloud" or "QRadar SaaS" today will land on a Palo Alto Networks product, not an IBM one.

**Google SecOps / Chronicle documentation** — grounds the Unified Data Model (UDM) field structure and YARA-L detection rule syntax used in the Chronicle/SecOps query examples and the cloud-native SIEM chapters.

**OWASP** — grounds the web-application threat categories (injection, identification and authentication failures, SSRF, and related classes) referenced in application-layer incident playbooks and in the developer-facing sections on secure coding remediation. Category names and numbering shift across editions — OWASP renamed "Broken Authentication" to "Identification and Authentication Failures" in the Top 10:2021 edition, and a Top 10:2025 edition has since been published — so treat specific category labels as version-dependent rather than fixed.

**FIRST (Forum of Incident Response and Security Teams)** — grounds the Traffic Light Protocol (TLP) classification scheme used throughout the book's information-sharing guidance, and the CVSS scoring methodology referenced in vulnerability-triage sections.

**ENISA** — grounds the European regulatory and threat framing referenced in the compliance-adjacent sections covering EU-specific incident-reporting obligations and cross-border coordination.

## A Note on Version Drift

Every one of the sources above evolves faster than a printed or PDF-frozen playbook can track. QRadar AQL syntax, Splunk CIM field names, ECS field versions, and even Windows Security Event ID behavior (auditing policy defaults have shifted across Windows Server releases) are all moving targets.

**[MANAGEMENT]** - Assign a named owner for periodic reference validation (annually at minimum, or after a major platform upgrade) as part of the playbook governance cadence described in the maintenance chapter. A reference list that was accurate at publication and never revisited becomes a liability, not an asset — analysts trust documentation that "used to be right" longer than they should.
