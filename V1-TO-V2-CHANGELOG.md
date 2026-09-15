# V1 → V2 Changelog

Scannable, per-file summary of everything changed in the second pass. Grouped by area. Format: `File/Playbook - what changed`. Book-wide issues that were identified but deliberately **not** fixed in this pass (reserved for a dedicated global pass, or flagged as a judgment call) are documented in `SECOND-PASS-QA-REPORT.md`'s Open Limitations section, not here.

---

## Foundations

- `01-what-is-a-soc-playbook.md` - Standardized escalation-tier language (Tier 2 analyst → L2 analyst); fixed the SOP closure-codes example ("Confirmed Malicious" → "True Positive"); fixed the IR Plan trigger-clause example ("Confirmed Malicious ... Severity 2 incident" → "True Positive ... High-severity incident"); added an explicit "then close as True Positive" to the decision-gate example; fixed two "Password Spray" → "Password Spraying" instances.
- `02-why-playbooks-exist.md` - Reviewed in full; no terminology, technical-accuracy, or writing issues found. Left unchanged.
- `03-stakeholder-view.md` - Fixed the worked-example Escalation Path field and an engineering note ("Tier-1"/"Tier-2" → "L1"/"L2").
- `04a-master-template-fields.md` - Fixed the Escalation Criteria field definition (Tier 2/3 → L2/L3); corrected the Severity field's example value list to the full, correctly-ordered five-level scale (Informational/Low/Medium/High/Critical) — this is the canonical field definition every playbook in the book inherits.
- `04b-master-template-filled-example.md` - Fixed Escalation Criteria text, Containment Approval text, and a Metrics table row label (Tier 3/Tier 2/Tier 1 → L3/L2/L1); fixed two "Password Spray" instances; fixed "Catch credential brute-forcing" (banned synonym) → "Catch credential brute force attacks." Cross-checked the full 58-field master template against this filled example field-by-field — no drift found.
- `05-decision-tree.md` - Fixed four Tier 1/Tier 2 references to L1/L2 (opening paragraph, diagram node D, Q4 note, worked example); relabeled decision-tree endpoint [F] from a bare "INCIDENT" to "TRUE POSITIVE," adding a path for a confirmed-but-contained case to close without automatically becoming a formal Incident, and clarified the True-Positive-vs-Incident distinction in the Q5 prose.
- `06-building-from-detection-rule.md` - Fixed "(password spray)" → "(password spraying)"; replaced the ambiguous "True Positive/Incident" closure category in section 6.12 with "True Positive" plus a clarifying sentence that Incident declaration is a separate downstream step gated on the IR Plan's threshold.

## Technical Reference

- `07a-windows-events-logon-session.md` - Corrected the raw Logon ID field-name claims for 4634/4647 (TargetLogonId, not LogonId) and 4672 (SubjectLogonId, not TargetLogonId); replaced three non-canonical verdict labels ("Confirmed credential misuse," "Confirmed malicious" x2) with "True Positive"; fixed "password spray" → "password spraying" terminology (x2).
- `07b-windows-events-process-service.md` - Corrected 4697's required audit subcategory to "Audit Security System Extension" (was incorrectly stated as "Audit Other Object Access Events," which actually governs 4698-4702) in both the main section and the closing management note.
- `07c-windows-events-account-group.md` - Fixed a broken KQL query in which Member and Group fields were swapped relative to the real 4732 event schema (MemberName vs. TargetUserName), which would have mislabeled every result row; replaced a non-canonical closure phrase with "True Positive, escalated to a full incident."
- `07d-windows-events-lockout-kerberos-ntlm.md` - Replaced two non-canonical disposition phrases ("Escalated as confirmed intrusion," "Confirmed Kerberoasting attempt") with canonical terms; replaced "brute-forcing" with "running a brute force attempt" per the preferred-term table.
- `07e-windows-events-high-signal-powershell.md` - Replaced "the case closes as Confirmed Malicious" with "True Positive"; replaced non-canonical "Sev-1" (the only instance book-wide) with "Critical severity."
- `07f-windows-logon-types.md` - Replaced "write the verdict: Confirmed Malicious" with "True Positive" in the Type 10 RDP worked example; added a short L1/L2/L3 handoff note after the 6-step RDP investigation flow.
- `08a-sysmon-process-network-image.md` - Added a config-dependency note that Sysmon Event ID 3 (Network Connection) is disabled in the stock config by default; corrected the Event ID 7 (Image Loaded) framing from "on by default, filtered" to "off by default, must be deliberately enabled."
- `08b-sysmon-file-registry-pipe-dns.md` - Added a missing ProcessGuid row to the Event ID 22 (DNSEvent) field table; added a missing NewName row to the Event ID 14 (registry rename) field table; added a [STAKEHOLDER] callout to the Event ID 11 (FileCreate) ransomware-sweep discussion, which previously had zero business-impact framing.
- `09a-linux-auth-ssh-evidence.md` - Added a missing SUSE/openSUSE/SLES row to the distro auth-log-path table; removed an incorrect trailing "ssh2" from an example sshd "Invalid user" log line; replaced a hedged, ID-less ATT&CK reference with the verified ID T1136.001 (Create Account: Local Account); added the RHEL-family logrotate config path (`/etc/logrotate.d/syslog`) alongside the Debian-only one previously given.
- `09b-linux-persistence-execution-evidence.md` - Corrected the parent/child ordering in a curl-download-and-execute EXECVE worked example; corrected an overclaim that auditd is standard/enabled across both RHEL-family and Debian/Ubuntu-family by default; added caveats for musl/Alpine minimal images (no per-container auditd) and non-systemd hosts (OpenRC/BusyBox equivalents).

## Identity

- `playbooks/10-identity-ad-account/00-index.md` - Corrected all 14 File-column entries, which pointed to non-existent numbered filenames, to the real on-disk filenames.
- `playbooks/10-identity-ad-account/domain-policy-change.md` - Added the verified real MITRE ID T1484.001 (Group Policy Modification) in place of a false "no ATT&CK ID exists" disclaimer; fixed a fabricated cross-reference ID; standardized Tier 2 → L2 language.
- `playbooks/10-identity-ad-account/gpo-changes.md` - Same T1484.001 MITRE correction as domain-policy-change.md; standardized Tier 2 → L2 language.
- `playbooks/10-identity-ad-account/new-account-creation.md` - Fixed a broken KQL join comparing a column to itself, which silently defeated the intended "group-add within 30 minutes of account creation" filter; fixed two disposition-terminology violations.
- `playbooks/10-identity-ad-account/password-spraying.md` - Fixed two disposition-terminology violations ("True Positive - Contained," "Benign Positive / Expected Activity"); added a Stakeholder Communication section (GO/NO-GO framing for a reset-all-vs-reset-confirmed decision) found missing during an L1-analyst usability stress test.
- `playbooks/10-identity-ad-account/user-account-deletion.md` - Fixed a disposition-terminology violation ("Benign Positive / Expected Activity" → "Expected Activity"); standardized Tier 2 → L2 language.
- `playbooks/10-identity-ad-account/admin-group-membership-change.md` - Fixed "Pass-the-Hash/Ticket" hyphenation to the preferred term "Pass the Hash/Pass the Ticket."
- `playbooks/10-identity-ad-account/account-lockouts.md` - Standardized Tier 1/Tier 2 language to L1/L2; added a single-account root-cause KQL query (the file previously only had a query for the rarer multi-account correlation case) and a Stakeholder Communication section, per the usability stress test.
- `playbooks/10-identity-ad-account/privileged-account-login.md` - Standardized Tier 2 → L2 language.
- `playbooks/10-identity-ad-account/repeated-login-failures.md` - Standardized Tier 1/Tier 2 language to L1/L2.
- `playbooks/10-identity-ad-account/service-account-misuse.md` - Standardized Tier 2 → L2 language.
- `playbooks/10-identity-ad-account/successful-login-after-failures.md` - Standardized Tier 1/Tier 2 language to L1/L2.
- `playbooks/10-identity-ad-account/unexpected-password-reset.md` - Standardized Tier 1/Tier 2 language to L1/L2, preserving the unrelated Tier-0 AD-tiering-model reference on the same row.
- `playbooks/11-identity-ad-kerberos/kerberos-anomalies-general.md` - Replaced "Confirmed Malicious (escalated)" with "True Positive (escalated)"; converted Tier 2/Tier 3 references to L2/L3.
- `playbooks/11-identity-ad-kerberos/00-index.md` - Spelled out "MITRE ATT&CK" on first use in the table header.
- `playbooks/11-identity-ad-kerberos/as-rep-roasting.md` - Converted "Tier 2 SOC" to "L2 SOC" in Containment Options.
- `playbooks/11-identity-ad-kerberos/kerberoasting.md` - Converted Tier 2 references to L2; replaced an unexecutable instruction ("check historical distribution," no window given) with an explicit 30-day query and decision rule; added a Stakeholder Communication section, per the usability stress test.
- `playbooks/11-identity-ad-kerberos/ntlm-abuse.md` - Fixed the title's non-preferred "Pass-the-Hash" to "Pass the Hash"; spelled out two never-introduced "PtH" abbreviations; converted Tier 2 references to L2.
- `playbooks/11-identity-ad-kerberos/pass-the-hash.md` - Converted "Tier 1" to "L1"; spelled out a bare, never-introduced "PtH"; fixed a broken example SPL query referencing an undefined CIM field ("dest") that would silently return an empty/zero result instead of an error; added a Stakeholder Communication section, per the usability stress test.
- `playbooks/11-identity-ad-kerberos/pass-the-ticket.md` - Removed the "(PtT)" abbreviation (no exception granted for it, unlike PtH) and spelled out "Pass the Ticket" throughout; converted Tier 2 references to L2.
- `playbooks/11-identity-ad-kerberos/silver-ticket-indicators.md` - Converted Tier 3 references to L3.
- `playbooks/11-identity-ad-kerberos/suspicious-ldap-enumeration.md` - Converted Tier 2 references to L2.
- `playbooks/11-identity-ad-kerberos/dcsync.md` - Fixed a broken example KQL query that filtered on the wrong field against an allowlist (would false-positive-flood on nearly every DC) and referenced a nonexistent field name; in a follow-up pass, fixed an FQDN-vs-short-hostname allowlist mismatch and removed an unsupported 4672 field reference, adding inline caveats; added a Stakeholder Communication section, per the usability stress test.

## Endpoint

- `playbooks/12-endpoint-execution/00-index.md` - Corrected all 16 File-column entries (two were wrong beyond just a stale prefix) to match real on-disk filenames; added T1197 to the bitsadmin row.
- `playbooks/12-endpoint-execution/bitsadmin-abuse.md` - Added the verified MITRE ID T1197 (BITS Jobs) in place of a false "doesn't map to any technique ID" disclaimer; added a missing SLA target line.
- `playbooks/12-endpoint-execution/certutil-abuse-download-decode.md` - Added a missing SLA target line (MITRE mapping already verified correct, no change needed there).
- `playbooks/12-endpoint-execution/encoded-obfuscated-powershell.md` - Added a missing SLA target line; fixed an absolute local-path image reference to a relative path so it actually renders off-machine; added explicit correlation windows/lookback defaults to two investigation steps, per the usability stress test.
- `playbooks/12-endpoint-execution/powershell-spawned-by-an-office-application.md` - Added a missing SLA target line (MITRE mappings verified correct, no change needed there).
- `playbooks/12-endpoint-execution/cmd-exe-spawned-by-an-office-application.md` - Replaced the forbidden disposition synonym "Confirmed Malicious" (x3) with "True Positive - Contained."
- `playbooks/12-endpoint-execution/mshta-abuse.md` - Added a missing SLA target line and a default 7-day/30-day lookback to the lateral-spread investigation step, per the usability stress test.
- `playbooks/12-endpoint-execution/regsvr32-abuse.md` - Replaced "True Positive – Contained" with "True Positive"; added an SLA target; tied an undefined investigation window to the already-defined ±5-minute window, per the usability stress test.
- `playbooks/12-endpoint-execution/remote-administration-tool-abuse.md` - Added the verified MITRE IDs T1219/T1219.002 (Remote Access Tools/Remote Desktop Software) in place of a false "not in this book's supplied ID set" disclaimer; added an SLA target.
- `playbooks/12-endpoint-execution/suspicious-process-generic.md` - Replaced "True Positive – Contained" with "True Positive"; corrected a 4103/4104 log-source row that wrongly attributed de-obfuscated script content to both event IDs (only 4104 carries it); added an SLA target.
- `playbooks/12-endpoint-execution/suspicious-rundll32-usage.md` - Replaced "True Positive – Malicious Execution" with "True Positive"; substantiated the previously-unsupported T1055 Process Injection mapping with Sysmon Event IDs 8/10 and a matching investigation step; added an SLA target.
- `playbooks/12-endpoint-execution/unknown-unrecognised-executable-execution.md` - Replaced "True Positive – Contained" with "True Positive"; added an SLA target.
- `playbooks/12-endpoint-execution/unsigned-binary-execution.md` - Replaced "True Positive - Malicious Execution" with "True Positive"; added an SLA target.
- `playbooks/12-endpoint-execution/usb-triggered-execution.md` - Added the verified MITRE ID T1091 (Replication Through Removable Media), previously omitted despite being exactly this playbook's scenario; corrected the 4103/4104 log-source row; added an SLA target.
- `playbooks/12-endpoint-execution/wscript-cscript-abuse.md` - Replaced the imprecise bare "T1059" mapping with the correct, current sub-techniques T1059.005/T1059.007; added an SLA target.
- `playbooks/13-endpoint-persistence/registry-run-key-persistence.md` - Fixed a typo ("seperate" → "separate"); added an explicit 7-day/30-day default lookback to the fleet-wide scope query, per the usability stress test.
- `playbooks/13-endpoint-persistence/security-tool-tampering-edr-disabled.md` - Added a default lookback to the lateral-spread check; fixed a real approval-authority gap by splitting host-isolation containment into a standard-endpoint row (SOC lead) and a server/DC/Tier-0-1 row (IR lead + infrastructure-owner sign-off), which had previously let one person unilaterally isolate a domain controller, per the usability stress test.

## Network

- `playbooks/14-network/beaconing.md` - Fixed a broken Splunk SPL query in which `stdev` was computed over a single-row group per src/dest pair (effectively always 0), which silently defeated the intended hour-over-hour regularity filter; rewrote as a two-stage stats calculation.
- `playbooks/14-network/known-malicious-ip-hit.md` - Fixed a broken example KQL query referencing an undefined variable; added the correct `ThreatIntelligenceIndicator` table definition and filters.
- `playbooks/14-network/c2-communication.md` - Fixed an invented disposition label ("True Positive – Confirmed C2") to canonical "True Positive."
- `playbooks/14-network/external-reconnaissance.md` - Fixed an invented disposition label ("True Positive - Contained") to canonical "True Positive" (Closure Criteria and case note).
- `playbooks/14-network/large-outbound-data-transfer.md` - Fixed an invented disposition label ("True Positive - Confirmed Exfiltration") to canonical "True Positive" (x2); fixed a divide-by-null trap in the example query that silently dropped never-baselined hosts (the ones most worth scrutinizing) from results, per the usability stress test.
- `playbooks/14-network/00-index.md` - Corrected External Reconnaissance's primary-technique listing to match the detail page (added T1046 alongside T1595).
- `playbooks/14-network/ssh-attacks.md` - Corrected a MITRE mapping error (a vague "T1136-adjacent" reference) to the accurate T1098.004 (Account Manipulation: SSH Authorized Keys) for planted authorized_keys entries.
- `playbooks/14-network/proxy-avoidance-tooling.md` - Removed three decoratively-attached, mismatched MITRE IDs (T1204, T1105, T1027) that didn't fit a voluntary self-install scenario; fixed two illegally-compounded disposition labels.
- `playbooks/14-network/smb-scanning.md` - Fixed a compounded disposition label ("Closed True Positive - Reconnaissance") in the example case note.
- `playbooks/14-network/suspicious-tls.md` - Tightened T1071 to the matching sub-technique T1071.001 (Web Protocols); fixed a compounded disposition label.
- `playbooks/14-network/tor-activity.md` - Removed two adversary-driven MITRE IDs (T1105, T1204) misapplied to the file's own explicitly-labeled "not malware" voluntary-install case; reworked Closure Criteria to split "True Positive" from a new "Policy Violation" disposition path.
- `playbooks/14-network/unexpected-inbound-service-exposure.md` - Fixed a compounded disposition label ("True Positive (Exposure Confirmed)") in two places.
- `playbooks/14-network/unusual-destination-country.md` - Fixed malformed depth-marker headings embedding tags directly into heading text; fixed a compounded disposition label.
- `playbooks/14-network/dns-tunnelling.md` - Fixed an example SPL query calling a non-existent Splunk function (`entropy()`), replacing it with the real URL Toolbox `ut_shannon()` macro plus a no-external-app fallback; fixed an undefined `apex_domain` grouping field, per the usability stress test.
- `playbooks/14-network/port-scanning.md` - Fixed a typo ("seperate" → "separate"), per the usability stress test.

## Web

- `playbooks/15-web/00-index.md` - Corrected all 18 File-column entries to match real on-disk filenames.
- `playbooks/15-web/credential-stuffing.md` - Corrected a confirmed factual error: added the verified MITRE sub-technique T1110.004 (Credential Stuffing) in place of a false claim that no such sub-technique exists; fixed compound/non-standard disposition labels and tier language; added a default 30-day baseline-window definition, per the usability stress test.
- `playbooks/15-web/malicious-file-upload.md` - Corrected a confirmed factual error: added the verified MITRE sub-technique T1505.003 (Web Shell) in place of a false "not in this book's supplied ID set" disclaimer; tightened T1071 to T1071.001; fixed a disposition label and tier language.
- `playbooks/15-web/admin-panel-scanning.md` - Fixed a numeric mismatch between the detection prose ("10+ paths") and the example query's threshold (`> 8`); fixed non-standard disposition labels and tier language.
- `playbooks/15-web/api-abuse.md` - Fixed non-standard/compound disposition labels, splitting a blended closure condition into two correctly-scoped ones; converted tier language.
- `playbooks/15-web/authentication-bypass.md` - Converted tier language to L2; defined the previously-undefined "preceding lookback window" term (default 24h) and expanded the unexplained "IDOR" acronym, per the usability stress test.
- `playbooks/15-web/bot-traffic-web-scraping.md` - Fixed a non-standard disposition label; converted tier language.
- `playbooks/15-web/command-injection.md` - Fixed a non-standard disposition label ("True Positive - Contained"); converted tier language.
- `playbooks/15-web/enumeration.md` - Fixed two inconsistent compound disposition labels used within the same Closure Criteria section, merging them into one correctly-worded criterion; converted tier language.
- `playbooks/15-web/lfi.md` - Fixed non-standard disposition labels; converted tier language.
- `playbooks/15-web/session-hijacking.md` - Corrected MITRE mapping (added T1550.004 Web Session Cookie, replaced a mismatched T1552.001 with T1539 Steal Web Session Cookie); fixed a forbidden disposition synonym; updated Unified Audit Log naming; standardized depth-marker formatting.
- `playbooks/15-web/xss.md` - Corrected MITRE mapping (replaced T1552.001 with T1539 for cookie/token theft); fixed a forbidden disposition synonym and a slash-combined disposition; standardized depth-marker formatting.
- `playbooks/15-web/web-shell-detection.md` - Corrected a confirmed factual error: added the verified MITRE sub-technique T1505.003 in place of a false "no technique exists" claim; fixed disposition-label formatting; replaced an inaccurate "no Event ID confirmed" hedge with the real Sysmon/Windows Event IDs (1/4688, 3).
- `playbooks/15-web/rce.md` - Replaced an inaccurate telemetry-gap hedge with verified Sysmon/Event IDs; fixed disposition-label formatting; standardized depth-marker formatting.
- `playbooks/15-web/path-traversal.md` - Replaced an inaccurate telemetry-gap hedge with verified Sysmon/Event IDs; fixed disposition-label formatting; standardized depth-marker formatting.
- `playbooks/15-web/sql-injection.md` - Replaced an inaccurate telemetry-gap hedge with verified Sysmon/Event IDs; fixed disposition-label formatting; standardized depth-marker formatting; added explicit correlation windows and time bounds to the example query, per the usability stress test.
- `playbooks/15-web/rfi.md` - Replaced an inaccurate "no ID confirmed" hedge with verified Sysmon/Event IDs; resolved an ambiguous slash-combined disposition and fixed label formatting.
- `playbooks/15-web/password-spraying-web-facing.md` - Removed a stale "Azure AD" legacy prefix in favor of "Entra ID"; fixed a disposition-label formatting issue.
- `playbooks/15-web/suspicious-user-agent.md` - Removed a stale "Azure AD" legacy prefix; fixed a disposition-label formatting issue (Closure Criteria and case note).

## Email

- `playbooks/16-email/account-takeover.md` - Replaced "Confirmed Malicious" with "True Positive"; fixed a KQL operator-precedence bug (`or`/`and` mixed without parentheses) that let nearly all normal successful interactive sign-ins match the "risky" correlation; fixed a "password-spray" preferred-term violation.
- `playbooks/16-email/bec.md` - Replaced a non-canonical disposition with "True Positive"; removed two decorative/mismatched MITRE mappings (T1580, T1552.001); fixed three "Password Spray" preferred-term violations.
- `playbooks/16-email/credential-phishing.md` - Fixed a malformed depth marker; fixed a broken example KQL query referencing nonexistent columns (`TimeGenerated`, `EmailReceivedTime`) and an unquoted `ResultType` comparison.
- `playbooks/16-email/executive-impersonation.md` - Replaced non-canonical dispositions with "True Positive"; fixed a broken example KQL query joining against a nonexistent table/columns, replaced with the real `AuthenticationDetails` column and `Timestamp` field.
- `playbooks/16-email/impossible-travel-mailbox-access.md` - Fixed two malformed depth markers.
- `playbooks/16-email/internal-compromised-account-phishing.md` - Replaced a disallowed compound disposition with "True Positive"; fixed a "password spray" preferred-term violation.
- `playbooks/16-email/mailbox-forwarding-rule-abuse.md` - Reviewed in full; no corrections needed.
- `playbooks/16-email/malicious-attachment.md` - Fixed an undersized (MD5-length) hash literal mislabeled as SHA256; corrected a wrong field name (`AttachmentName` → `FileName`); fixed a disallowed compound disposition; added a realism note that SHA256 is frequently unpopulated on this table.
- `playbooks/16-email/00-index.md` - Reviewed in full; no corrections needed.
- `playbooks/16-email/mass-outbound-email-from-compromised-mailbox.md` - Replaced a non-canonical disposition with "True Positive"; added a Microsoft Purview Audit naming clarification.
- `playbooks/16-email/oauth-app-abuse-consent-phishing.md` - Added the verified MITRE ID T1550.001 (Application Access Token), previously absent; fixed a non-canonical disposition; flagged fragile positional-index KQL logic; simplified Entra ID naming; updated Purview naming and tier language.
- `playbooks/16-email/phishing.md` - Fixed two invented disposition variants; fixed a misleading `leftouter` KQL join that behaved like an inner join; added a missing T1552.001 parent-technique prefix; simplified Entra ID/Purview naming.
- `playbooks/16-email/qr-code-phishing.md` - Fixed a non-canonical disposition (x2) and a leftover mid-edit text artifact; updated tier and Purview naming.
- `playbooks/16-email/spear-phishing.md` - Fixed a non-canonical disposition; replaced 5 stale "Azure AD" references with "Entra ID"; added a command-line-auditing GPO caveat for Event ID 4688; updated tier language.
- `playbooks/16-email/suspicious-inbox-rule-creation.md` - Fixed a non-canonical disposition; simplified Entra ID naming; added Purview naming; updated tier language.
- `playbooks/16-email/vendor-impersonation.md` - Fixed two invented closure-disposition labels (the most severe terminology violation found in this category) to canonical "True Positive"/"Incident"; relabeled containment tiers to L1/L2/L3; added Purview naming.
- `playbooks/16-email/malicious-link.md` - Fixed a misleading `leftouter` KQL join; updated tier language; added Purview naming; verified all MITRE mappings, no changes needed.

## Cloud

- `playbooks/17-cloud/access-from-unusual-geography.md` - Replaced "Confirmed Malicious" with "True Positive"; added Purview naming; added a haversine travel-speed formula, a worked example matching the file's own case note, and named geo-IP cross-check tools, per the usability stress test.
- `playbooks/17-cloud/cloud-audit-logging-disabled.md` - Fixed an invented compound disposition to canonical "Expected Activity"; added Purview naming; strengthened the Business Risk section with explicit decision-owners and SLA.
- `playbooks/17-cloud/cloud-shell-abuse.md` - Corrected an inaccurate MITRE mapping (T1059.001 PowerShell → T1059.004 Unix Shell, since AWS/GCP Cloud Shell are Bash-only); split an invented combined disposition into two correctly-scoped terms.
- `playbooks/17-cloud/credential-leakage-keys-in-code-logs.md` - Added Purview naming; no other defects found.
- `playbooks/17-cloud/impossible-travel-cloud-sign-in.md` - Replaced "Confirmed Malicious" with "True Positive"; fixed a real KQL logic bug where an `array_length` filter was applied after `mv-expand`, making it a no-op; added Purview naming.
- `playbooks/17-cloud/instance-vm-compromise-indicators.md` - Reviewed in full; MITRE mapping and disposition terms verified accurate, no edits required.
- `playbooks/17-cloud/mass-object-download-from-storage.md` - Reviewed in full, no edits required for MITRE/disposition; added a manual-sampling fallback procedure for classification when no DLP tagging exists, per the usability stress test.
- `playbooks/17-cloud/mfa-disabled-on-an-account.md` - Fixed a disposition list citing a forbidden synonym and an invented term, remapped to "True Positive"/"Policy Violation"; removed a dangling cross-reference to a nonexistent playbook; added Purview naming.
- `playbooks/17-cloud/new-access-key-creation.md` - Added Purview naming; no other defects found.
- `playbooks/17-cloud/00-index.md` - Added a Purview naming clarification; verified the 18-row index and category MITRE list are accurate.
- `playbooks/17-cloud/new-admin-global-admin-granted.md` - Added the verified MITRE sub-technique T1098.003 (Additional Cloud Roles); fixed non-canonical disposition wording; fixed a logic bug comparing a full IAM ARN directly against a bare username; added a session-boundary definition and correlation window, per the usability stress test.
- `playbooks/17-cloud/new-oauth-application-registered-consented.md` - Added the verified MITRE ID T1550.001, previously absent despite being the core mechanism covered; fixed a non-canonical disposition; added concrete publisher-verification lookup paths and a reputation-tool pointer, per the usability stress test.
- `playbooks/17-cloud/privilege-escalation-via-role-policy-chaining.md` - Added the verified MITRE sub-technique T1098.003; fixed non-canonical disposition wording.
- `playbooks/17-cloud/public-storage-bucket-exposure.md` - Fixed non-canonical disposition labels (Closure Criteria and case note).
- `playbooks/17-cloud/root-global-admin-account-usage.md` - Added the verified MITRE sub-technique T1098.003; removed two unsupported/decorative MITRE IDs (T1531, T1552.001); fixed non-canonical disposition wording; fixed a logic bug joining sign-ins against the actor who granted a role rather than the actor who holds it.
- `playbooks/17-cloud/security-group-opened-to-the-internet.md` - Split a combined, ambiguous disposition into two correctly-scoped canonical terms; added working AWS CLI/Azure CLI/gcloud enumeration commands and a stakeholder message template, per the usability stress test.
- `playbooks/17-cloud/storage-based-exfiltration.md` - Removed an unsupported/decorative MITRE ID (T1048); fixed non-canonical disposition labels; fixed a misleading example query that summed object-key string length as a proxy for bytes transferred.
- `playbooks/17-cloud/suspicious-api-call-sequences.md` - Fixed a non-canonical disposition; fixed a KQL query citing a non-existent table name, replaced with the real `AWSCloudTrail` table; flagged a cross-platform stitching gap in the union logic.
- `playbooks/17-cloud/suspicious-iam-policy-changes.md` - Removed an unsupported/decorative MITRE ID (T1531); added the verified MITRE sub-technique T1098.003; fixed a non-canonical disposition.

## AI Security

- `playbooks/18-ai-security/00-index.md` - Fixed a typo ("seperately" → "separately").
- `playbooks/18-ai-security/agent-privilege-abuse.md` - Corrected a mismatched MITRE mapping (T1550.003 Pass the Ticket → T1550.001 Application Access Token) for stolen/replayed agent session tokens.
- `playbooks/18-ai-security/ai-account-takeover.md` - Replaced the forbidden disposition synonym "Confirmed Malicious" with "True Positive."
- `playbooks/18-ai-security/ai-agent-performing-an-unauthorised-action.md` - Replaced two instances of "True Positive - Contained" with "True Positive."
- `playbooks/18-ai-security/ai-api-key-compromise.md` - Corrected a genuine MITRE ID/name error (mislabeled T1098.001); fixed two non-canonical dispositions; added a per-key 90-day baseline KQL query and a Stakeholder Communication section, per the usability stress test.
- `playbooks/18-ai-security/ai-assisted-malware-development-indicators.md` - Replaced an invented compound disposition with the canonical "Expected Activity."
- `playbooks/18-ai-security/ai-browser-agent-abuse.md` - Replaced two instances of "True Positive - Contained" with "True Positive."
- `playbooks/18-ai-security/ai-coding-agent-modifying-sensitive-files-unexpectedly.md` - Replaced two non-canonical dispositions; fixed an unrealistic exact-timestamp KQL join, rewritten with a repo-path key and a 30-minute window.
- `playbooks/18-ai-security/ai-generated-phishing-content-detected.md` - Fixed a non-canonical hybrid severity label ("Medium-High" → "Medium"); fixed two malformed depth markers; replaced an invented suffixed disposition.
- `playbooks/18-ai-security/automated-api-scraping-excessive-model-queries.md` - Replaced two non-canonical dispositions; fixed a broken example SPL query using invalid syntax (`stdev(eval(...))`, nonexistent `lag()`), rewritten with `streamstats`.
- `playbooks/18-ai-security/jailbreak-behaviour.md` - Removed a misapplied MITRE ID (T1595 Active Scanning) and pointed to MITRE ATLAS AML.T0054; fixed a disposition-term violation.
- `playbooks/18-ai-security/knowledge-base-poisoning.md` - Removed two decorative MITRE IDs (T1087, T1069); narrowed a T1552.001 justification that cited a non-matching phishing example; fixed a disposition-term violation and tier language.
- `playbooks/18-ai-security/llm-data-leakage.md` - Fixed an abbreviated disposition shorthand and a disposition-term violation.
- `playbooks/18-ai-security/mcp-server-abuse.md` - Replaced a mismatched MITRE ID (T1105 → T1195.001/.002 Supply Chain Compromise) for a trojanized MCP package; removed a misapplied T1595 pairing; fixed a banned disposition synonym.
- `playbooks/18-ai-security/model-connected-tool-misuse.md` - Removed two mismatched MITRE IDs (T1204, T1078.004) directly contradicted by the file's own scope note; added a note on the lack of a clean matching Enterprise ATT&CK ID for this confused-deputy pattern.
- `playbooks/18-ai-security/model-endpoint-abuse.md` - Fixed a disposition-term violation.
- `playbooks/18-ai-security/prompt-injection.md` - Updated stale "M365 Unified Audit Log" naming to Microsoft Purview Audit; fixed a disposition-term violation; added a session-scoped KQL query (the only prior example swept all sessions) and clarified an undefined investigation window, per the usability stress test.
- `playbooks/18-ai-security/indirect-prompt-injection.md` - Updated stale Unified Audit Log naming to Microsoft Purview Audit.
- `playbooks/18-ai-security/rag-poisoning.md` - Fixed disposition-term violations in Closure Criteria and the example case note; added a chunk_id-scoped SPL query (the only prior example aggregated across all chunks) and a Stakeholder Communication template, per the usability stress test.
- `playbooks/18-ai-security/sensitive-information-submitted-to-a-public-unsanctioned-ai-tool.md` - Fixed an abbreviated disposition ("Confirmed TP." → "Confirmed True Positive.").
- `playbooks/18-ai-security/system-prompt-extraction-prompt-leakage.md` - Removed a misapplied MITRE ID (T1595) and pointed to MITRE ATLAS AML.T0051/AML.T0068.
- `playbooks/18-ai-security/unusual-token-consumption.md` - Fixed a disposition-term violation; added a missing SLA target and Stakeholder Communication template, per the usability stress test.
- `playbooks/18-ai-security/agent-tool-abuse.md` - Added a session/agent-scoped SPL query (the only prior example was an aggregate sweep with no session filter) and a Stakeholder Communication template, per the usability stress test.
- `playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md` - Added CISO escalation/sign-off/notification triggers (previously absent from the file entirely); added a [STAKEHOLDER] business-continuity paragraph; fixed a dangling row-E cross-reference in Escalation Criteria/Priority; rewrote the closing case note to show realistic (non-instant, partially-corroborated) telemetry, per the master-playbook usability/CISO stress test.

## Insider

- `playbooks/19-insider/bulk-deletion-of-data.md` - Added the verified MITRE ID T1485 (Data Destruction) in place of a false "no ID exists" claim; fixed disposition drift; removed a dead no-op line from the SPL example query.
- `playbooks/19-insider/usb-copying.md` - Added the verified MITRE ID T1052/T1052.001 (Exfiltration Over Physical Medium: USB), previously omitted with a false disclaimer.
- `playbooks/19-insider/sensitive-repository-cloning.md` - Replaced generic T1567 with the specific sub-technique T1567.001 (Exfiltration to Code Repository); fixed disposition drift.
- `playbooks/19-insider/printing-of-sensitive-files.md` - Corrected a factual error: T1052 does not cover hardcopy/paper exfiltration; replaced with an accurate statement that no ATT&CK technique exists for it, cross-referenced to the USB-copying playbook.
- `playbooks/19-insider/departing-employee-activity.md` - Trimmed three unsupported MITRE IDs; added T1052.001 (previously missing despite being discussed); corrected a misapplied T1531 investigation step; fixed disposition drift; dropped a legacy "Azure AD /" prefix; added Purview naming.
- `playbooks/19-insider/access-outside-job-role-need-to-know.md` - Fixed disposition drift (x2); added Purview naming.
- `playbooks/19-insider/cloud-storage-upload-of-sensitive-data.md` - Fixed disposition drift; added Purview naming.
- `playbooks/19-insider/personal-email-transfer-of-company-data.md` - Fixed disposition drift; added Purview naming.
- `playbooks/19-insider/mass-file-access.md` - Fixed disposition drift (x2); added Purview naming.
- `playbooks/19-insider/large-download.md` - Fixed a non-canonical bolded disposition tag; fixed "Sysmon EventID" → "Sysmon Event ID" formatting.
- `playbooks/19-insider/privileged-access-misuse.md` - Fixed a non-canonical bolded disposition tag; fixed two "EventID" → "Event ID" instances; added Purview naming.
- `playbooks/19-insider/unusual-database-access.md` - Fixed a non-canonical bolded disposition tag; fixed an invalid single-backtick SPL comment that would have broken the markdown code fence.

## Master Playbooks

- `playbooks/20-data-exfiltration-master-playbook.md` - Fixed an unfulfilled-promise intro reference; added a full worked example (incident SUG-2026-0904-PELLETIER) demonstrating imperfect, partial telemetry across channels; expanded and [STAKEHOLDER]-tagged the Business Risk paragraph with an explicit decision/consequence/owner triad; added a missing "is this ours" decision point and Expected Activity classification criteria; revised Escalation Criteria to distinguish compromise-indicator cases from legitimate-access cases; added business-continuity content to Recovery Steps; rewrote Communication Requirements as a full stakeholder-notification table; added a Post Incident Tasks item; fixed an internal forward-reference bug.
- `playbooks/21-ransomware-master-playbook.md` - Added header governance metadata (Version/Status/Approver); added a new Known Limitations section (VPN/NAT attribution, shared accounts, clock drift, log delay, retention limits); added a consolidated Response SLA section; added the Cyber Insurance Carrier as an explicit stakeholder in the notification chain; fixed the worked-example notification log to show a realistic pending acknowledgment instead of instant universal ack; added a business-continuity decision-ownership sentence to Stage 10; clarified the SOC Manager's role in declaring Sev-1/designating the Incident Commander; fixed an SLA-table decision cell that duplicated the acknowledge cell instead of stating an actual decision.
- `playbooks/22-malware-master-playbook.md` - Rewrote Closure Criteria to the canonical "True Positive — Contained" disposition; expanded the FIN-WK-0417/n.abara worked example with realistic SOC friction (lagging EDR verdict, unscored hash, command-line-auditing gap, near-miss benign triage, ambiguous sandbox score); rewrote the [STAKEHOLDER] containment note to state SLA clocks and decision ownership explicitly; added a CISO notification trigger for Critical-severity cases; added a business-continuity paragraph to Recovery Steps; aligned the Critical-escalation trigger wording ("multiple hosts" → "three or more hosts") with the Escalation Criteria section.
- `playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md` - Also reviewed as a master-scale playbook for CISO/stakeholder usability (see AI Security section above for the specific edits).

## Operations & Governance

- `23-siem-queries-core.md` - Fixed a wrong SecurityEvent field name (`Process` → `NewProcessName`); fixed a query run against the wrong table for Event 4104 (rewritten against the generic `Event` table, since 4104 never lands in SecurityEvent); corrected a swapped Kerberos ticket-encryption-type mapping (0x11 = AES128, 0x12 = AES256, previously reversed).
- `23-siem-queries-case-studies.md` - Fixed "Password Spray" → "Password Spraying" and consolidated dispositions to canonical terms across five case studies; fixed SPL field names to match the book's own convention; added the verified MITRE sub-techniques T1136.002/T1098.007 and corrected a false "doesn't cleanly fit an ATT&CK ID" claim to T1070.001; fixed a logic bug (unused `join_window` filter, missing OR parentheses, an unextracted field reference) in a case-study SPL query.
- `24-correlation-thinking-core.md` - Re-verified end-to-end (Event IDs, logon type, sub-status codes, MITRE IDs, sequence-rule pseudocode); no changes needed.
- `24-correlation-thinking-case-studies.md` - Fixed an internal field-name inconsistency (`bin_time` vs. `_time`); normalized non-canonical disposition tags across four case studies; corrected a MITRE mapping (T1098 → T1098.007).
- `25-false-positive-engineering-core.md` - Renamed the non-canonical disposition "True Positive Benign" to "Test Activity"; removed a fabricated "Informational" disposition (Informational is a severity level, not one of the nine dispositions); fixed a bare "T1550" citation to T1550.002/.003; normalized "password-spray"/"Brute-Force" terminology.
- `25-false-positive-engineering-case-studies.md` - Fixed "Possible Password Spray" → "Possible Password Spraying" (title and prose); fixed a non-canonical "Medium-High" severity to "High"; fixed a bare "T1550" citation to T1550.004.
- `26-client-approval-go-nogo-core.md` - Corrected a false "no ATT&CK ID assigned" claim for Event 1102 log-clearing to the accurate T1070.001; fixed invalid/non-idiomatic KQL syntax in a worked example; standardized tier language and "password-spray" terminology.
- `26-client-approval-go-nogo-case-studies.md` - Corrected a wrong MITRE mapping (T1098.001/T1538 → T1528 Steal Application Access Token); fixed a fabricated "1486" reference presented as a Windows Event ID (T1486 is an ATT&CK ID); tightened a mapping to T1098.007; resolved an internal terminology contradiction in Case Study 3 (retitled it and standardized the disposition to "Expected Activity"); added an explicit BEC label to Case Study 2.
- `29-severity-model-core.md` - Fixed a table where the "% of Max" column didn't match its own score-range column (two rows corrected); reworded a Scope rubric cell that duplicated wording from an adjacent level; reworded the cap-floor row to remove a misleading "Isolated" qualifier contradicted by the case studies' own recurring-pattern example.
- `29-severity-model-case-studies.md` - Fixed "password spray"/"spray hit" terminology; corrected a rubric-application scoring error in the Bramwell Logistics case (Exploit Success mis-scored 2 instead of 1), recomputing the total score and updating the summary table.
- `30-automation-and-soar-core.md` - Fixed a contradiction with the book's own Playbook Approval Matrix: replaced an invented "CISO_ONCALL" fallback approver with the matrix's actual approver (SOC Manager on-call), adding an explicit CISO-notify field.
- `30-automation-and-soar-case-studies.md` - Fixed a non-canonical disposition ("True Positive Benign" → "Benign Positive").
- `31-ai-assisted-soc-case-studies.md` - Corrected a factual error in a Kerberoasting-detection walkthrough (4768 does carry a TicketEncryptionType field; rewrote the real defect explanation around per-SPN ServiceName grouping); replaced "Confirmed Malicious" with "True Positive" in three case studies; fixed "Pass-the-Ticket" → "Pass the Ticket"; added [STAKEHOLDER] callouts to two case studies previously missing them.
- `32-metrics-core.md` - Renamed a section header item to match its own table ("Playbook Review Cadence" → "% Playbooks Reviewed on Schedule").
- `32-metrics-case-studies.md` - Fixed a non-canonical disposition phrase ("confirmed malicious" → "True Positive") in Case Study 3.
- `33-governance-core.md` - Spelled out "MITRE ATT&CK" on first bare use.
- `33-governance-case-studies.md` - Corrected a factual error about Event 4672's fields (it carries no Workstation/host field) across two case studies, rewriting the host-attribution logic to require Logon-ID correlation to 4624; fixed two non-canonical disposition labels; fixed "spray" terminology.
- `34-playbook-testing-core.md` - Fixed "ATT&CK" → "MITRE ATT&CK" on first use; verified all Event IDs, query syntax, and the worked example, no other changes needed.
- `34-playbook-testing-case-studies.md` - Reviewed only; no edits needed, all IDs verified.
- `35-playbook-failure-examples-core.md` - Fixed vagueness in the chapter's own "corrected" example (named a log source/window); fixed a non-canonical disposition contraction; fixed a MITRE mislabel ("T1098" for mailbox-rule manipulation → T1114.003); fixed inconsistent bare-P-number/severity pairing; strengthened a [STAKEHOLDER] section with named roles/SLAs; added a genuinely new sixth bad-example pair (undefined containment authority), updating chapter counts accordingly.
- `35-playbook-failure-examples-case-studies.md` - Fixed a bare "P2" to "High/P2" for consistency with the core-chapter fix; verified all other Event/technique IDs, no other changes needed.

## Appendices

- `appendices/00-appendices-index.md` - Fixed a bare "ATT&CK" reference to "MITRE ATT&CK" on first use.
- `appendices/36a-quickref-windows-powershell.md` - Added an OS-version caveat to the 4697 row; softened the RC4-only Kerberoasting flag description to Microsoft's broader "any non-AES type" guidance; added OS-version caveats to the 4798/4799 rows.
- `appendices/36b-quickref-sysmon-mitre.md` - Added the missing sub-techniques T1110.004 (Credential Stuffing) and T1550.001 (Application Access Token), both now cited by playbooks the index had fallen out of sync with.
- `appendices/36c-quickref-linux-cloud-email.md` - Updated the Unified Audit Log row and ANALYST callout to lead with the current product name "Microsoft Purview Audit."
- `appendices/36d-quickref-iocs-lolbins-processes.md` - Spelled out "Indicator of Compromise (IOC)" on first use.
- `appendices/37a-templates-core.md` - Replaced a forbidden disposition synonym ("Confirmed Malicious / Suspected Malicious") in the Stakeholder Summary Template's confidence field with canonical disposition vocabulary.
- `appendices/37b-templates-process.md` - Fixed the Case Documentation Template's severity field, which listed the five levels in reverse order; corrected to canonical ascending order.
- `appendices/38a-maturity-model.md` - Reviewed; no factual corrections needed (a pre-existing typo and the image-path convention were left untouched per instructions).
- `appendices/38b-references.md` - Updated the Microsoft Learn entry with current Purview Audit naming; corrected the NIST entry to note SP 800-61 Revision 3 (2025) supersedes the four-phase Rev 2 framing cited; added ES|QL to the Elastic entry alongside KQL; added a Splunk/Cisco corporate-status note; added an IBM QRadar SaaS-transfer-to-Palo-Alto-Networks clarification; updated the OWASP entry's stale "broken authentication" category label; removed a banned buzzword ("landscape") from the ENISA entry.

## ID System

- `PLAYBOOK-ID-MIGRATION-MAP.md` - New file: one row per playbook (161 rows covering 160 unique playbooks — the AI master playbook is deliberately listed twice), documenting the old-ID-to-new-ID mapping, written before any playbook file was touched.
- All 160 playbook files (156 category playbooks + 4 master playbooks) - Re-IDed in place under the `<DOMAIN>-<NNN>` scheme (IAM, EP, NW, WEB, EML, CLD, AI, INS, RAN/MAL/EXF), numbered in BOOK-INDEX.md order within each domain; a full-repo grep confirmed zero old IDs remain anywhere under `playbooks/`.
- `PLAYBOOK-COVERAGE-MATRIX.md` - New file: a 160-row coverage matrix (new ID, Domain, Threat, ATT&CK Technique(s), Primary/Secondary Telemetry, Stakeholder, Response Owner) plus a closing "Coverage Gaps & Near-Duplicates" section.
- `BOOK-INDEX.md` - Updated with new Playbook IDs throughout; 135 stale parenthetical old-ID mentions refreshed; added the missing "Core: AI-Assisted SOC Operations" index entry (`31-ai-assisted-soc-core.md`), correcting a previously-published claim that no core chapter existed for that topic.
- ID collisions resolved as part of the migration - `beaconing.md`/`large-outbound-data-transfer.md` (both formerly `PB-NET-04`); `command-injection.md`/`path-traversal.md` (both formerly `WEB-15-004`); `indirect-prompt-injection.md`/`llm-data-leakage.md` (both formerly `AISEC-03`).
- Cross-references - Added 7 new targeted cross-references (Kerberoasting ↔ Golden Ticket/Silver Ticket + Event ID 4769, Pass the Hash ↔ Credential Dumping/Pass the Ticket, Golden Ticket ↔ DCSync, RAG Poisoning ↔ Knowledge Base Poisoning, Known Malicious IP ↔ Domain Hit) and fixed roughly 13 pre-existing in-prose cross-references that had gone stale after citing old IDs.

## Global

- MITRE ATT&CK ID verification - Verified 16 ground-truth technique IDs directly against attack.mitre.org; confirmed all current/correctly named; identified the credential-stuffing (T1110.004) and OAuth-token (T1550.001) gaps that were then fixed in the Web/Email/Cloud sections above.
- Windows Security Event ID verification - Verified all 38 event IDs, log channels, audit subcategories, and the logon-type table against Microsoft Learn; confirmed no outright factual errors in the ground truth, informing the Technical Reference and Appendix 36a fixes above.
- SIEM/logging product naming verification - Verified current naming/status for AWS CloudTrail, Azure Activity Log, Entra ID sign-in logs, Microsoft 365 Unified Audit Log (confirmed rebrand to Microsoft Purview Audit), Microsoft Defender XDR, Google Cloud Audit Logs, Microsoft Sentinel, Splunk (now "a Cisco company"), Google SecOps/Chronicle, IBM QRadar/AQL (SaaS assets moved to Palo Alto Networks in 2024), and Elastic/ES|QL — findings applied across the Email, Cloud, Insider, and Appendix sections above.
- AI-security terminology sanity check - Verified prompt injection, indirect prompt injection, RAG/knowledge-base poisoning, MCP server abuse, agent tool/privilege abuse, coding-agent risk, system-prompt extraction, and jailbreak-behaviour terminology against OWASP LLM Top 10 2025, MITRE ATLAS, Invariant Labs' MCP research, and Anthropic's many-shot-jailbreaking research; no factual corrections needed beyond what's listed in the AI Security section above.
- References appendix verification - Verified all 14 authoritative sources cited in `appendices/38b-references.md`; 12 confirmed current as-is, 2 (NIST SP 800-61, OWASP category naming) found stale and corrected (see Appendices section above).
