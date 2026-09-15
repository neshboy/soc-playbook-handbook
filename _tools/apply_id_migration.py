# -*- coding: utf-8 -*-
"""
Applies the Playbook ID migration described in PLAYBOOK-ID-MIGRATION-MAP.md.
For each file, replaces the OLD id token with the NEW id token, but only
within the header region (first HEADER_LINES lines) of the file, and only
where the old id appears as a standalone token (not part of a longer token).
Reports any file where the expected replacement count is not exactly what
was anticipated, so it can be checked by hand.
"""
import re
import sys

ROOT = "C:/Users/User/SOC-Playbook-Handbook/"
HEADER_LINES = 20

# (relative_path, old_id_or_None, new_id)
MIGRATIONS = [
    ("playbooks/10-identity-ad-account/repeated-login-failures.md", "IAM-AUTH-001", "IAM-001"),
    ("playbooks/10-identity-ad-account/brute-force.md", "IAM-AUTH-04", "IAM-002"),
    ("playbooks/10-identity-ad-account/password-spraying.md", "IAA-AUTH-04", "IAM-003"),
    ("playbooks/10-identity-ad-account/successful-login-after-failures.md", "IAM-AUTH-004", "IAM-004"),
    ("playbooks/10-identity-ad-account/account-lockouts.md", "IAM-AUTH-05", "IAM-005"),
    ("playbooks/10-identity-ad-account/privileged-account-login.md", "IAM-AUTH-002", "IAM-006"),
    ("playbooks/10-identity-ad-account/admin-group-membership-change.md", "IAM-AUTH-07", "IAM-007"),
    ("playbooks/10-identity-ad-account/new-account-creation.md", "ID-AD-01", "IAM-008"),
    ("playbooks/10-identity-ad-account/user-account-deletion.md", "AD-ACC-06", "IAM-009"),
    ("playbooks/10-identity-ad-account/unexpected-password-reset.md", "IAM-AUTH-010", "IAM-010"),
    ("playbooks/10-identity-ad-account/service-account-misuse.md", "IAM-AUTH-003", "IAM-011"),
    ("playbooks/10-identity-ad-account/domain-policy-change.md", "IAM-AUTH-12", "IAM-012"),
    ("playbooks/10-identity-ad-account/gpo-changes.md", "AD-GPO-07", "IAM-013"),
    ("playbooks/10-identity-ad-account/domain-admin-group-modification.md", "IAM-AD-014", "IAM-014"),

    ("playbooks/11-identity-ad-kerberos/kerberos-anomalies-general.md", "PB-IAM-KRB-01", "IAM-015"),
    ("playbooks/11-identity-ad-kerberos/golden-ticket-indicators.md", "IAM-KRB-04", "IAM-016"),
    ("playbooks/11-identity-ad-kerberos/silver-ticket-indicators.md", "PB-IAM-KRB-07", "IAM-017"),
    ("playbooks/11-identity-ad-kerberos/kerberoasting.md", "AD-KRB-003", "IAM-018"),
    ("playbooks/11-identity-ad-kerberos/as-rep-roasting.md", "PB-AD-KRB-04", "IAM-019"),
    ("playbooks/11-identity-ad-kerberos/dcsync.md", "PB-IAM-KRB-06", "IAM-020"),
    ("playbooks/11-identity-ad-kerberos/dcshadow.md", "PB-IAM-KRB-08", "IAM-021"),
    ("playbooks/11-identity-ad-kerberos/pass-the-hash.md", "IDN-KRB-11", "IAM-022"),
    ("playbooks/11-identity-ad-kerberos/pass-the-ticket.md", "PB-IAM-014", "IAM-023"),
    ("playbooks/11-identity-ad-kerberos/ntlm-abuse.md", "PB-IAM-KRB-10", "IAM-024"),
    ("playbooks/11-identity-ad-kerberos/suspicious-ldap-enumeration.md", "AD-KRB-011", "IAM-025"),

    ("playbooks/12-endpoint-execution/malware-detection-generic-av-edr-alert.md", "EP-EXE-01", "EP-001"),
    ("playbooks/12-endpoint-execution/suspicious-process-generic.md", "PB-END-EXE-001", "EP-002"),
    ("playbooks/12-endpoint-execution/encoded-obfuscated-powershell.md", "PB-EXEC-014", "EP-003"),
    ("playbooks/12-endpoint-execution/powershell-download-cradle.md", "EP-EXEC-004", "EP-004"),
    ("playbooks/12-endpoint-execution/cmd-exe-spawned-by-an-office-application.md", "EP-EXE-014", "EP-005"),
    ("playbooks/12-endpoint-execution/powershell-spawned-by-an-office-application.md", "EXEC-LOL-014", "EP-006"),
    ("playbooks/12-endpoint-execution/suspicious-rundll32-usage.md", "PB-EXE-011", "EP-007"),
    ("playbooks/12-endpoint-execution/regsvr32-abuse.md", "PB-END-EXE-008", "EP-008"),
    ("playbooks/12-endpoint-execution/mshta-abuse.md", "EP-EXEC-009", "EP-009"),
    ("playbooks/12-endpoint-execution/certutil-abuse-download-decode.md", "PB-END-EXE-010", "EP-010"),
    ("playbooks/12-endpoint-execution/bitsadmin-abuse.md", "PB-END-EXE-011", "EP-011"),
    ("playbooks/12-endpoint-execution/wscript-cscript-abuse.md", "EP-EXEC-012", "EP-012"),
    ("playbooks/12-endpoint-execution/unknown-unrecognised-executable-execution.md", "PB-END-EXE-013", "EP-013"),
    ("playbooks/12-endpoint-execution/unsigned-binary-execution.md", "PB-EXE-014", "EP-014"),
    ("playbooks/12-endpoint-execution/usb-triggered-execution.md", "EP-EXEC-015", "EP-015"),
    ("playbooks/12-endpoint-execution/remote-administration-tool-abuse.md", "END-EXE-014", "EP-016"),

    ("playbooks/13-endpoint-persistence/new-service-creation.md", "PB-PER-001", "EP-017"),
    ("playbooks/13-endpoint-persistence/scheduled-task-persistence.md", "PB-EP-13.2", "EP-018"),
    ("playbooks/13-endpoint-persistence/registry-run-key-persistence.md", "EP-13-01", "EP-019"),
    ("playbooks/13-endpoint-persistence/credential-dumping-lsass-access-mimikatz-indicators.md", "END-13.04", "EP-020"),
    ("playbooks/13-endpoint-persistence/process-injection.md", "PB-13.05", "EP-021"),
    ("playbooks/13-endpoint-persistence/mass-file-modification-ransomware-adjacent.md", "EP-PERS-006", "EP-022"),
    ("playbooks/13-endpoint-persistence/shadow-copy-vss-deletion.md", "PB-EP-13.7", "EP-023"),
    ("playbooks/13-endpoint-persistence/security-tool-tampering-edr-disabled.md", "EP-13.04", "EP-024"),

    ("playbooks/14-network/port-scanning.md", "NET-14-01", "NW-001"),
    ("playbooks/14-network/internal-network-reconnaissance.md", "NET-14-03", "NW-002"),
    ("playbooks/14-network/external-reconnaissance.md", "NET-14.01", "NW-003"),
    ("playbooks/14-network/c2-communication.md", None, "NW-004"),
    ("playbooks/14-network/beaconing.md", "PB-NET-04", "NW-005"),
    ("playbooks/14-network/dns-tunnelling.md", "NET-14-07", "NW-006"),
    ("playbooks/14-network/large-outbound-data-transfer.md", "PB-NET-04", "NW-007"),
    ("playbooks/14-network/suspicious-tls.md", "PB-NET-07", "NW-008"),
    ("playbooks/14-network/known-malicious-ip-hit.md", "PB-NET-01", "NW-009"),
    ("playbooks/14-network/known-malicious-domain-hit.md", "PB-NET-10", "NW-010"),
    ("playbooks/14-network/tor-activity.md", "PB-NET-11", "NW-011"),
    ("playbooks/14-network/proxy-avoidance-tooling.md", "NET-PXY-014", "NW-012"),
    ("playbooks/14-network/firewall-deny-spike.md", "NET-14-13", "NW-013"),
    ("playbooks/14-network/unusual-destination-country.md", "NET-07", "NW-014"),
    ("playbooks/14-network/unexpected-inbound-service-exposure.md", "NET-14-15", "NW-015"),
    ("playbooks/14-network/lateral-movement-network-view.md", "NET-14-16", "NW-016"),
    ("playbooks/14-network/smb-scanning.md", "NET-14-17", "NW-017"),
    ("playbooks/14-network/rdp-scanning.md", "NET-014", "NW-018"),
    ("playbooks/14-network/ssh-attacks.md", "NET-14-19", "NW-019"),

    ("playbooks/15-web/sql-injection.md", "WEB-15-003", "WEB-001"),
    ("playbooks/15-web/xss.md", "WEB-XSS-01", "WEB-002"),
    ("playbooks/15-web/command-injection.md", "WEB-15-004", "WEB-003"),
    ("playbooks/15-web/path-traversal.md", "WEB-15-004", "WEB-004"),
    ("playbooks/15-web/lfi.md", "WEB-LFI-05", "WEB-005"),
    ("playbooks/15-web/rfi.md", "WEB-RFI-01", "WEB-006"),
    ("playbooks/15-web/web-shell-detection.md", "WEB-04", "WEB-007"),
    ("playbooks/15-web/credential-stuffing.md", "WEB-15-008", "WEB-008"),
    ("playbooks/15-web/password-spraying-web-facing.md", "PB-15.1", "WEB-009"),
    ("playbooks/15-web/admin-panel-scanning.md", "WEB-15-010", "WEB-010"),
    ("playbooks/15-web/malicious-file-upload.md", "WEB-MFU-01", "WEB-011"),
    ("playbooks/15-web/rce.md", "WEB-RCE-01", "WEB-012"),
    ("playbooks/15-web/api-abuse.md", "WEB-15-013", "WEB-013"),
    ("playbooks/15-web/enumeration.md", "WEB-15-014", "WEB-014"),
    ("playbooks/15-web/authentication-bypass.md", "PB-15.15", "WEB-015"),
    ("playbooks/15-web/session-hijacking.md", "WEB-SH-01", "WEB-016"),
    ("playbooks/15-web/bot-traffic-web-scraping.md", "PB-15.17", "WEB-017"),
    ("playbooks/15-web/suspicious-user-agent.md", "PB-WEB-04", "WEB-018"),

    ("playbooks/16-email/phishing.md", "EML-PHISH-01", "EML-001"),
    ("playbooks/16-email/spear-phishing.md", "PB-EMAIL-002", "EML-002"),
    ("playbooks/16-email/bec.md", "EML-BEC-01", "EML-003"),
    ("playbooks/16-email/malicious-attachment.md", "PB-EMAIL-004", "EML-004"),
    ("playbooks/16-email/malicious-link.md", "EML-16-05", "EML-005"),
    ("playbooks/16-email/qr-code-phishing.md", "EML-16-006", "EML-006"),
    ("playbooks/16-email/credential-phishing.md", "PB-EML-04", "EML-007"),
    ("playbooks/16-email/internal-compromised-account-phishing.md", "EML-ACCT-08", "EML-008"),
    ("playbooks/16-email/mailbox-forwarding-rule-abuse.md", "PB-EMAIL-009", "EML-009"),
    ("playbooks/16-email/suspicious-inbox-rule-creation.md", "PB-EMAIL-010", "EML-010"),
    ("playbooks/16-email/oauth-app-abuse-consent-phishing.md", "PB-EMAIL-011", "EML-011"),
    ("playbooks/16-email/impossible-travel-mailbox-access.md", "PB-EML-004", "EML-012"),
    ("playbooks/16-email/account-takeover.md", "EMAIL-ATO-01", "EML-013"),
    ("playbooks/16-email/mass-outbound-email-from-compromised-mailbox.md", "PB-EMAIL-014", "EML-014"),
    ("playbooks/16-email/executive-impersonation.md", "EML-EXEC-15", "EML-015"),
    ("playbooks/16-email/vendor-impersonation.md", "EML-VEND-01", "EML-016"),

    ("playbooks/17-cloud/root-global-admin-account-usage.md", "PB-CLD-11", "CLD-001"),
    ("playbooks/17-cloud/new-access-key-creation.md", "CLD-17.04", "CLD-002"),
    ("playbooks/17-cloud/suspicious-iam-policy-changes.md", "CLD-IAM-04", "CLD-003"),
    ("playbooks/17-cloud/public-storage-bucket-exposure.md", "CLD-17-EXP-STOR-01", "CLD-004"),
    ("playbooks/17-cloud/security-group-opened-to-the-internet.md", "CLOUD-SG-01", "CLD-005"),
    ("playbooks/17-cloud/mfa-disabled-on-an-account.md", "PB-CLD-06", "CLD-006"),
    ("playbooks/17-cloud/impossible-travel-cloud-sign-in.md", "PB-CLD-07", "CLD-007"),
    ("playbooks/17-cloud/new-oauth-application-registered-consented.md", "CLD-OAUTH-08", "CLD-008"),
    ("playbooks/17-cloud/privilege-escalation-via-role-policy-chaining.md", "PB-CLD-09", "CLD-009"),
    ("playbooks/17-cloud/cloud-audit-logging-disabled.md", "CLD-AUD-01", "CLD-010"),
    ("playbooks/17-cloud/new-admin-global-admin-granted.md", "PB-CLD-19", "CLD-011"),
    ("playbooks/17-cloud/access-from-unusual-geography.md", "PB-CLD-12", "CLD-012"),
    ("playbooks/17-cloud/mass-object-download-from-storage.md", "CLD-STOR-13", "CLD-013"),
    ("playbooks/17-cloud/storage-based-exfiltration.md", "CLD-17-EXFIL-STOR-01", "CLD-014"),
    ("playbooks/17-cloud/suspicious-api-call-sequences.md", "CLD-17.15", "CLD-015"),
    ("playbooks/17-cloud/cloud-shell-abuse.md", "PB-CLD-17-06", "CLD-016"),
    ("playbooks/17-cloud/instance-vm-compromise-indicators.md", "CLD-17.17", "CLD-017"),
    ("playbooks/17-cloud/credential-leakage-keys-in-code-logs.md", "CLD-17.18", "CLD-018"),

    ("playbooks/18-ai-security/prompt-injection.md", "PB-AISEC-01", "AI-001"),
    ("playbooks/18-ai-security/indirect-prompt-injection.md", "AISEC-03", "AI-002"),
    ("playbooks/18-ai-security/llm-data-leakage.md", "AISEC-03", "AI-003"),
    ("playbooks/18-ai-security/sensitive-information-submitted-to-a-public-unsanctioned-ai-tool.md", "AI-SEC-01", "AI-004"),
    ("playbooks/18-ai-security/ai-api-key-compromise.md", "AI-SEC-005", "AI-005"),
    ("playbooks/18-ai-security/ai-account-takeover.md", "PB-AI-06", "AI-006"),
    ("playbooks/18-ai-security/ai-agent-performing-an-unauthorised-action.md", "AIS-AGT-07", "AI-007"),
    ("playbooks/18-ai-security/agent-tool-abuse.md", "PB-AI-18-08", "AI-008"),
    ("playbooks/18-ai-security/rag-poisoning.md", "AI-SEC-04", "AI-009"),
    ("playbooks/18-ai-security/knowledge-base-poisoning.md", "AI-18.10", "AI-010"),
    ("playbooks/18-ai-security/system-prompt-extraction-prompt-leakage.md", "AISEC-11", "AI-011"),
    ("playbooks/18-ai-security/jailbreak-behaviour.md", "AISEC-12", "AI-012"),
    ("playbooks/18-ai-security/ai-generated-phishing-content-detected.md", "AISEC-13", "AI-013"),
    ("playbooks/18-ai-security/ai-assisted-malware-development-indicators.md", "PB-AISEC-14", "AI-014"),
    ("playbooks/18-ai-security/model-endpoint-abuse.md", "AISEC-15", "AI-015"),
    ("playbooks/18-ai-security/unusual-token-consumption.md", "AISEC-16", "AI-016"),
    ("playbooks/18-ai-security/automated-api-scraping-excessive-model-queries.md", "AI-SEC-017", "AI-017"),
    ("playbooks/18-ai-security/data-exfiltration-attempted-through-prompts.md", "PB-AI-18-18", "AI-018"),
    ("playbooks/18-ai-security/ai-generated-command-execution-via-an-agent.md", "PB-AI-18-19", "AI-019"),
    ("playbooks/18-ai-security/model-connected-tool-misuse.md", "PB-AI-18-20", "AI-020"),
    ("playbooks/18-ai-security/mcp-server-abuse.md", "PB-AI-18-21", "AI-021"),
    ("playbooks/18-ai-security/ai-browser-agent-abuse.md", "AISEC-22", "AI-022"),
    ("playbooks/18-ai-security/ai-coding-agent-modifying-sensitive-files-unexpectedly.md", "PB-AI-18-23", "AI-023"),
    ("playbooks/18-ai-security/agent-privilege-abuse.md", "AIS-PRIV-24", "AI-024"),
    ("playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md", "PB-AISEC-24", "AI-025"),

    ("playbooks/19-insider/mass-file-access.md", "INSIDER-01", "INS-001"),
    ("playbooks/19-insider/large-download.md", "INSIDER-07", "INS-002"),
    ("playbooks/19-insider/usb-copying.md", "INS-EXFIL-003", "INS-003"),
    ("playbooks/19-insider/cloud-storage-upload-of-sensitive-data.md", "INS-19-04", "INS-004"),
    ("playbooks/19-insider/personal-email-transfer-of-company-data.md", "INS-19-05", "INS-005"),
    ("playbooks/19-insider/sensitive-repository-cloning.md", "INS-19-06", "INS-006"),
    ("playbooks/19-insider/printing-of-sensitive-files.md", "INS-07", "INS-007"),
    ("playbooks/19-insider/unusual-database-access.md", "INSIDER-08", "INS-008"),
    ("playbooks/19-insider/departing-employee-activity.md", "IT-19-002", "INS-009"),
    ("playbooks/19-insider/privileged-access-misuse.md", "INSIDER-10", "INS-010"),
    ("playbooks/19-insider/access-outside-job-role-need-to-know.md", "INSIDER-11", "INS-011"),
    ("playbooks/19-insider/bulk-deletion-of-data.md", "INSIDER-12", "INS-012"),

    ("playbooks/20-data-exfiltration-master-playbook.md", "PB-EXFIL-MASTER-001", "EXF-001"),
    ("playbooks/21-ransomware-master-playbook.md", "RAN-MASTER-21", "RAN-001"),
    ("playbooks/22-malware-master-playbook.md", "PB-MAL-MASTER-001", "MAL-001"),
]

def replace_in_header(text, old_id, new_id):
    lines = text.split("\n")
    header = lines[:HEADER_LINES]
    rest = lines[HEADER_LINES:]
    count = 0
    pattern = re.compile(r'(?<![A-Za-z0-9])' + re.escape(old_id) + r'(?![A-Za-z0-9])')
    new_header = []
    for line in header:
        new_line, n = pattern.subn(new_id, line)
        count += n
        new_header.append(new_line)
    return "\n".join(new_header + rest), count

results = []
for rel_path, old_id, new_id in MIGRATIONS:
    path = ROOT + rel_path
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if old_id is None:
        results.append((rel_path, old_id, new_id, "SKIPPED (no old id to replace; new id not inserted automatically)"))
        continue
    new_text, count = replace_in_header(text, old_id, new_id)
    if count == 0:
        results.append((rel_path, old_id, new_id, "WARNING: 0 replacements"))
        continue
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
    results.append((rel_path, old_id, new_id, "OK ({} replacement(s))".format(count)))

ok = sum(1 for r in results if r[3].startswith("OK"))
warn = [r for r in results if not r[3].startswith("OK")]
print("Applied: {} / {}".format(ok, len(results)))
if warn:
    print("Needs attention:")
    for r in warn:
        print("  {}  old={}  new={}  ->  {}".format(r[0], r[1], r[2], r[3]))
