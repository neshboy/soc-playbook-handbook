import re

FILES = """04a-master-template-fields.md
06-building-from-detection-rule.md
26-client-approval-go-nogo-core.md
appendices/37c-checklists-and-approval-matrix.md
playbooks/10-identity-ad-account/gpo-changes.md
playbooks/10-identity-ad-account/new-account-creation.md
playbooks/10-identity-ad-account/password-spraying.md
playbooks/10-identity-ad-account/user-account-deletion.md
playbooks/11-identity-ad-kerberos/dcsync.md
playbooks/11-identity-ad-kerberos/kerberoasting.md
playbooks/11-identity-ad-kerberos/ntlm-abuse.md
playbooks/11-identity-ad-kerberos/silver-ticket-indicators.md
playbooks/11-identity-ad-kerberos/suspicious-ldap-enumeration.md
playbooks/15-web/admin-panel-scanning.md
playbooks/15-web/api-abuse.md
playbooks/15-web/command-injection.md
playbooks/15-web/credential-stuffing.md
playbooks/15-web/enumeration.md
playbooks/16-email/malicious-link.md
playbooks/16-email/oauth-app-abuse-consent-phishing.md
playbooks/16-email/qr-code-phishing.md
playbooks/16-email/spear-phishing.md
playbooks/16-email/suspicious-inbox-rule-creation.md
playbooks/16-email/vendor-impersonation.md
playbooks/17-cloud/public-storage-bucket-exposure.md
playbooks/17-cloud/storage-based-exfiltration.md
playbooks/18-ai-security/knowledge-base-poisoning.md""".splitlines()

ROOT = r"C:\Users\User\SOC-Playbook-Handbook"
pattern = re.compile(r"\bL([123])\b")

total = 0
for rel in FILES:
    path = ROOT + "\\" + rel.replace("/", "\\")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    new_content, n = pattern.subn(lambda m: "Tier " + m.group(1), content)
    if n:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        total += n
        print(rel, "->", n, "replacements")
    else:
        print(rel, "-> NO MATCH (investigate)")

print("TOTAL:", total)
