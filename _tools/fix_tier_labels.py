import re

FILES = """00-frontmatter.md
01-what-is-a-soc-playbook.md
02-why-playbooks-exist.md
03-stakeholder-view.md
04b-master-template-filled-example.md
05-decision-tree.md
07f-windows-logon-types.md
27-escalation-quality-core.md
PLAYBOOK-COVERAGE-MATRIX.md
playbooks/10-identity-ad-account/account-lockouts.md
playbooks/10-identity-ad-account/domain-policy-change.md
playbooks/10-identity-ad-account/privileged-account-login.md
playbooks/10-identity-ad-account/repeated-login-failures.md
playbooks/10-identity-ad-account/service-account-misuse.md
playbooks/10-identity-ad-account/successful-login-after-failures.md
playbooks/10-identity-ad-account/unexpected-password-reset.md
playbooks/11-identity-ad-kerberos/as-rep-roasting.md
playbooks/11-identity-ad-kerberos/kerberos-anomalies-general.md
playbooks/11-identity-ad-kerberos/pass-the-hash.md
playbooks/11-identity-ad-kerberos/pass-the-ticket.md
playbooks/15-web/authentication-bypass.md
playbooks/15-web/bot-traffic-web-scraping.md
playbooks/15-web/lfi.md
playbooks/15-web/malicious-file-upload.md
playbooks/18-ai-security/00-malicious-file-uploaded-into-ai-system.md""".splitlines()

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

print("TOTAL:", total)
