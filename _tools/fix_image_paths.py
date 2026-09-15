import os
import re

ROOT = r"C:\Users\User\SOC-Playbook-Handbook"
ABS_PREFIX = "C:/Users/User/SOC-Playbook-Handbook/"
EXCLUDE = {"SECOND-PASS-QA-REPORT.md", "V1-TO-V2-CHANGELOG.md", "TERMINOLOGY-STANDARD.md", "SECOND-PASS-INVENTORY.md"}
SKIP_DIRS = {"_tools", "_build", "_drafts", "node_modules", "__pycache__"}

pattern = re.compile(r"\]\(C:/Users/User/SOC-Playbook-Handbook/(assets/[^)]+)\)")

changed_files = []
total_replacements = 0

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fname in filenames:
        if not fname.endswith(".md"):
            continue
        if fname in EXCLUDE:
            continue
        full = os.path.join(dirpath, fname)
        with open(full, "r", encoding="utf-8") as f:
            content = f.read()
        if "C:/Users/User/SOC-Playbook-Handbook/assets/" not in content:
            continue
        rel_to_assets_root = os.path.relpath(os.path.join(ROOT, "assets"), dirpath).replace("\\", "/")

        def repl(m):
            global total_replacements
            total_replacements += 1
            asset_rel = m.group(1)[len("assets/"):]  # e.g. diagrams/foo.png
            return "](" + rel_to_assets_root + "/" + asset_rel + ")"

        new_content = pattern.sub(repl, content)
        if new_content != content:
            with open(full, "w", encoding="utf-8") as f:
                f.write(new_content)
            changed_files.append(os.path.relpath(full, ROOT))

print("Files changed:", len(changed_files))
print("Total replacements:", total_replacements)
for f in changed_files:
    print(" -", f)
