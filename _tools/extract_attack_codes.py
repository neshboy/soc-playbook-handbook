import re, os

root = "playbooks"
skip_dirs = {"_drafts"}
out = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in skip_dirs]
    for fn in sorted(filenames):
        if not fn.endswith(".md"):
            continue
        if fn == "00-index.md":
            continue
        path = os.path.join(dirpath, fn).replace("\\", "/")
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        codes = re.findall(r'T\d{4}(?:\.\d{3})?', text)
        seen = []
        for c in codes:
            if c not in seen:
                seen.append(c)
        out.append((path, ",".join(seen[:6])))

for path, codes in out:
    print(path + " || " + codes)
