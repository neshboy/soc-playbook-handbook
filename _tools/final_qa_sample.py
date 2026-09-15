import fitz
import os

doc = fitz.open(r"C:\Users\User\SOC-Playbook-Handbook\_build\SOC_Playbook_Handbook.pdf")
out = r"C:\Users\User\SOC-Playbook-Handbook\_build"
print("total pages:", doc.page_count)

targets = {}
targets[0] = "final_p1_cover.png"
targets[1] = "final_p2_toc.png"

for i in range(doc.page_count):
    if doc[i].search_for("Kerberoasting Pattern"):
        targets[i] = "final_kerberoasting.png"
        break

for i in range(doc.page_count):
    if doc[i].search_for("Tier 1") and doc[i].get_images():
        targets[i] = "final_tier_and_image.png"
        break

mid = doc.page_count // 2
targets[mid] = "final_middle.png"
last = doc.page_count - 1
targets[last] = "final_last.png"

for idx, fname in targets.items():
    pix = doc[idx].get_pixmap(dpi=140)
    pix.save(os.path.join(out, fname))
    print(fname, "-> page", idx + 1)
