import fitz
import os

doc = fitz.open(r"C:\Users\User\SOC-Playbook-Handbook\_build\SOC_Playbook_Handbook.pdf")
out = r"C:\Users\User\SOC-Playbook-Handbook\_build"

targets = {}
for i in [0, 1, 2]:
    targets[i] = "sample_p%d.png" % (i + 1)

for i in range(doc.page_count):
    if doc[i].get_images():
        targets[i] = "sample_first_image_p%d.png" % (i + 1)
        break

mid = doc.page_count // 2
targets[mid] = "sample_middle_p%d.png" % (mid + 1)

last = doc.page_count - 1
targets[last] = "sample_last_p%d.png" % (last + 1)

for idx, fname in targets.items():
    pix = doc[idx].get_pixmap(dpi=140)
    pix.save(os.path.join(out, fname))
    print(fname, "page index", idx)
