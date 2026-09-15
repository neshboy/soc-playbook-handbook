import fitz
import os

doc = fitz.open(r"C:\Users\User\SOC-Playbook-Handbook\_build\SOC_Playbook_Handbook.pdf")
out = r"C:\Users\User\SOC-Playbook-Handbook\_build\linkedin-carousel"
os.makedirs(out, exist_ok=True)
print("total pages:", doc.page_count)


def find_first(needle, start=0):
    for i in range(start, doc.page_count):
        if doc[i].search_for(needle):
            return i
    return None


def find_first_image(start=0):
    for i in range(start, doc.page_count):
        if doc[i].get_images():
            return i
    return None


picks = []
picks.append(("01-cover", 0))
picks.append(("02-toc", 1))

p = find_first("Four-Lens")
if p is None:
    p = find_first("four-lens")
if p is None:
    p = find_first("[STAKEHOLDER]", 10)
picks.append(("03-depth-markers", p))

p = find_first_image(10)
picks.append(("04-colorful-diagram", p))

p = find_first("Ransomware Full Attack Lifecycle")
if p is None:
    p = find_first_image(p + 5 if p else 200)
picks.append(("05-ransomware-diagram", p))

p = find_first("QR-Code Phishing")
if p is None:
    p = find_first("Kerberoasting")
picks.append(("06-playbook-sample", p))

p = find_first("Alert Volume by Severity")
if p is None:
    p = find_first_image(picks[-1][1] + 1 if picks[-1][1] else 600)
picks.append(("07-metrics-chart", p))

for name, idx in picks:
    if idx is None:
        print("SKIP (not found):", name)
        continue
    pix = doc[idx].get_pixmap(dpi=200)
    fname = os.path.join(out, name + ".png")
    pix.save(fname)
    print(name, "-> page", idx + 1, "->", fname)
