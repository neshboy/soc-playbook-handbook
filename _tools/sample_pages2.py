import fitz
import os

doc = fitz.open(r"C:\Users\User\SOC-Playbook-Handbook\_build\SOC_Playbook_Handbook.pdf")
out = r"C:\Users\User\SOC-Playbook-Handbook\_build"
print("total pages:", doc.page_count)

searches = {
    "drafts_note": "playbooks/_drafts/",
    "siem_query": "KQL",
    "quickref_table": "Logon Type",
    "references": "MITRE ATT&CK",
}

found = {}
for key, needle in searches.items():
    for i in range(15, doc.page_count):
        if doc[i].search_for(needle):
            found[key] = i
            break

for key, idx in found.items():
    fname = "check_%s_p%d.png" % (key, idx + 1)
    pix = doc[idx].get_pixmap(dpi=140)
    pix.save(os.path.join(out, fname))
    print(key, "-> page", idx + 1, "->", fname)

# also grab the actual last content page (before end) and second-to-last
for off, label in [(0, "veryend"), (1, "secondlast")]:
    idx = doc.page_count - 1 - off
    fname = "check_%s_p%d.png" % (label, idx + 1)
    pix = doc[idx].get_pixmap(dpi=140)
    pix.save(os.path.join(out, fname))
    print(label, "-> page", idx + 1, "->", fname)
