# SIGNAL TO ACTION: The Complete SOC Playbook Handbook

**A Practitioner's Guide to Designing, Operating and Governing Modern SOC Playbooks**

📄 **[Download the full PDF](./SOC_Playbook_Handbook.pdf)** — ~1,260 pages, ~475,000 words.

This is a full-length handbook for SOC analysts (L1 through senior/detection engineering), SOC managers, incident responders, detection engineers, and the stakeholders (CISOs, risk/audit teams, business owners) who depend on their output. It covers what a SOC playbook actually is, how to build one from a bare detection rule, a full Windows/Sysmon/Linux evidence reference, a library of 160+ individual playbooks across Identity, Endpoint, Network, Web, Email, Cloud, AI Security, and Insider Threat, four full end-to-end master playbooks (Ransomware, Malware, Data Exfiltration, AI Malicious File Upload), and the operational disciplines that make a playbook program work in production — escalation quality, stakeholder communication, severity scoring, automation gating, metrics, governance, and testing.

## Reading the book

- **[SOC_Playbook_Handbook.pdf](./SOC_Playbook_Handbook.pdf)** — the assembled, print-ready book. Start here.
- **[BOOK-INDEX.md](./BOOK-INDEX.md)** — the full table of contents in reading order, if you'd rather browse the Markdown source chapter by chapter.

## What's synthetic vs. real

Every playbook, case study, company name, IP address, and log excerpt in this book is fictional/synthetic, built to be technically accurate and realistic without describing any real organization, incident, or individual. Every chart uses clearly-labeled synthetic example data. There are no real screenshots of any commercial security product in this book — diagrams are original Mermaid flowcharts, not vendor UI captures.

## How it was built

- `_tools/build_book.js` — assembles every chapter into one HTML document and prints it to PDF via headless Chrome.
- `_tools/render_mermaid.py` — renders the diagrams under `assets/diagrams/source/*.mmd` to PNG using Mermaid.js and headless Chrome.
- `_tools/add_watermark.py` — applies the diagonal watermark to every page.
- `TERMINOLOGY-STANDARD.md` — the canonical vocabulary (disposition outcomes, depth markers, severity scale, escalation-tier naming) enforced across the whole manuscript.
- `SECOND-PASS-QA-REPORT.md` and `V1-TO-V2-CHANGELOG.md` — a full, unedited account of an independent second-pass technical and editorial audit, including everything that was found, fixed, and deliberately left open.
- `PLAYBOOK-ID-MIGRATION-MAP.md` and `PLAYBOOK-COVERAGE-MATRIX.md` — the canonical playbook ID scheme and a full coverage matrix across all 160+ playbooks.

## Rebuilding it yourself

```
cd _tools
npm install
node build_book.js
# then print _build/book.html to PDF with headless Chrome, e.g.:
chrome --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer \
  --print-to-pdf=../SOC_Playbook_Handbook.pdf _build/book.html
python add_watermark.py
```
