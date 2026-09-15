# Second-Pass Inventory

Taken before any v2 edits, against the live manuscript at `C:\Users\User\SOC-Playbook-Handbook`. A full untouched snapshot of this exact state is preserved at `C:\Users\User\SOC-Playbook-Handbook-release-v1` for comparison/rollback.

## What exists

| Asset | Location | Count | Status |
|---|---|---|---|
| Front matter / Foundations chapters | root `00-` through `06-*.md` | 8 files | In reading path (BOOK-INDEX.md) |
| Technical reference (Windows/Sysmon/Linux) | root `07*`, `08a/08b`, `09a/09b` | 10 files | In reading path |
| Playbook Library (individual playbooks + category indexes) | `playbooks/10-*` through `19-*` | 170 files | In reading path |
| Master playbooks (synthesised) | `playbooks/20-*`, `21-*`, `22-*`, `playbooks/18-ai-security/00-*` | 4 files | In reading path |
| Master playbook drafts (working notes) | `playbooks/_drafts/` | 31 files | NOT in reading path by design; retained as source material |
| Operations & Governance (core + case studies) | root `23-*` through `35-*` | 26 files | In reading path |
| Appendices | `appendices/` | 10 files | In reading path |
| Diagrams (rendered) | `assets/diagrams/*.png` | 50 files | In reading path (embedded in chapters) |
| Diagram sources (editable) | `assets/diagrams/source/*.mmd` | 50 files | Source material, not directly read by BOOK-INDEX.md but referenced by VISUAL-INVENTORY.md |
| Charts (rendered, synthetic data) | `assets/charts/*.png` | 12 files | In reading path (embedded in chapters) |
| Master TOC / build map | `BOOK-INDEX.md` | 1 file | Authoritative reading order |
| Visual asset ledger | `VISUAL-INVENTORY.md` | 1 file | Authoritative figure list |
| Rendering toolchain | `_tools/` (build_book.js, render_mermaid.py, node_modules/mermaid) | - | Infrastructure, not manuscript content |
| Assembled build output | `_build/book.html`, `_build/SOC_Playbook_Handbook.pdf` | 2 files | v1 build output; will be regenerated for v2, not hand-edited |

**Not present in this project and out of scope for "recapture": DOCX, BUILD-MANIFEST.md, EVIDENCE-MANIFEST.md, REFERENCES.md (a References appendix exists at `appendices/38b-references.md` and serves that purpose), and any real product screenshots (none were ever captured — v1 used only Mermaid diagrams and synthetic matplotlib charts, per an explicit earlier decision to avoid faking vendor UI or making unreviewed changes to this PC's real security/audit configuration to generate "real" lab evidence). That decision stands for v2 as well unless directed otherwise.**

## Debris found and removed before v2 work started

Three orphaned files existed on disk from an earlier, abandoned first-draft workflow run (stopped mid-execution in favor of the finer-grained structure that actually shipped). They duplicated content that exists correctly elsewhere under split filenames and were not referenced by BOOK-INDEX.md or any other file:

- `05-06-decision-tree-and-building-a-playbook.md` (superseded by separate `05-decision-tree.md` + `06-building-from-detection-rule.md`)
- `08-sysmon-reference.md` (superseded by `08a-sysmon-process-network-image.md` + `08b-sysmon-file-registry-pipe-dns.md`)
- `09-linux-log-reference.md` (superseded by `09a-linux-auth-ssh-evidence.md` + `09b-linux-persistence-execution-evidence.md`)

Verified via grep that nothing referenced these three filenames before deleting them. They remain in the `release-v1` snapshot as an accurate record of what v1 actually contained.

## Known issue flagged for the second pass (see TERMINOLOGY-STANDARD.md)

Playbook IDs use at least six different, inconsistent prefix/numbering conventions across categories (e.g. `IAM-AUTH-04` vs `PB-IAM-BF-001` vs `ID-AD-01` within Identity alone). This needs one canonical scheme plus a migration map, not a silent rename — assigned to the Cross-Reference & Playbook-ID System agent in the second-pass swarm.

## Revalidation requirement

Every item marked "In reading path" above is in scope for full independent re-audit in this second pass. Nothing is assumed correct because a first-pass QA agent already looked at it.
