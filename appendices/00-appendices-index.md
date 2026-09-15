# Appendices — Index

Everything in this section is reference material, not narrative. The main chapters explain *why* a decision gets made and walk through the reasoning; the appendices are what you actually keep open in a second monitor while you're triaging, filling out a ticket, or arguing for budget in a QBR. Nothing here is meant to be read cover to cover — it's meant to be found in under ten seconds when you need it.

Nine files, three purposes: quick-reference lookup tables (36A–36D), fillable templates and checklists (37A–37C), and the two "step back and assess the program" pieces (38A–38B). If you're mid-investigation and need a field name or an Event ID, you want the 36-series. If you're building or fixing a playbook and need the actual document to fill in, you want the 37-series. If you're being asked "how mature is our detection program" or "where did this Event ID claim come from," you want the 38-series.

## Quick-Reference Tables (36-series)

Strip-the-narrative lookup tables pulled from the detailed chapters. No investigative reasoning here — just the ID, the name, and the one-line meaning. Print these, laminate them, or pin them in your SOAR notes panel.

| File | Covers |
|---|---|
| **36A** — Windows Events, Logon Types & PowerShell | Security log Event IDs (logon/session, process/service, account/group, Kerberos/NTLM), Windows logon type codes, PowerShell logging fields |
| **36B** — Sysmon & MITRE ATT&CK | Sysmon Event ID table (process, network, image load, registry, file, pipe, DNS), plus the MITRE ATT&CK technique index used throughout the book |
| **36C** — Linux, Cloud/M365, Email, Network | Linux auth log locations by distro family, cloud/SaaS audit log sources, email header forensics, firewall/proxy/DNS investigation fields |
| **36D** — IOCs, LOLBins & Process Lineage | IOC type taxonomy, living-off-the-land binary abuse patterns, common persistence locations, normal vs. suspicious process lineage |

## Templates and Checklists (37-series)

Copy these into your ticketing system, wiki, or SOAR case template and strip the italicized guidance text once you understand what goes in each field. Keep the field *names* consistent with what's printed here — that consistency is what lets you build metrics later without reformatting years of backlog.

| File | Covers |
|---|---|
| **37A** — Templates Cluster A | Master Playbook Template, Stakeholder Summary, Investigation Template, Escalation Template |
| **37B** — Templates Cluster B | Incident Timeline, Tuning Request, GO/NO-GO Decision, Exception Request, Case Documentation |
| **37C** — Checklists & Approval Matrix | Playbook Review Checklist, QA Checklist, Testing Checklist, and the Approval Matrix that ties them together |

## Program-Level Reference (38-series)

| File | Covers |
|---|---|
| **38A** — Playbook Maturity Model | Level 0 (no documentation) through Level 5 (continuous feedback and adaptive detection) — score playbook-by-playbook, not SOC-wide |
| **38B** — References | Source categories (Microsoft Learn, Sysmon docs, MITRE ATT&CK, NIST, SANS, CISA, cloud vendor documentation) grounding the Event IDs, technique IDs, and field names used across the book, plus a note on version drift |

If you came here looking for something and none of the above sounds right, it's probably explained in full in its source chapter instead — every 36-series and 37C entry links back to one.
