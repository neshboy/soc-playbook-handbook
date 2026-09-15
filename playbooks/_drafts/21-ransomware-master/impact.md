# Impact Stage: Scope Assessment in the First Hour

By the time you're reading this section, containment has usually already started — isolating switches, pulling VLANs, killing domain trust relationships. The Impact stage isn't a phase you enter deliberately; it's the phase you realize you're already in, usually because the helpdesk queue just went from 4 tickets to 400. This section covers what the business actually experiences during active encryption/exfil-for-leverage activity, and how the incident commander (IC) builds a defensible scope picture inside the first 60 minutes — before backup status is confirmed, before legal/exec briefing, before anyone says the word "ransom."

## What the Organization Experiences

Ransomware impact rarely announces itself as a single event. It shows up as a pattern of unrelated-seeming complaints that converge:

| Symptom reported | Likely underlying cause | Who notices first |
|---|---|---|
| "My files have a weird extension" / ransom note (`README_TO_DECRYPT.txt`, `HOW_TO_RECOVER_FILES.html`) dropped in every directory | Active mass file rewrite via `T1486` Data Encrypted for Impact | End users, helpdesk |
| File server / share unreachable, SMB timeouts | Encryptor process consuming disk I/O, or host already crashed/rebooted mid-encryption | IT ops, monitoring |
| Backup jobs failing overnight, backup console unreachable | Backup infrastructure targeted directly, or credentials burned earlier in the intrusion | Backup admin, not SOC |
| VSS/Volume Shadow Copy service disabled, `vssadmin delete shadows` history | `T1490` Inhibit System Recovery — almost always precedes or coincides with encryption | Analyst reviewing Sysmon/4688 |
| Domain controllers unresponsive, GPO changes not applying | DCs encrypted or deliberately targeted last to maximize blast radius | Domain admins |
| Production line / OT system down | IT/OT segmentation failure, or ransomware crossing into historian/SCADA-adjacent Windows hosts | Plant ops — reaches SOC last, hurts most |

The pattern that separates ransomware impact from a garden-variety outage is **simultaneity across unrelated systems**. One dead file server is a hardware problem. A file server, three backup targets, and the DC all going sideways inside a 20-minute window is impact stage.

**[STAKEHOLDER]** - The business doesn't care about encryption algorithms in hour one. They care about three questions: can we take orders, can we ship, can we pay people. Translate every technical finding into those terms in your first briefing — "domain controllers in Site B are encrypted" means nothing to a CFO; "Site B cannot process invoices and payroll runs from Site B are at risk Friday" does.

## Building the Scope Picture (First Hour)

The IC's job here is not root-cause analysis — that's Investigation-stage work running in parallel. It's a **blast-radius map** built fast and revised often.

**[ANALYST]** - Work these evidence sources in parallel, not sequentially, because none of them alone is reliable:

- **Sysmon Event ID 11 (FileCreate)** — look for a burst of ransom-note file creation across many hosts in a short window; the note filename is often consistent per-affiliate and is your fastest single indicator of confirmed vs. suspected hosts.
- **Sysmon Event ID 23 (FileDelete)** — mass deletion patterns (shadow copies, backup catalogs, log files) frequently precede or accompany encryption; don't assume a host with only deletes and no ransom note yet is safe — it may just be mid-encryption.
- **Windows Event ID 4688 / Sysmon Event ID 1** — hunt for `vssadmin.exe`, `wbadmin.exe`, `wmic.exe shadowcopy delete`, `bcdedit.exe` invocations with disabling command lines (`T1490`). These often fire minutes before the encryptor binary itself.
- **EDR/AV alert volume by host, not by alert type** — a host throwing 200 near-simultaneous file-modify detections is a different animal from a host throwing one.

Expect gaps. Domain controllers may be encrypted before their logs forward to the SIEM. EPS spikes from mass file events can overwhelm ingestion, so the SIEM's own dashboards may under-report host count for the first 15-30 minutes — don't treat "only 12 hosts alerting" as ground truth this early, treat it as a floor.

**[ENGINEERING]** - A quick scoping query pattern against EDR/Sysmon telemetry (adjust field names to your platform):

```
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(readme|decrypt|how_to_recover|restore_files).*\.(txt|html|hta)$")
| stats count, min(_time) as first_seen, max(_time) as last_seen by Computer
| sort - count
```

Cross-reference the resulting host list against your CMDB/asset inventory to tag business function (file server, DC, backup target, OT-adjacent) — that tagging is what turns a host list into an impact statement.

**[MANAGEMENT]** - The first-hour deliverable is a living scope document with four columns: host/system, business function, confirmed-encrypted vs. suspected vs. clean, backup status (untested — do not assume "backups exist" means "backups are restorable"). Update it every 15 minutes during active impact and timestamp every revision; this document becomes the spine of the exec briefing, the legal/insurance notification, and later the after-action review. Backup integrity verification and the pay/not-pay decision are downstream of this document, not part of it — the SOC's job in hour one is scope, not remediation strategy.
