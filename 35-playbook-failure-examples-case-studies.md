# Playbook Failure Examples — Additional Worked Case Studies

The core chapter walked through *why* playbooks fail — stale assumptions, missing branches, automation that outruns its guardrails, ownership that nobody re-checked. This file is the five failures that don't get talked about until they've already cost someone a bad night: a detection rule quietly starved of the logs it was built on, a containment action that fires exactly as designed and still causes an outage, a decision tree with a leaf that was never drawn, an escalation step pointing at a person who left the company, and a checklist that calls the job done one step too early. Each one shows the trigger, the evidence, the decision point, where it landed, and the one line for what happens if nobody catches it.

---

## Case Study 1: The Golden Ticket Alert That Never Had a Chance to Fire

**Organization:** Ashgrove Health Network (ashgrovehealth.example.com)

**Alert/Trigger:** None — that's the point. The organization's playbook for T1558.001 (Golden Ticket) depends on a correlation rule watching `4768` for anomalous ticket lifetime and encryption downgrade on domain controllers. It never fired. The activity only surfaced weeks later during root-cause work on an unrelated ransomware incident that hit a file share on `FS-CLIN02`.

**Evidence gathered:**

| Source | Finding |
|---|---|
| SIEM search, DC01–DC03, prior 60 days | Zero `4768` events ingested from `DC01` for a 40-day window; `DC02` and `DC03` ingesting normally |
| Windows Event Forwarding subscription status on `DC01` | Subscription certificate expired 40 days earlier; forwarding silently stopped, no local error surfaced to the SOC |
| Local Security log, pulled directly from `DC01` (never left the box) | `4768` events present locally for the entire gap period, including several with ticket lifetimes well outside domain Kerberos policy and a legacy encryption type inconsistent with the domain's enforced minimum |
| `1102` on `DC01`, same log | Audit log partially cleared eleven days into the gap — Subject resolved to a domain admin account not normally used interactively |

**Reasoning/decision points:** **[ENGINEERING]** The detection logic itself was fine — the rule would have caught this if the events had arrived. Nobody had a health check on the log source the rule depended on, so a 40-day silent ingestion gap on one of three domain controllers looked, from the SIEM's side, identical to 40 quiet days. The playbook told analysts what to do if the alert fired. It never told anyone what to do if the alert's own inputs went dark, because "confirm the source is actually reporting" wasn't written in as a step for any rule in the identity-abuse category.

**Outcome:** Retroactive hunt across the local DC log (once pulled directly) confirmed forged-ticket characteristics consistent with T1558.001, plus the `1102` clear as anti-forensics mid-dwell. Scope was ultimately tied to the same access path that led to the later ransomware event. Certificate renewal automated with a 14-day-advance alert; a per-log-source heartbeat check (last-event-received time, alerting if any Tier-0 log source goes silent for more than a defined window) was added as a standing detection independent of any single playbook.

**Without this discipline:** the SIEM keeps reporting "no alerts" as if that means "no activity," and the only reason this one ever got found is that a second, louder incident forced someone to go pull logs by hand — most silent ingestion gaps never get that second chance.

---

## Case Study 2: The Auto-Containment That Worked Exactly as Written

**Organization:** Palmetto Foods Co (palmettofoods.example.com)

**Alert/Trigger:** SOAR playbook auto-isolates any host at the network layer where EDR observes a shadow-copy deletion command, tagged as a high-confidence ransomware precursor (T1490), with no human approval step — a deliberate design choice made after a prior incident where a manual isolation call came too late.

**Evidence gathered:**

| Event | Detail |
|---|---|
| `4688` | New Process Name `vssadmin.exe`, Command Line consistent with shadow-copy deletion, Creator Process Name `ArcVaultAgent.exe` on `BKUP-SQL01` (10.60.5.40) |
| Change calendar | Nightly retention-pruning job scheduled for `ArcVaultAgent` at the exact timestamp of the command |
| Cross-host check | No matching activity on any other host in the environment; no `4719` audit-policy tampering; no `4672` privileged-logon anomaly preceding it |
| SOAR action log | Network isolation fired within four seconds of the `4688` event, per design |

**Reasoning/decision points:** **[ENGINEERING]** The automation matched exactly what it was built to match — a shadow-copy deletion command — and did exactly what it was told to do. The gap wasn't in execution, it was in scope: the rule never checked what process asked for the deletion, so legitimate backup-retention housekeeping and an actual ransomware precursor look identical to it. **[MANAGEMENT]** This is a governance question, not a tuning question: should a Tier-0 backup host ever be auto-isolated on a single indicator with no corroborating signal, or does an asset at that criticality need either a second indicator (lateral movement, new service, credential-dumping activity) or a human in the loop before containment fires?

**Outcome:** Closed Benign Positive / Expected Activity, containment reversed. Every downstream backup job for the finance cluster had already failed for the night before anyone caught it. Playbook logic updated to require a parent-process allow-list check (known backup agents excluded) plus at least one corroborating indicator before auto-isolation executes against anything tagged backup infrastructure; anything below that bar routes to a paged analyst instead of firing automatically.

**Without this discipline:** the honest risk isn't just one bad night of backups — it's that after the second or third false auto-isolation, someone quietly disables the rule out of frustration, and the actual ransomware precursor it was built to catch sails through with nothing watching at all.

---

## Case Study 3: The Decision Tree With No Branch for a Vendor

**Organization:** Driftwood Capital (driftwoodcapital.example.com, cloud tenant)

**Alert/Trigger:** Cloud identity alert on a new credential added to an identity object, mapped to T1098.001. The playbook's decision tree has exactly two leaves: "human user confirmed the change" and "human user did not confirm — escalate High/P2."

**Evidence gathered:**

- Cloud audit log: credential added to a guest object, `vendor-integration@partnerco.example.com`, provisioned nine months earlier for a third-party reporting connector.
- Cloud Service Dashboard access (T1538) immediately following, from an ASN not associated with the vendor's known egress ranges.
- Follow-on activity consistent with T1580 (Cloud Infrastructure Discovery) — enumeration of storage containers and role assignments in the same session.

**Reasoning/decision points:** **[ANALYST]** The first analyst on the ticket spent the better part of an hour trying to identify "the employee" who added the credential, because that's the only question the playbook's tree asked. There was no employee — the identity object was a guest account tied to a vendor integration, something the tree simply didn't model. Time was lost not because the analyst reasoned poorly, but because the tool they were handed only had two doors and neither one was the right one. **[ENGINEERING]** The fix isn't a better analyst, it's a third branch keyed off the identity object's type attribute (member / guest / service principal), pulled directly from the directory rather than inferred, with its own routing: guest and service-principal credential events go straight to a vendor-access review path, not the human-confirmation path.

**Outcome:** Once correctly routed, the vendor's leaked integration token was revoked, the guest object's access was reviewed and scoped down, and the partner was notified their credential had been exposed. No confirmed exfiltration (T1530) — enumeration was caught and access cut before anything left the tenant, but that was closer than the SLA clock suggested it should have been.

**Without this discipline:** every future vendor-credential compromise burns the same wasted hour looking for an employee who was never going to exist, and the SLA clock the business actually cares about keeps running the whole time.

---

## Case Study 4: The Escalation Contact Who Left Six Months Ago

**Organization:** Bramwell Logistics (bramwelllogistics.example.com)

**Alert/Trigger:** DNS security tooling flags a workstation generating high-entropy, high-volume queries against an external domain, consistent with T1071.004 / T1572. The playbook's escalation step reads: "Notify Network Engineering on-call for firewall block and packet capture" and lists a named individual's direct email address.

**Evidence gathered:**

- DNS query logs: sustained abnormal query volume and subdomain entropy against `sync-cdn-relay.example.net`, NXDOMAIN rate elevated well above baseline for that host.
- Proxy logs: no corresponding legitimate web traffic to the same domain from any other host, ruling out a shared CDN dependency.
- Ticketing system: escalation email delivered successfully — to a mailbox that had been disabled when the named individual left the company six months prior, with no auto-forward or bounce notification configured.
- 24+ hours later: EDR data-loss monitoring separately flags a large sustained outbound transfer from the same workstation, consistent with T1048, which is what actually got someone looking back at the original ticket.

**Reasoning/decision points:** **[MANAGEMENT]** The escalation step was never wrong on the day it was written — it became wrong the day that person's account was deactivated, and nothing in the playbook lifecycle treated a named contact as an asset that needed the same review cadence as a detection rule. There was also no acknowledgment-timeout mechanism: a handoff that goes unacknowledged for 24 hours generated no secondary alert of its own, so a failed escalation looked, from the SOC's side, exactly like a successful one that was simply being worked quietly by someone else.

**Outcome:** Once discovered, the domain was blocked, the host reimaged, and the tunnel closed. Scope of what actually left the network over that 24-plus-hour window is only partially reconstructable — DNS log retention on this platform rolls off faster than most other sources, and a chunk of the earliest activity had already aged out by the time anyone went looking. Escalation paths across the playbook set were converted from named individuals to role-based paging with a defined acknowledgment SLA and automatic re-escalation if unacknowledged.

**Without this discipline:** stale handoffs like this one don't announce themselves — they sit in a queue looking handled until something louder forces a second look, and plenty of them never get that second look at all.

---

## Case Study 5: The Checklist That Called It Done

**Organization:** Halden Manufacturing (haldenmfg.example.com)

**Alert/Trigger:** Endpoint alert on a phishing-driven execution chain — T1204 into T1059.001 PowerShell — on `WKS-0087`. The playbook's eradication checklist: kill the process, quarantine the dropped file, run an AV scan, mark Remediated, close the ticket.

**Evidence gathered — first pass (day of alert):**

- `4688`: PowerShell process, Creator Process Name a script-hosting document opened minutes earlier from an email attachment.
- Quarantine confirmation on the dropped payload; subsequent AV scan clean.
- Ticket closed Remediated same day. No step in the checklist called for a scheduled-task, run-key, or new-service check.

**Evidence gathered — second pass (fourteen days later):**

| Event | Detail |
|---|---|
| `4698` | Scheduled task created on the same host, name mimicking a legitimate update task |
| `7045` | New service registered days after the "remediated" close, running from a user-writable path |
| `4104` | Script block content matching the same loader family as the original alert, including base64-wrapped segments (T1027) |

**Reasoning/decision points:** **[ANALYST]/[ENGINEERING]** The original response killed the process that was visible at the time, which was real work and not wasted — but the same script had created a scheduled task in the seconds before it was terminated, and nothing in the checklist ever looked for it. "Remediated" measured whether the checklist's boxes were ticked, not whether the host was actually clean, and those turned out to be two different questions. A phishing-to-execution eradication step isn't complete without a persistence sweep — scheduled tasks, autostart registry entries, new services, and any new local accounts — and this playbook's checklist stopped one step short of that.

**Outcome:** The second event was opened as a continuation of the first incident rather than a new one once the loader-family match was confirmed, which mattered for scoping — it meant the attacker had a working foothold on that host for the entire fourteen days in between. Full persistence sweep run, task and service removed, host reimaged rather than just cleaned this time. The eradication checklist was rewritten to require an explicit persistence-artifact check before any ticket can be marked Remediated.

**Without this discipline:** "Remediated" gets treated as fact instead of a claim, the ticket stays closed, and the only thing anyone's watching for on that host going forward is a repeat of the exact alert that already fired once — not the quiet foothold sitting one step to the side of it.

---

## Cross-Case Patterns

| Case | Failure mode | What the fix actually was |
|---|---|---|
| Golden Ticket / silent ingestion gap | Detection rule trusted a log source nobody was monitoring for health | Heartbeat check on Tier-0 log sources, independent of any single rule |
| Auto-containment on backup host | Automation matched on one indicator with no context or corroboration | Parent-process allow-list plus corroborating-signal requirement before auto-action on critical assets |
| Cloud credential alert, no vendor branch | Decision tree modeled "employee" and nothing else | Route on identity object type, not inferred human-ness |
| DNS tunneling, stale escalation contact | Named-person handoff with no lifecycle review or ack-timeout | Role-based paging, acknowledgment SLA, automatic re-escalation |
| Phishing eradication, missing persistence sweep | Checklist completeness stopped at "process killed," not "host clean" | Mandatory persistence-artifact check before any Remediated close |

None of these five were caused by a bad analyst decision in the moment — every individual step taken was defensible given what each playbook actually told people to check. That's the harder failure to catch, and it's exactly why a playbook needs the same maintenance discipline as the detections it triggers on: log sources get re-verified, automation gets corroboration requirements, decision trees get new branches when the environment adds new kinds of identity, ownership gets reviewed on a cadence, and "done" gets defined by what's actually true on the host, not by what box got checked.
