# Playbook Governance — Worked Case Studies

Six composites built around the governance mechanisms from the main chapter — version control, authority-to-act, exceptions with expiry, deconfliction against authorized activity, review cadence, and the audit trail that feeds back into the playbook itself. Each one shows the trigger, what got pulled as evidence, the actual decision point, where it landed, and the one-line failure mode if the discipline had been skipped.

## Case Study 1: Two Versions of the Same Playbook

**Organization:** Northwind Logistics (northwindlogistics.example.com)

**Alert/Trigger:** Correlation rule "Kerberos Pre-Auth Failure Burst" fires on 22 distinct `4771` events from a single Client Address inside 8 minutes. Tagged T1110.003.

**Evidence gathered:**

| Event | Key fields | Observation |
|---|---|---|
| 4771 x22 | Client Address, Account Name, Failure Code | Source 10.40.12.55, 22 distinct target accounts, Failure Code `0x18` for 19 of them |
| 4740 x6 | Caller Computer Name | All point to `NWL-WKS-1187`, DHCP-mapped to 10.40.12.55 |
| 4625 x6 | Sub Status | `0xC0000234` (account locked) for the same six accounts |
| 4624 sweep | — | Zero successful logons for any of the 22 targeted accounts in the window |

**Reasoning/decision points:** The on-shift analyst has two copies of the containment playbook open — an offline PDF saved to her desktop months earlier during onboarding, and the live wiki page. The PDF (predates the version-stamp field entirely) says disable every affected account and force a domain-wide reset. The live version — rewritten after an earlier password-spraying incident's mass-reset step flooded the help desk and stalled warehouse logins for two hours — says isolate the source host first and only disable accounts that show a follow-on successful `4624`, since a guessed-against account isn't the same as a compromised one. The ticket template has a mandatory "Playbook Version Used" field; the PDF has nothing to put there, and that gap is what makes her go find the canonical copy instead of working from memory.

**Outcome:** `NWL-WKS-1187` isolated. Investigation traces it to a phishing attachment opened three days earlier (T1566.001), running an automated internal password-spraying tool. None of the six locked accounts shows a successful follow-on logon, so remediation stays scoped to the host — no domain-wide reset, no help-desk flood.

**Without this discipline:** the stale PDF's mass-reset instruction hits the whole warehouse OU mid-shift, badge-linked scanner logins fail across the floor, and the resulting operational outage ends up logged as a bigger incident than the intrusion it was responding to.

---

## Case Study 2: Who Gets to Pull the Plug

**Organization:** Halbrook Freight & Warehousing (halbrookfreight.example.com)

**Alert/Trigger:** EDR/SIEM correlation on `FS03` (10.55.3.12), the warehouse label-printing and inventory server, fires on a new scheduled task and a new service install within the same two minutes — during peak shipping week. Tagged T1053.005 / T1543.003.

**Evidence gathered:**

- `4698`: Task Name `\Microsoft\Windows\WindowsUpdate\SyncTask2`, Task Content action `powershell.exe -enc <base64>`.
- `4104` decodes the block: a second-stage download plus a staged `vssadmin delete shadows /all /quiet` command (T1490 signal), wrapped in base64 (T1027).
- `7045`: Service Name `WinDefendUpdate`, Image Path under `C:\ProgramData\`, Start Type Auto, running under a local account with no business reason to exist on that host.

**Reasoning/decision points:** The precursor playbook calls for network isolation within 15 minutes of confirmation. `FS03` is tagged Tier 1 – Revenue Impacting in the CMDB, and isolating it mid-shift halts label printing for outbound trucks. Governance requires sign-off from the on-call Incident Commander before anything at that tier gets isolated, with a 10-minute SLA and an automatic secondary escalation to the site's operations lead if the IC doesn't respond — the analyst can request and prepare, but the authority to pull the trigger sits with a named role, not with whoever happens to be on shift.

**[MANAGEMENT]** - the threshold that matters here was agreed in advance, during a calmer week, not negotiated in the ten minutes after the alert fires. That's what makes a 10-minute SLA workable instead of theoretical.

**Outcome:** IC responds in four minutes and approves isolation. `FS03` comes off the network before any shadow-copy deletion completes; forensics finds staged binaries but no encrypted files — T1486 anticipated, never executed. Warehouse operations fall back to the documented manual label-printing process for about 40 minutes.

**Without this discipline:** either the analyst waits for an answer nobody was obligated to give quickly and the encryption finishes, or isolates unilaterally and gets overruled an hour later by an operations director who was never looped in — and either way, the SOC's standing to act fast on the next one takes the hit.

---

## Case Study 3: The Exception That Expired Without Anyone Noticing

**Organization:** Alder Health Partners (alderhealth.example.com)

**Alert/Trigger:** "Elevated `4769` volume, single client, RC4 across multiple SPNs" fires. Tagged T1558.003.

**Evidence gathered:**

- `4769` x31: Account Name `j.ferro` (a help-desk technician, not an admin), Client Address 10.15.4.201, Service Name spans roughly 30 distinct SPNs across the domain inside 90 seconds, Ticket Encryption Type `0x17` for nearly all, Failure Code `0x0` — tickets granted, meaning this is a live offline-cracking setup, not a probing failure.
- One requested SPN: `HTTP/erp-legacy.alderhealth.example.com`, tied to the service account `svc-legacyERP`.

**Reasoning/decision points:** **[ANALYST]** - standard remediation is immediate password rotation for any account behind a requested SPN. `svc-legacyERP` carries a documented exception: rotation breaks the SOAP binding to a 2009-era ERP integration on an unsupported vendor build, with compensating controls of a restricted SPN target, honeytoken monitoring, and a lowered alert threshold in its place. Before deferring on the strength of that exception, check the expiry — this one lapsed on 2026-07-01, more than two months before this alert. A lapsed exception isn't a live control, it's a placeholder for a conversation nobody had. Combined with clear breadth-of-attack evidence — 30 SPNs in 90 seconds from one low-privilege account isn't routine service authentication under any reading — this stops being a maintenance-window decision and becomes an active-incident decision: rotate now, and coordinate the outage instead of avoiding it.

**Outcome:** IT Risk Owner and app owner pulled in the same day. `svc-legacyERP` rotated with a rollback plan on standby; the ERP integration degrades for about 20 minutes and recovers clean. `j.ferro`'s account is separately found compromised via credential reuse from an unrelated personal-account breach (T1078.002); session revoked, password reset.

**Without this discipline:** the stale exception gets read as still-valid because nobody checks the date under pressure, remediation gets deferred again "because it's on the list," and the attacker has the runway to crack the RC4 ticket offline and try the recovered password against whatever else it was reused on.

---

## Case Study 4: Confirming the Deconfliction List Instead of Trusting It

**Organization:** Cascade Analytics (cascadeanalytics.example.com)

**Alert/Trigger:** External recon detection fires on a port sweep and endpoint enumeration against Cascade's public API hosts (T1595, T1046), followed by a burst of exploit attempts against the customer login endpoint (T1190) and a spike of `4625` failures against the admin portal.

**Evidence gathered:**

- Source IP 203.0.113.44 hitting sequential ports and paths in a scripted, low-jitter pattern — a scanner signature, not opportunistic traffic.
- Timing and target list line up closely with an entry in the deconfliction register: vendor RedStone Security, authorized window Sept 14 09:00–Sept 19 17:00, scope limited to the public API and customer portal, with the admin backend and internal VPN explicitly excluded.

**Reasoning/decision points:** **[STAKEHOLDER]** - invoking the full external-intrusion playbook starts a contractual customer-notification clock and drafts an internal legal/comms package. That's expensive to trigger over sanctioned testing, and just as expensive to skip if scope has quietly changed mid-engagement. Governance requires live confirmation from the named pentest coordinator's phone line before a register match is treated as sufficient on its own, because scope amendments don't always make it back into the register in real time. The call confirms the base recon is in scope. Minutes later, a `4672` fires for an account newly holding admin-equivalent rights, and the matching `4624` for that Logon ID traces back to the same source IP — that's the admin backend, explicitly excluded under the rules of engagement. The RoE's own deviation clause requires an immediate pause-and-report, regardless of who's doing it.

**Outcome:** Engagement paused. RedStone confirms their scanner auto-crawled a discovered admin link outside its configured scope; corrected exclusion list applied, engagement resumes 40 minutes later. Base recon logged Expected Activity; the privilege-escalation event logged as a minor RoE deviation, not an incident.

**Without this discipline:** either this becomes a customer-notification false alarm that has to be walked back publicly, or the opposite failure mode — genuine scope creep during a pentest gets waved off as "probably just the pentest" on the strength of an unconfirmed register entry, and nobody catches the actual excursion.

---

## Case Study 5: The Review Cadence That Paid Off Before the Incident Happened

**Organization:** Alder Health Partners (alderhealth.example.com)

**Alert/Trigger:** M365 unified audit log records a `New-InboxRule` operation on a clinician's mailbox, forwarding messages matching "invoice," "statement," and "patient" to an external address, alongside an `Add-MailboxPermission` grant to an unfamiliar mailbox. Tagged T1114.003 and T1098.002.

**Evidence gathered:**

- `MailboxOwnerUPN`: `d.osei@alderhealth.example.com`. `ClientIP` geolocates to a country with no match in the clinician's known travel or VPN egress history.
- Forwarding target domain is a lookalike of a legitimate address, one character off.
- Delegate-access target mailbox has no prior collaboration history with the account.

**Reasoning/decision points:** Two years earlier, this playbook's notification step read only "notify direct manager, reset password." A scheduled quarterly review — a standing cadence check, not a reaction to any incident — flagged that step as insufficient six months before this alert, because a regulatory change had tightened breach-notification timelines for accounts flagged clinical/PHI-access in the CMDB. The playbook was updated then: mandatory Privacy Officer and legal counsel notification, with its own SLA clock running separately from the technical containment clock. When the real incident lands, nobody has to argue in the moment about whether legal needs to know — the version in front of the analyst already answers that.

**Outcome:** Password reset, forwarding rule and delegate grant removed, session revoked, Privacy Officer notified inside the required window. Scoping review finds a limited set of messages were exposed before detection — closed True Positive, limited scope, not "no harm done."

**Without this discipline:** the mailbox gets cleaned up technically and the case feels finished, while the regulatory notification clock quietly expires unmet because the playbook in front of the analyst never said to call legal — turning a contained security incident into a separate compliance failure discovered months later in an audit.

---

## Case Study 6: What the Audit Trail Caught That the Outcome Didn't

**Organization:** Northwind Logistics (northwindlogistics.example.com)

**Alert/Trigger:** Correlation alert "new Domain Admin-equivalent membership + privileged logon from an unusual host," followed shortly by "Security audit log cleared."

**Evidence gathered:**

| Event | Key fields | Observation |
|---|---|---|
| 4728 | Group Name, Member Name, Subject | `Domain Admins` gains `svc-backup01`, a backup service account with no reason to hold that membership; Subject is a former contractor account whose access review had lapsed |
| 4672 | Subject: Account Name, Logon ID | `svc-backup01` assigned sensitive privileges on a new logon, Logon ID `0x4A2B1C90` — 4672 carries no host or workstation field of its own; the source machine has to come from the `4624` that shares this exact Logon ID |
| 1102 | Subject | Audit log cleared by `svc-backup01`, roughly 20 minutes after the privileged logon |

Later analysis ties the sequence to T1003.006 DCSync activity against `NWL-DC01`.

**Reasoning/decision points:** The playbook mandates, as a documented step rather than a suggestion, matching the privileged Logon ID from `4672` to the `4624` that shares that exact Logon ID before scoping containment — specifically because `1102` erases local context, and analysts under pressure default to grabbing whichever `4624` landed closest in time rather than confirming the Logon ID actually matches, which isn't always the same host. Governance requires every step executed or skipped in the case system to be timestamped and attributed automatically, because the case record gets audited later, not just discussed informally in a debrief.

The post-incident case audit — a standing review, not an ad hoc one — finds the on-shift analyst skipped the Logon ID match-back step under time pressure and instead read `NWL-WKS-2044` off the nearest `4624` by timestamp, without confirming its Logon ID actually matched the one on the `4672` record. It happened to be correct here, but it was never verified, and the case tool let the step be skipped silently.

**Outcome:** The incident itself resolves correctly — `svc-backup01` disabled, group membership reverted, domain integrity assessed from a separate, independently verified privileged account, credentials rotated across the privileged tier. The audit-trail finding feeds the monthly governance report and the playbook-adherence metric reported to management; the playbook is revised so the Logon ID match-back step becomes a hard gate the case tool won't let anyone bypass, rather than one that can be quietly missed.

**Without this discipline:** this time the shortcut landed on the right host anyway. A case system that tolerates skipped steps eventually lets a "close enough" containment scope miss the real foothold on a different machine, and nobody finds out until the same actor is back.

---

## Cross-Case Patterns

| Case | Governance mechanism exercised | Discipline that mattered |
|---|---|---|
| Two versions of the same playbook | Version control, single source of truth | A missing version stamp is what triggered the double-check |
| Who gets to pull the plug | Named authority threshold, escalation SLA | Authority agreed in advance, not negotiated mid-incident |
| The exception that expired | Exception expiry, forced re-justification | Checking the date, not just the existence, of the exception |
| Trusting the deconfliction list | Live confirmation over register lookup | RoE deviation clause caught scope creep the register alone would have missed |
| Review cadence paying off early | Scheduled review independent of incidents | The playbook was already fixed before it needed to be |
| The audit trail vs. the outcome | Mandatory step logging, post-incident audit | A correct outcome didn't excuse an unverified shortcut |

None of these six needed a dramatic failure to justify the governance overhead — in five of the six, the control worked exactly as intended and the cost was a phone call, a short delay, or an uncomfortable conversation about a deadline. That's what the discipline is supposed to cost on a good day. The bad day is the one where it's missing.
