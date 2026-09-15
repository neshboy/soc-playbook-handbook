# Part 32 Companion: SOC Metrics Case Studies

The core chapter covers what to measure, how to define it precisly, and why a metric that looks good on a dashboard isn't the same thing as a SOC that's actually working. This file is where that gap shows up in practice — five cases where a metric either caught something real or, just as often, told a misleading story until someone checked what was underneath it. None of these are about building a dashboard. They're about the decision made *because of* one.

---

## Case Study 1: The MTTA That Looked Perfect and Wasn't

**Organization:** Colby Fintech (colbyfintech.example), online lending platform.

**Trigger:** Nothing broke. The opposite — for two straight quarters, the team's Mean Time to Acknowledge on Sev2 alerts sat at 2.1 minutes against a 5-minute target, the best figure in the program's history, and it got called out favorably in the monthly leadership review. Metrics governance's routine quarterly QA sample (ten random "fast ack" tickets, pulled specifically because they look too good) is what actually surfaced the problem.

**Evidence gathered:**

| Ticket | Alert created | Acknowledged | First evidence query run | MTTA (measured) | Real time-to-first-action |
|---|---|---|---|---|---|
| INC-4471 | 09:12:03 | 09:13:29 | 09:54:10 | 1m 26s | 41m 41s |
| INC-4488 | 11:02:40 | 11:03:55 | 11:47:02 | 1m 15s | 43m 47s |
| INC-4502 | 14:20:11 | 14:21:02 | 14:22:19 | 0m 51s | 1m 17s |

Three of ten sampled tickets, all from the same analyst, showed the acknowledgment click landing in under 90 seconds but the first actual investigative action — the first 4624/4688 query run against the flagged account — not happening until 40+ minutes later. The alert itself: "Anomalous Sign-In Following Credential Phishing Click" (T1566.002 into T1078.002), correlating a link-click event from the secure email gateway with a successful 4624 logon from a new source IP for the same account within 24 hours.

**Reasoning:** MTTA measures the click, not the work. On its own it can't distinguish "picked this up immediately and started working it" from "clicked acknowledge to stop it counting against me, then got to it when the queue allowed." The tell here was correlating MTTA against a second metric — that same analyst's Sev2 rework/reopen rate, which was running at 22% against a team average of 6%. Fast acks, slow real starts, high rework: that's a queue-pressure coping pattern, not malice.

**[MANAGEMENT]** - The instinct is to treat this as a discipline problem for one analyst. It wasn't, once two more people on the team turned out to be doing the same thing under the same shift-coverage pressure. The fix was structural: a required secondary field, "time to first evidence query," populated automatically from the first log-query action taken on the case rather than a manual click, reported next to MTTA on the same dashboard rather than replacing it.

**Outcome:** MTTA target retained, but never reported alone again. The analyst and two others received coaching on queue triage, not discipline — the underlying cause was staffing pressure during a coverage gap, which got its own separate fix. Rework rate for all three dropped to team average within six weeks.

**Without this discipline:** the dashboard keeps telling leadership the team is faster than ever while real response time quietly gets worse, and nobody finds out until an incident with actual damage traces back to a gap the metrics said didn't exist.

---

## Case Study 2: The SLA Breach That Was a Clock, Not a Team

**Organization:** Vantage Underwriters (vantageunderwriters.example), MSSP client, insurance.

**Trigger:** The monthly SLA compliance report — contractual target of 95% of Sev1/Sev2 tickets acknowledged inside the SLA window — shows a drop from 93% to 71% in a single month. Alert volume was up only 4% over the prior month; nothing about staffing had changed. The client's account manager escalates directly, asking whether the MSSP was understaffing the account.

**Evidence gathered:**

| Source | Field checked | Finding |
|---|---|---|
| New branch-office firewall (recently onboarded) | Device local clock | Reporting local time (UTC-5, DST-observing), no offset tag sent to the log pipeline |
| SIEM ingestion pipeline | Timestamp normalization | Assumed UTC on all sources by default; new connector's onboarding profile hadn't been set to apply the offset |
| Ticketing platform | SLA clock start field | Computed against the (mis-normalized) embedded event time, not the actual detection/alert-creation time |
| Breach cluster | Source of breached tickets | Nearly all breaches traced to alerts sourced from the one new firewall connector; every other log source's SLA math was unaffected |

Every breached ticket looked, on paper, like it had already burned most of its SLA window before the analyst ever saw the alert — because the event timestamp feeding the clock was effectively backdated by the missing timezone offset.

**Reasoning:** **[ENGINEERING]** - Before answering a client's staffing question with a staffing commitment, verify that the clock producing the metric agrees with itself across every hop: source device, SIEM ingest, ticketing system. A compliance number that moves 22 points in a month with no corresponding change in headcount, alert volume, or process is a data-integrity question first, a performance question second.

**Outcome:** The new connector's onboarding profile was missing timezone normalization — a gap in the onboarding checklist for new log sources, not a one-off mistake. Corrected and recalculated, the month's true compliance came out to 94.6%, essentially at target. The corrected report went to the client with a plain explanation of the root cause, before the client found the discrepancy independently.

**Without this discipline:** the MSSP either eats a penalty and a credibility hit for a breach that never happened, or overcorrects with headcount for a problem that isn't there — while the onboarding gap that will corrupt every future SLA calculation from that connector stays open.

---

## Case Study 3: Same Mailbox, Third Time

**Organization:** Delacroix Shipping (delacroixshipping.example).

**Trigger:** The quarterly repeat-incident-rate report — incidents grouped by asset/account and root-cause tag — flags `ap.clerk@delacroixshipping.example` as involved in three separate Sev2 tickets in eleven weeks. Each one had already been closed independently, by three different analysts, as True Positive and resolved.

**Evidence gathered:**

| Ticket | Week | Finding | Closure action |
|---|---|---|---|
| INC-2201 | Wk 1 | Inbox rule created, forwarding invoice/remittance keywords externally (T1114.003) | Password reset, rule removed, closed |
| INC-2244 | Wk 6 | Same account, same rule pattern, anomalous sign-in beforehand (T1078.002) | Password reset, rule removed, closed |
| INC-2298 | Wk 11 | Same account, same rule pattern again | Flagged for review before closing, this time |

Each individual closure was technically sound — real compromise, correct remediation, clean close. Nothing in any single ticket looked wrong. What none of the three analysts had visibility into, at the point of closing their own ticket, was that this was the same mailbox for the third time.

**Reasoning:** **[ANALYST]** - On the third occurrence, someone finally asked why a password reset keeps failing to hold. The answer: this one mailbox sat on a documented legacy-protocol exception — a vendor EDI integration that required basic authentication and had never been migrated when the rest of the tenant moved to modern auth with MFA enforcement. Every phishing or credential-stuffing hit against that mailbox specifically bypassed MFA entirely, because MFA was never actually in the path for it. Resetting the password closed the symptom and left the actual door open every time.

**[MANAGEMENT]** - The repeat-incident data became the business case for a decision nobody wanted to force on their own: require the vendor to migrate off basic auth, even though it meant a short disruption to their EDI feed. Three independent "successful closures" in the metrics, same root cause, was the argument that got the vendor conversation prioritized over the vendor's schedule preference.

**Outcome:** Legacy-protocol exception closed for that one mailbox specifically — not a tenant-wide change, which wasn't needed and would have been a heavier lift to push through change control. Vendor migrated within two weeks. Zero recurrences the following quarter.

**Without this discipline:** the SOC keeps notching clean wins against the same open door, quarter after quarter, because time-to-close and per-ticket disposition both look fine in isolation — repeat incident rate is the only metric built to notice the door was never actually shut.

---

## Case Study 4: The Playbook Nobody Used, For the Wrong Reason

**Organization:** Hollis Instruments (hollisinstruments.example), industrial manufacturer, roughly 900 employees.

**Trigger:** Routine quarterly governance review of playbook invocation frequency shows the "Insider Data Exfiltration" playbook invoked twice in the trailing twelve months, against 40–60+ invocations for the phishing and impossible-travel playbooks over the same period. Read at face value across two consecutive quarterly reviews: low-risk category, appropriately rare for this org's size, no action needed.

The real trigger for re-examination wasn't a metric at all — it was a manual tip-off. An engineering manager reports, outside the SIEM entirely, that a departing employee appears to have pulled a large volume of proprietary CAD files before resigning (consistent with T1530 and T1119). The SOC goes looking for the alert that should have caught this and finds nothing in the queue for that user, that volume, or that timeframe.

**Evidence gathered:**

**[ENGINEERING]** - Checking the health of the log source feeding the large-volume-download detection rule (cloud storage audit connector) turns up an auth token that expired five months earlier during an unrelated app-registration cleanup. The detection rule's query logic was fine and had been the entire time — its input had been empty for five months. No errors were thrown; the rule simply had nothing to evaluate and never fired, on anything, for that entire window.

**Reasoning:** The low invocation count wasn't evidence the threat category was genuinely rare for this organization — it was evidence the sensor feeding that category was blind. A usage-frequency metric read as a pure threat-volume signal, without a corresponding check on the health of the telemetry underneath it, led two straight quarterly reviews to close the same finding as reassuring.

**[MANAGEMENT]** - Governance fix: any playbook whose invocation count drops meaningfully quarter over quarter, or sits persistently below an expected baseline for its detection category, now triggers a log-source health check *before* it gets accepted as good news. Low usage becomes a question to answer, not an answer in itself.

**Outcome:** Connector token restored; the source's own retained raw logs allowed a partial backfill covering roughly the prior 30 days, but the bulk of the five-month gap was unrecoverable — logged in the incident record as a permanent evidence gap rather than papered over. The original insider case was substantiated separately through endpoint and file-share logs and referred to HR/Legal on its own evidentiary basis.

**Without this discipline:** playbook usage numbers keep getting read as threat volume, and a silent detection outage on a low-and-slow category like insider exfiltration sits unnoticed indefinitely — because the one metric that might have flagged it sooner, a sustained unexplained drop, gets filed as reassurance instead of investigated.

---

## Case Study 5: Nineteen Percent

**Organization:** Prairiewind Utilities (prairiewindutilities.example), regional utility.

**Trigger:** The monthly quality report shows the reopen/rework rate for the "New Scheduled Task Created" detection (T1053.005, 4698) climbing from 4% to 19% over three months, target is under 8%, and the increase is concentrated almost entirely on the night shift.

**Evidence gathered:**

| Ticket | Night-shift closure reasoning | Day-shift reopen finding |
|---|---|---|
| INC-5510 | Task name resembled routine maintenance naming convention; closed as Expected Activity | Task Content XML action string ran an encoded PowerShell launcher — closed rule content never checked |
| INC-5539 | Same reasoning, same disposition | Task pointed to a binary in a temp directory inconsistent with any known maintenance job |
| INC-5561 | Same reasoning, same disposition | Task correlated with a later, unrelated alert on the same host — reopened during that follow-up investigation |

**Reasoning:** **[ANALYST]** - A rising reopen rate concentrated on one rule and one shift is exactly the kind of pattern that a single case-level "was this closure correct" check will never catch — each individual ticket, read narrowly and on its own, looked like a plausible call. The pattern only became visible once the metric aggregated dozens of closures across weeks.

**[MANAGEMENT]** - First response wasn't disciplinary. The night shift is comparatively junior, and the pattern read like a training gap — skipping the step of actually opening Task Content to check the real command/action behind the task name — rather than corner-cutting for its own sake. The fix went into the playbook itself: the step to close a scheduled-task alert as Expected or Benign now requires recording the actual action string from Task Content, not just the task name, as a mandatory field. Review cadence was formalized too: reopen rate by shift and by rule reviewed monthly, with a defined threshold — above 12% on any single rule for two consecutive months triggers a mandatory case-level audit, not just a mention in the metrics deck.

**Outcome:** Reopen rate on that rule dropped to 6% within two months of the checklist change and a short refresher session. Two of the reopened cases turned out to be confirmed low-severity persistence attempts left over from an earlier, already-remediated compromise — closed properly on reopen, no further spread found.

**Without this discipline:** a slow climb in one quality metric gets shrugged off as normal noise, and the specific gap behind it — one shift skipping one evidence field on one high-value rule — keeps letting real persistence mechanisms get waved through as expected activity, shift after shift, until something bigger happens on a host that was already closed clean twice.

---

## What Ties These Together

None of these five started with someone deciding to lie with a number. A queue-pressured analyst clicking acknowledge early, a mis-normalized firewall clock, three technically-correct closures on the same mailbox, a detection rule quietly starved of input for five months, a training gap hiding inside otherwise-reasonable individual judgment calls — none of it is dramatic on its own. What made each one visible was a metric built to catch exactly that shape of problem, paired with someone willing to ask what was underneath the number before acting on it in either direction — good news or bad. Chase the headline figure alone in any of these five, and the actual condition it was supposed to reveal stays hidden for another quarter, or another year, or until it becomes an incident with a much longer writeup.
