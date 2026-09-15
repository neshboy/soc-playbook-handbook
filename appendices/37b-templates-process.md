# Appendix 37B — Templates & Process, Cluster B

The five templates in this cluster cover the paperwork that surrounds an investigation rather than the investigation itself: how you reconstruct what happened in order, how you ask for a detection to be changed, how you get a room full of stakeholders to actually commit to a decision, how you document a risk acceptance, and how you close a case in a way that survives an audit six months later. None of these are creative writing exercises — they're built to be filled in under time pressure, so every field is short, direct, and has an obvious answer.

Copy the section you need into your ticketing system or case management tool. Fields in `[brackets]` are placeholders; delete the brackets when you fill them in. Where a field has a fixed set of valid values, they're listed.

---

## 1. Incident Timeline Template

Use this for any case where sequencing matters — lateral movement, data staging, multi-stage phishing, anything with more than two or three discrete events. Timestamps go in UTC only. If your source log is local time, convert it and note the offset in the Notes column; do not leave mixed timezones in the same timeline. This single rule causes more re-work than any other timeline mistake — someone builds a beautiful timeline and it's off by the analyst's local UTC offset because one log source wasn't normalized.

| # | Timestamp (UTC) | Source / Tool | Event Description | Analyst | Evidence Ref | Notes |
|---|---|---|---|---|---|---|
| 1 | `[YYYY-MM-DD HH:MM:SS]` | `[e.g., EDR, Sysmon, Firewall, IdP logs]` | `[what happened, factual, no interpretation]` | `[initials]` | `[ticket attachment / log ID]` | `[gaps, retention limits, ingestion delay noted here]` |
| 2 | | | | | | |
| 3 | | | | | | |

**[ANALYST]** - Keep the Event Description column factual ("process `powershell.exe` spawned from `winword.exe` on `HOST-FIN-042`") and put your interpretation in Notes, not the description itself. Mixing the two makes it hard for a second reviewer to tell what's evidence and what's your read on it. Flag any gap in coverage explicitly (e.g., "no EDR telemetry between 03:10–03:40, agent was offline for patching") rather than leaving a silent hole — a missing entry looks like nothing happened, when really you just don't know.

---

## 2. Tuning Request Template

For any change to detection logic — new threshold, added exclusion, suppression rule, retiring a rule. Ties directly into the tuning governance process covered elsewhere in this book; this is just the intake form.

| Field | Entry |
|---|---|
| Request ID | `[auto-generated or TUNE-YYYY-###]` |
| Date Submitted | `[YYYY-MM-DD]` |
| Requested By | `[name / team]` |
| Rule / Detection Name | `[e.g., "Suspicious LSASS Access"]` |
| Rule ID | `[internal rule ID, SIEM correlation ID, or vendor detection ID]` |
| Current Logic Summary | `[one or two lines, not the full query]` |
| Problem Being Solved | `[false positive volume, missed detection, alert fatigue, performance]` |
| False Positive Examples | `[link to 3–5 representative alerts, with why each is benign]` |
| Proposed Change | `[exact wording of the new condition, exclusion, or threshold]` |
| Business Justification | `[why this matters, what it costs to leave as-is]` |
| Risk of Making the Change | `[detection coverage lost, blind spot created, if any]` |
| Testing Plan | `[shadow mode duration, backtest window, environment]` |
| Requested Priority | `[Critical / High / Medium / Low]` |
| Approver | `[detection engineering lead / SOC manager]` |
| Approval Date | `[YYYY-MM-DD]` |
| Deployment Date | `[YYYY-MM-DD]` |
| Post-Deployment Validation | `[confirmed no coverage loss — how, by whom, and when]` |

**[ENGINEERING]** - "Proposed Change" should be exact syntax where possible — the literal exclusion clause or threshold value — not a paraphrase. A reviewer approving "exclude the backup service account" without seeing the actual account name and scope has approved something they can't verify. If the rule can't be tested in shadow/audit mode before going live, say so in the Testing Plan field and explain why (some SaaS detections don't support it).

**[MANAGEMENT]** - No tuning change ships without an Approver and Approval Date populated. Set a recurring review (quarterly is typical) to confirm tuned-down rules haven't quietly become tuned-out — track this on the same tuning register the request feeds into.

---

## 3. GO/NO-GO Decision Template

For any decision with real blast radius — enabling blocking mode on a new detection, executing a containment action against a production system, disabling a control during an incident, cutting over to a DR environment. This exists so the decision, the people who made it, and the reasoning are on record before anyone acts, not reconstructed afterward from memory.

| Field | Entry |
|---|---|
| Decision Title | `[what is being decided, in one line]` |
| Date / Time (UTC) | `[YYYY-MM-DD HH:MM]` |
| Decision Owner | `[single named person, not a team]` |
| Stakeholders Present | `[names / roles — SOC, IT Ops, application owner, legal, comms as needed]` |
| Related Case / Ticket | `[ID]` |
| Context Summary | `[2–4 sentences: what happened, what's being proposed]` |
| Risk if GO | `[what could go wrong if we act]` |
| Risk if NO-GO | `[what could go wrong if we don't act — often understated]` |

**Decision Criteria**

| Criterion | Met? (Y/N) | Notes |
|---|---|---|
| Containment action tested / understood | | |
| Business owner notified | | |
| Rollback plan exists and is confirmed workable | | |
| Legal / compliance impact reviewed (if applicable) | | |
| Communication plan ready (internal / customer-facing) | | |

| Field | Entry |
|---|---|
| Decision | `[GO / NO-GO / GO WITH CONDITIONS]` |
| Conditions (if any) | `[e.g., "GO, but only outside business hours, with app owner on the bridge"]` |
| Rollback Plan | `[specific steps, owner, time to execute]` |
| Sign-off | `[name, role, timestamp — repeat row per approver]` |

**[STAKEHOLDER]** - This template forces the "what happens if we do nothing" question onto the same page as "what happens if we act." Teams under pressure tend to only evaluate the risk of acting and skip the cost of inaction — leaving a live intrusion in place while everyone debates the blast radius of pulling the plug. Both risks belong in front of whoever has final sign-off.

**[MANAGEMENT]** - Decision Owner is a named individual, not "the SOC" or "leadership." If the decision goes wrong, or right, you need to know who actually made the call under the information available at the time — this is not about blame, it's about being able to reconstruct the decision later with an accurate picture of what was known.

---

## 4. Exception Request Template

For any deviation from standard control or policy — a system that can't be patched on schedule, an account that needs standing admin rights, a detection rule that has to stay disabled on a specific host for a legacy application reason. An exception is a documented, time-bound risk acceptance, not a permanent shrug.

| Field | Entry |
|---|---|
| Exception ID | `[EXC-YYYY-###]` |
| Requested By | `[name / team]` |
| Date Requested | `[YYYY-MM-DD]` |
| Asset / Scope | `[hostname, IP range, application, account — be specific, not "the finance environment"]` |
| Control Being Excepted | `[policy or standard reference, e.g., "Patch SLA — Critical within 14 days"]` |
| Reason for Exception | `[technical or business constraint — be specific]` |
| Compensating Controls | `[network segmentation, enhanced monitoring, MFA, restricted access — what's covering the gap]` |
| Risk Rating (if not remediated) | `[Critical / High / Medium / Low, with brief rationale]` |
| Duration Requested | `[fixed end date — no open-ended exceptions]` |
| Review / Expiry Date | `[YYYY-MM-DD]` |
| Approver | `[risk owner — typically CISO, IT security manager, or delegated authority per risk tier]` |
| Approval Date | `[YYYY-MM-DD]` |

**Renewal History**

| Renewal Date | Requested By | Approved By | New Expiry | Justification for Renewal |
|---|---|---|---|---|
| | | | | |

**[MANAGEMENT]** - Every exception needs an expiry date at submission — "indefinite" is not a valid entry, and an exception with no expiry is how a temporary risk acceptance becomes permanent, unmonitored risk. Renewals should require the same level of scrutiny as the original request, not a rubber stamp; if a system has renewed the same exception four times running, that's a remediation-planning conversation, not a tuning problem.

---

## 5. Case Documentation Template

The standard structure for closing out an investigated alert. This is the artifact that gets pulled during an audit, a post-incident review, or six months later when someone asks "did we ever look at this before?"

```text
Case ID:                  [SIEM/SOAR case number]
Analyst:                  [name / handle]
Date Opened / Closed:     [YYYY-MM-DD HH:MM UTC] / [YYYY-MM-DD HH:MM UTC]

ALERT
  Alert Name:             [detection rule / alert title]
  Alert ID:                [source system ID]
  Time (UTC):              [first triggered timestamp]

AFFECTED ENTITY
  Host / User / Asset:    [hostname, username, IP, cloud resource ID]
  Owner / Business Unit:  [system owner, department]

SOURCE
  Log Source(s):          [EDR, firewall, IdP, DNS, cloud audit log, etc.]
  Ingestion Notes:        [delay, partial telemetry, parsing issues if relevant]

INITIAL EVIDENCE
  [Raw fields / fragment of the triggering event — process, command line,
   source/destination IP, hash, URL, etc. Facts only, no conclusions yet.]

ENRICHMENT
  Threat Intel Lookup:    [IP/domain/hash reputation, source, verdict]
  Asset Context:          [criticality, patch level, known vulnerabilities]
  Identity Context:       [role, privilege level, recent access changes]
  Geolocation / ASN:      [if network-related]

HISTORICAL ACTIVITY
  [Has this entity, IP, hash, or pattern appeared before? Prior cases,
   baseline behavior, known-good business process it might match.]

CORRELATED ALERTS
  | Alert ID | Alert Name | Time (UTC) | Related Entity | Relevance |
  |----------|------------|------------|-----------------|-----------|
  |          |            |            |                 |           |

INVESTIGATION
  [Narrative of what was checked, in what order, and why. Include
   negative findings — "checked X, found nothing" is evidence too.]

TIMELINE
  [Reference to, or embedded copy of, the Incident Timeline Template
   above if the case is complex enough to warrant one.]

ASSESSMENT
  [Analyst's read on what actually happened, in plain language.]

SEVERITY
  Assigned:                [Informational / Low / Medium / High / Critical]
  Rationale:               [why this severity, not another]

MITRE ATT&CK MAPPING
  | Tactic | Technique ID | Technique Name | Evidence Supporting Mapping |
  |--------|--------------|-----------------|------------------------------|
  |        |              |                 |                              |

ACTIONS TAKEN
  [Containment, eradication, or remediation steps actually performed,
   with timestamps and who performed them.]

RECOMMENDATION
  [What should change — tuning request filed, exception needed,
   asset owner action required, no action needed.]

STAKEHOLDER DECISION
  [If escalated: who decided what, and when. Reference the
   GO/NO-GO Decision Template if one was used.]

CLOSURE REASON
  [Select one: True Positive / Benign Positive / False Positive /
   Insufficient Evidence / Expected Activity / Duplicate]
  Closure Notes:           [brief justification for the closure reason chosen]

DETECTION FEEDBACK
  [Did this alert fire correctly? Should logic be tuned? Reference
   Tuning Request ID if one was filed as a result of this case.]
```

**[ANALYST]** - Not every case ends in True Positive. Insufficient Evidence is a legitimate, honest closure when telemetry gaps or retention limits mean you genuinely can't confirm either way — don't force a verdict the evidence doesn't support just to close the ticket cleanly. Benign Positive (the detection logic worked correctly and caught real but non-malicious activity, like an admin's legitimate use of a dual-use tool) is different from False Positive (the detection logic itself misfired) — closing these the same way erodes the tuning signal your detection engineering team relies on.

**[MANAGEMENT]** - Detection Feedback is not optional decoration. Cases closed without it are how the same false positive gets re-investigated by three different analysts over three different shifts before anyone files the tuning request that would have stopped it. Track Detection Feedback completion rate as a case-quality metric, not just time-to-close.
