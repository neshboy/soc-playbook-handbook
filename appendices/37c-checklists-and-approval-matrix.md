# Appendix 37C — Playbook Review, QA, and Testing Checklists, and the Approval Matrix

Three checklists, one table. The checklists answer three different questions that get conflated constantly: is this playbook still *governed* (Review), is this playbook *correct* the day it's published or changed (QA), and has this playbook actually been *proven* against real or simulated data (Testing). Part 29 covers the governance fields these tie back to, and Part 30 covers the testing methods referenced below — this appendix is the working copy you print, attach to a change ticket, or paste into a pull request template. Use `- [ ]` as-is in your own tracker; that's deliberate.

## Playbook Review Checklist

Run this at the cadence set in Part 29's review table (tiered by severity), and again at incident closure if the playbook was invoked. This checklist is about currency and ownership, not about re-testing detection logic line by line — that's what the Testing Checklist below is for.

**Ownership and approval**
- [ ] Owner is a named individual, currently in role, still the right person for this control
- [ ] Approver is a different named individual from Owner, currently in role
- [ ] Version number matches what's actually deployed in the SIEM/SOAR, not just the document
- [ ] Change History entry exists for every substantive edit since the last review, with a named approver per entry

**Currency**
- [ ] Review Date has not lapsed without a completed review (a stale "Validated" status older than the cadence window is treated as a gap, not a pass)
- [ ] Evidence Source still matches the live log source — field names, table names, and forwarding path checked against current SIEM config, not assumed unchanged
- [ ] Escalation contacts (analyst tier, SOC Manager, client contact, IAM/IT/legal as applicable) are current names and reachable channels, not a distribution list nobody monitors
- [ ] Any linked SOAR automation still points at the correct action (block, isolate, disable) and hasn't silently drifted after a platform upgrade

**Exceptions and related controls**
- [ ] Every open exception has an expiry date, and none are past it without remediation or a documented renewal
- [ ] Exceptions still map to the original justification (the legacy host the exception covers still exists and is still legacy)
- [ ] ATT&CK technique references and compliance control cross-references still point at things that actually exist in the current framework version

**[MANAGEMENT]** - A completed review should be evidenced by more than a checkbox ticked by the Owner. At minimum: someone other than the Owner ran the query or exercised the workflow against current data, logged with a date and a name.

## Playbook QA Checklist

Run this before a new or revised playbook goes live — this is the pre-publish gate, not the periodic one. It catches the stuff a governance review won't: broken syntax, ambiguous instructions, and formatting that will confuse whoever's on shift at 3 a.m.

**Structure and language**
- [ ] Every step is a single, unambiguous action — no step that requires the analyst to interpret intent ("assess if suspicious" without criteria is not a step, it's a gap)
- [ ] Decision points explicitly state the branching condition and both outcomes, not just the "yes" path
- [ ] No step depends on a tool, dashboard, or access level the on-call analyst tier doesn't actually have
- [ ] Severity assignment and escalation trigger are stated as concrete thresholds, not "if it looks bad"
- [ ] Acronyms and internal system names are spelled out at least once, or linked to a glossary entry

**Technical accuracy**
- [ ] Every query in the playbook has been syntax-checked against the actual query language of the target platform, not copy-pasted from a different SIEM's dialect
- [ ] Field names referenced in queries and steps match the live schema — no renamed, deprecated, or vendor-migrated field slipped through
- [ ] Any Windows/Sysmon event ID or MITRE ATT&CK technique ID cited is verified against a trusted reference, never typed from memory
- [ ] Sample evidence (screenshots, log excerpts) in the document uses fictional hosts, accounts, and IPs — no real production data pasted into a shared template

**Cross-references and housekeeping**
- [ ] Links to related playbooks, SOAR automations, and governance fields (Owner, Approver, Evidence Source) resolve and are filled in, not placeholder text
- [ ] Playbook ID is unique and follows the org's naming convention, with no leftover draft comments or reviewer notes in the published version
- [ ] Formatting is consistent with the org's playbook template (headings, table structure, checkbox style)

**[ENGINEERING]** - Treat the query-syntax check as a build step, not a courtesy read-through. Lint queries against a schema snapshot before merge if your pipeline supports it — the QA checklist is the last human backstop, not the first line of defense.

## Playbook Testing Checklist

Run this whenever detection logic changes, and at minimum before a new playbook goes from draft to production. This checklist proves the playbook works against something real — a query that "looks right" and has never been run is still a hypothesis.

**Before testing**
- [ ] Test method selected and documented (tabletop, atomic test, lab simulation, purple team, historical replay, synthetic injection, or controlled attack simulation — see Part 30 for which fits which failure mode)
- [ ] Expected outcome written down *before* running the test — what should fire, what fields should populate, what the analyst should see
- [ ] Test environment or dataset identified, and confirmed to reasonably represent production (same log format version, same GPO/agent baseline where relevant)

**During testing**
- [ ] Actual outcome recorded, including partial matches and near-misses, not just pass/fail
- [ ] Any gap between expected and actual outcome traced to a root cause (rule logic, field extraction, parser, threshold, missing telemetry) before calling the fix done
- [ ] False-positive exposure checked against historical data where the method allows it — a rule that never fired in the lab but would fire 4,000 times a month in production is not ready

**After testing**
- [ ] Fix applied and retested against the same scenario that originally failed
- [ ] Testing Status and Last Validation fields updated on the playbook header with date, method, and result
- [ ] Result logged in Change History if the test triggered a change to logic, threshold, or evidence source
- [ ] Sign-off recorded from whoever owns QA/detection engineering for this playbook tier

**[ANALYST]** - If you're the one asked to "just confirm the rule fires," don't just trigger the behavior and watch for an alert. Check that the *evidence* attached to the alert is complete — the account name, source IP, and targeted resource fields the playbook promises the next analyst will have. A rule that fires with an empty evidence panel passes the pass/fail test and still fails the analyst in the queue six months later.

## Playbook Approval Matrix

Who can act unilaterally, and who has to sign off first — by action, not by generic "high/medium/low" severity. Blast radius and reversibility drive the matrix more than raw severity does: a global domain block is lower severity than an active ransomware detonation, but it can knock out a legitimate business partner's mail flow for every user in the company, so it sits behind more approval than an isolated workstation containment does.

**Legend**

| Symbol | Meaning |
|---|---|
| **Act** | Can perform this action independently, no prior sign-off required |
| **Recommend** | Can identify the need and prepare the action, but cannot execute it — must hand off to a role marked Act or Approve |
| **Approve** | Must give explicit go-ahead before the action is taken (or, under a documented emergency-authority exception, ratify it within a defined window afterward) |
| **Notify** | Must be informed the action happened or is happening, but holds no approval authority over it |
| **—** | Not part of this decision |

| Action | Tier 1 | Tier 2 | Tier 3 | SOC Manager | Client | CISO |
|---|---|---|---|---|---|---|
| Enrichment (IOC lookup, log pull, context gathering) | Act | Act | Act | — | — | — |
| Escalation (raise severity, hand off to next tier / IR) | Act | Act | Act | Notify (Critical only) | Notify (per contract) | — |
| Block a malicious hash (confirmed IOC, EDR/AV blocklist) | Recommend | Act | Act | Notify | Notify | — |
| Disable an employee account (standard user) | Recommend | Act | Act | Notify | Approve (or executes, per contract) | — |
| Isolate a workstation | Recommend | Act | Act | Notify | Notify (Approve if production-critical) | — |
| Disable an executive account | Recommend | Recommend | Recommend | Approve | Approve | Notify |
| Block a domain globally | Recommend | Recommend | Act, with SOC Manager notified | Approve | Approve | Notify (if business-critical domain affected) |

A few rows deserve the reasoning spelled out, since a matrix without context gets misapplied.

**Enrichment carries no approval gate anywhere** because it's non-destructive — pulling threat intel on a hash or checking a source IP's history doesn't change production state. Any tier acts on it freely.

**Escalation is a communication action, not a containment one**, so it scales differently — every analyst tier can escalate, because *not* escalating fast enough is the more common and more expensive failure mode. The gate here is Notify, not Approve.

**Disabling an employee account** is where MSSP contracts diverge most. Some clients grant the SOC direct IAM execution rights for confirmed-compromise cases; others require the client's own IT or HR-adjacent process to pull the trigger, with the SOC only recommending. Confirm which model applies per contract — this row is the one most likely to need per-client customization rather than a single fixed answer.

**Disabling an executive account and blocking a domain globally sit behind the same logic**: high blast radius, low reversibility in practice (an exec locked out during a board call, or a domain block that takes down a vendor's invoicing portal, both generate business impact fast), so approval sits with SOC Manager and Client jointly, with the CISO notified rather than gating the decision — the CISO doesn't need to approve every domain block, but does need to know one just happened to a business-critical partner.

**[MANAGEMENT]** - Build an emergency-authority clause into this matrix rather than pretending approval will always arrive before action is needed. A common pattern: during an active, spreading incident (ransomware encrypting shares in real time), Tier 3 or the SOC Manager may isolate a workstation — or even an executive's — ahead of formal approval, provided the action is logged immediately and Client/CISO approval is obtained retroactively within a fixed window (commonly one hour for containment actions). Document that clause once, in this matrix, so nobody is improvising authority mid-incident.

**[STAKEHOLDER]** - This matrix is the answer to "who let that happen" before anyone has to ask it. If a domain gets blocked and it turns out to be a Benign Positive — a partner's mail server got flagged on a shared blocklist, say, and normal business mail stopped flowing — this table tells you in one glance whether that block was authorized at the right level or whether someone skipped a step, without needing to reconstruct the incident timeline from chat logs.
