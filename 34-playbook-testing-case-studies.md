# Playbook Testing — Worked Case Studies

Five tests pulled from the kind of exercises that actually happen to a playbook once it's live: a tabletop that trips over a missing telemetry field, a purple-team live-fire that proves the detection worked and the phone tree didn't, a cold walkthrough that exposes a sentence only the veterans could read correctly, a post-incident retro that reruns a real case through the documented decision tree and gets the wrong answer, and a migration regression test that catches a query silently returning nothing. Same five elements each time: the alert/trigger, what got pulled, the decision point, where it landed, and the one-line failure mode if nobody had run the test.

---

## Case Study 1: The Tabletop That Found a Missing Field Before an Attacker Did

**Organization:** Alder Point Health System (alderpointhealth.example.com)

**Test type:** Quarterly tabletop exercise for the "Kerberoasting Response" playbook — scripted scenario, walked against live production log data rather than a whiteboard narrative, so the evidence-gathering steps get exercised for real.

**Alert/Trigger:** Facilitator injects the scripted condition: "High-Volume RC4 Service Ticket Requests" (T1558.003) for account `svc_labresults`, nine distinct SPNs requested in six minutes, source host `RAD-WKS-11` (10.12.8.44).

**Evidence gathered:**

| Step | Playbook instruction | Result during test |
|---|---|---|
| 1 | Pull `4769` detail — SPNs, Ticket Encryption Type, Client Address | Clean, RC4 confirmed, matches scenario |
| 2 | Identify requesting process via `4688` on the client address | `4688` events present, correct PID chain |
| 3 | **Capture Command Line from the `4688` to confirm what invoked the ticket requests** | Command Line field **blank on every event** for this host |

**Reasoning/decision points:** The analyst running the walkthrough stopped at Step 3 and flagged it rather than improvising a workaround, which is the entire point of running the test against real infrastructure instead of a hypothetical. Digging into why: the Radiology OU had "Include command line in process creation events" excluded from its GPO eight months earlier during a legacy imaging-app compatibility fix, and nobody re-enabled it once the fix shipped. Nobody had needed that field for that OU since — until a scripted test asked for it. A discussion-only tabletop ("we'd check the command line, right, good, next question") would have sailed past this; running the actual query against the actual environment is what surfaced it.

**Outcome:** Step 3 logged as a failed test step, not a passed one with a caveat. Change ticket raised to re-enable command-line auditing on the Radiology OU. The playbook itself was revised to add a pre-flight check ("confirm command-line auditing is enabled for the source OU before relying on Step 3") plus a documented fallback using `4104` script block correlation and raw `4688` parent-process chain when it isn't. Retested six weeks later against the same scenario — clean pass.

**Without this discipline:** the first real Kerberoasting attempt against a radiology service account hits the same blank field mid-incident, and the analyst burns SLA time trying to figure out whether the evidence is missing on purpose or missing because the environment is broken — exactly the kind of thing you don't want to be diagnosing for the first time during a live case.

---

## Case Study 2: Live-Fire Proved the Detection Worked and the Phone Didn't Ring

**Organization:** Cascade Metals & Fabrication (cascademetals.example.com)

**Test type:** Scheduled purple-team exercise — red cell runs an approved atomic-test simulating LSASS memory access (T1003.001) against a designated test host, mapped end-to-end to the "Credential Dumping Response" playbook, not just the underlying detection rule.

**Alert/Trigger:** EDR fires on `ENG-TEST07` (10.55.3.20) when the atomic-test binary opens a handle to `lsass.exe` with the access rights the rule watches for. Corroborating `4688` shows the process launch with the expected parent chain.

**Evidence gathered:**

- Detection fired within SLA — no complaint here, the rule did its job.
- Playbook Step 2 requires paging the on-call IR lead within fifteen minutes. Purple team's independent clock shows the page went out on time, over the correct paging system, to the phone number on file in the playbook's escalation contact table.
- That number belonged to an IR lead who left the company three months earlier. The line was reassigned internally but unmonitored for security pages — nobody had told the security team the roster changed.
- No acknowledgment inside the SLA window. Escalation stalled at Step 2 for the entire duration of the exercise.

**Reasoning/decision points:** **[MANAGEMENT]** Detection logic and escalation logic are two separate things that both have to pass, and live-fire is the only test that checks the second one honestly. A tabletop would have someone say "we'd call the on-call lead" and move on without anyone actually being called — the failure mode never surfaces because nobody's phone has to ring. Live-fire dials the real number. Keeping the on-call roster synced with HR offboarding wasn't clearly owned before this; it is now, folded into the same quarterly review that bumps the playbook's version number.

**Outcome:** Escalation contact information was pulled out of the static playbook document entirely and replaced with a live reference to the on-call scheduling tool, resolved at time of use instead of baked into a doc that goes stale the day someone changes roles. Retested the following quarter with a fresh atomic-test run: page acknowledged in four minutes.

**Without this discipline:** the detection rule fires exactly as designed during a real credential-dumping attempt, and the incident sits unactioned for hours because the page rang a disconnected line — while the SOC's own dashboard shows "escalation sent," green, satisfied, and nobody is looking for a problem that already happened.

---

## Case Study 3: The Cold Walkthrough That Found a Sentence Only the Veterans Could Read

**Organization:** Bellhaven Wealth Partners (bellhavenwealth.example.com)

**Test type:** Onboarding validation — a new Tier 1 analyst is handed a canned scenario cold, no coaching, to test whether the "Cloud Account Compromise" playbook is actually followable by someone with zero tribal context, or only by the people who wrote it.

**Alert/Trigger:** Canned scenario built from a real alert shape — impossible-travel flag (T1078.004) on advisor account `r.calloway@bellhavenwealth.example.com`, two push-approved sign-ins six minutes apart from geographically distant IPs.

**Evidence gathered:** The scripted log excerpt handed to the new analyst shows four denied push prompts followed by one approval, all within a three-minute window, then the second sign-in. The playbook's decision point reads: *"If MFA method is push-approved with no fatigue pattern present, treat as low-confidence and downgrade."*

**Reasoning/decision points:** **[ANALYST]** The new analyst read "no fatigue pattern present," looked at four denials followed by an approval, and — because the term "fatigue pattern" is never defined anywhere in the document — genuinely couldn't tell whether that counted as one. She made a defensible guess and downgraded a case that should have escalated. That's not an analyst failure; that's a document failure. Whoever wrote that sentence already knew what a fatigue pattern looks like, so the ambiguity was invisible to them. It's only visible when someone with no prior context tries to execute the sentence literally, which is exactly what a structured cold walkthrough is designed to force.

**Outcome:** The playbook was rewritten with a numeric threshold: three or more denied push prompts within a ten-minute window, followed by an approval, constitutes a fatigue pattern regardless of any other signal, and routes to escalation automatically. Re-tested with the next onboarding analyst using the same scripted scenario — correct decision reached unaided, no coaching required.

**Without this discipline:** the ambiguity survives quietly for years because everyone senior enough to be trusted with the case already knows the unwritten threshold, right up until a live MFA-fatigue compromise lands on someone new who reads the sentence exactly as literally as it's written and waves it through as a normal push approval.

---

## Case Study 4: Rerunning a Real Incident Through the Decision Tree and Getting the Wrong Answer

**Organization:** Turnstone Logistics (turnstonelogistics.example.com)

**Test type:** Post-incident playbook validation — after a confirmed BEC case closed, the review board reruns the incident's actual timeline through the documented "BEC / Account Compromise" decision tree as a regression check, to see whether the written logic reaches the same verdict the analyst reached by judgment at the time.

**Alert/Trigger (original incident):** Account compromise via legacy IMAP authentication (T1078.004) that never triggered an MFA challenge at all, followed by a forwarding rule (T1114.003). The original analyst escalated same-day based on device-log evidence contradicting the account owner's self-report.

**Evidence gathered during the retest:** Feeding the same incident data into the documented tree, the first branch point asks: *"Was MFA challenged? Yes / No."* Legacy IMAP authentication doesn't trigger MFA at all — the honest answer is neither yes nor no, it's not applicable, a third state the tree was never built to hold. Forced into the nearest available branch ("No — MFA not challenged, low prior likelihood on this path"), the documented tree walks to an "undetermined, continue monitoring" outcome.

That does not match what actually happened. The real incident was escalated and confirmed the same day, entirely on the strength of a human analyst noticing that a legacy protocol bypassing MFA is itself the finding, not a footnote on the way to a different branch.

**Reasoning/decision points:** A decision tree that can't reproduce a verdict its own senior staff already know is correct isn't a tested control, it's a diagram. The discipline here is treating a closed incident as a regression test case the same way you'd rerun a bug against fixed code — if the documented logic and the correct real-world outcome disagree, the logic is what has to change, not a footnote reminding analysts to use their judgment instead of the tree they were handed.

```text
// decision tree fragment — before and after, testing reference only

BEFORE:
IF mfa_challenged == "Yes" AND new_forwarding_rule == "Yes" -> escalate
IF mfa_challenged == "No"  AND new_forwarding_rule == "Yes" -> low_confidence, monitor
// legacy auth forces a "No" here with no way to distinguish it from a normal failed MFA case

AFTER:
IF auth_protocol IN (legacy_imap, legacy_pop, smtp_auth_legacy) -> escalate
    // MFA-incapable protocol is itself the signal, independent of every other branch
ELSE IF mfa_challenged == "Yes" AND new_forwarding_rule == "Yes" -> escalate
ELSE IF mfa_challenged == "No"  AND new_forwarding_rule == "Yes" -> low_confidence, monitor
```

**Outcome:** The tree was revised to add an explicit branch ahead of the existing MFA question: authentication over a protocol that doesn't support MFA routes straight to escalation, independent of every downstream answer. A synthetic case built from this incident's own data was added to the standing regression suite, so any future edit to this playbook gets rerun against it automatically before sign-off.

**Without this discipline:** the same undefined branch keeps producing "undetermined, continue monitoring" for every future legacy-auth compromise, and whether it gets escalated in time depends entirely on whether that particular day's analyst happens to carry the same unwritten judgment the original one did — which is precisely the inconsistency a playbook exists to remove in the first place.

---

## Case Study 5: The Migration Regression Test That Caught a Query Returning Nothing

**Organization:** Meridale Retail Group (meridaleretail.example.com)

**Test type:** Scheduled regression test ahead of a SIEM platform migration cutover — every saved query embedded in the playbook library gets rerun against the new platform using deliberately seeded synthetic events, before the old platform is decommissioned.

**Alert/Trigger for the test:** Synthetic `4740` (account locked out) events generated against a disposable test account across three test hosts, seeded specifically to trip the "Account Lockout Storm" playbook's trigger condition on the new platform.

**Evidence gathered:** The seeded events are confirmed present in the new platform's raw index — that part of the pipeline works. The playbook's saved detection query, migrated verbatim from the old platform, returns **zero results**. No error, no warning, no broken-query flag anywhere in the console. Root cause, once traced: the new platform's field-normalization layer renamed `Caller Computer Name` to a different canonical field, and the migrated query still referenced the old name — a mismatch that fails silently rather than loudly.

```text
// pseudo-query, engineering reference only

BROKEN (post-migration, old field name):
source=4740 | stats count by CallerComputerName
    // field no longer exists under this name on the new platform — returns empty, not an error

FIXED:
source=4740 | stats count by src_host_normalized
    // matches the new platform's normalized field taxonomy
```

**Reasoning/decision points:** **[ENGINEERING]** A query returning zero results is the most dangerous kind of broken, because it looks exactly like "nothing happened" — no red banner, no alert-on-alert-failure, just a quiet dashboard. The only reason this got caught before cutover is that the test compared an *expected* count from known-seeded data against the *actual* count returned, rather than just confirming the query ran without erroring. "Query executes cleanly" and "query returns the right thing" are different bars, and migration testing has to check the second one specifically.

**Outcome:** Every playbook-embedded query across the library was re-mapped to the new field taxonomy and re-validated against seeded expected counts, not just nonzero results. Cutover was delayed two days to finish the full requery pass across the playbook set before the old platform went dark.

**Without this discipline:** cutover proceeds on the original schedule, and for weeks every lockout, spray, and service-install query in the playbook library quietly returns "no results" — read by everyone as "a quiet week" — while the SOC has an actual blind period across an entire category of alerting, discovered only when an unrelated audit or a real attack produces evidence the tooling should have caught and didn't.

---

## Cross-Case Patterns

| Case | Test method | What it actually validated | Discipline that mattered |
|---|---|---|---|
| Kerberoasting evidence step | Tabletop against live data | Whether the required field even exists in this environment | Run the query for real, don't just discuss it |
| Credential-dumping escalation | Purple-team live-fire | The human/paging chain, not just the detection rule | Test the phone, not just the alert |
| MFA-fatigue decision point | Cold walkthrough, new analyst | Whether the written instruction survives with zero tribal context | Ambiguity is invisible to whoever wrote it |
| BEC decision tree | Post-incident regression | Whether documented logic reproduces a known-correct verdict | Real closed cases are regression tests |
| Lockout query, post-migration | Seeded-data regression | Whether "runs without error" also means "returns the right thing" | A silent empty result is a failure, not a quiet day |

Every one of these was found on purpose, on a schedule, before it mattered — a missing GPO setting, a stale phone number, an undefined threshold, an unhandled branch, a renamed field. None of them announce themselves. That's the argument for testing a playbook on a cadence instead of trusting it still works because it worked the last time someone needed it.
