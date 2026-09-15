# Part 24: SOC to Stakeholder Communication

## Why the Translation Layer Matters

Somewhere around the third time a CISO asks "wait, so are we hacked or not?" after reading a SOC ticket verbatim, most analysts learn the hard lesson: a technically accurate sentence and a *useful* sentence are not the same thing. A ticket that says "4769 observed with RC4 encryption type against SPN HTTP/sqlprod01.example.com" is exactly right for the next analyst who picks up the case. It is close to meaningless for a VP of Finance trying to decide whether to pull sqlprod01 offline during month-end close.

This isn't about dumbing content down. It's a deliberate re-encoding of the same finding for a different decision-maker, with a different job, a different vocabulary, and a different question they're actually trying to answer ("do I need to act, and how fast?" rather than "what's the raw evidence?"). Get this wrong in either direction and you create real damage: understate it and leadership doesn't fund the response; overstate it and you burn credibility the first time it turns out to be a benign positive, and next time nobody picks up the phone.

## The Core Principle: Accuracy and Uncertainty Level Must Survive Translation

The rule that governs every example below: **you can simplify the language, but you may not simplify the confidence.** If the technical finding is confirmed malicious, the stakeholder version has to land as confirmed. If the technical finding is "suspicious, still under investigation, could be a benign positive," the stakeholder version has to carry that same hedge — not a flattened "we think you were breached" and not a falsely reassuring "nothing to worry about."

Three things get lost most often when analysts translate on the fly, and all three are the actual point of the translation, not decoration:

1. **Scope** — one host vs. the domain, one mailbox vs. the whole tenant. Collapsing "affected one workstation" into "the network was compromised" is a common, avoidable escalation of language.
2. **Confidence** — "confirmed" vs. "likely" vs. "suspected" vs. "unconfirmed, still validating" are different words for a reason. Stakeholders make different decisions on each.
3. **Status** — active and ongoing vs. contained vs. already remediated. A finding from three days ago that's already closed reads very differently than one still in progress, and leadership needs to know which they're getting.

**[ANALYST]** - Before you write the stakeholder line, write down for yourself: what do I actually know, what am I inferring, and what's still open. Translate all three, not just the first.

**[MANAGEMENT]** - This is also a liability question. If an executive briefing overstates certainty ("we confirmed data exfiltration") and the case later closes as Insufficient Evidence, that gap has to be explained — to the board, sometimes to counsel, sometimes to a regulator. Calibrated language protects the SOC as much as it protects the business.

## Paired Examples

Each pair below keeps the same scope and confidence level in both the technical and the plain-language version — that's the part to study, not just the vocabulary swap.

### 1. Malicious document execution (Phishing + PowerShell)

**Technical:** "4688 showed encoded PowerShell spawned by WINWORD.EXE."

**Stakeholder:** "A user opened a document that caused Microsoft Word to launch a hidden PowerShell command, which is not expected behaviour and may indicate malicious execution. We've isolated the device and are checking what else it may have touched before we call this contained."

Note: "may indicate" preserves the fact that this is still process-lineage evidence, not a confirmed compromise. Maps to T1566.001 (Phishing: Attachment), T1059.001 (PowerShell), and T1027 (Obfuscated Files or Information) if the SOC wants to reference technique behind the scenes — the stakeholder version doesn't need the MITRE ATT&CK IDs at all.

### 2. Password spraying against multiple accounts

**Technical:** "4625 logon failures with Sub Status 0xC000006A observed against 40 distinct accounts from a single source IP within 20 minutes, consistent with T1110.003."

**Stakeholder:** "Someone attempted to log in to 40 different employee accounts from a single external location, using guessed passwords, over a short period. No successful logins have been confirmed yet, but this looks like a coordinated attempt to break into accounts rather than a normal mistake. We're blocking that source and resetting passwords for the affected accounts as a precaution."

Note: keeps scope (40 accounts, one source) and confidence ("no successful logins confirmed yet") explicit rather than implying the spraying succeeded.

### 3. Kerberoasting attempt

**Technical:** "4769 shows a spike in service ticket requests using RC4 encryption (0x17) for multiple SPNs from a single user context, pattern consistent with T1558.003."

**Stakeholder:** "We saw one user account request an unusually large number of service credentials in a short window, using an older, weaker encryption method. This is a known technique attackers use to try to steal service account passwords for offline cracking. We have not confirmed a password was cracked or misused — we are validating whether this account's behaviour is legitimate admin activity or something else."

Note: explicitly separates "the technique was attempted" from "the technique succeeded" — a distinction that gets lost constantly in verbal handoffs.

### 4. Ransomware precursor activity

**Technical:** "Mass file rename/encryption activity detected on file server FS02, correlated with shadow copy deletion consistent with T1490 and T1486. Encryption is actively in progress."

**Stakeholder:** "A file server is currently being encrypted by what appears to be ransomware, and the attacker has also deleted our local backup snapshots on that server to make recovery harder. This is active and ongoing right now. We need a decision on isolating that server from the network immediately."

Note: this is one of the rare cases where the stakeholder line should carry *more* urgency markers than the technical ticket, not fewer — "active and ongoing," "immediately" — because the decision window is short and the business owner is the one who can authorize isolation of a production system.

### 5. Business email compromise / mailbox rule abuse

**Technical:** "Investigation centers on a newly created inbox rule forwarding finance-related mail to an external address, consistent with T1114.003 following a confirmed T1078.004 logon from an unrecognized geolocation."

**Stakeholder:** "An employee's email account was accessed from a location they don't normally log in from, and shortly after, a rule was quietly added to that mailbox that forwards finance-related emails to an outside address without the employee's knowledge. This looks like an attempt to intercept financial communications, possibly to redirect a payment. We recommend notifying the employee, disabling the rule, and reviewing recent financial correspondence from that account before any pending payments go out."

Note: translates the ATT&CK-mapped mechanics into the actual business risk (payment fraud) — this is the point where a stakeholder can act (hold a wire transfer) faster than the SOC can finish the technical investigation.

### 6. Lateral movement via stolen credentials

**Technical:** "4624 Logon Type 3 from Workstation-A to Server-B using credentials for svc_backup, with 4648 explicit-credential logons observed shortly beforehand from an unrelated host — pattern consistent with T1550.002 and T1021.002."

**Stakeholder:** "An attacker appears to be reusing a stolen service account's login to move between systems on our network, rather than logging in with a normal password. This account has now touched at least two servers it doesn't normally access. We are treating this as active movement inside the environment and are working to contain it."

Note: "at least two servers it doesn't normally access" gives a concrete, bounded scope statement instead of a vague "moving around the network" that invites the assumption of full compromise.

### 7. Insider privilege change

**Technical:** "4728 shows Subject jdoe added member asmith to security-enabled global group 'Domain Admins' outside of change-management hours, no associated ticket found."

**Stakeholder:** "An employee with administrative access granted another employee full administrative rights over the network, and this change wasn't tied to any approved change request or ticket. We're checking whether this was legitimate but undocumented, or something we need to escalate."

Note: honestly flags this could still be Benign Positive (a rushed but legitimate change) — the stakeholder line doesn't accuse, it flags a control gap and an open question.

### 8. Log tampering / anti-forensics

**Technical:** "1102 audit log cleared, Subject = local Administrator on DC01, no corresponding change ticket, occurred 40 minutes before ransomware encryption activity began."

**Stakeholder:** "Someone deliberately erased the security log on one of our domain controllers shortly before a ransomware attack started on that same system. Clearing that log is not something legitimate administration normally does — it's a strong indicator the attacker was trying to cover their tracks. We treat this as confirmed malicious activity, and we've lost some visibility into exactly what else happened on that system in the window before the log was cleared."

Note: this is a case where confidence is genuinely high — say so plainly ("confirmed malicious") — while still being honest about the resulting evidence gap instead of pretending the timeline is complete.

## Uncertainty Calibration Cheat Sheet

Keep language consistent across the SOC so stakeholders learn to trust the words, not just the tone of whoever is briefing them that day.

| SOC internal status | Stakeholder-safe phrasing |
|---|---|
| Confirmed malicious, root cause established | "We have confirmed this was malicious activity." |
| High confidence, awaiting final confirmation | "This is very likely malicious; we're finishing verification now." |
| Suspicious, active investigation | "This looks suspicious. We don't have a final answer yet — we're actively investigating." |
| Insufficient Evidence (closed) | "We investigated and could not confirm malicious activity either way. We're not treating this as resolved-safe, just as inconclusive." |
| Benign Positive (closed) | "This looked suspicious but turned out to be legitimate [admin/business] activity. No action needed." |
| Expected Activity (closed) | "This matched a known, approved activity pattern (e.g., scheduled maintenance, approved pen test). No concern." |

**[STAKEHOLDER]** - If a briefing ever uses the word "confirmed," it should always mean the SOC has evidence, not a hunch. Ask what evidence, if it isn't offered — a good SOC will have an answer ready.

## Common Translation Failures Worth Naming

- **Overclaiming for impact.** Turning "suspicious" into "breach" to get budget or attention approved faster. This works once and costs trust for years afterward.
- **Underclaiming to avoid alarm.** Softening "active ransomware encryption" into "we're monitoring an issue on the file server" because nobody wants to be the one who says the scary word on a Friday afternoon call. This delays the decision that actually matters.
- **Jargon dumping.** Pasting the raw event fields into an executive email and letting the reader sort it out. If the recipient has to google "Sub Status 0xC0000234," the translation didn't happen.
- **Dropping scope.** "A host was compromised" quietly becoming "the network was compromised" by the third retelling in a chain of Slack messages. Restate scope every time the finding is repeated, not just the first time.
- **Silence on remediation status.** Leadership's real question after any technical detail is almost always "is it still happening, and what have we done about it." If the translation doesn't answer that, it isn't finished.

**[MANAGEMENT]** - Maintain a small, living library of pre-approved translation patterns for your most common alert categories (phishing execution, brute force, credential theft, ransomware, BEC, insider/privilege change, log tampering) so analysts aren't improvising executive-facing language mid-incident. Review the library quarterly, and after every major incident post-mortem, check whether the stakeholder-facing language during that incident actually matched the confidence level the SOC held at the time — that gap, if any, is a lesson worth writing down before the next call.
