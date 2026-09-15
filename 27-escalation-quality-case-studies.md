# Escalation Quality — Worked Case Studies

Six composites pulled from the kind of tickets that actually cross a queue: a lockout storm, a Kerberoasting spike, a Business Email Compromise (BEC) that comes with a plausible cover story, a ransomware precursor, a cloud alert that resolves clean and then doesn't, and an exfil alert that isn't a security incident at all. Each one shows the trigger, what got pulled, the actual decision point, where it landed, and the one-line failure mode if the discipline had been skipped.

## Case Study 1: The Lockout Storm That Was Two Different Problems

**Organization:** Harlow Insurance Group (harlowinsurance.example.com)

**Alert/Trigger:** Correlation rule fires on fifteen `4740` (account locked out) events across the Finance OU inside a ten-minute window. Auto-tagged as probable password spraying (T1110.003).

**Evidence gathered:**

| Event | Key fields | Observation |
|---|---|---|
| 4740 x14 | Caller Computer Name | All point to `FIN-APP01` (10.20.4.15) |
| 4771 (preceding) | Failure Code, Client Address | 0x18 bad password, source = FIN-APP01, single target account (`svc_invproc`), repeated every ~45 seconds |
| 4740 x1 (outlier) | Caller Computer Name | Points to `JUMP-02` (10.20.4.201), not FIN-APP01 |
| 4771 (outlier thread) | Client Address, Account Name | Source = VPN pool range, five distinct target accounts, `svc_reports` included |
| 4625 (outlier thread) | Sub Status | 0xC000006A across all five accounts, no successful auth |

**Reasoning/decision points:** Fourteen of fifteen lockouts trace to one host hammering one account with a stale password — classic "IT rotated the service account secret and nobody updated the app's stored credential" pattern, confirmed by checking the change log (password for `svc_invproc` rotated the prior evening). That's a Benign Positive, not an attack, and it gets closed as such with a ticket to the app owner to update the stored credential. The fifteenth lockout doesn't belong to that story: different source host, different account, and — critically — that source host was hitting five separate accounts, not one. Bucketing all fifteen lockouts as "the known noisy app" would have buried it.

**Outcome:** Bulk lockouts closed Benign Positive with the rotation ticket referenced as root cause. The `svc_reports` thread escalated separately as T1110.003 with its own evidence package (distinct source, multiple targeted accounts, timing pattern inconsistent with the app). IR traced the VPN session to a contractor account that should have been deprovisioned two weeks earlier; access revoked same day.

**Without this discipline:** the spray gets absorbed into "the usual FIN-APP01 lockout noise" ticket, closed in bulk, and the contractor account keeps guessing.

---

## Case Study 2: Kerberoasting Under a Legitimate-Looking Volume Spike

**Organization:** Prescott Logistics (prescottlogistics.example.com)

**Alert/Trigger:** UEBA flags a burst of `4769` events — six distinct Service Names requested by one account (`jsmith`, a helpdesk analyst) inside two minutes, all with Ticket Encryption Type `0x17` (RC4). Tagged T1558.003.

**Evidence gathered:**

- `4769`: six SPNs, all RC4, none of which jsmith's role has ever queried in the prior ninety days of baseline.
- `4104` on `WKS-0142`: script block content matching a Kerberoasting-style ticket-request loop, including base64-wrapped segments consistent with T1027 (Obfuscated Files or Information).
- `4688`: `powershell.exe` spawned with Creator Process Name `winword.exe`, timestamped four minutes before the ticket burst.
- Follow-up: the Word document traced to an email attachment received that morning — T1566.001.

**Reasoning/decision points:** `4769` volume is normally filtered noise on this network — that's exactly why it's a comfortable place to wave something through. The question that matters isn't "is RC4 unusual in general," it's "is RC4 unusual for *this account*." Baseline says jsmith has never touched an SPN. The parent-child anomaly (Word spawning PowerShell) and the obfuscated script block close the loop: this isn't an app quirk, it's T1059.001 execution off a phishing attachment, followed by an offline-cracking setup against six service accounts' RC4 keys.

**Reasoning check** — **[ENGINEERING]** Detection logic here can't just threshold on RC4 ticket count; it needs the account-vs-historical-SPN-set baseline, otherwise every legitimate legacy app that still negotiates RC4 trips the same rule and drowns the real ones.

**Outcome:** Escalated with the full chain — 4769 detail, 4104 script block, 4688 parent mismatch, and the phishing attachment — to IR within the hour. The six service accounts were rotated to AES-capable keys where the app supported it; the rest got password resets before any successful reuse of a cracked hash was observed.

**Without this discipline:** the ticket burst gets closed as "normal 4769 volume, no action" (a completely defensible-sounding line if you don't check the account baseline), and the attacker has days offline to crack six service account passwords with no clock running against them.

---

## Case Study 3: The BEC That Comes With Its Own Alibi

**Organization:** Meridian Financial Group (meridianfg.example.com)

**Alert/Trigger:** Email security tooling flags a new inbox rule on an AP clerk's mailbox forwarding anything matching "invoice" or "wire" to an external address. Tagged T1114.003, underlying account access tagged T1078.004.

**Evidence gathered:**

- M365 sign-in log: successful authentication for Denise Okafor forty minutes before the rule was created, source ASN geolocated to Lagos, via a legacy IMAP connection — no MFA challenge recorded.
- Endpoint: Windows `4624` on Denise's laptop that same window shows Logon Type 2 (interactive), Source Network Address internal, Workstation Name matching her assigned device — i.e., she was logged into her own laptop in Chicago at the exact time the cloud session claims she was creating the rule.
- Forwarding target domain is one character off Denise's stated personal address — a lookalike, not the real one.

**Reasoning/decision points:** **[ANALYST]** Tier 1's first instinct after calling Denise was to close the ticket — she confirmed, in good faith, that she set up forwarding to work from home. That confirmation is worth exactly nothing against the log evidence: her own device shows her working locally in Chicago at the same minute the cloud session she's taking credit for originated from Lagos over legacy auth with no MFA. Self-report from the account owner is a data point, not a verdict, and this is the case that proves why — she wasn't lying, she was simply wrong about which rule she thinks she made versus the one the logs show actually being made in that window.

**Outcome:** Escalated as confirmed account compromise despite the user's initial reassurance. Password reset, session tokens revoked, rule deleted, legacy IMAP disabled tenant-wide as a hardening follow-up. Finance notified because the mailbox held live vendor payment threads — any pending wire instructions from that thread got a verbal reconfirmation before release.

**Without this discipline:** ticket closes as Expected Activity on the strength of a confident phone call, the forwarding rule stays live, and the next invoice thread in that mailbox gets quietly redirected for a payment-diversion attempt weeks later.

---

## Case Study 4: Getting the Severity Right, Not Just the Verdict

**Organization:** Colby Manufacturing (colbymfg.example.com)

**Alert/Trigger:** EDR flags a new service on `FS-PROD03` (10.40.2.30) named `WinDefendUpdate`, ImagePath under `C:\ProgramData\`. Logged in the System log as `7045`; no matching `4697` in the Security log, because service-operation success auditing wasn't enabled on that host — a gap worth noting, since the System log source caught what the Security log missed. Tagged T1543.003.

**Evidence gathered:**

| Event | Detail |
|---|---|
| 4719 | Process Creation auditing subcategory disabled, minutes before the service install — logging got dimmed but not before this event itself made it out (T1562.001) |
| 7045 | `WinDefendUpdate`, Start Type Auto, running under a local service account |
| 4688 | Service binary spawning `cmd.exe` with a command line invoking shadow-copy deletion (T1490) |

**Reasoning/decision points:** **[MANAGEMENT]** Tier 1's initial severity was Medium — one host, EDR already flagged it, seemed contained. That score answered "how confident are we this is malicious," which was already high, but not "what happens if we're slow." FS-PROD03 hosts the finance share and is a backup source for two departments. Confidence and severity are two different axes — this one needed Critical/P1 on blast radius alone, independent of how sure anyone was about intent, because shadow-copy deletion attempts are a precursor signal for T1486, not a wait-and-confirm signal.

**Outcome:** Escalated Critical, host isolated at the network layer, IR engaged inside SLA. No encryption observed — the shadow-copy deletion attempt itself was the trigger for isolation rather than evidence of completed impact.

**Without this discipline:** it sits in the Medium queue overnight because "EDR already caught it," shadow copies and the two departments' recent backups get wiped before anyone with authority to isolate the host is looped in.

---

## Case Study 5: The Clean Explanation That Wasn't the Whole Story

**Organization:** Solstice Retail Co (cloud environment, `solstice-prod` subscription)

**Alert/Trigger:** CSPM alert on a new access key issued for service principal `svc-terraform-prod`, tagged T1098.001.

**Evidence gathered:** Pipeline logs confirm a scheduled Terraform apply job ran in the same window, from the expected runner IP range, matching an open change ticket for a credential rotation. Clean match, textbook Expected Activity.

**Reasoning/decision points:** **[ANALYST]** The alert is fully explained at this point — most queues would close it here. The remaining step is the adjacent-activity sweep: what else touched this subscription in the surrounding hour, regardless of whether it triggered its own alert. That sweep turns up an owner-level role assignment granted to a principal nobody recognizes, with no change ticket and no pipeline identity behind it, preceded a few minutes earlier by a burst of storage-bucket and role enumeration from the same session (T1580). None of that showed up on the original alert — it surfaced because someone kept looking after the first question was already answered.

**Outcome:** Original alert closed Expected Activity, change ticket referenced. The role-assignment activity opened as a new, unrelated incident: credentials revoked, assignment removed, and the session traced back to a personal access token committed in cleartext to a developer's public repository (T1552.001).

**Without this discipline:** the CSPM ticket closes clean the moment the Terraform job explains it, and the privilege grant sitting in the same hour's log never gets a second look until someone notices unexplained resource changes weeks later.

---

## Case Study 6: When the Right Escalation Isn't to IR

**Organization:** Ashford & Kline Consulting

**Alert/Trigger:** Data Loss Prevention (DLP) / proxy alert on a 2.3 GB upload from a departing project manager's laptop to a personal cloud storage service, the evening before their last scheduled day. Resignation, not termination-for-cause. Tagged T1567.

**Evidence gathered:** Proxy logs show a sustained upload over roughly forty minutes to a personal storage domain. `4688` process history on the endpoint shows the employee's own file browser and a standard archive utility run against a "Client Deliverables" share they had legitimate day-to-day access to as part of their role. Badge and session logs show them physically in the office, logged in normally, during normal hours — no credential compromise, no privilege change, no attempt to obscure the activity.

**Reasoning/decision points:** **[STAKEHOLDER]** The first branch in escalation criteria isn't "is this bad," it's "is this ours." No compromised account, no control bypass, no malware — from a pure intrusion standpoint this is a non-event, and closing it Expected Activity in the SIEM is technically correct. But "not an intrusion" and "nothing to do" aren't the same conclusion. Volume, timing, and destination together describe a genuine data-handling risk that belongs to HR, Legal, and whoever owns the client relationship — not to IR, and not to nobody.

**Outcome:** SOC ticket closed Expected Activity with the evidence package (what was taken, when, where it went) forwarded to HR and Legal as a documented referral, with a case reference retained so a legal hold can be requested later if the client relationship is affected.

**Without this discipline:** it closes quietly as "employee had access, nothing technical to see," proxy logs roll off retention in thirty or sixty days, and there's no evidence left the day the client asks why their deliverables showed up at a competitor.

---

## Cross-Case Patterns

| Case | Closure category | Discipline that mattered |
|---|---|---|
| Lockout storm | Split: Benign Positive + Incident (T1110.003) | Not bucketing an outlier into the majority explanation |
| Kerberoasting | Incident | Baselining against the account, not the event type |
| BEC with alibi | Incident | Evidence outranks a confident self-report |
| Ransomware precursor | Incident | Severity is blast radius, not just confidence |
| Cloud key rotation | Expected Activity + separate Incident | Finishing the adjacent-activity sweep after the alert is "explained" |
| Departing PM upload | Expected Activity, referred | Right routing beats a binary escalate/don't-escalate call |

None of these closed the way the first ten minutes suggested they would. That's normal — it's what the evidence-gathering and decision-point steps from the main chapter are actually for.
