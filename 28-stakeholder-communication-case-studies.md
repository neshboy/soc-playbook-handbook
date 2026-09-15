# Part 24 Companion: Stakeholder Communication Case Studies

The core chapter covers translation sentence by sentence — technical finding in, calibrated business language out. This file is the deep end: five full case studies showing the trigger, what the analyst actually collected, the decision points where a communication choice mattered as much as a technical one, how it landed, and what breaks without that discipline.

## Case Study 1: Ransomware Precursor and the Materiality Clock

**Organization:** Cascade Regional Health (cascaderegional.example).

**Trigger:** EDR alerts on host `WKS-FIN-014` for `vssadmin delete shadows /all /quiet`, captured via 4688 with command-line auditing enabled. Twelve minutes later, 7045 shows a new service, `WinDefragSvc`, image path pointing to `C:\Windows\Temp\wdsvc.exe` — not a legitimate component.

**Evidence gathered:** A 4698 scheduled task, `SysMaintenanceCheck`, created two minutes before the shadow-copy deletion, Task Content pointing to an encoded PowerShell launcher. A 1102 event on the workstation itself, and — because WKS-FIN-014 had an open SMB session to file server `FS-CASC-03` three days earlier — that host was pulled into scope too, where a gap in the Security log looked consistent with an attempted, partially failed clear. Outbound connections from WKS-FIN-014 to two external IPs never seen on that host in 90 days. EDR isolated the host within 90 seconds.

**Reasoning and decision points:** The pattern maps to T1490 and T1562.001 staged ahead of T1486, delivered via T1053.005 — but the judgment call wasn't the mapping, it was what to tell leadership at minute 30, when scope was "one workstation, contained" but lateral movement was still unconfirmed either way.

**[STAKEHOLDER]** - "We caught early-stage ransomware behavior on one finance workstation before any files were encrypted. That machine is isolated. We're actively checking whether the attacker reached any other systems before we cut it off — we don't have that answer yet."

Two hours later, once lateral movement was ruled out, the harder question arrived: does this meet the bar for external disclosure under Cascade's debt-covenant diligence obligations and state breach-notification thresholds? That call belongs to Legal, but Legal can't make it without a precise answer to three questions — what data was accessed, was anything exfiltrated, is it still ongoing. The SOC's job was answering those exactly, and flagging which were still open rather than rounding "not found yet" up to "confirmed none."

**[STAKEHOLDER]** - What went to Legal at the two-hour mark: "No evidence of data access, no evidence of exfiltration, and no sign the activity is still spreading — based on the isolated host and the network logs reviewed so far. The five-day forensic follow-up isn't finished, so treat this as our best answer today, not a final one. We'll flag immediately if that changes."

**Outcome:** Five-day forensic review confirmed no lateral movement (the FS-CASC-03 log gap traced to an unrelated scheduled backup job, not attacker activity), no staged exfiltration, no encryption anywhere. Closed as an Incident — confirmed malicious activity, contained pre-impact. Legal determined the event did not meet the materiality bar, based on that scoped answer, and documented the reasoning in case it was ever questioned later.

**Without this discipline:** an overstated minute-30 update forces a premature disclosure call before the facts are in; an understated one leaves Legal making a materiality decision on incomplete information that unravels if new evidence turns up during the forensic window.

## Case Study 2: BEC Mailbox Rule — the Vendor Call Nobody Wanted to Make

**Organization:** Harborview Freight (harborviewfreight.example); vendor Aldergate Fabrication (aldergatefab.example).

**Trigger:** A successful sign-in to the accounts-payable clerk's mailbox from a country she's never worked or traveled from, no MFA challenge satisfied (legacy protocol still enabled for this mailbox) — T1078.004. Six minutes later, an Exchange Online audit entry for `New-InboxRule`, forwarding messages containing "invoice," "remittance," and "wire" to an external Gmail address with `StopProcessingRules` set, so the clerk would never see the originals — T1114.003.

**Evidence gathered:** Server-side search of the mailbox found three real inbound threads from Aldergate Fabrication about an outstanding $84,600 invoice, already forwarded externally before anyone caught it. No confirmed fraudulent reply yet — that check was still running.

**Reasoning and decision points:** The real decision wasn't how to phrase "your mailbox was compromised" — it was whether to call Aldergate directly before the investigation finished.

**[STAKEHOLDER]** - What went to Harborview's CFO, who owns the vendor relationship: "An employee's email account was accessed by someone outside the company, and a hidden rule was set up to secretly copy invoice-related emails to an outside address, including at least three real threads with Aldergate Fabrication about an $84,600 invoice. We haven't found evidence yet that a fake payment request was sent, but the attacker had what they'd need to send one. Recommend calling Aldergate now, by phone, to confirm any payment instructions verbally before anything is paid or changed."

The CFO called within the hour. Aldergate's AP team had, in fact, received a follow-up email — from a domain one character off from Harborview's own — asking them to redirect the $84,600 to a new account. It hadn't been paid yet.

**Outcome:** Payment held, fraudulent redirect email preserved as evidence, rule removed, credentials rotated, legacy authentication disabled tenant-wide. Closed as an Incident (confirmed Business Email Compromise (BEC) / invoice fraud attempt); no funds lost.

**Without this discipline:** waiting for full investigation closure before warning the vendor almost certainly costs $84,600 — the lookalike-domain email had already gone out by the time the rule was found. A vague, hedged notice doesn't get someone on the phone in time; a specific, urgent one does.

## Case Study 3: Retracting an Escalation — the Kerberoasting Alert That Wasn't

**Organization:** Meridian Trust Bank (meridiantrust.example).

**Trigger:** A tuned correlation rule fires on 47 service ticket requests across 30 SPNs in four minutes, all RC4 (0x17), all under `svc_qualys`. Per Meridian's escalation SLA for credential-theft patterns, this auto-pages the on-call CISO bridge before an analyst even opens the ticket — a deliberate speed-over-precision tuning choice.

**Evidence gathered:** Source host `SCAN-VULN-02` had an approved, scheduled authenticated vulnerability scan starting four minutes before the first request. `svc_qualys` is a documented, read-only scanning account with no history of interactive logons. The RC4 flag traced to several legacy line-of-business SPNs that haven't been re-keyed since a 2019 migration — a known, ticketed technical-debt item, not new attacker behavior.

**Reasoning and decision points:** By the time the analyst had this picture, "possible Kerberoasting attempt, investigating" had already gone out — accurate at the time, now needing a retraction, not a quiet close.

**[MANAGEMENT]** - Quietly closing the ticket because nothing bad happened is the wrong move. If the CISO hears the alarm and never hears the resolution, the next real page from this rule gets less trust, not more.

**[STAKEHOLDER]** - The follow-up: "This was our vulnerability scanner running its scheduled, approved scan, using a legitimate scanning account. The pattern looked identical to a credential-theft technique because of an old application dependency using weaker encryption — a known issue we're tracking separately. Closing this as Expected Activity. The detection worked as designed; we're tuning it so this scan window doesn't re-page without losing sensitivity to an actual attacker using a different account."

**Outcome:** Closed as Expected Activity. Rule tuned with a narrow, change-calendar-aware exception for this account and host during approved windows only — not a blanket allowlist. A separate ticket opened to retire the RC4 dependency, tracked as a control gap rather than forgotten.

**Without this discipline:** either the CISO stops trusting this alert category after enough unexplained pages, or the SOC overcorrects by suppressing it broadly, and the next real Kerberoasting attempt from a different account never pages anyone.

## Case Study 4: Insider Account Manipulation — Routing Around the Wrong Person

**Organization:** Brightleaf Retail Group (brightleafretail.example).

**Trigger:** Not a SIEM alert first — an HR-initiated flag. IT administrator Daniel Voss submitted his resignation, and per the insider-risk playbook, any resignation from a standing-admin account triggers a defensive activity review. That review surfaced 4799 events showing Voss enumerating membership of several local groups outside his normal ticket-driven pattern, followed same afternoon by 4732 adding his own personal account to local Administrators on three servers outside his scope, and a 4726 deleting a colleague's service-desk account with no matching offboarding ticket.

**Evidence gathered:** Five distinct group-enumeration queries in 40 minutes (T1069, T1087). Administrator access added on `SRV-APP-07`, `SRV-APP-11`, `SRV-FILE-04` — none in his 90-day ticket queue. No corresponding 4720, ruling out a hidden backdoor account for this window.

**Reasoning and decision points:** The playbook routes findings like this through HR and Legal first, never through the subject's direct manager — Voss and his manager are close, and a well-meaning heads-up would tip him off before access is revoked and evidence preserved.

**[ANALYST]** - Every event was exported with timestamps, source system, and an unbroken chain-of-custody note — not because intent was confirmed, but because it might need to hold up later even if it wasn't malicious.

**[MANAGEMENT]** - What went to HR and Legal jointly, deliberately neutral: "We identified account activity by [employee] inconsistent with normal job duties following resignation notice, including administrative access grants outside assigned scope and deletion of a colleague's account without an associated ticket. We are not characterizing intent — providing the facts so HR/Legal can determine next steps. Recommend revoking standing access pending that determination." No accusation of malice, no manager copied.

**Outcome:** Access suspended within the hour under an "administrative access review" rationale. HR's exit interview determined Voss was trying to preserve access he feared losing early, not staging theft or sabotage — closed as a substantiated Policy Violation, not a malicious-insider case. Offboarding accelerated, no legal action, documentation retained in the HR file.

**Without this discipline:** loop in the wrong person and the evidence-preservation window disappears the moment the subject is tipped off; skip the neutral, fact-only framing and a clean policy-violation file turns into a wrongful-termination exposure the moment someone quotes a speculative message back later.

## Case Study 5: Cloud Storage Exposure — Giving Legal a Number They Can Defend

**Organization:** Solace Analytics (solaceanalytics.example), SaaS vendor holding customer data for roughly 40 enterprise clients.

**Trigger:** Impossible travel on an engineering admin account — successful sign-ins 19 minutes apart from geographically implausible locations, MFA satisfied via a push the owner later said she didn't approve. Shortly after, a new client secret is added to an app registration, `data-export-svc`, that already holds broad read access to a storage bucket — T1098.001 layered on T1078.004.

**Evidence gathered:** The new secret authenticated 42 minutes later and ran List/GetObject operations against 1,842 distinct objects in `solace-customer-exports` over eleven minutes (T1530, with T1580 for the preceding discovery calls). The same session briefly opened the billing/usage dashboard (T1538), read-only, no config changes. Content review of the 1,842 objects showed customer contact records — name, work email, company, account tier — with zero hits against the separate financial-transactions store, verified independently through that store's own access logs.

**Reasoning and decision points:** Solace's contracts carry breach-notification clauses with specific windows, and Legal cannot start that clock on "some data may have been accessed." Every hour spent waiting for a rounder answer is an hour taken out of whatever window applies.

**[ENGINEERING]** - The deliverable to Legal was a scoped fact set, not a narrative: exact object count, exact fields present, explicit confirmation the financial store wasn't touched, and a stated confidence level — "confirmed access and download, based on successful GetObject responses, not just List calls" — rather than a hedge dressed up as precision.

**[STAKEHOLDER]** - "We have confirmed an attacker accessed customer contact records — names, work emails, company names, account tier — for 1,842 records. This is confirmed access and download, not just an attempt. We have confirmed the attacker did not reach the system storing payment and financial data, based on that system's own independent logs. We can provide the specific list of affected accounts within the hour."

**Outcome:** Legal determined notification was required, scoped to exactly the 1,842 records identified — not a blanket notice to all 40 clients, which the SOC's precision made unnecessary. Credential and app-registration secret revoked; conditional access tightened to block impossible-travel sign-ins outright.

**Without this discipline:** an imprecise scope forces a choice between an expensive blanket notification to everyone or an underscoped one that misses someone — and a record later found in scope but never disclosed becomes a second, worse incident on top of the first.

## Recurring Patterns Across These Cases

| Case | Discipline that mattered most | What breaks without it |
|---|---|---|
| Ransomware precursor | Precise answers to Legal's three scope questions, no rounding | Wrong-timed disclosure decision |
| BEC mailbox rule | Urgent, specific warning before investigation closed | Vendor pays the fraudulent invoice |
| Kerberoasting false positive | Formal retraction with root cause, not a silent close | CISO stops trusting the alert category |
| Insider account manipulation | Neutral, fact-only language routed around the conflicted party | Tipped-off subject, or wrongful-termination exposure |
| Cloud storage exposure | Exact scope handed to Legal, no hedging dressed as precision | Overbroad or underscoped regulatory notification |

The common thread isn't a template — in every case the technical finding and the business decision sat exactly one imprecise sentence apart from going wrong. The discipline is closing that gap every time, not just when the incident feels big enough to deserve the extra care.
