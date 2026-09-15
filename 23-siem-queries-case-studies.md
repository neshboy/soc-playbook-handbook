# Playbook Queries Across SIEM Platforms — Worked Case Studies

The chapter this file supports walked through how the same detection logic gets expressed differently in Splunk SPL, Microsoft Sentinel KQL, and Elastic EQL/KQL, and why a playbook needs to carry the *intent* of a query, not just one platform's syntax. What follows are five full case studies pulled from the shape of real investigations — company names, hosts, and IPs are invented, but the log behavior and decision points are the kind of thing that actually happens on a shift. Each one closes with a one-line gut-check: what would have slipped through without this discipline.

---

## Case Study 1 — Password Spraying That Almost Looked Like Normal Lockout Noise

**Company:** Meridian Health Networks (multi-site healthcare provider, hybrid AD/Entra ID)
**Platform:** Microsoft Sentinel (KQL), on-prem AD forwarded via Azure Monitor Agent

### Trigger

The SOC's Tier 1 queue got a cluster of "Account Lockout" tickets from the helpdesk — four users in Radiology and Billing locked out within twenty minutes, all reporting they hadn't been trying to log in. Individually these look like routine end-of-shift-change noise. The playbook for account lockout requires pulling the **4740** events and checking `Caller Computer Name` before closing anything as user error, and that step is what turned this into an actual case.

### Evidence Gathered

**[ANALYST]** - All four 4740 events pointed to the same `Caller Computer Name`: a workstation in a shared imaging-review room, `WKS-RAD-07`, with no reason to be authenticating as four different back-office accounts. The wider window on that host showed the real pattern — dozens of **4625** failures across roughly sixty distinct accounts, each tried once or twice (low-and-slow spray, not a brute-force hammer on one account), sub status `0xC000006A` (bad password) on nearly all of them, with a handful returning `0xC0000234` (already locked) later on. Buried in the same window was one **4624** success — service desk account `svc-billing-sync`, network logon — followed almost immediately by a **4648** explicit-credential logon from that session probing a file server it doesn't normally touch.

### Reasoning / Decision Points

**[ENGINEERING]**

```kql
SecurityEvent
| where EventID in (4625, 4740)
| where TimeGenerated > ago(2h)
| summarize DistinctAccounts = dcount(TargetAccount), Attempts = count()
    by Computer, bin(TimeGenerated, 15m)
| where DistinctAccounts > 15 and Attempts < DistinctAccounts * 3
```

The threshold — many distinct accounts, few attempts each — is what separates a spray from a mass-lockout caused by a mobile device pushing a stale cached password to every account it touches. That's common enough at Meridian's shared radiology tablets that the on-call analyst's first instinct was "cached credential, not an attacker." The decision point was checking whether `svc-billing-sync`, the account that succeeded, had ever logged on from `WKS-RAD-07` before — it hadn't, not once in ninety days of baseline — which ruled out the benign explanation.

### Outcome

**True Positive** — an external actor had gained access to a shared kiosk workstation and ran a password-spraying attack against a harvested account list, catching one weak service account credential. `svc-billing-sync` was disabled, the workstation was isolated, and the attack was traced to a stale RDP exposure on that machine that infra had flagged for decommission six months earlier and never finished. MITRE ATT&CK: T1110.003 Password Spraying, T1078.002 Valid Accounts (Domain Accounts) for the follow-on use of the compromised credential.

**Without this discipline:** the four lockout tickets get closed individually as "user mistyped password," the spray keeps running against the other fifty-six accounts overnight, and the next successful guess might not be a low-privilege sync account.

---

## Case Study 2 — Kerberoasting Caught Before the Hash Cracked

**Company:** Bracken Insurance Group (single-forest AD, Splunk Enterprise Security)
**Platform:** Splunk SPL

### Trigger

A scheduled correlation search built straight out of the Kerberos section of this handbook fired: a single account requesting service tickets for an unusual number of distinct SPNs in a short window, with `Ticket Encryption Type` `0x17` (RC4) on requests where the domain had rolled out AES enforcement for privileged service accounts six months prior.

### Evidence Gathered

**[ANALYST]** - The account, `j.alvarez`, was a claims adjuster with no reason to request service tickets for `SQL/finance-db01`, `SQL/hr-db02`, `HTTP/legacy-crm`, and nine other SPNs inside four minutes — normal activity touches one or two services a session, not a dozen unrelated ones back to back. The **4769** events all showed RC4 encryption despite the environment defaulting to AES since the rollout, which meant either these were legacy service accounts still pinned to RC4 (plausible baseline noise the team had seen before) or something was deliberately requesting the weaker cipher. Cross-referencing **4104** script block logs on `j.alvarez`'s workstation settled it: a PowerShell script block with a `System.DirectoryServices` SPN enumeration pattern consistent with a Kerberoasting tool, run from a process chain tracing back to a macro-enabled attachment opened forty minutes earlier.

### Reasoning / Decision Points

**[ENGINEERING]**

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| bucket _time span=5m
| stats dc(Service_Name) as distinct_spns, values(Service_Name) as spns by Account_Name, _time
| where distinct_spns > 5
```

The team's first instinct was to dismiss the RC4 flag, because two of Bracken's genuinely legacy service accounts request RC4 tickets constantly and had been whitelisted months earlier to cut noise. That whitelist is exactly why the correlation search needed the *distinct SPN count* condition layered on top of the encryption filter — RC4 alone was too noisy to act on, but RC4 plus a burst of unrelated SPNs from a non-service account wasn't covered by the whitelist logic, and that's the gap the analyst had to reason through before escalating.

### Outcome

**True Positive**, caught early enough to matter: the offline hash-cracking attempt was still in progress (verified against the timeline — no anomalous service authentication occurred afterward) when the affected service account passwords were rotated, invalidating the harvested tickets before they could be cracked and reused. Bracken's identity team also used the finding to finish the AES-enforcement rollout on the two whitelisted legacy accounts instead of leaving them permanently exempted. T1558.003 Kerberoasting, T1059.001 PowerShell, T1078.002 Valid Accounts (Domain Accounts) for the phished foothold account.

**Without this discipline:** the RC4 filter alone gets suppressed as "known noise" from the legacy-account whitelist, and the actual roasting activity rides through unnoticed until one of those harvested service account passwords gets cracked offline at leisure.

---

## Case Study 3 — The Insider Who Cleaned Up After Himself

**Company:** Solace Logistics (mid-size freight/logistics firm, Elastic Stack)
**Platform:** Elastic (EQL / KQL)

### Trigger

A quarterly access-review job — not a real-time alert — flagged a domain account, `d.reyes`, still active a full six weeks after the associated IT contractor's engagement end date in the HR feed. That review kicked off a retroactive log pull, which is where the actual case started.

### Evidence Gathered

**[ANALYST]** - Three weeks before the review caught it, `d.reyes` had used his still-valid access to create a new domain account, `svc-netreport`, via a **4720** event with no linked change ticket. Nine minutes later, a **4728** event showed `svc-netreport` added to a security-enabled global group mapping to file-server admin rights across three warehouse sites — a group `d.reyes` had no business adding anyone to, contractor or otherwise. What made this unambiguous rather than sloppy offboarding: an **1102** "audit log cleared" event on the domain controller that handled the group change, four minutes after the 4728, with `Subject` resolving back to `d.reyes`'s own credentials.

### Reasoning / Decision Points

**[ENGINEERING]**

```eql
sequence by winlog.event_data.SubjectUserName with maxspan=30m
  [any where event.code == "4720"]
  [any where event.code == "4728"]
  [any where event.code == "1102"]
```

**[MANAGEMENT]** - The decision to escalate to HR and Legal rather than quietly disabling the backdoor account came down to intent versus accident. A contractor's account outliving offboarding by six weeks is, on its own, an IT-hygiene failure the SOC sees constantly and would normally route back to identity governance as a process gap. What moved this into confirmed-malicious territory was the log clearing specifically — nobody accidentally creates a backdoor account, grants it admin-equivalent group membership, and then clears the Security log on the DC that recorded it. That combination is what this playbook family exists to surface, and ownership for what happens next sits with HR/Legal, not the analyst who found it.

### Outcome

**True Positive**, escalated as a confirmed insider **Incident**. The backdoor account was disabled, the group membership reverted, and the case was referred to HR and Legal with a preserved evidence package (the analyst deliberately left logging on the affected DC untouched before handoff, to avoid contaminating the record). MITRE ATT&CK: T1136.002 Create Account (Domain Account), T1098.007 Account Manipulation (Additional Local or Domain Groups), and T1070.001 Indicator Removal (Clear Windows Event Logs) for the audit-log clearing — a technique that maps cleanly to an existing ATT&CK ID rather than needing to be waved off as generic anti-forensics color commentary. T1078.002 Valid Accounts (Domain Accounts) covered the still-active contractor credential that made all of it possible.

**Without this discipline:** the access review flags an overdue offboarding, someone disables `d.reyes`'s account, and the backdoor `svc-netreport` — now orphaned but still enabled with admin rights — sits untouched indefinitely, because nobody traced the 4720/4728/1102 sequence back to what it actually was.

---

## Case Study 4 — Business Email Compromise, Stopped Before the Wire Went Out

**Company:** Alderway Legal Partners (mid-size law firm, Microsoft 365, logs shipped to Splunk)
**Platform:** Splunk SPL (Splunk Add-on for Microsoft 365, Unified Audit Log)

### Trigger

A conditional access policy flagged a risky sign-in for a partner-track associate's mailbox — new country, new ASN, legacy-auth-adjacent client string — that itself wasn't unusual enough to page anyone at 6:40 p.m. on a Thursday. What escalated it was the correlation rule that checks for a mailbox rule or forwarding change created within sixty minutes of a risky sign-in for the same identity, which fired eleven minutes later.

### Evidence Gathered

**[ANALYST]** - The Unified Audit Log showed a `New-InboxRule` operation with `ForwardTo` pointed at a Gmail address, scoped to subject lines containing "wire," "invoice," and "closing" — a targeted rule, not a blanket forward. `ClientInfoString` on the creation event showed a PowerShell/remote-session client, which the associate never uses; she works entirely in Outlook desktop and OWA. Message Trace confirmed the rule had already silently forwarded two client emails, including one thread from a real estate closing referencing an upcoming wire transfer — exactly the pattern this scenario exists to catch.

### Reasoning / Decision Points

**[ENGINEERING]**

```spl
index=o365 (Operation=New-InboxRule OR Operation=Set-Mailbox)
| search Parameters="*ForwardTo*" OR Parameters="*ForwardingSmtpAddress*"
| eval target_domain=lower(mvindex(split(coalesce(ForwardTo, ForwardingSmtpAddress),"@"),1))
| where NOT target_domain IN ("alderwaylegal.com")
| join type=inner UserId
    [ search index=azuread_signin RiskLevel=high
      | eval join_window=_time+3600
      | fields UserId, join_window ]
| where _time <= join_window
```

**[STAKEHOLDER]** - The decision that mattered here wasn't technical, it was procedural: once the closing-related thread was confirmed forwarded, the incident lead escalated directly to the managing partner and the client relationship attorney rather than waiting for a full scope assessment, because the exposure window for wire fraud on a real estate closing is measured in hours, not the usual SLA clock. Notify now with an incomplete picture, versus wait for certainty — that call is one the playbook pushes up to the IR lead, not a Tier 1 analyst.

### Outcome

**True Positive** — confirmed BEC attempt, contained before financial loss. The forwarding rule was removed, the compromised session revoked, MFA reset, and — critically — the firm proactively called the closing agent and buyer's counsel to warn that wire instructions from that thread should be verified by phone before funds moved. No fraudulent wire was ever sent; the rule was caught in the collection phase, before a spoofed wire-instructions email went out through it. T1566.002 Phishing (Spearphishing Link) as the likely initial-access path, confirmed via browser history around the risky sign-in, T1114.003 Email Collection (Email Forwarding Rule), and T1098.001 Account Manipulation (Additional Cloud Credentials) for a new MFA method registered during the same session, caught and revoked.

**Without this discipline:** the risky sign-in alert gets triaged alone, closed as "user probably used a VPN," and the forwarding rule — which doesn't show up in the associate's own Outlook rules pane because it was never checked, and which nobody was specifically looking for — keeps feeding live wire-transfer threads to an outside mailbox for as long as the attacker wants.

---

## Case Study 5 — The Brute-Force Alert That Was Really a Coordination Failure

**Company:** Corvid Water Utility (municipal utility, OT/IT boundary environment, Microsoft Sentinel)
**Platform:** Microsoft Sentinel (KQL)

### Trigger

An overnight UEBA-flavored correlation rule fired "possible brute force" against a service account, `svc-scada-report`, showing repeated **4625** failures against two internal database servers between 1:00 a.m. and 1:45 a.m. On-call got paged.

### Evidence Gathered

**[ANALYST]** - Every failure traced to a single internal source: `10.40.12.7`, the SCADA reporting batch host — not an external IP, not a spray across multiple accounts, just one account failing repeatedly against the same two targets on a fixed interval. That interval (every ten minutes, on the dot) was itself informative: a scheduled task retrying on a fixed clock is a strong hint of automation with a stale credential, not an attacker fumbling logins. `Sub Status` on the 4625 events was consistently `0xC000006A` (bad password), and a later **4740** confirmed the account actually did lock out around 1:40 a.m. — a real, if self-inflicted, operational impact.

### Reasoning / Decision Points

**[ENGINEERING]**

```kql
SecurityEvent
| where EventID == 4625 and TargetAccount == "svc-scada-report"
| where TimeGenerated > ago(6h)
| summarize Attempts=count(), SourceIPs=make_set(IpAddress), 
    Targets=make_set(Computer) by TargetAccount
```

The single-source, single-account, fixed-interval shape was the first tell that this wasn't a spray or a credential-guessing attack. The second was cross-referencing the change calendar: IT security had rotated a batch of service account passwords eight hours earlier during a scheduled AD hardening pass, and the batch job's stored credential still held the old password — nobody had updated the secrets vault entry it pulled from before the rotation went live. **[MANAGEMENT]** - That gap between "password rotated in AD" and "password updated everywhere it's used" is a coordination problem between the identity team and the OT/reporting team, not a security event, and closing it correctly meant looping in both rather than just suppressing the alert.

### Outcome

**Benign Positive** — no malicious actor, but a real process gap that had already caused a lockout and would have caused it again on the next scheduled run. The credential in the batch job's secrets store was updated, the account unlocked, and the change management runbook for service account rotations was updated to require confirming all dependent scheduled tasks before a rotation is marked complete, with a linked problem ticket for the process gap.

**Without this discipline:** the alert gets escalated as a possible brute-force attack against a SCADA-adjacent system — not a category anyone wants to under-react to — burning hours chasing an external-actor theory that the source IP and interval pattern would have ruled out in the first five minutes, or worse, someone force-resets the account mid-shift and breaks the reporting job a second time without ever finding the actual cause.

---

Five different SIEM stacks in the field will express these five queries five different ways — the field names, the join syntax, the aggregation functions all shift. What doesn't shift is the sequence: know what the alert claims, pull the specific events the playbook says matter, check the source and scope before assuming intent, and be honest when the answer is "expected activity" instead of forcing a confirmed-malicious verdict because that's the more satisfying story to close the ticket on.
