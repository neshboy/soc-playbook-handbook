# Correlation Thinking — Worked Case Studies

This file is a companion to the Correlation Thinking chapter — it doesn't re-explain the framework, it applies it. Six scenarios, each a different flavor of "the first alert lied to you a little, and the job was figuring out how much." Not every one ends in a confirmed incident — a chapter full of nothing but confirmed-malicious endings would teach you to expect a clean answer every time, and that's not how the queue actualy runs.

---

## Case Study 1: The Lockout Storm With a Decoy Source

**Scenario type:** Identity / brute force, NAT masking the real origin.

**Trigger.** A correlation rule fires just after 09:00 on a Tuesday: more than 15 distinct accounts generating Event ID **4771** (Kerberos pre-authentication failed, Failure Code `0x18`) within a 10-minute window, plus a cluster of **4740** account lockouts. This maps to T1110.003 (Password Spraying).

**Evidence gathered.**

| Source | Finding |
|---|---|
| 4771 events | 22 distinct accounts, all `0x18`, Client Address consistently `10.20.14.87` |
| 4740 events | Caller Computer Name = `WKSTN-HR07` for every lockout |
| Asset inventory | `WKSTN-HR07` is the RDS gateway terminating the corporate VPN split-tunnel — *every* remote user's Kerberos traffic looks like it's coming from that one box |
| VPN/RADIUS logs | 47 concurrent VPN sessions active; one, user `l.ferris`, authenticated successfully from an external IP never seen on that account before |
| Follow-up 4768 | A single successful TGT issuance (`0x0`) for `l.ferris` two minutes after the spray traffic stopped |

**Reasoning and decision points.**

**[ANALYST]** - The naive read of 4740's Caller Computer Name says "the attack is coming from HR07, isolate it." Wrong — HR07 is a shared NAT point, not an attacker. Pulling the real client IP means going one hop further, into VPN/RADIUS logs outside the Windows pipeline.
**[ENGINEERING]** - The join key isn't "same source IP" (useless behind NAT) — it's "same account, spray-window timestamp, followed by a lone success." Something close to:

```
4771 where FailureCode=0x18
| bin _time span=10m
| stats dc(Account_Name) as sprayed_accounts by ClientAddress, _time
| where sprayed_accounts > 15
| join Account_Name [ search 4768 where ResultCode=0x0 ]
```

That join is what turns "noisy lockout storm" into "one compromised account inside the noise."

**Outcome.** `l.ferris`'s credentials were confirmed compromised (likely reused password from an external breach). Password reset, session killed, conditional access tightened on that account. Classified **True Positive — Account Compromise**, scoped narrowly to one account rather than the whole HR subnet.

**Without this discipline:** the team isolates an innocent RDS gateway, the real compromised account keeps a live session through the outage, and the actual breach isn't found until it does something louder.

---

## Case Study 2: Kerberoasting That Didn't Stop at the Ticket Request

**Scenario type:** Credential access escalating into privilege escalation.

**Trigger.** UEBA baseline deviation: the service account `svc-backup` requests **4769** service tickets for 14 different SPNs in under three minutes, all with Ticket Encryption Type `0x17` (RC4) — the classic Kerberoasting fingerprint (T1558.003), from a workstation that account has never logged into interactively before.

**Evidence gathered.**
- 4769 volume/encryption anomaly as above, source workstation `WKSTN-DEV19`.
- **4648** on that same host: explicit-credential logon using `svc-backup`, initiated from a logged-on user `t.okafor`'s session — meaning a human is driving the service account, not a scheduled process.
- **4104** script block log recovers the actual PowerShell used: an SPN enumeration/ticket-request loop, base64-decoded from an obfuscated one-liner (T1027, T1059.001).
- ~40 minutes later: **4624** logon type 3 for a *different* account, `svc-reports`, from a host it never uses, followed by **4672** (special privileges assigned) — elevated rights nobody cleaned up after a 2025 migration.
- **4728**: `svc-reports` is added to a domain-wide security group that has effective admin rights on the backup infrastructure.

**Reasoning and decision points.**

**[ANALYST]** - Kerberoasting alerts alone are notoriously noisy — plenty of legitimate tooling requests RC4 tickets for compatibility reasons. The decision point isn't "did Kerberoasting happen," it's "did anything downstream *use* a cracked ticket." That means holding the alert open for a second-stage indicator instead of closing it as informational, which is the default move on most SPN-scan alerts.
**[ENGINEERING]** - The link between stage one and stage two is the account named in the 4769 batch (`svc-backup` was one of the SPNs requested, cracked offline; the *attacker's own foothold account* `svc-reports` was privileged and got added to a group — two accounts, one operator). Correlation walked: requested-SPN account list → any of those accounts logging in somewhere new → any privileged-group change touching accounts seen in the first thirty minutes.

**Outcome.** Escalation confirmed. `svc-reports` disabled (4725), removed from the group (4729), `svc-backup` password rotated, `t.okafor`'s workstation isolated for forensic imaging. **True Positive**, MITRE ATT&CK chain T1558.003 Kerberoasting → T1078.002 Valid Accounts (Domain Accounts) → T1098.007 Account Manipulation (Additional Local or Domain Groups).

**Without this discipline:** the Kerberoasting alert gets triaged as "routine SPN enumeration noise, closing" — which is the single most common way this exact attack chain slips through in real environments — and the group membership change three groups down never gets tied back to it.

---

## Case Study 3: The Forwarding Rule That Wasn't Spam Config

**Scenario type:** Cloud identity / Business Email Compromise.

**Trigger.** Two low-severity cloud alerts land nine minutes apart: an anomalous sign-in from an unfamiliar ASN for the finance controller's account, and a new inbox forwarding rule created on the same mailbox pointing to `ap-invoices@vendor-support.example` (T1114.003, T1078.004).

**Evidence gathered.**
- Sign-in log: successful authentication satisfying MFA via a legacy authentication path that bypasses the conditional access policy meant to catch new-device sign-ins.
- Mail gateway logs: four minutes prior to the sign-in, the same mailbox received and clicked a link in a phishing email impersonating an accounting SaaS vendor (T1566.002) — the timestamps line up too cleanly to be coincidence.
- The forwarding target domain, `vendor-support.example`, is one character off from the real vendor domain the finance team actually uses.
- **T1098.002** (Additional Email Delegate Permissions): a delegate grant was added on the mailbox roughly two minutes after the forwarding rule.
- SharePoint access logs: same session touched three files with "wire" and "ACH" in the filename within the following ten minutes (T1530).

**Reasoning and decision points.**

**[ANALYST]** - Individually, an inbox-rule alert is one of the most commonly deprioritized cloud alerts there is — users create weird rules constantly, most of them harmless. What forces escalation is the causal chain: phishing click → new-device sign-in → forwarding rule → delegate grant → targeted file access, all inside fifteen minutes, all one mailbox. That requires stitching three separate log sources (mail gateway, identity provider, SharePoint) into one timeline, because none of them alone tells the whole story.
**[STAKEHOLDER]** - the business risk isn't "email is misconfigured," it's a live setup for invoice fraud — the rule exists to intercept a reply to a wire-transfer conversation before finance sees it. That framing is what gets this escalated to the CFO's office in the same hour rather than sitting in a ticket queue.

**Outcome.** Session revoked, forwarding rule and delegate grant removed, finance team alerted before any fraudulent payment instruction went out. **True Positive — Account Compromise / BEC Staging**, T1566.002 → T1078.004 → T1114.003 → T1098.002.

**Without this discipline:** the forwarding-rule alert sits in a low-priority queue for two or three days (a very normal SLA for that alert class on its own), by which point the attacker has already replied to a live invoice thread with altered banking details.

---

## Case Study 4: The 11:40 PM Alert That Was Actually Authorized

**Scenario type:** Expected Activity — the "don't overreact" case.

**Trigger.** A rule tuned to catch ransomware staging fires: **4732** (member added to local Administrators) on `FIN-APP03` combined with **4698** (scheduled task created) within the same two-minute window, at 23:40 on a Saturday — a pattern that in isolation looks exactly like pre-encryption staging.

**Evidence gathered.**
- Subject on both events: a named admin account, not a service account.
- **4624** logon type 10 (RDP) sourcing from `10.20.5.10`, the documented jump host / bastion for privileged access.
- **4648** shows explicit-credential use matching a runbook-listed maintenance account.
- Scheduled Task Content (XML) references a vendor-signed patch installer path, not an unfamiliar binary.
- Change management export: `CHG0004521`, approved emergency patch window for `FIN-APP03`, 23:00–01:00 that exact Saturday.

**Reasoning and decision points.**

**[ANALYST]** - The tempting move is to see the ticket number, match the timing, and close it out in thirty seconds. Don't. Tickets get spoofed, and stolen credentials get used during real maintenance windows precisely *because* attackers know analysts relax during them. The step that actually matters is an out-of-band verification call to the on-call engineer named on the ticket — not confirming the ticket exists, but confirming a human currently holding that phone kicked off the task.
**[MANAGEMENT]** - This is also where the rule gets tuned, narrowly: allow-list the specific maintenance account for the specific approved window, not the whole host or a blanket "ignore weekend admin activity" exception. Broad maintenance-window exceptions are a known blind spot attackers time around.

**Outcome.** Verified over the phone, ticket and timing both check out. Classified **Expected Activity**, documented with the ticket reference, correlation rule updated with a scoped exception.

**Without this discipline:** either a full incident response gets spun up over a routine patch (burns hours, damages the SOC's credibility with the on-call engineer who gets woken up for nothing), or — the worse failure mode — the team starts blanket-whitelisting maintenance windows by host and hands attackers a predictable gap to operate in.

---

## Case Study 5: The Fan-Out That Got Caught Before Encryption

**Scenario type:** Ransomware precursor, multi-host correlation under time pressure.

**Trigger.** **7045** (new service installed) on one host with an unsigned binary sitting in `C:\ProgramData\Updater\svcupdate.exe`. Unremarkable alone — this is a common false-positive-heavy signal, plenty of legitimate updaters do exactly this.

**Evidence gathered.**
- Within four minutes, the *same* service name and image path appear via 7045 on 11 additional hosts.
- **4104** on the origin host recovers a base64-decoded loader script (T1027, T1059.001) that pulled the binary down (T1105).
- **4688** across all 12 hosts shows the identical New Process Name launched under the same Logon ID, all within a six-minute window — consistent with a PsExec-style push via SMB/Windows admin shares (T1021.002) rather than 12 separate admins doing 12 separate things.
- **1102** (audit log cleared) attempted on two of the twelve hosts roughly ninety seconds before the service install landed — anti-forensics, and a very high-signal event on its own regardless of context.
- **4698** on the same hosts references commands consistent with inhibiting shadow-copy-based recovery (T1490), staged but not yet executed everywhere.

**Reasoning and decision points.**

**[ENGINEERING]** - The single most important correlation dimension here is *not* the service name or the binary — it's the same account/Logon ID producing the same New Process Name across multiple hosts inside a tight window. That separates "updater doing its normal thing on one machine" from "someone deploying at scale." A rule shaped like:

```
4688 New Process
| stats values(host) as hosts, dc(host) as host_count by Logon_ID, New_Process_Name, bin(_time, 5m)
| where host_count > 5
```

turns twelve individually-forgettable alerts into one unmistakable one.

**[ANALYST]** - The 1102 event is what removes any ambiguity about intent — nobody clears the security log as part of a routine patch deployment. Once that shows up next to the fan-out pattern, this stops being a "monitor and gather more" case and becomes "declare now, contain now."

**Outcome.** **True Positive** — ransomware deployment precursor. Network isolation pushed to all matching hosts, compromised account disabled, and containment landed before T1486 (Data Encrypted for Impact) triggered — only 2 of an apparent 40-host target list had the service actually land before the push was cut off.

**Without this discipline:** each 7045 event sits under the alert-fatigue line as "just another updater," gets triaged individually and closed, and the team finds out about the incident when the ransom note shows up on a file share.

---

## Case Study 6: The One That Stayed Open as "We Don't Know"

**Scenario type:** Insufficient Evidence — telemetry gap, and why closing it honestly matters.

**Trigger.** DNS security tooling flags a sustained pattern of TXT record lookups against a rotating set of subdomains under one parent domain, from `WKSTN-ENG22` — the shape of the traffic is consistent with DNS-based tunneling (T1071.004, T1572).

**Evidence gathered — and what was missing.**
- DNS/proxy logs confirm the query pattern is real and sustained over several hours.
- Pivot to **4688** on the host to find the responsible process fails: command-line auditing was never enabled on the engineering OU (scoped to tier-0 servers only), so the Command Line field is blank — process name alone isn't enough.
- **4104** script block log on that host has a 7-day local retention window; the activity is 9 days old by the time anyone pulls the thread — gone.
- EDR agent status: last check-in 11 days ago, silently stopped reporting after an unrelated update — no process tree, no network telemetry from that source either.
- A timezone mismatch between the DNS collector (UTC) and the local Windows timestamps (not DST-normalized in the export) initially hid a full hour of matching activity before someone caught the offset.
- User interview: nothing unusual noticed. Browser history shows visits to a marketing analytics vendor whose CDN also uses fast-rotating subdomains for legitimate reasons — uncomfortably similar to tunneling on a DNS graph alone.

**Reasoning and decision points.**

**[ANALYST]** - There's real pressure to pick a side here — wave it off as "probably that analytics vendor," or escalate as a confirmed tunnel, because an open-ended answer feels unsatisfying to write up. Neither is supportable from what's in hand. The discipline is checking *coverage* before concluding anything: is command-line auditing even in scope for this host, is the EDR agent alive, are the two log sources reading the same clock. All three came back negative, which isn't a dead end — it's the actual finding.
**[MANAGEMENT]** - The closure carries teeth: fix the dead EDR agent, extend the command-line auditing GPO scope to the engineering OU, and put a 30-day watchlist on the host and user rather than just filing the case away.

**Outcome.** Classified **Insufficient Evidence**, with three compensating actions opened as tracked remediation items and a watchlist in place. Not a satisfying ending, but the correct one — there wasn't a defensible basis for calling it either benign or malicious.

**Without this discipline:** the case gets rubber-stamped "benign — analytics traffic" on a guess and a live tunnel potentially keeps running, or it gets declared a confirmed incident on a coincidental DNS pattern and burns IR hours chasing a ghost — and either way, nobody notices the EDR agent has been dead for eleven days until the next thing that agent should have caught also gets missed.
