# Part 31: Playbook Failure Examples

Every SOC has at least one playbook step that reads fine in the tabletop exercise and falls apart at 03:14 on a Saturday when a Tier 1 analyst actually has to execute it. These are usually not big architectural mistakes — nobody forgets to mention SIEM ingestion or EDR isolation. They're single sentences, written by someone senior who "just knew what they meant," that leave the analyst guessing. Guessing under pressure produces inconsistent handling, missed escalations, and — worse — confident-sounding wrong answers in the incident ticket.

Below are six phrasings that show up constantly in real playbooks (the first three are the classics; the other three are just as common and arguably do more damage because they look precise). For each: the bad instruction as it's actually written, why it fails in practice, and a corrected version an analyst could actually follow without pinging a Slack channel first.

## Example 1: "Check the IP."

**As written in the playbook:**
> Step 4: Check the IP.

**Why it fails:** This sentence has at least six unstated assumptions. Check it *where* — a threat intel platform, a firewall log, passive DNS, an internal asset inventory? Check it *for what* — reputation, geolocation, ownership, prior appearances in this environment? Which IP, if the alert has both a source and a destination? And critically: what does "checked" produce — a verdict, a note, a decision to escalate? An analyst under time pressure will do a single VirusTotal lookup, see "0/94 vendors flagged," write "checked, looks clean," and close the ticket — even if the IP is a brand-new VPS registered three days ago with no history simply because nobody's scanned it yet. Absence of a bad reputation is not evidence of benign intent, and this instruction gives the analyst no way to know that.

**Corrected version:**

| Step | Action | Evidence to capture |
|---|---|---|
| 4a | Identify direction: is this IP the source or destination of the flagged connection? Confirm against firewall/proxy logs, not just the alert summary. | Source/destination, port, protocol, timestamp (UTC) |
| 4b | Run WHOIS/RDAP and ASN lookup. Note registrant, ASN owner, and allocation date. | ASN, registrant org, first-seen date if available |
| 4c | Check reputation across at least two independent sources (e.g., internal TI platform + one external feed). Do not close on a single "clean" verdict. | Verdict per source, screenshot or export |
| 4d | Check internal history: query firewall/proxy logs (or the SIEM's long-term index if retention there is longer) for this IP and its /24 over the trailing 90 days. Has it communicated with this environment before, and was that traffic expected (e.g., known SaaS range, partner site)? | Prior sightings with timestamps, associated tickets |
| 4e | Record a verdict: **Malicious**, **Suspicious — needs SME review**, **Benign Positive / Expected Activity**, or **Insufficient Evidence** — this last one is a valid closure, not a failure to investigate. | Verdict + justification in ticket |

**[ANALYST]** - "Clean" from one feed is not a verdict, it's one data point. An IP tied to a scanning campaign (T1595 Active Scanning) or acting as an egress point for tunneled traffic (T1572, T1090) can sit unflagged on public feeds for weeks. Treat the lookup as evidence gathering, not as the decision itself.

## Example 2: "Escalate if suspicious."

**As written in the playbook:**
> Step 6: Escalate if suspicious.

**Why it fails:** "Suspicious" is doing all the work in that sentence and defining nothing. Every analyst has a different threshold for what feels off, which means escalation volume and quality vary by who's on shift — the exact inconsistency a playbook exists to prevent. It also doesn't say escalate *to whom*, *how* (ticket reassignment? phone call? paging?), *with what attached*, or *within what timeframe*. The result in practice: analysts either escalate everything mildly odd (Tier 2 drowns in noise) or under-escalate because they don't want to look like they're crying wolf, and a real Kerberoasting attempt sits in the queue for six hours because "suspicious" never got defined against the actual technique.

**Corrected version:**

> Step 6: Escalate to Tier 2 (via IR queue, severity High / priority `P2`) if **any** of the following objective criteria are met — do not rely on gut feel alone:
> - A single account shows 5+ Kerberos service ticket requests (4769) with ticket encryption type 0x17 (RC4) against 3+ distinct SPNs within 15 minutes — pattern consistent with T1558.003 Kerberoasting.
> - A privileged account (member of a Tier 0/1 group) has a 4648 explicit-credential logon to a host it has never authenticated to in the prior 30 days.
> - Any 1102 (audit log cleared) event, unconditionally — no threshold, escalate immediately regardless of source account.
>
> Escalation must include: the triggering event IDs, account name, source/destination host, and a one-line summary of what was checked in Step 4/5. SLA: escalate within 15 minutes of criteria being met for High/P2, within 5 minutes for the 1102 case (treat the 1102 case as Critical/P1).

**[ENGINEERING]** - If your SIEM can score against these criteria directly, do it — a correlation rule that raises severity automatically on the 1102 case removes the ambiguity entirely rather than leaving it to a human reading a paragraph.

**[MANAGEMENT]** - Review escalation criteria quarterly against actual outcomes: if Tier 2 is closing 90% of High/P2 escalations as benign, the threshold is too loose; if a real incident was found buried in a Low/P4, it's too tight.

## Example 3: "Block malicious IP."

**As written in the playbook:**
> Step 9: Block malicious IP.

**Why it fails:** This is the most dangerous of the three classics because it sounds like an action, not an ambiguity, and analysts will act on it fast. It skips the two questions that actually matter operationally: **who approves the block**, and **is this IP actually safe to block**. Plenty of "malicious-looking" traffic originates from IPs you do not get to unilaterally blackhole:

- A CDN edge node (Cloudflare, Akamai, Fastly) — blocking it can take down every other tenant site behind that same edge, including your own vendor portals.
- A VPN exit node or Tor relay — legitimate remote employees or partners may share that same egress IP with an attacker who happened to use the same commercial VPN service.
- Carrier-grade or corporate shared NAT — blocking it can silently cut off an entire branch office or ISP subscriber block, not just the attacker.

An analyst who blocks a /32 that turns out to be a shared CDN IP has just caused an outage while the actual attacker rotates to the next address in five minutes.

**Corrected version:**

| Step | Action | Owner |
|---|---|---|
| 9a | Determine if the IP is CDN/cloud-shared: check ASN against known CDN/cloud ranges and confirm via reverse DNS / TLS cert on that IP. If shared infrastructure, do **not** block at the IP level — escalate for URL/host-header or application-layer blocking instead. | Analyst (Tier 2) |
| 9b | If dedicated (not shared), draft the block request: IP/CIDR, direction (inbound/outbound/both), duration (temporary 24h vs standing), and justification tied to the evidence from Step 4. | Analyst |
| 9c | Submit for approval. Standard blocks: **Network on-call engineer** approves within business hours SLA (30 min). Active incident with data-loss risk in progress: **IR Duty Manager** can authorize an emergency block outside change control, logged and reviewed within 24h. | Network on-call / IR Duty Manager |
| 9d | Implement, confirm via test traffic or firewall hit-count, and record the change ticket number in the incident. | Network engineer |
| 9e | Set a review date to remove/renew the block — standing blocks with no expiry become the config nobody remembers the reason for. | IR Duty Manager |

**[STAKEHOLDER]** - The point of the approval step isn't bureaucracy for its own sake — it's the difference between stopping an attacker and causing a business outage. The **Network on-call engineer** owns that call within a 30-minute SLA for a standard block; the **IR Duty Manager** owns it immediately, outside change control, when data-loss risk is active — and either way it's a named role with a logged decision, not an analyst alone at 3am absorbing a call nobody signed up to own.

## Three more from the same failure family

**Undefined containment authority:**
> Bad: "Isolate affected hosts as needed."

This is the fourth classic in disguise — it reads like a decision but names no trigger, no scope, and no approver, so the "as needed" gets negotiated live, mid-incident, by whoever happens to be on the call. The book catches this exact phrase in its own Ransomware Master Playbook, which calls it out directly: *"If the IR plan says 'the SOC will isolate as needed,' that's not an authority model, that's a hope."* That chapter fixes it with a pre-agreed authority table, scaled to blast radius, so nobody is negotiating isolation rights against a live encryption event. The failure-mode is generic, though — it shows up in credential-theft, DDoS, and insider-threat playbooks just as often as ransomware, and each of those needs the same fix, not a one-off callout in a single chapter.

Corrected — the reusable pattern, not the ransomware-specific version:

| Scope | Who can authorize | Escalation/notification trigger |
|---|---|---|
| Single host/endpoint | On-shift analyst/handler, no approval needed | Log in ticket, immediate |
| VLAN/subnet or shared service (e.g., a file server used by one department) | Tier 2 / Incident Commander | Notify asset owner within 15 minutes |
| Site, business unit, or Tier-0 infrastructure (domain controller, backup server, core switch) | Incident Commander + IT Director/CISO delegate jointly | CISO notified immediately; asset owner notified before or at execution, not after |

Whatever table a given playbook ends up with, the point is the same: the tiers and approvers exist on paper before the incident starts, so "as needed" never has to mean "whoever's loudest on the bridge call decides."

**Vague threshold, undefined "normal":**
> Bad: "Alert if a user has too many failed logon attempts."

This has no time window, no count, and no account-type distinction. "Too many" for a human analyst account might be 3 in five minutes; for a batch service account with a scheduled job that occasionally races a credential rotation, 3 failures might be a Tuesday. Without a defined baseline, analysts either chase routine service-account noise (T1110.001-shaped fatigue) or miss a real password-spray (T1110.003) spread thin across many accounts to stay under a naive per-account count.

Corrected: "Alert if any single **standard user account** has 5+ 4625 events (sub status 0xC000006A) within 10 minutes from a single source, OR if 10+ distinct accounts each show 1-2 failures from the same source IP within 30 minutes (spray pattern). Exclude accounts tagged `svc-` in AD unless failures exceed 20 in an hour, reviewed against the service account's known job schedule." Baselines get reviewed at each detection-tuning cycle, not set once and forgotten.

**Missing owner for an approval step:**
> Bad: "Get approval before disabling the account."

No named approver, no fallback if that person is asleep or on leave, no record of who actually said yes. In practice this either stalls a real containment action for hours or gets rubber-stamped by whoever's easiest to reach, with nothing documented if it turns out to be a mistaken disablement of the CFO's account.

Corrected: "Request approval from the **account owner's manager** (pulled from HR system field, not guessed) via the IR approval form. If unreachable within 15 minutes and the account shows active malicious use (e.g., ongoing T1114.003 mailbox forwarding-rule manipulation), the **IR Duty Manager** may authorize disablement under emergency authority. Record approver name, timestamp, and method in the ticket regardless of path taken."

## The pattern behind all six

Every one of these failures traces back to the same habit: writing the instruction the way you'd say it out loud to someone who already knows the environment, instead of writing it for the analyst who's covering someone else's shift, three months into the job, at the point in the night where nobody's answering Slack. If a step names a judgment call ("suspicious," "too many," "malicious," "normal," "as needed"), the playbook needs to make that judgment call for them, or name exactly who does.
