# Part 6: Building a Playbook from a Detection Rule

Every playbook in a mature SOC starts life smaller than a playbook — usually a single sentence in a Jira ticket, a whiteboard note from a threat-hunt debrief, or a line item in a detection backlog. This part takes one such sentence and walks it through to a finished, testable, metric-tracked playbook, in the order a detection engineer actually works it — not the tidy order it appears in once someone writes it up for the wiki.

The sentence we're starting from: **detect repeated failed Windows authentication followed by a successful login.**

## 6.1 Start with the Threat Scenario, Not the Query

Before touching a query editor, write down in plain language what you're actually trying to catch. Skip this step and you'll build a technically correct rule that answers the wrong question.

> An actor — external, or an insider using a compromised or borrowed credential — attempts to authenticate to a Windows account by guessing passwords. Either they hammer one account repeatedly (brute force), or they try a small number of common/leaked passwords across many accounts to dodge per-account lockout thresholds (password spraying). Eventually, one attempt succeeds and the actor is now authenticated as that user.

That one paragraph already splits into two distinct attacker shapes, and a good detection engineer keeps them seperate rather than writing one rule and hoping it covers both:

- **One account, many attempts, one source** — classic credential guessing against a target of interest (a VIP, an admin account, a service account someone found in a leaked breach dump).
- **Many accounts, few attempts each, one source** — spraying, designed specifically to stay under the lockout threshold and avoid tripping 4740 events on any single account.

Which shape you're chasing changes what "supporting evidence" you go looking for downstream. A spray against a perimeter-facing service (VPN, OWA, RDP gateway) usually reads as reconnaissance ahead of something bigger. A tight brute-force burst against one privileged account reads as targeted — someone already knows who they want.

**[STAKEHOLDER]** - This detection matters because credential guessing is one of the cheapest, lowest-skill ways into an environment, and it works precisely because organizations reuse passwords and rarely enforce lockouts aggressively enough to stop determined attempts without also locking out real users constantly. A successful brute force or spray hands the attacker a legitimate-looking session — no exploit, no malware signature, just a login that looks like any other login from that point forward. Catching it at the failed-attempts-then-success boundary is the cheapest point in the kill chain to stop it.

## 6.2 Map It to MITRE ATT&CK

This detection objective sits under **T1110 Brute Force**, and specifically its two relevant sub-techniques:

- **T1110.001 Password Guessing** — the single-account, many-attempts pattern.
- **T1110.003 Password Spraying** — the many-account, few-attempts-each pattern.

Once the login succeeds, the attacker holds a valid credential and the picture shifts to **T1078 Valid Accounts** (specifically **T1078.002 Domain Accounts** for an AD account) — because from here, everything the attacker does looks, to most tooling, like ordinary authenticated activity. That's why this detection sits at this exact boundary: the last point the activity is cleanly abnormal before it blends into "just a logged-in user."

Write both technique IDs into the playbook header. When an analyst later pivots to hunt for follow-on activity, they should already know to expect T1078-flavored behavior — persistence via the compromised account, not necessarily new malware.

## 6.3 Detection Logic — First Pass

**[ENGINEERING]** - Stated plainly, the logic is: *N or more failed authentication attempts for an identity within a bounded window, followed by a successful authentication for that same identity within a bounded period afterward.* That's the whole rule at its core. Everything else — thresholds, field selection, correlation by source, exclusions — is refinement layered on top of that sentence. A rough first pass, in KQL-style pseudocode against a Windows Security event table:

```kql
let Threshold = 5;
let Window = 15m;
Failures
| where EventID == 4625 and SubStatus == "0xc000006a"
| summarize FailCount = count(), LastFail = max(TimeGenerated)
    by Account = TargetUserName, Computer, bin(TimeGenerated, Window)
| where FailCount >= Threshold
| join kind=inner (Successes | where EventID == 4624) on Account, Computer
| where TimeGenerated between (LastFail .. LastFail + Window)
```

Resist the urge to refine thresholds before this core pairing is validated against real data. Get the failed-then-success match working first, on a generous threshold, and tighten once you know the environment's actual noise floor.

## 6.4 Required Telemetry and Event IDs

This is the step most often skipped, and the one that causes the most pain three months later when a rule has been "live" but silently blind. Before writing correlation logic, confirm the logs exist, are flowing into the SIEM, and contain what you assume.

| Event ID | Log Source | What It Tells You |
|---|---|---|
| 4625 | Security log, target machine | An account failed to log on |
| 4624 | Security log, target machine | An account successfully logged on |
| 4740 | Security log, domain controller | A user account was locked out |
| 4771 | Security log, domain controller | Kerberos pre-authentication failed |

**[ENGINEERING]** - A few things trip people up here. First, 4625 and 4624 are logged by whichever machine the account authenticates *to* — for a domain account hitting a file server, that's the file server's Security log, not the domain controller's. Kerberos pre-authentication failures land as 4771 on the domain controller and often won't show up as 4625 at all — a rule built only on 4625 has a blind spot for Kerberos-based guessing tools that never touch NTLM. Second, 4740 doesn't tell you an attempt happened — it tells you the *consequence* of enough failed attempts, and its `Caller Computer Name` field is genuinely useful for finding the real source of a lockout storm once an account has bounced across several front-end servers.

Confirm, before trusting the rule at all: audit policy for logon and Kerberos authentication events is actually enabled on the relevant domain controllers and member servers; the SIEM is ingesting Security logs from *every* domain controller, not just the first one someone configured — a spray landing on different DCs via load balancing looks like isolated noise if you're only watching one; and the forwarding collector for these channels hasn't quietly died, which produces the worst kind of false negative — the alert never fires because the data never arrived.

## 6.5 Important Fields

| Field | Event | Purpose |
|---|---|---|
| Account Name / TargetUserName | 4625, 4624 | Identity being authenticated |
| Status / Sub Status | 4625 | Why it failed — this is where the signal lives |
| Logon Type | 4625, 4624 | Access vector: 3 = network, 10 = RDP, 2 = interactive |
| Source Network Address | 4625, 4624 | Where the attempt originated |
| Caller Process Name | 4625 | What software on the source generated the attempt |
| New Logon Account Name / Logon ID | 4624 | Confirms the identity and gives a Logon ID to pivot from into subsequent activity |
| Caller Computer Name | 4740 | Real source of a lockout, useful when the account has hit multiple servers |
| Client Address | 4771 | Source of the Kerberos pre-auth failure |
| Pre-Authentication Type | 4771 | Which pre-auth mechanism was in use |

The sub status on 4625 is the field the whole rule hinges on. `0xC000006A` (bad password) is the actual brute-force signal. `0xC0000234` (account locked out) and `0xC0000072` (account disabled) are *downstream consequences* of a lockout policy or admin action, not evidence of ongoing guessing — a rule that counts all three as equivalent "failures" will inflate its own attempt count with noise the attacker didn't generate, and analysts will learn to distrust the alert's numbers within a week.

## 6.6 Normal vs. Suspicious Activity

**[ANALYST]** - Before calling something suspicious you need a working idea of normal failure noise in this environment, because it's never zero. Expected background failures: a user mistyping a password once or twice after a forced reset; a stale cached credential in Outlook or a mapped drive retrying against an old password until the user notices, producing a slow drip of 4625s over hours rather than a burst; a service account whose password rotated in the vault but a dependent scheduled task wasn't updated, failing at the same time daily like clockwork. None of that is an attack — dont treat every 4625 burst as hostile by default, or you'll bury the SOC in tickets and train analysts to close first, look later.

Suspicious activity differs in *shape*, not just raw count:

- A single source address generating failures against many distinct accounts in a short window — the spray signature.
- One account receiving failures from several source addresses that are geographically or organizationally inconsistent, in quick succession — consistent with credential stuffing using a leaked password list.
- Failures immediately followed by a success from a source that account has never authenticated from before.
- A burst of 4771 failures with little or no matching 4625 activity — a lower-noise Kerberos-focused guessing tool that never touches the NTLM path at all.

## 6.7 Correlation Layer

The core pairing (failures then success, same identity, bounded window) is necessary but not sufficient to justify an analyst's time. Layer these correlations on top before the alert reaches a human queue:

- **Same source, multiple accounts** — pivot the source address against the last 24 hours; other identities touched confirms a spray rather than a targeted guess.
- **4740 lockout correlated to the same source** — a lockout during the burst (via 4740's `Caller Computer Name`) corroborates real guessing rather than a monitoring tool double-logging.
- **Logon Type consistency** — does the successful logon's type match what this account normally uses, or is a network-only service account suddenly authenticating interactively?
- **Post-logon pivot** — once the success is confirmed, pull the Logon ID from 4624 forward through subsequent activity on that session to see what the attacker did once inside.

## 6.8 Enrichment

A raw match above says almost nothing about severity by itself. Enrich before it reaches a triage queue:

- **Identity context** — privileged account, service account, or an ordinary helpdesk-resettable user? Pull this from the identity provider or HR feed, not from memory.
- **Source reputation** — GeoIP/ASN on the source address, known VPN or Tor exit-node status, any threat intel hits against that IP.
- **Asset criticality** — is the target a domain controller or finance server, or a kiosk machine nobody would bother attacking?
- **Historical pairing** — has this account ever authenticated from this source before, ever, in the retention window available?

## 6.9 Decision Points

This is where the analyst applies judgment, structured so it's consistent shift to shift. Was there an open password-reset ticket for this account — expected activity, close it out with the ticket number as evidence. Is the source a documented VPN concentrator, jump box, or known automation host — if trusted, validate the account is behaving within its documented function. Does this match the account's own baseline — some accounts genuinely fail logons at volume for benign, fixable reasons like the credential-rotation mismatch described earlier. Is there supporting evidence anywhere else — a threat intel hit, a correlated EDR alert on the target host, another account showing the same source in the same window. Only once those are worked through does "can malicious intent be confirmed" become the deciding question — not the first one asked.

## 6.10 Escalation

**[MANAGEMENT]** - Write escalation criteria into the playbook rather than leaving it to individual judgment. Automatic escalation to IR, regardless of how routine the alert looks: a privileged or admin-equivalent account is involved; the target or source is a domain controller; the successful logon is followed by lateral movement, a new scheduled task, or a credential-access indicator on the target host. Standard-user, single-host cases with no supporting evidence stay with Tier 1/Tier 2 for closure under Insufficient Evidence, Benign Positive, or Expected Activity — escalation isn't the default outcome and shouldn't be treated as one.

## 6.11 Containment

Containment options, roughly ordered by severity: force a password reset and MFA re-registration; disable the account outright if compromise looks likely rather than probable; block the source address at the perimeter or via conditional access if external; isolate the target host if the successful logon led to activity on the box itself. Match the action to what's actually confirmed — disabling a legitimate user's account on a hunch, mid-shift, has its own cost to the business and to the SOC's credibility with that user's manager.

## 6.12 Closure

Every closure should land in one of four categories — True Positive, Benign Positive, Expected Activity, or Insufficient Evidence — and record which decision point it exited at. A True Positive that crosses the SOP's declared-incident threshold (privileged account, confirmed follow-on activity) also gets formally declared an Incident per the IR Plan; that's a separate downstream step, not a fifth closure category. That matters more than it sounds: closures clustering at the baseline-check step point to a tuning problem (threshold doesn't match this environment's noise floor); clustering at the supporting-evidence step points to a genuinely ambiguous case class worth a dedicated hunt later, not a rule problem.

## 6.13 Testing the Rule

Don't trust a correlation rule you haven't personally watched fire. In a lab, or against a disposable test account in a non-production OU, script the exact pattern: repeated failed logons with a deliberately wrong password past the configured threshold, followed by one correct-password logon inside the window. Confirm the alert fires at the expected latency and every field populates as designed. Then run the inverse test — replay a known-benign historical case (a genuine reset-and-recovery sequence from last month's logs) through the same logic and confirm it does *not* fire, which catches thresholds set tight enough to flag ordinary mistakes as attacks. Where a purple team function exists, run T1110-aligned test cases against the lab domain controller before production, and re-test after any threshold change — tuning sensitivity without re-testing is how a "fixed" rule quietly goes blind weeks later.

## 6.14 Metrics Tracked After Go-Live

**[MANAGEMENT]** - Once live, track: time-to-detect from the first failed logon to alert generation; time-to-triage from alert creation to first analyst action; closure-category distribution over a rolling 30/90 days, since a rule producing overwhelmingly Benign Positive closures is a tuning candidate rather than a quiet success; false-positive rate normalized against total 4625 volume for that environment, because raw counts alone scale with headcount and tell you little; and the escalation-to-confirmed-incident ratio, which is the clearest signal on whether the escalation criteria from 6.10 are calibrated correctly. Review this on a fixed cadence with a named owner — monthly while the rule is new, quarterly once it's stable — rather than only after a near-miss forces the question.
