# Account Lockouts

**Category:** Identity & Active Directory - Account & Authentication
**Playbook ID:** IAM-005

An account lockout alert is deceptive because the event that fires it - `4740` - looks decisive. It isn't. A `4740` just means the domain's lockout threshold was crossed; it tells you nothing on its own about *why*. The same event fires for a genuine password-spray victim, a user whose phone is still holding a password from three rotations ago, and a scheduled task nobody has touched since the service account owner left the company. Most SOCs get this playbook wrong in one of two directions: treating every lockout as a helpdesk non-event and closing it on autopilot, or treating every lockout as a live attack and burning analyst time chasing stale Exchange ActiveSync caches. The point of this playbook is to make that call quickly and defensibly, using the one field almost everyone skips - Caller Computer Name.

## Business Risk

**[STAKEHOLDER]** - A lockout is either a security event (someone is trying to get into an account that isn't theirs) or an operational one (a real employee can't work, and helpdesk is fielding the ticket). Both cost the business something, but they need completely different responses - one needs containment, the other needs a fix to a stale credential somewhere. Getting the triage wrong in either direction is expensive: chase every lockout as an incident and the SOC drowns; wave every lockout through as noise and a live spray campaign sits unnoticed until an account finally authenticates successfully.

## Severity / Priority Default

- **Default: Low (P4)** - single account, single known source device, no correlated failure pattern from an unfamiliar host.
- **Escalates to Medium (P3)** when the source (Caller Computer Name) does not resolve to a device the user owns, or the account has been locked out more than twice in 24 hours with no explained root cause.
- **Escalates to High (P2)** when multiple distinct accounts lock out from the same Caller Computer Name / source within a short window (spray-shaped), or the locked account is privileged.
- **Escalates to Critical (P1)** when a lockout pattern is immediately followed by a successful authentication on any of the affected accounts, or lockouts coincide with other indicators of an active credential-stuffing/spray campaign already tracked elsewhere.

## MITRE ATT&CK Techniques

- **T1110 Brute Force**
  - **T1110.001** Password Guessing - repeated wrong-password attempts against one account driving it to lockout
  - **T1110.003** Password Spraying - many accounts, each pushed to (or near) lockout from one source, low attempts per account
- **T1078 Valid Accounts** (.002 Domain Accounts) - relevant when the attacker already has a correct username and is guessing the password against it, i.e., they know the account is real

Account lockouts are a *side effect*, not a technique in themselves - the underlying technique is whatever's driving the failed authentications. Detail on the attack pattern itself belongs in the Brute Force and Password Spraying playbooks elsewhere in this book; this playbook is specifically about triaging the lockout signal.

## Trigger / Detection Logic Summary

**[ENGINEERING]** - Primary trigger is any `4740` on a monitored account (all accounts, or at minimum privileged/VIP accounts plus anything on a watchlist). Layer in:

- `4740` correlated backward against preceding `4625` (Sub Status `0xC000006A` bad password) or `4771` (Failure Code `0x18`) events for the same Account Name in the 15-30 minutes prior, to reconstruct the actual attempt pattern that caused the threshold breach.
- `4625`/`4776` with Sub Status/Error Code `0xC0000234` (account locked out) appearing *after* the `4740` - these are attempts continuing to hit an already-locked account, useful for measuring how long the source keeps trying with a stale or guessed credential.
- Group multiple `4740` events by **Caller Computer Name** within a rolling 10-15 minute window: one source locking out several distinct accounts is the spray-shaped pattern that changes this from a helpdesk ticket into an escalation.
- Suppress/deprioritize (but don't silently drop) lockouts where Caller Computer Name matches a device already known to be the account owner's, especially within a short window of a `4723` self-service password change.

## Required Log Sources & Event IDs

| Source | Event IDs | Purpose |
|---|---|---|
| Domain Controller Security log | 4740, 4767 | The lockout itself and its resolution (who/what unlocked the account) |
| Domain Controller Security log | 4625, 4776 | Failed logon attempts preceding and following lockout (NTLM path); Sub Status/Error Code progression from bad-password to locked-out |
| Domain Controller Security log | 4771, 4768 | Kerberos pre-auth failures (Failure Code 0x18) preceding lockout; 4768 Result Code 0x12 helps rule out "disabled" being mistaken for "locked" |
| Domain Controller Security log | 4724, 4738 | Recent admin-driven password reset or attribute change that may explain the lockout (old cached credential still in use somewhere) |
| Domain Controller Security log | 4723 | Self-service password change - common root cause of a subsequent self-inflicted lockout on other devices |
| Endpoint / mobile device management (if available) | N/A (out of Windows scope) | Confirms whether Caller Computer Name is a device the account owner actually uses (phone, mapped drive, scheduled task host) |

## Key Fields to Inspect

**[ANALYST]** -

- `4740`: **Caller Computer Name** - the actual source of the bad attempts, not the DC that logged the event. This is the single most useful field on this event and the one most often skipped.
- `4740`: **Target Account Name**, timestamp - basic scoping.
- `4625`/`4776` preceding the lockout: **Sub Status/Error Code** progression - a run of `0xC000006A` (bad password) followed by the account tipping into `0xC0000234` (locked) confirms the mechanism; a run that's mostly `0xC0000064` (user doesn't exist) mixed with real accounts suggests enumeration, not just one mistyped password.
- `4767`: **Subject** (who performed the unlock) and timestamp - verify unlock was done by an authorized helpdesk identity/process, not self-service abuse or an unexpected account.
- `4723`/`4724`: timestamp relative to the lockout - a password change minutes or hours before a lockout storm on the *same* account, from a *different* device, is the classic stale-credential signature.
- `4771` **Client Address** / `4625` **Source Network Address** - where available, resolve whether the source is internal (workstation, server, scheduled task host) or arrives via VPN/NAT (in which case the visible address may just be the concentrator, not the real endpoint - a known friction point in this category).

## Normal vs Suspicious Pattern

| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Accounts affected | One account, isolated event | Multiple distinct accounts locked from the same Caller Computer Name within minutes |
| Caller Computer Name | Resolves to the user's own laptop, phone (via mail sync), or a known scheduled task host | Unrecognized host, a server with no business reason to authenticate as that user, or an address that doesn't resolve at all |
| Timing vs password change | Lockout follows a `4723` self-service change by minutes/hours - old cached credential still trying elsewhere | No recent password change on record; lockout is unexplained by any account lifecycle event |
| Failure reason before lockout | Consistent `0xC000006A` against one known account (typo/stale cache) | Mixed sub statuses across many accounts, or attempts too regular in cadence to be a human retrying a password |
| Post-lockout attempts | Attempts stop once the account is locked (source gave up or got the "account locked" message and moved on) | Attempts continue hitting the locked account repeatedly (`0xC0000234`) - attacker or script hasn't registered the lockout and keeps trying |
| Unlock pattern | Single `4767` from helpdesk identity, ticket on file | Repeated lock/unlock cycles on the same account in a short period, or unlock from an unexpected Subject |

## Investigation Steps

1. Pull the `4740` for the affected account and record **Caller Computer Name** and timestamp - this is the starting point for everything else.
2. Pull preceding `4625`/`4771`/`4776` events for that account in the 15-30 minutes before the lockout to reconstruct the Sub Status/Failure Code progression (bad password → locked) and confirm the source matches the Caller Computer Name on the `4740`.
3. Resolve Caller Computer Name: known workstation/device belonging to the account owner, a server/scheduled task host, or an unregistered/unknown asset. This single lookup usally decides which direction the investigation goes.
4. Query for other `4740` events across the environment in the same window, grouped by Caller Computer Name - if multiple distinct accounts locked out from the same source, treat as a probable spray (T1110.003) and widen scope to every account hit, not just the one that paged.
5. Check for a recent `4723`/`4724` on the account - a self-service or admin-driven password change shortly before the lockout strongly suggests a stale cached credential (mapped drive, mobile mail profile, browser-saved password, scheduled task) rather than an attack.
6. If the source is unresolved, external, or inconsistent with the user's normal pattern, check whether any attempt against this or related accounts eventually succeeded (`4624`/`4768` Result Code 0x0) - a success anywhere in this account population changes the disposition entirely.
7. Confirm who performed the `4767` unlock and whether it matches an authorized helpdesk workflow; flag any unlock performed outside the expected process.
8. Document: account(s) affected, Caller Computer Name resolution, root cause (stale credential vs. suspected attack), and whether containment was needed, before closing.

## True Positive Indicators

- Multiple distinct accounts locked from the same unfamiliar Caller Computer Name within a short window (spray pattern).
- Caller Computer Name is an unregistered, external, or otherwise unexplainable asset with no legitimate reason to authenticate as the account.
- Continued `0xC0000234` attempts after lockout, at a mechanical/scripted cadence.
- Any successful authentication (`4624`/`4768` success) on any account in the affected population during or shortly after the lockout window.
- No corresponding `4723`/`4724` or other account-lifecycle event that would explain a legitimate stale-credential cause.

## False Positive / Benign Positive Indicators

- Lockout follows a recent `4723` self-service password change, and Caller Computer Name resolves to a device the user is known to use (phone, mapped drive, scheduled task on a server they own).
- Single account, single known source, no repeat pattern, ticket already open with helpdesk before the SIEM alert fired.
- Caller Computer Name resolves to a shared kiosk, print/scan appliance, or lab machine with a documented history of noisy failed logons from multiple legitimate users.
- Service account lockout tied to a known credential-rotation job that hasn't finished propagating to every dependent host (same root cause pattern as covered in the Repeated Login Failures playbook, just tipped over the lockout threshold this time).

## Escalation Criteria

Escalate to Tier 2 / IR when: five or more distinct accounts lock out from the same Caller Computer Name within a 15-minute window; the locked account is privileged or on the VIP watchlist; any account in the affected population shows a successful authentication during or after the lockout burst; the account locks out repeatedly (three-plus times in 24 hours) with no benign root cause identified; or Caller Computer Name cannot be resolved to any known asset at all.

## Containment Options & Approval Authority

**[MANAGEMENT]** -

| Action | Approval Needed | Notes |
|---|---|---|
| Unlock account after confirming benign cause | Tier 1 analyst, standard SOP | Standard resolution for confirmed stale-credential cases; log the root cause so the user can fix the source device |
| Force password reset alongside unlock | Tier 1 analyst | Default when source of bad attempts can't be fully confirmed as benign |
| Leave account locked pending investigation | Tier 1 analyst, notify account owner | Used when spray/attack pattern is suspected but not yet confirmed |
| Block or isolate the source host (Caller Computer Name) | Tier 2 lead / Network Engineering on-call | Only when the source is an internal asset behaving abnormally, not a legitimate user device |
| Disable account entirely | IAM team lead or IR lead sign-off | Reserved for confirmed compromise or active spray with elevated risk; notify manager/owner |

Review cadence: lockout volume and root-cause breakdown (stale credential vs. spray-suspected vs. unresolved) reviewed weekly by the IAM/detection engineering owner - a rising unresolved percentage is itself a signal the lockout policy or credential propagation process needs attention, not just the SOC queue.

## Example Query (Microsoft Sentinel KQL)

Start here for the single-account case that generated the alert (Investigation Steps 1-2) - this is the query almost every lockout ticket actually needs first, before you ever get to the multi-account correlation below:

```kql
SecurityEvent
| where EventID in (4740, 4625, 4771, 4776, 4723, 4724, 4767)
| where TargetUserName =~ "<account under investigation>"
| where TimeGenerated between (ago(30m) .. now())
| project TimeGenerated, EventID, TargetUserName, CallerComputerName, IpAddress, WorkstationName, SubStatus, FailureCode
| sort by TimeGenerated asc
```

Then widen to check whether this is one isolated lockout or part of a spray-shaped pattern hitting other accounts from the same source (Investigation Step 4):

```kql
SecurityEvent
| where EventID == 4740
| summarize LockoutCount = count(), Accounts = make_set(TargetUserName)
    by CallerComputerName, bin(TimeGenerated, 15m)
| where LockoutCount >= 5 or array_length(Accounts) >= 5
| sort by LockoutCount desc
```

## Stakeholder Communication

**[STAKEHOLDER]** - Most lockouts never reach a stakeholder call - a Benign Positive closes with the user/helpdesk and nobody outside the SOC needs to hear about it. Use this only once the case has moved past Low/P4 (i.e., Caller Computer Name doesn't resolve to the user's own device, multiple accounts are involved, or a success is found). If you have to make that call, here's the five-part answer in the order the business owner will ask for it:

- **What happened:** "[Account] locked out after repeated bad-password attempts from [Caller Computer Name/source] at [time]." State only what the 4740/4625/4771 chain confirms - don't speculate beyond the evidence.
- **The risk:** A lockout by itself is not compromise - it's evidence something is hammering the account. The risk is what it might be a symptom of: an active spray/guessing campaign against this account or others (see the risk framing in the Password Spraying/Brute Force playbooks if this hands off to one).
- **The evidence:** Number of accounts affected, whether Caller Computer Name resolves to a known device, and whether any authentication in the affected population succeeded (4624/4768 0x0) - that last point is the single fact that changes the conversation from "FYI" to "we need a decision now."
- **The decision needed:** Whether to leave the account locked pending investigation (safe, but the user can't work) versus unlock/reset now (restores access, but only justified once the source is understood).
- **GO (unlock/reset now) vs. NO-GO (leave locked pending investigation):** GO restores the user's productivity immediately but carries risk if the root cause turns out to be a live attack that hasn't been fully scoped yet. NO-GO protects against that risk but costs the user's access until the investigation clears - the business owner, not the SOC alone, should own that trade-off whenever the case isn't a clean Benign Positive.

## Closure Criteria

Close as **Benign Positive** when Caller Computer Name resolves to a known device belonging to the account owner (or a known service/scheduled task host) and the cause traces to a stale or recently-rotated credential, with remediation (device re-authenticated, task credential updated) confirmed. Close as **True Positive** when the pattern matches spray/guessing behavior from an unresolved or attacker-controlled source, containment is applied, and full account scope is documented - hand off to the Brute Force or Password Spraying playbook for the underlying attack investigation. Close as **Insufficient Evidence** when Caller Computer Name cannot be resolved and no repeat, no spray breadth, and no success is observed within 48 hours - place the account on a short watchlist rather than closing it silently.

**Example case-note line:** *"2026-09-15 09:47 UTC - 4740 lockout on jromero (vantagepoint.example.com). Caller Computer Name = WKS-FIN-014, resolves to jromero's own laptop. Preceding 4625 x4, Sub Status 0xC000006A, consistent with a self-service password change (4723) at 09:31 not yet updated in a mapped network drive credential. No other accounts locked from this host; no success events found. Unlocked via 4767 by HELPDESK-SVC, user re-mapped drive with new credential. Closed as Benign Positive - stale cached credential."*
