# Repeated Login Failures

**Category:** Identity & Active Directory - Account & Authentication
**Playbook ID:** IAM-001

Repeated login failures is the single highest-volume alert category in most SOCs and, for that exact reason, the one analysts get complacent about fastest. Most of the volume is genuine noise - a user who forgot they rotated their password on a phone that's still trying the old one, a service account with a stale credential cached on three servers, a printer with hardcoded creds from 2019. But this is also the raw telemetry signature behind password spraying, credential stuffing from breach lists, and the early recon phase of most external-facing AD compromises. The job of this playbook is triage discipline: separate "annoying but expected" from "this is attempt #1 of a campaign" before the account locks out or, worse, before attempt #40 succeeds.

## Business Risk

**[STAKEHOLDER]** - A sustained wave of failed logins against one account or across many accounts is usually either a credential-guessing attack in progress or an unmanaged password/sync problem quietly locking out staff. Left untriaged, the first scenario risks account takeover and everything downstream of it (mailbox access, VPN, admin escalation); the second scenario generates helpdesk load and business disruption without any attacker involved. The decision point for the business is simple: is this an attack that needs blocking, or a hygiene problem that needs fixing at the source.

## Severity / Priority Default

- **Default:** Medium (P3)
- **Escalates to High (P2)** when the target account is privileged, when failures originate from an external/internet-facing source, when a spray pattern spans more than ~15 accounts from one source, or when a lockout storm is actively disrupting business operations.
- **Escalates to Critical (P1)** when repeated failures are immediately followed by a successful authentication (4625 storm followed by a 4624 or 4768 success) on the same account.

## MITRE ATT&CK Techniques

- **T1110 Brute Force**
  - T1110.001 Password Guessing - sustained failures against a single account
  - T1110.003 Password Spraying - low-and-slow failures spread across many accounts from one or few sources
- **T1078 Valid Accounts** (.002 Domain Accounts) - the follow-on risk if a guess or spray succeeds
- **T1595 Active Scanning** - occasionally the precursor when failures follow port/service discovery against an exposed auth endpoint (RDP, VPN gateway, OWA)

## Trigger / Detection Logic Summary

Alert fires when either condition is met inside a rolling window (default 15 minutes, tune per environment):

1. **Single-account threshold:** ≥5 consecutive 4625 (or 4771/4776 equivalents) events for one Account Name from one or more source hosts, with no intervening 4624 success.
2. **Spray pattern:** ≥15 distinct Account Names with ≥1 failure each, originating from the same Source Network Address (or same small /28-ish range, or same Caller Computer Name in the 4740 case), within the window.

Both conditions should also fire on a **near-miss lockout window**: if failures approach (not necessarily reach) the domain lockout threshold for a given account, treat it as a live-attack indicator, not just a nuisance.

## Required Log Sources & Event IDs

| Source | Event IDs | Why |
|---|---|---|
| Domain Controller Security log | 4625, 4771, 4776, 4740, 4767, 4768, 4769 | Core failure/lockout telemetry, both NTLM and Kerberos paths |
| Domain Controller Security log | 4624, 4634, 4647 | Confirms whether a failure run ended in a success |
| Domain Controller Security log | 4719, 1102 | Detects log tampering/policy changes hiding a longer campaign |
| Domain Controller Security log | 4720, 4722-4726, 4738 | Follow-on account manipulation if compromise is suspected |
| Perimeter (VPN/RDP gateway/reverse proxy) | vendor auth logs correlated to internal 4625/4776 | Maps external source IP to the internal account being targeted |
| Endpoint (if RDP direct-exposed) | 4625 with Logon Type 10 or 3 | Confirms remote-service targeting vs local console |

## Key Fields to Inspect

**[ANALYST]**
- **Account Name** - is it real, disabled, service, or non-existent (typo vs. targeted guessing)?
- **Failure Reason / Sub Status** on 4625: `0xC000006A` (bad password) vs `0xC0000064` (user does not exist) vs `0xC0000234` (already locked) vs `0xC0000072` (disabled). A run of `0xC0000064` across many names is classic spray/enumeration; a run of `0xC000006A` against one name is classic guessing.
- **Source Network Address / Source Port** on 4625, 4776 - internal RFC1918 range vs external. One source hitting many accounts is the spray signature.
- **Caller Computer Name** on 4740 - this is the actual originating host in a lockout storm, not the DC that logged the lockout.
- **Logon Type** - 3 (network), 10 (RemoteInteractive/RDP), 2 (interactive) changes the likely vector.
- **Pre-Authentication Type and Result Code** on 4768/4771 - `0x18` is bad password/failed pre-auth, useful when NTLM is disabled and everything routes through Kerberos.
- **Authentication Package** on the eventual 4624 if one appears - NTLM succeeding on a domain that should be Kerberos-only is itself worth a side note.

## Normal vs Suspicious Pattern

| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Volume per account | 1-3 failures, self-resolves with a 4624 shortly after (user re-typed password) | 5+ failures, no success, or success arrives abruptly after a long failure run |
| Source diversity | Same 1-2 hosts each time (user's own laptop/phone) | Single external IP or small IP block hitting 10+ distinct accounts |
| Timing | Clustered around business hours, morning logon rush, password-expiry cycles | 02:00-05:00 local time, steady drip over hours (spray pacing to dodge lockout thresholds), or bursts immediately after a breach-list dump becomes public |
| Failure reason mix | Mostly `0xC000006A` for one known-good account | Mixed `0xC0000064` across many accounts (enumeration behavior) |
| Account type | Human user with normal usage history | Never-used, disabled, or newly created accounts suddenly targeted |

## Investigation Steps

1. Pull all 4625/4771/4776 events for the affected account(s) and Source Network Address across the alert window plus 24 hours before/after - confirm this is a new pattern, not a recurring known-noisy source (some proxies and load balancers legitimately reuse a source IP for many users).
2. Check for a terminating 4624 or successful 4768. If present, treat this as a probable account-takeover event and jump straight to escalation - do not keep triaging as routine.
3. Resolve the source: is the Source Network Address internal or external? If internal, identify the physical host/owner (DHCP logs, CMDB, EDR) - a misconfigured scheduled task or a mapped drive with cached creds is a very common root cause.
4. Check Caller Computer Name on the 4740 lockout event, not just the DC - this is the actual attacking/misconfigured host, a step analysts skip surprisingly often.
5. Cross-reference the account against privileged group membership (4728/4732 history, or a live AD group query) - privileged targets get escalated regardless of volume.
6. If external, pivot to VPN/RDP gateway or reverse-proxy logs to correlate the source IP with any earlier T1595 scanning activity or known threat-intel indicators.
7. Check for a 4719 or 1102 near the same timeframe - an attacker who succeeds sometimes tries to blind or clear the log immediately after.
8. Document account state (locked, disabled, password age) and decide disposition per the criteria below.

## True Positive Indicators

- Failure run terminates in a successful 4624/4768 on an account that didn't request or expect access at that time.
- Source IP is external, unrecognized, or matches threat-intel feeds for credential-stuffing/spray infrastructure.
- Spray signature: one source, many distinct accounts, mostly `0xC0000064`/`0xC000006A`, spaced to avoid lockout thresholds.
- Followed by 4648 explicit-credential logons, 4672 privileged logon, or new 4720/4728 account/group activity - indicates the attacker is operationalizing access.

## False Positive / Benign Positive Indicators

- Source resolves to the user's own known device and the failures stop after a successful logon minutes later (password rotation lag on a phone or mapped-drive credential).
- Service account failures tied to a known credential-rotation job that hasn't finished propagating to every dependent server (very common after a scheduled password reset).
- Load balancer / NAT gateway address showing high volume across many accounts by design, not attack (validate against a known baseline before dismissing).
- Recently disabled or offboarded account still being hit by an old scheduled task, script, or mobile device - benign but needs remediation, not incident escalation.

## Escalation Criteria

Escalate to Tier 2 / IR immediately if any of the following are true:
- A successful logon follows the failure run on the targeted account.
- The account is a Domain Admin, Tier-0 service account, or has 4672 special-privilege history.
- Spray pattern spans 15+ accounts from a single external source.
- A 1102 or 4719 event appears in the same window as the failure run.

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Approval Needed | Notes |
|---|---|---|
| Force password reset on targeted account | Tier 1 analyst, standard SOP | Low friction, apply liberally on suspected TP |
| Manual account lock (beyond automatic AD lockout) | Tier 1 analyst | Immediate stopgap while investigating |
| Block source IP at perimeter/WAF | Tier 2 lead sign-off | Coordinate with network team, watch for shared-NAT collateral blocking |
| Disable account entirely | IAM team or on-call IR lead | Required if takeover confirmed; notify account owner/manager |
| Force sign-out of active sessions / revoke tokens | IR lead | For hybrid/cloud-synced accounts, coordinate with identity platform owner |

Review cadence: spray/guessing rule tuning and false-positive rate reviewed monthly by the detection engineering owner; lockout-source patterns feeding back into a watchlist reviewed weekly during active-threat periods.

## Example Query (Splunk SPL)

```spl
index=wineventlog EventCode IN (4625,4771,4776)
| eval src_ip=coalesce(Source_Network_Address, IpAddress)
| bin _time span=15m
| stats dc(Account_Name) as distinct_accounts, count as failures, values(Sub_Status) as reasons by src_ip, _time
| where failures>=5 OR distinct_accounts>=15
| sort -failures
```

## Closure Criteria

Close as **True Positive** only after confirming source, blast radius, and whether any success occurred, with containment action logged. Close as **Benign Positive** when the source and cause are identified and tied to a known non-malicious process (rotation lag, stale script, shared NAT). Close as **Insufficient Evidence** when the source cannot be resolved and no follow-on activity or success is observed within 48 hours - keep the account on a watchlist rather than fully closing the loop.

**Example case note:**
`2026-09-15 03:41 UTC - 4771 failures x22 against svc-backup-sync from 10.14.6.51 (app-server-03), all 0xC000006A. Traced to Group Policy password rotation completed 03:15 UTC on the DC but not yet propagated to app-server-03's stored credential in Task Scheduler. Credential updated manually, service restarted, failures stopped. Closed as Benign Positive - rotation lag. Recommended: automate credential push to dependent hosts as part of rotation runbook.`
