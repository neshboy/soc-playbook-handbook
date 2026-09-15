# Unexpected Password Reset

**Category:** Identity & Active Directory - Account & Authentication
**Playbook ID:** IAM-010

A password reset is one of those events that's completely mundane 95% of the time and genuinely alarming the other 5%, with almost nothing in the raw event to tell you which one you're looking at. Someone else changing a user's password (4724) is a normal helpdesk function, a normal IAM automation task, and also the single cleanest way for an attacker who's gained delegated rights or domain-level privilege to take over an account without ever guessing a password. The reset itself isn't the compromise - it's usually evidence that a compromise or a privilege abuse already happened somewhere upstream (a phished helpdesk analyst, an over-permissioned OU delegation, a domain admin session used from the wrong host). This playbook is about catching the reset fast enough to interrupt the takeover before the attacker gets a clean logon with the new credential.

## Business Risk

**[STAKEHOLDER]** - An account whose password changes without the owner's knowledge or consent is, functionally, an account that just changed hands. If it's a regular user, that's a productivity and helpdesk-load problem plus a possible mailbox/data exposure risk. If it's a privileged, service, or Tier-0 account, an unexpected reset is one of the fastest paths to full domain compromise available to an attacker, faster and quieter than cracking a hash or exploiting a service. The business decision here is whether the reset was requested and by whom - and if it wasn't, whoever performed it needs to be identified and locked down immediately, not just the target account.

## Severity / Priority Default

- **Default:** Medium (P3) - most resets tie cleanly to a helpdesk ticket or a self-service portal event.
- **Escalates to High (P2)** when the target account is privileged, service, or Tier-0; when the reset has no corresponding ticket/change record; or when the account performing the reset (the Subject) isn't a recognized IAM/helpdesk identity.
- **Escalates to Critical (P1)** when a successful logon on the target account follows the reset from an unfamiliar Source Network Address or Workstation Name, or when the reset is part of a burst affecting multiple privileged accounts in a short window.

## MITRE ATT&CK Techniques

- **T1098 Account Manipulation** - the reset itself, when performed by an attacker with delegated or stolen rights, to seize or maintain access.
- **T1078 Valid Accounts** (.002 Domain Accounts, .004 Cloud Accounts) - the follow-on risk once the new credential is known and used to authenticate.
- **T1531 Account Access Removal** - when the reset is used offensively to lock the legitimate owner out (common in insider-threat and pre-ransomware scenarios where an attacker resets admin credentials to deny defenders access during an active intrusion).

## Trigger / Detection Logic Summary

Alert on any of the following, evaluated per event and correlated over a rolling window (default 30 minutes for burst detection):

1. **4724 (password reset by someone else)** where the Subject Account Name is not on the approved IAM/helpdesk service-account allowlist.
2. **4724** targeting an account in a privileged or Tier-0 group (Domain Admins, Enterprise Admins, break-glass accounts, service accounts tied to critical systems), regardless of who performed it.
3. **Burst pattern:** ≥3 4724 events from the same Subject against distinct target accounts within the window - a normal helpdesk analyst resets one user at a time, not a batch, outside a declared mass-reset change window.
4. **4724 or 4738** (password-related attribute change) followed within a short window by a **4624** on the target account from a Source Network Address or Workstation Name that account has never authenticated from before.

## Required Log Sources & Event IDs

| Source | Event IDs | Why |
|---|---|---|
| Domain Controller Security log | 4724, 4723 | Core reset telemetry - reset-by-other vs self-service |
| Domain Controller Security log | 4738 | Confirms the password-related attribute actually changed on the target object |
| Domain Controller Security log | 4740, 4767, 4625 | Lockout/unlock and failed-logon evidence that the legitimate owner is locked out or still trying the old password |
| Domain Controller Security log | 4624, 4648, 4672 | Who logged on with the new credential, from where, and whether it carried privileged rights |
| Domain Controller Security log | 4728, 4729, 4732, 4733, 4720 | Follow-on account/group manipulation - the usual next move after a takeover |
| Domain Controller Security log | 1102, 4719 | Anti-forensics check - log clearing or audit policy change around the reset |
| Endpoint (Subject's workstation) | 4688, 4103, 4104 | Detects `Set-ADAccountPassword`, `net user /domain`, `dsmod`, or scripted/bulk reset tooling |
| IAM/helpdesk ticketing system | Change/ticket ID | Ground truth for whether the reset was requested and approved |

## Key Fields to Inspect

**[ANALYST]**
- **Subject Account Name/SID** on 4724 - is this a real, currently-employed helpdesk or IAM automation identity, or a regular user account, a decommissioned admin account, or something that shouldn't have reset rights at all?
- **Target Account Name** - check its tier, group memberships, and normal usage pattern before assuming this is routine.
- **Changed Attributes** on the paired 4738 - confirm the password attribute actually changed; don't assume 4724 alone proves it went through cleanly.
- **Subject's own recent logon (4624/4648)** immediately before the reset - Logon Type, Source Network Address, Workstation Name. A helpdesk analyst's session originating from an unfamiliar host or geography is the tell that the *resetter's* account, not the target, is the actual compromise.
- **New Logon Account Name / Source Network Address / Workstation Name** on the first 4624 for the target account after the reset - this is the single highest-value field in this entire playbook.
- **Time-to-first-logon** after the reset - a legitimate user who just had their password reset by the helpdesk usually logs on from their known device within minutes; an attacker logging on from an unrecognized host is the takeover signature.

## Normal vs Suspicious Pattern

| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Subject | Known helpdesk/IAM service identity, ticket on file | Unrecognized account, peer user, or decommissioned admin identity |
| Target account tier | Standard user, matches ticket | Privileged, Tier-0, service, or break-glass account |
| Volume | One reset per Subject per ticket | 3+ resets by one Subject in a short window, no matching change record |
| Post-reset logon source | Target's known device/location | New Source Network Address, foreign geography, or unfamiliar Workstation Name |
| Owner behavior after reset | Owner logs on normally within minutes/hours | Owner generates 4625 failures using the old password (evidence they weren't told), or no logon at all for days |
| Companion events | None unusual | 1102/4719 nearby, or 4728/4732/4720 shortly after |

## Investigation Steps

1. Pull the 4724 event and immediately check for a matching ticket/change record in the IAM or helpdesk system. No matching record moves this straight to high priority.
2. Identify and vet the Subject - confirm employment status, role, and whether delegated reset rights on this OU/account are expected and documented.
3. Check the Subject's own authentication trail (4624/4648) in the minutes before the reset - an unusual source or Logon Type here points to the resetter's own account being the true point of compromise.
4. Check the target account's tier and group memberships - privileged or Tier-0 targets get escalated regardless of how clean the ticket looks.
5. Watch for the first post-reset 4624 on the target account and compare Source Network Address/Workstation Name against that account's known baseline. This is the step that separates routine resets from account takeover.
6. Check for 4625 failures on the target account after the reset - a wave of failed attempts using the old password is strong evidence the real owner was never informed, meaning the reset wasn't theirs to request.
7. Check for 4103/4104 or 4688 evidence of scripted/bulk reset activity on the Subject's host, and check for a matching 4724 burst against other accounts in the same window.
8. Check 1102/4719 in the same timeframe, and check whether the reset was quickly followed by 4728/4732 (group changes) or 4720 (new account) - the classic next moves once an attacker has a working credential.

## True Positive Indicators

- 4724 with no matching ticket, targeting a privileged or Tier-0 account.
- Post-reset 4624 from a Source Network Address/Workstation Name never seen before for that account.
- Burst of 4724 events from one Subject across multiple accounts outside a declared mass-reset window.
- Subject's own recent session shows signs of compromise (unusual source, followed by 4648 explicit-credential use to another host).
- Reset closely followed by group membership change, new account creation, or a 1102/4719 anti-forensics event.

## False Positive / Benign Positive Indicators

- 4724 matches an open, approved helpdesk ticket, Subject is a verified helpdesk analyst, and the target logs on normally from their known device shortly after.
- 4723 self-service reset through the organization's SSPR portal with MFA satisfied - expected activity, no further action.
- Scheduled service-account credential rotation performed by a known IAM automation identity, matching a documented rotation calendar.
- Declared mass-reset event (post-incident precautionary reset, planned credential rotation project) with change record covering the burst pattern.

## Escalation Criteria

Escalate to Tier 2 / IR immediately if any of the following are true:
- Target account is privileged, Tier-0, or a service account tied to critical infrastructure.
- No ticket or change record exists for the reset.
- A post-reset logon occurs from an unfamiliar source, or no owner logon occurs at all within the expected window.
- The reset is one of several in a burst from a single Subject, or is accompanied by 1102/4719, group membership changes, or new account creation.

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Approval Needed | Notes |
|---|---|---|
| Re-reset password immediately, force MFA re-enrollment | Tier 1 analyst, standard SOP | Apply on any unconfirmed/no-ticket reset of a standard account |
| Disable target account pending verification | Tier 2 lead | For privileged/Tier-0 targets or any confirmed no-ticket reset |
| Notify account owner out-of-band (phone, not email) | Tier 1 analyst | Email account itself may be the compromised channel |
| Suspend Subject's reset/delegation rights and disable Subject account | IAM team + IR lead | Required if Subject's own account shows compromise indicators |
| Revoke active sessions/tokens for target account | IR lead | Especially for hybrid/cloud-synced identities where the new password may already be in use elsewhere |
| Full IR engagement, isolate related hosts | IR lead / CISO delegate | If burst pattern or Tier-0 targeting confirms active takeover campaign |

Review cadence: delegated reset-rights (who in AD/Entra can reset whose password) reviewed quarterly by the IAM team; unexpected-reset alert tuning and false-positive rate reviewed monthly by detection engineering.

## Example Query (Splunk SPL)

```spl
index=wineventlog EventCode=4724
| lookup helpdesk_allowlist.csv subject_sid as Subject_SID OUTPUT is_allowed
| where isnull(is_allowed) OR Target_Account IN (privileged_accounts_lookup)
| bin _time span=30m
| stats count as resets, values(Target_Account) as targets by Subject_Account, _time
| where resets>=3 OR isnull(is_allowed)
```

## Closure Criteria

Close as **True Positive** only after identifying the actual Subject, confirming lack of authorization, and completing containment on both the target and (if compromised) the Subject account. Close as **Benign Positive** when a matching ticket, SSPR event, or documented rotation calendar accounts for the reset and the target's subsequent logon matches their known baseline. Close as **Insufficient Evidence** when the Subject cannot be conclusively tied to a ticket and no follow-on logon or malicious activity is observed within 48 hours - keep the target account on a watchlist rather than closing the loop entirely.

**Example case note:**
`2026-09-15 09:12 UTC - 4724 reset on jsato@example.com performed by Subject svc-helpdesk-01, no matching ticket found in ServiceNow at time of alert. First post-reset 4624 at 09:19 UTC from Workstation Name CORP-LT-2291, Source Network Address 10.22.4.187 - not in jsato's known device history (baseline: CORP-LT-0447, 192.168.12.0/24). Contacted jsato by phone; confirmed she did not request a reset and is currently locked out using her old password (4625 x6 at 09:20-09:24 UTC from her actual device). Disabled target account, forced re-reset with MFA re-enrollment, opened IR case to trace svc-helpdesk-01 credential usage. Closed this alert as True Positive - escalated to account-takeover investigation.`
