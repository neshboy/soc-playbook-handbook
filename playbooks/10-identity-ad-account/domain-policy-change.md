# Playbook: Domain Policy Change

## Playbook ID & Name

**IAM-012 — Domain Policy Change (Password, Account Lockout, Kerberos & Audit Policy)**

Category: Identity & Active Directory — Account & Authentication

Scope note before anything else, because this is where analysts new to the category get lost: this playbook covers changes to the domain-wide *security policy settings* that live inside the Default Domain Policy and Default Domain Controllers Policy GPOs — password policy, account lockout policy, Kerberos ticket policy, and audit policy. It is not the same as playbook 13 (GPO Changes), which covers broader GPO object management — new GPOs, links, scripts, drive maps, security filtering — and it's not playbook 14 (Domain Admin Group Modification), which covers who's *in* privileged groups rather than what the authentication rules themselves say. The three overlap in practice because the tooling is shared (GPMC, the GroupPolicy PowerShell module, `secedit`), but the blast radius here is different: a domain policy change doesn't just affect one GPO's targets, it can change how *every* authenticated principal in the domain is allowed to log on, get locked out, or hold a Kerberos ticket. There is also a real gap you need to know about up front — native Windows auditing does not emit a clean, dedicated "domain policy was changed" event in this book's supported event ID set. You are triangulating from the audit-policy event that *is* directly available (4719), the administrative session and tooling trail, and the downstream authentication behavior the change actually produces.

## Business Risk

**[STAKEHOLDER]** - The password policy, lockout policy, and Kerberos policy aren't just IT settings — they're the rules that decide how hard it is to guess a password, how long an attacker gets to keep trying before the door locks, and how long a stolen Kerberos ticket stays valid. One quiet edit to any of these, made by a compromised admin account or a misconfigured automation job, doesn't attack one user — it changes the risk calculus for the entire domain at once. A lockout threshold silently raised from 5 to 500, or a Kerberos ticket lifetime stretched from 10 hours to 10 days, doesn't look like an attack in isolation; it looks like a settings screen. The business exposure is that this category of change is both extremely high-impact and extremely low-visibility, which is exactly the profile an attacker wants before they run a brute-force or persistence play elsewhere.

## Severity / Priority Default

- **Default: High (P2)** — any change to password, lockout, Kerberos, or audit policy on a Default Domain Policy / Default Domain Controllers Policy scope is treated as high by default, purely because of blast radius, and downgraded only after the change is confirmed authorized.
- **Downgrades to Medium (P3)** once the change is confirmed to match a documented change ticket, was made by the expected on-call Tier-0 admin from a known admin host, and the direction of change is neutral or tightens security posture.
- **Escalates to Critical (P1)** when the change loosens audit visibility, lockout, or Kerberos policy and is followed by a `1102` audit-log clear, a `7045` new service on the same DC, or any correlated brute-force/lockout-storm activity already open elsewhere in the queue.

## MITRE ATT&CK Techniques

- **T1484.001 Domain or Tenant Policy Modification: Group Policy Modification** — the core technique for this playbook: editing the password, lockout, Kerberos, or audit-policy settings carried in Default Domain Policy/Default Domain Controllers Policy to weaken controls or create an attacker-favorable condition domain-wide.
- **T1562.001** Impair Defenses: Disable or Modify Tools — an audit-policy subcategory set to "No Auditing," or a lockout/password policy relaxed to make brute-force detection or prevention less effective.
- **T1098** Account Manipulation — a domain policy edit used to create or extend a persistence condition, e.g., lengthening Kerberos ticket/renewal lifetimes so a stolen ticket stays useful longer.
- **T1207** Rogue Domain Controller (DCShadow) — when the policy change is pushed via unauthorized directory replication from a rogue or compromised DC rather than through the normal GPO-edit-and-`gpupdate` path; consider this whenever the acting Subject or source DC doesn't match the environment's known Tier-0 change process.
- **T1558** Steal or Forge Kerberos Tickets (.001 Golden Ticket, .003 Kerberoasting) — referenced where Kerberos policy tampering (ticket lifetime, encryption downgrade) is a precursor to a ticket-based attack rather than the objective itself.

## Trigger / Detection Logic Summary

**[ENGINEERING]** - Primary trigger is any `4719` on a domain controller for a Subcategory this environment cares about (Audit Policy Change, Account Logon, Account Management, Logon/Logoff, System), layered with:

- `4719` where **New Policy** removes Success or Failure auditing from a subcategory that was previously fully audited — this is the single highest-value line in the whole playbook.
- `4688`/`4103`/`4104` on a domain controller matching `auditpol.exe /set`, `secedit.exe /configure` (bulk security-template import — one command can silently rewrite password, lockout, Kerberos, and audit policy in a single pass), `ntdsutil.exe`, or PowerShell script blocks invoking `Set-ADDefaultDomainPasswordPolicy` or the GroupPolicy module against Default Domain Policy/Default Domain Controllers Policy.
- Any `4719` (or the tooling trail above) followed within 10–15 minutes by `1102` (log cleared) or `7045` (new service) on the same DC — treat as a single correlated incident, not two alerts.
- Domain-wide shifts in `4740` (lockout) volume dropping to zero, `4768`/`4771` Result/Failure Code patterns changing, or `4769` ticket encryption type shifting toward RC4 (`0x17`) across many service tickets right after an unexplained policy-adjacent admin session — the confirmation that a policy edit actually took effect, since the edit itself often isn't directly logged.
- `4672` absent on the same Logon ID as the acting `Subject` in `4719` — a policy change performed by a session that never showed a privileged-logon flag is worth chasing on its own; it suggests either a logging gap or a privilege path that shouldn't exist.

## Required Log Sources & Event IDs

| Source | Event IDs | Purpose |
|---|---|---|
| Domain Controller Security log | 4719 | Primary signal — Subcategory, old/new setting, Subject, Logon ID |
| Domain Controller Security log | 1102 | Audit log cleared — check immediately after any audit-weakening 4719 |
| Domain Controller Security log | 4740, 4768, 4769, 4771, 4776 | Downstream authentication behavior — confirms whether a lockout/Kerberos/NTLM-relevant policy change actually took effect |
| Domain Controller Security log | 4738 | Individual account attribute changes surfacing around the same time — can indicate the policy change or disguise tampering as "policy-driven" |
| Domain Controller Security log | 4624, 4648, 4672 | Who made the change, from where, with what privilege level, and whether explicit-credential/RunAs was used |
| Domain Controller Security log | 4688 | Process creation — `auditpol.exe`, `secedit.exe`, `ntdsutil.exe`, `mmc.exe`/GPMC, `powershell.exe` with full command line if auditing enabled |
| DC / admin host PowerShell Operational log | 4103, 4104 | Module logging and script block text for scripted or automated policy edits, including obfuscated variants |
| Domain Controller System log | 7045 | New service installed on the same DC around the same time — possible persistence riding along with a legitimate-looking change window |

## Key Fields to Inspect

**[ANALYST]** -

- `4719`: **Subcategory**, **Changes / New Policy** value vs prior baseline, **Subject Account Name**, **Logon ID**, and the specific DC — this is your delta; don't close anything until you know exactly what changed from what to what.
- `4688`: full **Command Line** for `auditpol`/`secedit`/PowerShell invocations, and **Creator Process Name** — GPMC/`mmc.exe` launched interactively reads very differently than `powershell.exe` spawned by a remote session or an unexpected parent.
- `4104`: **ScriptBlockText** — look specifically for `Set-ADDefaultDomainPasswordPolicy`, GroupPolicy module cmdlets targeting Default Domain Policy/Default Domain Controllers Policy, or `secedit /configure /db ... /cfg` importing a security template.
- `4624`/`4648`: **Logon Type** (10/RDP or 4/batch from a known jump host is routine; 3/network from an unfamiliar address is not), **Source Network Address**, **Workstation Name**.
- `4672`: confirm the acting Subject's Logon ID actually carries admin-equivalent privileges — a policy-changing Subject with no matching 4672 is a gap worth escalating on its own.
- `1102`/`7045`: **Subject** and timestamp delta from the preceding 4719 — minutes, not hours, is the pattern that matters.

## Normal vs Suspicious Pattern

| Signal | Normal / Benign | Suspicious |
|---|---|---|
| Who | Known Tier-0 admin account, matches on-call roster and a change ticket | Non-Tier-0 account, service account, or an admin account acting outside its documented window |
| Timing | Inside a published change window, ticket number referenced in session/PAM checkout | Off-hours edit, or an edit immediately following a spike in 4625/4771 failures on the same DC |
| Direction of change | Tightens or is neutral (longer minimum password, lower lockout threshold, more audit subcategories enabled) | Loosens (audit subcategory set to "No Auditing," lockout threshold raised/disabled, password complexity relaxed, Kerberos ticket/renewal lifetime extended) |
| Sequence | Change stands alone, no log clearing, no new services on the same host afterward | Followed within minutes by 1102 (log cleared) or 7045 (new service) on the same DC |
| Session context | Logon Type 10 (RDP) or 4 (scheduled job) from a known admin jump host, matches PAM checkout | Logon Type 3 from an unusual address, no PAM checkout on record, or explicit-credential (4648) use from a non-Tier-0 workstation |
| Scope of change | Single, isolated subcategory/setting edit consistent with a specific ticket | Batch of 4719 events across many subcategories at once with no corresponding baseline-refresh job scheduled |

## Investigation Steps

1. Pull the `4719` — record Subcategory, exact old-to-new value, Subject Account Name, Logon ID, and the DC it fired on. This is the anchor for every step that follows.
2. Correlate the Subject's Logon ID back to its originating `4624`/`4648` to establish Logon Type, source workstation/IP, and confirm whether `4672` fired on the same Logon ID with the privilege level actually used.
3. Check change-ticket/PAM checkout records for the Subject and time window — a matching CAB ticket is the fastest path to a benign close; its absence doesn't confirm malice by itself, but it removes the easy out.
4. Pull `4688`/`4103`/`4104` in a tight window around the `4719` on the same host to reconstruct *how* the change was made — GPMC GUI, `auditpol`/`secedit` command line, or a PowerShell script — and whether that tooling matches this admin's normal pattern.
5. Check for `1102` or `7045` on the same DC in the following 10–15 minutes. A policy change that immediately precedes a log clear or new service install should escalate regardless of what step 3 found.
6. If the change touched lockout, password, or Kerberos policy specifically, pull domain-wide `4740`/`4768`/`4769`/`4771` volume before and after — a real shift (lockouts stopping, ticket lifetimes or encryption types changing, pre-auth failure volume dropping) confirms the change actually took effect.
7. If the edit was made by directly modifying Default Domain Policy/Default Domain Controllers Policy in GPMC rather than via command-line tooling, cross-check against any open GPO Changes (playbook 13) investigation — this is very often the same incident worked from two angles and shouldn't be duplicated.
8. Document Subject, method, exact setting delta, ticket status, and downstream authentication-behavior confirmation before closing.

## True Positive Indicators

- Policy loosened (audit subcategory disabled, lockout threshold raised/removed, password length/complexity reduced, Kerberos ticket lifetime extended) by an account with no matching change ticket or PAM checkout.
- Change made via explicit credentials (`4648`) or a session (`4624` Logon Type 3) sourced from a host that isn't a documented Tier-0 admin jump box.
- `4719` (or its downstream effects) followed within minutes by `1102` or `7045` on the same DC.
- Change occurs within minutes/hours of a failed-logon burst (`4625`/`4771`) or any privileged-account compromise indicator already open elsewhere.
- Acting Subject lacks the `4672` privileged-logon context matching the access actually exercised.

## False Positive / Benign Positive Indicators

- Change matches a documented CAB ticket, made by the on-call Tier-0 admin inside the published window, via GPMC/PowerShell from a known admin jump host.
- Change tightens posture (raises minimum password length, lowers lockout threshold, enables additional audit subcategories) — doesn't clear it alone, but shifts the risk read.
- Recurring, scheduled baseline-compliance job (CIS/DISA STIG remediation, SCM tooling) reapplying an already-approved setting; confirm against the job's known run schedule.
- A batch of `4719` events across many subcategories at once, correlated to an IT-driven `gpupdate /force` baseline refresh rather than a single targeted edit.

## Escalation Criteria

Escalate to Tier 2/IR when: an audit subcategory covering Logon/Logoff, Account Management, or Account Logon is set to "No Auditing" or has Success auditing removed; lockout policy is disabled or its threshold raised outside a documented change; Kerberos ticket or renewal lifetime is extended without a ticket; the change is followed by `1102` or `7045` on the same DC; the acting Subject's source session doesn't match its normal admin pattern; or the change coincides with any open brute-force, spray, or lockout-storm investigation on the same domain.

## Containment Options & Approval Authority

**[MANAGEMENT]** -

| Action | Approval Needed | Notes |
|---|---|---|
| Revert the specific setting to its prior value | Tier 2 lead, coordinate with IAM/AD team | Pull the rollback value directly from the 4719 old-setting field — don't guess it |
| Suspend the acting admin account pending review | IR lead or IAM team lead sign-off | Used when source session doesn't match normal pattern or no ticket exists |
| Force domain-wide password reset / rotate krbtgt (Kerberos ticket re-issuance) | CISO/IR lead sign-off, planned change-control rollout | Reserved for confirmed Tier-0 compromise or evidence of ticket-policy abuse enabling persistence — high blast radius, needs staged execution, not an ad hoc fix |
| Isolate the domain controller where the change originated | IR lead + Infrastructure on-call, joint sign-off | Only for confirmed compromise; affects authentication for that DC's site/replication scope |
| Re-enable the affected audit subcategory and validate end-to-end log flow | Tier 2 analyst / detection engineering | Standard follow-up any time a 4719 disabled or narrowed a subcategory this playbook depends on |

## Example Query (Splunk SPL)

```spl
index=win_security EventCode=4719
| rex field=Changes "Success Removed:(?<success_removed>[^\r\n]+)"
| rex field=Changes "Failure Removed:(?<failure_removed>[^\r\n]+)"
| where isnotnull(success_removed) OR isnotnull(failure_removed)
| table _time, host, Account_Name, Subcategory, Changes
| sort - _time
```

## Closure Criteria

Close as **True Positive** when the change is unauthorized, loosens security posture, and ties to a compromised or misused Tier-0 credential, or precedes a log clear/service install — hand off to IR for full compromise scope. Close as **Benign Positive** when the change matches a documented CAB ticket or a scheduled baseline-compliance job and the direction is neutral-or-tightening. Close as **Insufficient Evidence** when the Subject or source session can't be fully corroborated within the retention window — common when only a subset of Directory Service auditing subcategories are enabled, or ingestion delay pushed the correlating events past the lookback — but no downstream `1102`/`7045`/lockout-storm effect is observed; flag for a policy-baseline review rather than closing silently.

**Example case-note line:** *"2026-09-15 14:12 UTC - 4719 on DC02.vantagepoint.example.com: Subcategory 'Audit Account Logon Events' changed from Success and Failure to No Auditing. Subject: d.chen-adm, Logon ID 0x3F8A2C1, Logon Type 10 from ADM-DCHEN01 (10.20.5.12), 4672 present, matches PAM checkout CHG-22417 for scheduled Kerberos-policy remediation window. No 1102/7045 on DC02 in following 30 min. auditpol.exe command line in 4688 matches documented remediation script. Domain-wide 4768/4771 volume unchanged post-change. Closed as Benign Positive - authorized change, re-enabled subcategory confirmed via follow-up 4719 at 14:19 UTC."*
