# Part 4B — Fully Worked Example: Brute Force Authentication Followed by Successful Logon

Part 4A laid out the master template and argued for why each field earns its place. This section runs it end to end against a scenario every SOC eventually staffs a 3am call for: a burst of failed logons against one account, then a success. On paper it's the simplest playbook in the book. In practice analysts get it wrong often — closing too fast because "the password eventually worked," or treating every password-reset mishap like a nation-state intrusion. The filled-out playbook below is the version this book expects every shorter example to trace back to.

Fictional environment: **Cardinal Peak Financial**, a mid-size wealth management firm running hybrid Active Directory (on-prem AD DS, synced to Microsoft Entra ID). Domain `CARDINALPEAK`, DNS suffix `cardinalpeak.example.com`. SIEM is Microsoft Sentinel, fed from domain controllers and a Remote Desktop jump host used by remote finance staff.

---

## Header Fields

| Field | Value |
|---|---|
| **Playbook ID** | PB-IAM-BF-001 |
| **Playbook Name** | Brute Force Authentication Followed by Successful Logon (Single Account) |
| **Version** | 2.1 |
| **Status** | Active – Production |
| **Owner** | SOC Detection & Response, Identity Track |
| **Technical Owner** | Priya Nazari, Senior Detection Engineer |
| **Business Owner** | Marcus Webb, Director of Identity & Access Management |
| **Approver** | Dana Ferris, SOC Manager |
| **Last Updated** | 2026-06-18 |
| **Next Review Date** | 2026-12-18 (semi-annual, or immediately after any P1 tied to this playbook) |

## Detection Source

Microsoft Sentinel, scheduled analytics rule against the `SecurityEvent` table (collected via Azure Monitor Agent from domain controllers DC01/DC02 and jump host RDP01), correlated against `SigninLogs` for hybrid-synced accounts. Backed by an equivalent Splunk search on the same raw events for sites still on legacy Windows Event Forwarding during the Sentinel migration.

## Alert Name

**IAM-014: Multiple Failed Logons Followed by Successful Authentication — Single Target Account (Password Guessing Pattern)**

## Description

Fires when a single account accumulates a defined number of failed logons (4625) within a short window, followed by a successful logon (4624) for the same account within a following window. Correlates against Kerberos pre-authentication failures (4771) and NTLM validation failures (4776) on domain controllers, since RDP failures against a jump host and Kerberos failures against a DC can be the same attack seen from two log sources.

## Objective

Catch credential brute force attacks or targeted password guessing early enough to contain it before the attacker moves from "got a password" to "did something with it" — mailbox access, lateral movement, or fraud in a finance-adjacent account.

## Business Risk

**[STAKEHOLDER]** - A brute-forced account is a foothold, not the endgame. The accounts most often targeted here belong to finance and operations staff who can approve wire transfers or touch client records. A takeover isn't an abstract "unauthorized access" line item; it's a plausible path to payment fraud or a disclosable client-data exposure. The contain-now-vs-monitor call belongs to IAM and the SOC Manager once a privileged or client-facing account is involved, not to the on-call analyst alone.

## Severity

High by default at rule level; analysts may re-score to Medium once triage rules out a true positive (see Decision Points).

## Priority

P2. Escalates to P1 automatically if the target account holds elevated privileges, is flagged VIP, or the successful logon falls outside the account owner's normal working pattern combined with an unrecognized source.

## MITRE ATT&CK

- **T1110** Brute Force — **T1110.001** Password Guessing (this playbook's primary pattern); **T1110.003** Password Spraying if the same source touches multiple accounts (see Related Playbooks)
- **T1078.002** Valid Accounts: Domain Accounts (post-compromise use of the now-successful credential)
- **T1021.001** Remote Services: RDP (if the successful logon is interactive, Logon Type 10, and the attacker pivots onward)

## Applicable Systems

Domain-joined Windows servers and workstations authenticating against `CARDINALPEAK` AD DS; jump host RDP01 used for remote finance access; any system where NTLM or Kerberos auth against a DC is logged. Entra ID-only cloud identities are out of scope — covered by a separate cloud sign-in brute-force playbook.

## Data Sources

Windows Security Event Log (DCs and jump host), Entra ID sign-in logs (secondary confirmation for hybrid-synced accounts), VPN concentrator session logs (source of the NAT'd address seen at RDP01).

## Log Sources

| Log Source | Collection Method | Retention (hot / total) |
|---|---|---|
| DC01 / DC02 Security log | Azure Monitor Agent → Sentinel | 90 days / 365 days |
| RDP01 Security log | Azure Monitor Agent → Sentinel | 90 days / 365 days |
| VPN concentrator (Cisco ASA) | Syslog → Sentinel connector | 30 days |
| Entra ID Sign-in Logs | Native Sentinel connector | 90 days |

## Required Fields

| Event ID | Fields Used |
|---|---|
| 4625 | Account Name, Failure Reason, Status / Sub Status, Logon Type, Source Network Address, Caller Process Name |
| 4624 | Subject, New Logon Account Name/Domain/SID, Logon ID, Logon Type, Process Name, Workstation Name, Source Network Address, Source Port, Authentication Package |
| 4740 | Caller Computer Name (real source in a lockout storm) |
| 4771 | Account Name, Client Address, Pre-Authentication Type, Result Code |
| 4776 | Logon Account, Source Workstation, Error Code |
| 4672 | Post-logon check: does the session hold admin-equivalent privileges |

## Prerequisites

Advanced Audit Policy set for **Logon/Logoff → Logon** and **Account Logon → Credential Validation / Kerberos Authentication Service**, Success and Failure, on all in-scope hosts. NTP sync verified across DCs and jump host — clock drift has made a real timeline look impossible more than once. Sentinel connector health confirmed; a stalled Azure Monitor Agent silently kills this detection.

## Dependencies

CMDB/asset inventory for host criticality; HR/IAM roster for privileged and VIP flags; threat intel feed wired into Sentinel enrichment; on-call IAM contact for after-hours account actions; the **Account Lockout Storm Triage** playbook, which this one hands off to when the failure volume looks like a spray rather than a single-account guess.

## Trigger Condition

At least **8 failed logons (4625)** against one target account within a **10-minute** rolling window, from one or more sources, followed by **at least one successful logon (4624)** for that account within **15 minutes** of the last failure. Secondary trigger: 5+ Kerberos pre-authentication failures (4771, Result Code 0x18) against the same account in the same window, correlated to a subsequent successful 4768/4624 pair.

## Detection Logic Summary

**[ENGINEERING]**

```kql
let FailureThreshold = 8;
let FailWindow = 10m;
let SuccessWindow = 15m;
SecurityEvent
| where EventID == 4625
| where TargetUserName !endswith "$"                     // exclude machine accounts
| summarize FailCount = count(),
            FirstFail = min(TimeGenerated),
            LastFail  = max(TimeGenerated),
            SourceIPs = make_set(IpAddress)
    by TargetUserName, Computer, bin(TimeGenerated, FailWindow)
| where FailCount >= FailureThreshold
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType in (2,3,10)     // interactive, network, RDP
    | project SuccessTime = TimeGenerated, TargetUserName, Computer,
              SuccessIP = IpAddress, LogonType, TargetLogonId
  ) on TargetUserName, Computer
| where SuccessTime between (LastFail .. LastFail + SuccessWindow)
| project TargetUserName, Computer, FailCount, SourceIPs,
          FirstFail, LastFail, SuccessTime, SuccessIP, LogonType, TargetLogonId
```

The join keys on account + host, not account + source IP — attackers rotating through a small proxy pool would otherwise slip under a source-IP-scoped join with no single IP hitting the threshold.

## Known Limitations

VPN NAT means `Source Network Address` on RDP01's 4625/4624 events shows the concentrator's internal pool address (e.g., `10.20.9.53`), not the client's real origin — the true source has to be pulled from the ASA session log and joined on timestamp. Kerberos pre-auth failure volume (4771) is high-cardinality and gets filtered upstream during EPS spikes, delaying or dropping the secondary trigger. No command-line auditing is required here, so the trigger says nothing about what ran after logon — that's Investigation's job.

## Known False Positives

- User forgets a just-reset password, fails a few times, then gets it right.
- A mapped drive, scheduled task, or mobile mail client caches an old password and retries until the user re-authenticates the app manually.
- Password expiration hits mid-shift; several apps retry with the stale cached credential before the user updates it everywhere, then the correct one succeeds.
- An approved pentest/red team engagement against RDP01 that wasn't added to the suppression list before kickoff.

## Initial Triage

**[ANALYST]**

1. Pull the raw 4625/4624 pair and confirm account, host, and timestamps match the alert summary — entity mapping occasionally attaches the wrong `TargetUserName` when a SID doesn't resolve cleanly.
2. Check whether the account was recently reset or is mid-onboarding/offboarding. This alone closes a large share of these alerts.
3. Identify the true source: for RDP01 hits, pull the matching VPN session from the ASA log by timestamp, not just the NAT'd address in the Windows event.
4. Check for a corresponding 4740 (lockout) — if the account locked before the "success," that success may belong to a later session after a manual unlock.
5. Note the owner's normal working hours and location pattern before doing anything else; you'll need it for validation either way.

## Enrichment

Threat intel lookup on any externally-visible source IP/ASN (excluding Cardinal Peak's own VPN gateway range). Asset criticality tag from CMDB for the target host. User context from IAM roster: role, group memberships, VIP flag, any open HR case. Historical logon baseline for the account: typical hours, source, logon type. Cross-reference open cases for the same account or source IP — a source that also tripped a scanning alert this week changes the read.

## Investigation

**[ANALYST]** Reconstruct the timeline: first failure, failure cadence (steady, machine-paced intervals read differently than clustered bursts with human-length gaps), last failure, success timestamp, and the gap between last failure and success. A short, clean gap is more suspicous than one long enough for someone to have re-typed a password by hand.

Then check what happened after the successful logon — this is where most of the real investigative value sits:

| Event | Meaning | Technique |
|---|---|---|
| 4672 | Admin-equivalent token — raise severity | T1078.002 |
| 4648 | Explicit creds used elsewhere from this session | T1550.002 |
| 4688 (odd parent/child or command line) | Tooling/recon execution | T1059.001 / T1059.003 |
| 4103 / 4104 | Obfuscated PowerShell; check de-obfuscated 4104 content | T1027, T1059.001 |
| 4698 | Scheduled task persistence | T1053.005 |
| 4697 / 7045 | Service install, persistence or lateral tooling | T1543.003 |
| 4728 / 4732 | Group membership added — privilege escalation | T1098 |
| 4720 | Account created for persistence | T1136 |

**[ENGINEERING]** Pivot the successful `TargetLogonId` across the Security log on that host and anywhere it touched — 4634/4647 events tied to that Logon ID scope the session's lifetime; any 4648 from that session is a lateral-movement lead.

## Validation

Confirm the successful logon is genuinely anomalous, not just numerically attached to a failure streak. Contact the account owner out-of-band and ask if they attempted the login. Compare source, host, and logon type against the 30-day baseline from enrichment. If confirmed and explainable ("forgot my new password four times"), close as Benign Positive. If unreachable or denied, treat as a live potential compromise and move to containment without waiting on further confirmation.

## Decision Points

- Does the source resolve to something the organization controls, or to something external and unrecognized once NAT is unwound? External/unrecognized pushes toward true positive.
- Is the account privileged, VIP, or does it touch mailbox/financial systems? Any yes raises priority to P1.
- Did the owner confirm the activity when reached? Confirmed and explainable closes Benign Positive; unreachable or denied proceeds to containment.
- Is there follow-on activity from the Investigation table? Any hit moves this from "suspicious logon" to "active incident."

## True Positive Indicators

Uniform, machine-paced failure intervals; source has no legitimate business reason to authenticate as this account; owner denies the activity or is on leave and shouldn't be logging in at all; follow-on privileged token, lateral movement, or persistence events present in the same session; source IP has prior threat intel hits or tripped a scanning/recon alert.

## False Positive Indicators

Failure timestamps and pattern match a human re-typing a password (irregular gaps, decreasing failure rate); source is an internal, known device consistent with the user's normal location; owner confirms and explains the activity; failures stopped in other systems once the user updated a cached credential elsewhere.

## Benign Positive Conditions

Approved, pre-registered pentest or red team activity against the in-scope host (verify against the current engagement calendar). Confirmed user error following a password reset, self-resolved without IAM intervention. IAM-initiated bulk password rotation whose automation itself generates the failure/success pattern.

## Escalation Criteria

Escalate to Tier 3/IR immediately if: the account is privileged or VIP; there is confirmed follow-on activity from the Investigation table; the same source IP hits multiple distinct accounts (reclassify as spray, hand off to that playbook); there's any sign of mailbox access or forwarding-rule creation on an account with client financial data; or the owner can't be reached within one SLA cycle and the pattern is anomalous.

## Containment Options

| Option | Action | Business Impact |
|---|---|---|
| Force password reset | Expire credential, require change at next logon | Low — inconvenience only |
| Disable account | Blocks all further use of the credential | Medium — user locked out until reviewed |
| Revoke active sessions | Terminate Logon ID/RDP session, invalidate Kerberos tickets | Low-Medium — also kills a legitimate session if misidentified |
| Block source IP/range | Firewall or VPN ACL block on the resolved true source | Low, unless a shared corporate NAT egress |
| Enforce step-up MFA | Require MFA before the session is trusted | Low — mild friction |
| Isolate host (EDR) | Only if malware/tooling confirmed post-logon | High — removes host from production |

## Containment Approval

Account disable/reset on a non-privileged account: Tier 2 analyst may act unilaterally if Escalation criteria are met, with IAM on-call notified within 15 minutes. Privileged or VIP account actions require IAM on-call or SOC Manager sign-off first, except where waiting would let confirmed malicious activity continue — act first, document the emergency justification within one hour. Network/IP blocks may be actioned by Tier 1 without prior approval.

## Recovery Steps

Reset the credential through the secure IAM channel (identity verified via a second factor — never by phone or email). Confirm MFA enrollment hasn't been silently re-registered to an attacker device. Revert any group membership or mailbox rule changes made during the session. Re-enable only after IAM and the analyst agree containment is complete. Apply heightened monitoring for 72 hours.

## Evidence Collection

Raw 4625/4624/4771/4776 events for the incident window; the VPN session log entry tying the NAT'd address to the real source; EDR process timeline for the target host covering the session's Logon ID; export of any group membership/mailbox changes found; owner's confirmation (or non-response) with timestamp; ticket number and analyst identity for each containment action.

## Case Documentation

Full timeline (first failure → success → containment → recovery); account and host identifiers; resolved true source and how it was resolved; MITRE techniques observed, not just the trigger technique; all containment/recovery actions with timestamps and approvers; closure classification (True Positive / False Positive / Benign Positive / Insufficient Evidence); root cause category for trending.

## Communication Requirements

Notify the account owner's manager if containment is executed outside the user's own request. Notify IAM on-call for any privileged or VIP account regardless of outcome. Notify Legal/Privacy only where evidence shows actual access to client PII or financial records, not merely the possibility. For a confirmed True Positive with follow-on activity, notify the SOC Manager and open the incident bridge per the org's IR communication plan (Part 6). No blanket department notification for routine Benign Positive closures.

## SLA

**[MANAGEMENT]**

| Severity/Priority | Acknowledge | Initial Triage Complete | Containment Decision | Full Resolution |
|---|---|---|---|---|
| P1 (privileged/VIP or confirmed follow-on) | 10 minutes | 30 minutes | 45 minutes | 4 hours |
| P2 (standard, this playbook's default) | 15 minutes | 1 hour | 2 hours | 8 business hours |

## Closure Criteria

Account secured (reset/disabled/re-enabled per outcome) with malicious access confirmed removed; no further authentication attempts or follow-on activity for 72 hours post-closure; all Evidence Collection fields populated; closure classification assigned; owner notified of outcome where applicable.

## Post Incident Tasks

For any True Positive: lessons-learned review within 5 business days if containment failed or SLA was breached; tuning ticket opened per Detection Feedback below; security awareness follow-up with the owner's manager; IAM policy review if the incident exposed an MFA or password-policy gap.

## Detection Feedback

Loop findings back to Detection Engineering: was the 8-failure/10-minute threshold appropriate, or did it fire too late/early relative to actual compromise? Was the VPN NAT gap a material triage delay? Log every Benign Positive root cause in the tuning backlog even when no rule change is made immediately — the pattern across a quarter justifies the eventual ticket.

## Tuning Opportunities

Add a suppression window keyed to IAM's bulk password-rotation schedule to avoid a predictable monthly false-positive spike. Separate thresholds for RDP01 (externally reachable, tighter) versus internal workstation logons (looser, lower inherent risk). Layer in impossible-travel logic for accounts with an Entra ID identity. Pre-register pentest/red team IP ranges from the engagement calendar rather than relying on analysts to check manually.

## Metrics

**[MANAGEMENT]**

| Metric | Target | Last Quarter Actual |
|---|---|---|
| Mean Time to Triage | < 30 min | 41 min |
| Mean Time to Containment Decision (P1) | < 45 min | 38 min |
| False Positive Rate | < 50% | 58% |
| Benign Positive Rate | tracked, no target | 21% |
| True Positive Rate | tracked, no target | 12% |
| Insufficient Evidence Rate | < 15% | 9% |
| Escalation-to-Tier 3 Rate | tracked, no target | 7% |

## Automation Potential

High for enrichment (threat intel lookup, baseline pull, VPN session correlation, HR/IAM roster check) — already scripted into the SOAR playbook that pre-populates the case before an analyst opens it. Medium for containment: auto-notifying the owner via an out-of-band channel can run automatically, but account disable/reset stays analyst-confirmed-execute, since a false auto-disable on a legitimate VIP logon creates its own incident.

## Related Rules

IAM-015 (Password Spraying — Multiple Accounts, Single Source), IAM-009 (Account Lockout Storm), IAM-022 (Impossible Travel — Correlated Sign-In), IAM-031 (Abnormal Kerberos Service Ticket Volume — Kerberoasting Pattern).

## Related Playbooks

Account Lockout Storm Triage; Password Spraying — Multiple Accounts; Privileged Account Compromise; Post-Compromise Lateral Movement Investigation; Cloud Identity Brute Force (Entra ID Sign-In Risk).

## References

Microsoft Learn — Windows Security Event Reference and Advanced Audit Policy Configuration; MITRE ATT&CK — T1110 Brute Force and sub-techniques; NIST SP 800-63B, Digital Identity Guidelines; SANS Institute incident handling references for credential-based attacks; CISA guidance on password spraying and brute-force defenses.

## Revision History

| Version | Date | Author | Summary of Changes |
|---|---|---|---|
| 1.0 | 2025-02-10 | Priya Nazari | Initial version, single-source threshold only |
| 1.5 | 2025-09-04 | Priya Nazari | Added 4771 secondary trigger after a missed DC-only attack |
| 2.0 | 2026-03-01 | Nazari, Ferris | Rewrite to current master template; added VPN NAT limitation |
| 2.1 | 2026-06-18 | Priya Nazari | Added follow-on activity table; tightened P1 VIP criteria |
