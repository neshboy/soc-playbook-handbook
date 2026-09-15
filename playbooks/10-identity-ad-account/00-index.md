# Identity & Active Directory — Account & Authentication

This category covers the alerts that fire when something about *who* is logging in, *how* they're logging in, or *what their account is allowed to do* changes or looks wrong. It's the oldest and highest-volume alert family in most SOCs, and for good reason — nearly every attack chain, whether it starts with a phished credential, a stuffed password list, or a compromised service account, eventually has to authenticate as someone. Get account and auth monitoring right and you catch a huge share of intrusions early, before they pivot into anything that looks obviously "malicious." Get it wrong and you either drown the queue in noise or miss the one 4625 that mattered buried under ten thousand that didn't.

The common thread across every playbook in this folder is that they're built on the same small set of Windows Security events — logon success and failure, Kerberos ticket issuance, account lifecycle changes, and group membership changes — read in context. A single 4625 means nothing. A pattern of 4625s against one account from one source in ninety seconds means something different than the same pattern spread across two hundred accounts from one source in ninety seconds. This category is fundamentally about pattern recognition over identity events, not single-event triage, which is why almost every playbook here leans on aggregation windows, thresholds, and baselining rather than a single alert rule.

**Log sources and tooling that matter most:**

- **Domain Controllers** — the authoritative source for 4624, 4625, 4634/4647, 4648, 4672, 4720–4738, 4740, 4767, 4768/4769/4771, 4776, and 1102. If your DC audit policy isn't logging these subcategories (Logon/Logoff, Account Management, Account Logon), the rest of this category is theoretical.
- **SIEM/UEBA correlation layer** — Splunk, Sentinel, Elastic, QRadar or equivalent, for the threshold and outlier logic that turns raw logon events into a Brute Force or Password Spraying alert.
- **Identity provider / Entra ID sign-in logs** — where the environment is hybrid, on-prem 4624/4625 alone won't show a spray hitting cloud-facing endpoints (webmail, VPN with SSO, Entra-joined devices).
- **EDR** — for tying a suspicious logon (Logon Type, source workstation) to subsequent process activity on the target host.
- **PAM/privileged access tooling** — if privileged accounts are supposed to be checked out of a vault, a 4672 outside that workflow is itself a finding.

**[ANALYST]** - Expect the friction in this category to be less "is this technically malicious" and more "can I even trust what the log is telling me." Source IPs get masked by NAT, VPN concentrators, or load balancers, so the "attacking host" in a 4625 or 4740 is often an internal jump box, not the real origin. Service accounts running scheduled batch jobs generate legitimate 4624/4625 patterns that look identical to brute force at 2 AM. Clock drift and timezone mismatches between the DC, the SIEM, and the analyst's own head cause "sequence of events" reconstructions to be wrong by exactly one hour more often than anyone likes to admit. And a chunk of these investigations correctly close as Benign Positive (a locked-out user who forgot they changed their password on their phone) or Insufficient Evidence (single source IP, no repeat, no lateral movement) — not every lockout is an attack.

## Playbooks in this category

| # | Playbook | File |
|---|---|---|
| 1 | Repeated Login Failures | `repeated-login-failures.md` |
| 2 | Brute Force | `brute-force.md` |
| 3 | Password Spraying | `password-spraying.md` |
| 4 | Successful Login After Failures | `successful-login-after-failures.md` |
| 5 | Account Lockouts | `account-lockouts.md` |
| 6 | Privileged Account Login | `privileged-account-login.md` |
| 7 | Admin Group Membership Change | `admin-group-membership-change.md` |
| 8 | New Account Creation | `new-account-creation.md` |
| 9 | User Account Deletion | `user-account-deletion.md` |
| 10 | Unexpected Password Reset | `unexpected-password-reset.md` |
| 11 | Service Account Misuse | `service-account-misuse.md` |
| 12 | Domain Policy Change | `domain-policy-change.md` |
| 13 | GPO Changes | `gpo-changes.md` |
| 14 | Domain Admin Group Modification | `domain-admin-group-modification.md` |
