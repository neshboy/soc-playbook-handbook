# Sensitive Repository Cloning

## Playbook ID & Name

**INS-006 — Sensitive Repository Cloning / Bulk Source Code Exfiltration via Git**

This one gets missed constantly because a `git clone` is the single most normal action a developer performs every day. There's no malware, no odd process name, nothing that pattern-matches to "attack" — it's an engineer using git exactly as designed. The signal you're actually chasing is scope and destination: how many repos, how much history, from what device, and where the bytes went after the clone finished. Most orgs don't even log this well until they've had a scare.

## Business Risk

**[STAKEHOLDER]** - Source code is intellectual property in the most literal sense: product logic, pricing algorithms, unreleased firmware, sometimes hardcoded credentials or key material that never got cleaned out of commit history. A departing engineer who mirrors a dozen repos to a personal laptop the week before their last day can hand a competitor years of R&D for free, and unlike a database export there's rarely a DLP rule tuned to catch it because "developers cloning code" is the baseline, not the exception.

## Severity/Priority Default

**High** when the clone covers repositories outside the actor's normal working scope, uses full-history mirror mode, or is followed by movement to an external destination. **Medium** for scope/volume anomalies alone with no corroborating destination evidence, pending investigation. Escalate to **Critical** when the actor is in a resignation/termination window, the repositories contain export-controlled or regulated code, or evidence shows the content already left the managed environment.

## MITRE ATT&CK Techniques

- **T1078.002 / T1078.004** — Valid Accounts (Domain / Cloud): this is almost always a legitimate, currently-provisioned credential doing something outside its normal usage pattern, not a stolen one.
- **T1119** — Automated Collection: scripted or bulk `--mirror`/API-driven cloning across many repositories in a short window rather than one-at-a-time manual work.
- **T1530** — Data from Cloud Storage: most git hosting today (GitHub Enterprise Cloud, GitLab.com, Bitbucket Cloud) is itself SaaS-hosted storage the actor is pulling from.
- **T1567.001** — Exfiltration Over Web Service: Exfiltration to Code Repository — the specific sub-technique for this playbook's exfil leg: clone/push activity landing on a personal GitHub/GitLab account or other external SaaS git tenant.
- **T1552.001** — Unsecured Credentials in Files: a very common secondary finding once you actually look inside the cloned repos — hardcoded API keys, service account passwords, or `.env` files that were never purged from history.
- **T1098.001** — Additional Cloud Credentials: watch for a personal access token, deploy key, or OAuth app grant created on the actor's account shortly before the bulk clone — minted specifically to enable it, then never used again.

## Trigger / Detection Logic Summary

Alert fires on git platform audit telemetry showing an actor cloning or fetching a number of distinct repositories, or a data volume, well above their personal baseline within a short rolling window (e.g., more repos touched in one session than in the prior 90 days combined), particularly when the clone uses full-history mirror/bare mode rather than a routine working clone. Secondary triggers: creation of a new personal access token or SSH deploy key immediately preceding the clone burst, clone traffic originating from an unmanaged device or unexpected geography/ASN, and repository scope that spans teams or projects the actor has no assigned relationship to per the access-governance/RBAC record.

## Required Log Sources & Event IDs

| Source | Field/Event | Why it matters |
|---|---|---|
| Git hosting audit log (GitHub Enterprise, GitLab, Bitbucket, Azure Repos) | `git.clone` / `git.fetch` / `repo.download_zip` / repository export events — repo name, actor, protocol, source IP, credential used | Primary evidence of the clone itself; this is where scope and volume live |
| Git platform token/key management events | Personal access token creation, SSH deploy key registration, OAuth app authorization — scope, creation time, first-use time | Flags a credential minted right before the bulk activity, used once, then abandoned |
| Identity provider / SSO logs (Entra ID, Okta, on-prem AD) | Authentication event backing the git platform session — MFA status, source IP, device trust signal | Confirms which session performed the clone and whether it matches the actor's normal auth pattern |
| VPN / remote access logs | Session start/end, assigned IP, split-tunnel status | Shows whether the clone happened on the expected network path or bypassed it |
| Endpoint EDR / process telemetry | git.exe / IDE clone process creation, full command line, parent process | Confirms local clone flags (`--mirror`, `--bare`, `--depth`) and what launched the operation |
| Proxy / CASB logs | Destination domain/category, direction, byte count | Flags traffic to unsanctioned personal git tenants or SaaS storage post-clone |
| DLP (endpoint or network) | Source-code content match, upload destination | Corroborates whether cloned content moved off the managed device afterward |

## Key Fields to Inspect

**[ANALYST]**

- **Actor identity type** — human account vs. CI/CD service account; service accounts doing scheduled mirror pulls for build pipelines are routine and need to be excluded from the baseline, not flagged as insider behavior.
- **Repository sensitivity and ownership** — pull the classification/data-owner tag if your repo registry tracks one; "internal tooling repo" and "flight-controller firmware repo" are not the same risk.
- **Clone type/depth** — full `--mirror`/`--bare` clone (entire history including old, possibly-deleted, secret-laden commits) vs. shallow/single-branch clone vs. browser "Download ZIP" — mirror and ZIP carry materially higher exfil weight than an IDE-integrated working clone.
- **Volume and session shape** — number of distinct repos touched, total data transferred, elapsed time between first and last clone in the session.
- **Source IP/ASN/geo and device trust** — corporate-managed endpoint on the expected VPN path vs. unmanaged device or unfamiliar geography.
- **Timing** — relative to normal working hours, and relative to any known resignation, PIP, or termination date from HR.
- **Downstream fate of the content** — does the clone get followed by a push to an external remote, a ZIP upload to personal cloud storage, or an attachment in personal webmail.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| One or a handful of repos tied to the actor's current sprint/project | Dozens of repos across unrelated teams cloned in one session |
| Shallow or single-branch clone through an IDE integration | Full-history `--mirror`/`--bare` clone or bulk "Download ZIP" |
| Corporate-managed device, on VPN/corporate network, business hours | Unmanaged/personal device, off-VPN, weekend/late-night timing |
| Access matches current RBAC assignment and team membership | Repos outside actor's assigned project scope, no ticket or access-review record explaining it |
| Existing, previously-used PAT/SSH key | Brand-new PAT or deploy key created same day, used once, never reused |
| No onward movement — content stays in the dev environment/build pipeline | Clone followed within hours by push to a personal external git remote or upload to personal cloud storage |

## Investigation Steps

1. Pull the git platform audit log for the actor across 30-90 days to baseline normal clone/fetch cadence and repository scope, then compare against the triggering session's volume and breadth.
2. Identify the exact repositories touched, their sensitivity classification and data owner, and cross-check against the actor's current team/project assignment and access-review records — verify current group membership rather than assuming the access itself was wrongly granted.
3. Determine clone method and depth (full mirror vs. shallow, HTTPS+PAT vs. SSH+deploy key vs. browser ZIP export) — this changes how much data actually moved and how much old, possibly-secret-laden history came with it.
4. Check whether a new personal access token, SSH deploy key, or OAuth app grant was created on the account shortly before the clone burst, and whether it was used only once.
5. Correlate source IP/device against identity provider and VPN logs to confirm whether the session ran from a corporate-managed endpoint on the expected network path.
6. Check the HR/case-management system for a pending resignation, termination, or active performance case — this changes urgency and who needs to be looped in before any action is taken.
7. Follow the data forward through proxy/CASB/DLP and endpoint telemetry for evidence the cloned content was pushed to an external remote, zipped to personal cloud storage, or attached to personal webmail in the hours after the clone.
8. Engage the repository/data owner and, through HR/Legal per policy, the actor's manager to confirm business justification before finalizing a verdict — an approved platform migration or onboarding rotation can look identical to exfiltration on the wire.

## True Positive Indicators

- Full-history mirror/bare clone or bulk ZIP export of multiple sensitive repositories outside the actor's normal project scope in a single short session.
- New PAT/deploy key/OAuth grant created same-day with broad repo scope, used once for the bulk clone, then never touched again.
- Session originates from an unmanaged/personal device or unexpected external IP with no matching VPN session.
- Clone activity immediately followed by a push to an external personal git remote, a ZIP upload to personal cloud storage, or repo content attached to personal webmail.
- Timing coincides with a resignation notice, PIP, or pending termination (context confirmed via HR, not inferred from timing alone).
- Repositories contain genuinely sensitive material — proprietary product logic, unreleased firmware, cryptographic material, customer-data-handling code — not boilerplate or shared internal tooling.

## False Positive / Benign Positive Indicators

- Scheduled CI/CD or build-automation service account performing routine mirror pulls — check the account against the known automation inventory before treating it as a human actor.
- Approved platform migration (e.g., self-hosted git server to a cloud-hosted platform) run by platform engineering under a documented change ticket.
- New hire or engineer completing an onboarding/role-change rotation that legitimately grants access to multiple repos at once.
- Security or DevOps engineer running an approved org-wide secret-scanning or SBOM audit with elevated, authorized access.
- **Insufficient Evidence** is the right call when volume/scope looks unusual but there's no external destination, unmanaged device, or off-hours pattern to corroborate exfiltration intent — put it on a watchlist rather than force a verdict.

## Escalation Criteria

Escalate immediately to IR, Legal, and HR jointly when: the cloned repositories contain export-controlled, regulated, or cryptographic key material; the actor is in a resignation/termination window; proxy/DLP/CASB evidence shows the content already reached an external destination; the same actor's account shows a newly-created, broadly-scoped credential used once and abandoned; or multiple unrelated repositories were pulled in full-mirror mode in one sitting. Because this playbook sits at the intersection of security and employment action, treat HR/Legal engagement as a gate on containment, not an optional courtesy.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Approval Needed | Notes |
|---|---|---|
| Revoke/rotate the specific PAT, deploy key, or OAuth grant used for the clone | SOC Team Lead — can act immediately if the token is clearly the vector | Fast, scoped, stops the specific credential without touching account-wide access |
| Disable git platform account access (SSO app deprovision) | HR + Legal sign-off if this is offboarding-adjacent; IT/Security Team Lead for a clear compromise case | Coordinate with HR first — acting unilaterally on an employee's access can complicate an active HR process |
| Force MFA re-enrollment / revoke active sessions | Security Team Lead | More relevant to a suspected account-compromise angle than a confirmed authorized-user misuse case |
| Legal hold and forensic preservation of clone/audit evidence | Legal + IR Lead | Required before any employment action proceeds — preserves the chain of evidence |
| Preserve the endpoint — no wipe/reimage | HR + Legal + IT | Critical: standard offboarding reimage-and-reissue workflows will destroy evidence if run before this case is cleared |

SLA target: initial triage decision (escalate vs. monitor vs. close) within 4 hours for Medium severity, 1 hour for High/Critical given the narrow window before content typically leaves the environment.

## Example Query (Splunk SPL)

```spl
index=git_audit (action="git.clone" OR action="git.fetch" OR action="repo.download_zip")
| bin _time span=1h
| stats dc(repo) as distinct_repos, sum(bytes) as total_bytes,
        values(clone_type) as clone_types by user, _time
| where distinct_repos>10 OR clone_types="mirror"
| sort -distinct_repos
```

## Closure Criteria

Close as **True Positive** once the actor and credential are confirmed, scope/destination of the cloned content is documented, and containment (token revocation, access review, evidence preservation) is complete and reflected in the case. Close as **Benign Positive** when the repo owner or platform engineering confirms the clone as documented migration, onboarding, or automation activity, with the account/token added to the known-automation baseline. Close as **Insufficient Evidence** when scope or volume was anomalous but no destination, device, or timing signal corroborates exfiltration — hold on a 30-day watchlist rather than closing silent, since this category has a real long-tail (notice periods run 2-4 weeks in many jurisdictions).

**Example case note:** *"User dsanchez (Engineering, notice period active per HR case #4471) cloned 14 repositories across three unrelated product teams between 22:10-22:47 on a Saturday, all via `--mirror`, from source IP 203.0.113.44 (no matching VPN session) using PAT `pat_9f3c...` created 11 minutes prior with full-org repo scope. Proxy logs show a 210MB upload to github.com/dsanchez1987 (personal account) at 23:02 the same night. Repos include meridian/flight-controller-firmware and meridian/customer-data-connector. Legal hold placed, endpoint preserved (no reimage), PAT revoked, account access held pending HR/Legal joint decision. Classified True Positive — T1078.002 / T1119 / T1567.001 / T1098.001."*
