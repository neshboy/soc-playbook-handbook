# WEB-009 — Password Spraying (Web-Facing Authentication)

## Business Risk

**[STAKEHOLDER]** - A single compromised low-privilege account through a spray campaign is rarely the real damage; the real damage is what an attacker does *after* — mailbox access, MFA-fatigue follow-on, lateral movement into SaaS admin consoles, or a foothold for a business email compromise fraud chain. This risk is cheap to reduce (MFA, conditional access, smart lockout) but expensive to ignore, because web-facing portals (O365/Entra ID, Okta, VPN gateways, Citrix, webmail) are internet-reachable 24/7 and get sprayed constantly — the business decision here is really "how much authentication friction are we willing to accept" versus "how much residual exposure."

## Severity / Priority Default

- **Default:** Medium (P3) for detection-only, no successful authentication.
- **Escalate to High (P2)** automatically if any targeted account shows a subsequent successful sign-in.
- **Critical (P1)** if a privileged, service, or break-glass account is among the successful hits.

## MITRE ATT&CK Techniques

| Technique | Relevance |
|---|---|
| T1110 Brute Force | Parent technique for the campaign |
| T1110.003 Password Spraying | Primary technique — one/few passwords across many usernames |
| T1087 Account Discovery | Username enumeration frequently precedes or accompanies the spray (differential error responses, autodiscover probing) |
| T1078.002 Valid Accounts: Domain Accounts | If the compromised identity is a federated/on-prem AD account exposed via the web portal |
| T1078.004 Valid Accounts: Cloud Accounts | If the compromised identity is a cloud-native account (Entra ID, Okta) |

## Trigger / Detection Logic Summary

**[ENGINEERING]** Alert fires when a single source (IP, ASN, or small IP pool sharing infrastructure fingerprints) generates authentication failures against an unusually high number of *distinct* usernames within a short window, with a low attempts-per-username ratio — the inverse signature of classic brute force (many attempts, one account). Tune on ratio, not raw volume: e.g., ≥15 distinct usernames from one IP/ASN in 30 minutes with ≤3 attempts per username, using invalid-password result codes specifically (not MFA-required, not locked, not disabled — those are different result codes and muddy the ratio if not separated).

## Required Log Sources & Event/Field References

| Source | What to pull |
|---|---|
| Entra ID Sign-in logs | `ResultType` codes: `50126` (invalid username/password), `50053` (account locked from repeated bad passwords), `50055` (expired password — exclude from spray math) |
| Okta System Log | `eventType: user.session.start` (failure), `user.account.lock`, `outcome.reason` |
| ADFS (if federated) | ADFS admin/security log, "Bad Password" audit entries |
| WAF / reverse proxy (F5, Cloudflare, Akamai) | HTTP status 401/403 on login POST endpoints, `cs-uri-stem`, client IP, TLS JA3 fingerprint if available |
| VPN gateway / Citrix Gateway logs | Failed auth events, source IP, client type |
| IIS/W3C logs (self-hosted portals) | `sc-status`, `cs-username`, `c-ip`, `cs(User-Agent)` |

Note: on-prem Windows Security Event ID 4625 is only relevant here if the web-facing portal proxies auth back to a domain controller (e.g., ADFS/OWA) — don't assume it exists for pure cloud IdP flows; pulling it anyway when it's not in scope wastes ingestion budget and adds timezone-normalization headaches for no benefit.

## Key Fields to Inspect

**[ANALYST]**
- Source IP, ASN, and geolocation — spray infra usually sits on a handful of cheap VPS/proxy ASNs, not residential ranges
- Distinct username count vs. total attempts per source (the spray ratio)
- User-Agent string — often a single stale or scripted UA (e.g., `BAV2ROPC`, old `python-requests`) reused across thousands of attempts
- Result code distribution — invalid password vs. locked vs. MFA-challenged vs. success
- Timing pattern — spray tools often throttle to one attempt per account per interval specifically to dodge lockout thresholds; don't dismiss "low volume" as benign without checking spread
- Whether the same username set overlaps with a known breach compilation or a prior campaign against this tenant

## Normal vs. Suspicious Pattern

| Normal | Suspicious |
|---|---|
| One user, several failed attempts, same device/browser, resolves with password reset or correct entry | Many distinct users, 1-3 attempts each, single IP/ASN or small rotating pool |
| Failures cluster around password-expiry cycles or after a mass password reset rollout | Failures cluster on accounts with no other legitimate activity from that source's geography |
| User-Agent matches known corporate device fleet | Generic/scripted User-Agent, or none, reused identically across all failed usernames |
| MFA challenges present and expected | MFA absent entirely (legacy auth / basic auth endpoint being targeted specifically to bypass MFA) |

## Investigation Steps

1. Pull all authentication events from the source IP/ASN across the full detection window (not just the alert window) — spray campaigns often run in bursts over days.
2. Compute the username-to-attempt ratio and compare against the campaign's known accounts list; check whether targeted usernames map to a pattern (e.g., firstname.lastname convention scraped from LinkedIn, or a leaked internal directory).
3. Check for any `ResultType`/`outcome` showing success or MFA-satisfied among the targeted set — this is the single most important pivot in the whole investigation.
4. Pivot on ASN/IP reputation (known VPS hosting, Tor exit, open proxy, or previously flagged in threat intel feeds).
5. Cross-reference legacy/basic-auth endpoints (IMAP, POP, ActiveSync, SMTP AUTH) — spray tools frequently target these specifically because they can't be MFA-gated.
6. If any account shows success, immediately pull that account's full sign-in and mailbox-audit history for 30 days back — look for inbox rule creation, OAuth app consent grants, or forwarding changes.
7. Confirm whether the source IP also appears in unrelated legitimate traffic (shared NAT egress, corporate VPN concentrator) before treating IP-block as safe.
8. Document all targeted usernames, valid vs. invalid, to feed a scoped password-reset/credential-review action.

## True Positive Indicators

- Distinct username-to-attempt ratio consistent with spraying (many accounts, few tries each) from one IP/ASN or coordinated pool.
- Password values (where visible in logs, e.g., via honeytoken accounts) matching common seasonal/corporate patterns (`Company2026!`, `Welcome1`).
- At least one successful authentication or MFA-satisfied event within the targeted set.
- Targeting concentrated on legacy/basic-auth protocols specifically to route around Conditional Access/MFA.
- Overlap with a known leaked credential dump or a previous campaign fingerprint against the same tenant.

## False Positive / Benign Positive Indicators

- Mass password-expiry event (e.g., quarterly rotation policy) causing many legitimate users to fail once with the *old* cached password across mobile/desktop clients — this can mimic a spray ratio almost exactly; check for `50055` codes and a single corporate ASN.
- Misconfigured application or script using one shared service-account credential against many endpoints, tripping per-account thresholds without being a real attacker.
- Third-party SaaS integration retrying stale OAuth/basic-auth credentials after a credential rotation.
- Security researcher or internal red team exercise not yet deconflicted with SOC (always check the current authorized-testing calendar before escalating).

## Escalation Criteria

Escalate immediately (P2/P1 per severity table) if: any successful sign-in follows a failed spray pattern; a privileged, admin, service, or VIP account is among the targeted or successful set; the attempt volume exceeds a defined percentage of the tenant's total user base; or legacy-auth targeting is confirmed (this alone should trigger a Conditional Access review even without a successful login).

## Containment Options & Approval Authority

**[MANAGEMENT]**
| Action | Who can approve |
|---|---|
| Block source IP/ASN at WAF or edge firewall | Tier 2 analyst, no further approval needed |
| Enable/tighten smart lockout or sign-in risk policy | SOC lead + IAM/Identity team sign-off |
| Force password reset on targeted accounts | IAM owner approval; user notification required |
| Disable legacy/basic-auth protocols tenant-wide | Change advisory board — business-impacting, needs comms plan |
| Revoke sessions/tokens on compromised account | Tier 2 analyst on confirmed TP, IR lead notified |

## Example Query (KQL — Microsoft Sentinel, Entra ID Sign-in Logs)

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126","50053")
| summarize DistinctUsers = dcount(UserPrincipalName), Attempts = count()
    by IPAddress, AppDisplayName
| where DistinctUsers >= 15 and Attempts / DistinctUsers <= 3
| order by DistinctUsers desc
```

## Closure Criteria

Close as **True Positive** only after confirming whether any targeted account authenticated successfully and, if so, that account has been reset/reviewed and session-revoked. Close as **Benign Positive** when the ratio is explained by a legitimate mass-credential event (password rotation, app misconfiguration) with no successful unauthorized logins. Close as **Insufficient Evidence** when source telemetry is incomplete (e.g., WAF logs purged before ingestion, ADFS not forwarding) and no corroborating success/failure pattern can be confirmed either way — flag the logging gap to engineering rather than guessing at a verdict.

**Example case note:** *"IP 203.0.113.44 (ASN AS64512, flagged VPS hosting) attempted auth against 43 distinct UPNs in contoso-corp tenant over 22 min, avg 1.4 attempts/user, all ResultType 50126, targeting OWA basic-auth endpoint only. No successful sign-ins or MFA challenges recorded for any targeted account. IP blocked at Cloudflare WAF; legacy auth disablement change request opened with IAM (CHG-4471). Closed as True Positive — attempt only, no compromise confirmed."*
