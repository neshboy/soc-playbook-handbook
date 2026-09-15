# Playbook: Suspicious LDAP Enumeration

## Playbook ID & Name
**IAM-025 — Suspicious LDAP Enumeration (AD Object, Group & Trust Discovery)**

## Business Risk
**[STAKEHOLDER]** - Active Directory holds the map of who can access what: every user, every group, every trust relationship to a partner domain, every account flagged with an interesting privilege or a weak configuration. LDAP is the language attackers use to read that map. A single successful enumeration sweep against AD can hand an intruder — or a compromised low-privilege employee account — a complete blueprint of which accounts are worth stealing next, without touching a single file server or triggering an antivirus alert. This almost never causes damage on its own, but it is reliably the reconnaissance phase that precedes credential theft, privilege escalation and ransomware staging. Catching it here is catching the attacker before they know which door to pick.

## Severity/Priority Default
**Medium** as a baseline for a confirmed enumeration tool signature from an unexpected account or host; escalate to **High** when the source is a workstation with no administrative function, when trust/domain-wide queries are involved, or when enumeration is immediately followed by targeted Kerberos ticket requests or credential-dumping indicators; **Low/Informational** for known, scheduled, or vendor-tool sources pending allow-listing.

## MITRE ATT&CK Technique(s)
- T1087 — Account Discovery (primary — enumerating user/service accounts via LDAP filters against `objectClass=user`)
- T1069 — Permission Groups Discovery (primary — enumerating group membership, nested groups, `AdminSDHolder`-protected groups)
- T1482 — Domain Trust Discovery (primary — enumerating `trustedDomain` objects, forest/domain trust direction and transitivity)
- T1550.003 / T1558.003 / T1558.004 / T1003.006 — not part of this detection's scope directly, but the almost-universal *next* steps once enumeration succeeds; treat their appearance shortly after an enumeration event as strong corroboration, not coincidence

## Trigger / Detection Logic Summary
Native Windows Security auditing does not log the actual LDAP search filter a client sends to a domain controller — that gap is a real one and worth saying plainly rather than papering over. This playbook does not rely on a single "LDAP query" event ID because none of the IDs supplied in this book's reference set capture that directly. Instead it detects the *behavioral fingerprint* that LDAP-driven AD reconnaissance tools leave across telemetry that Windows already generates: a burst of local/security-group membership enumeration calls spread across many hosts in a short window (4798/4799), an unusual breadth of Kerberos service ticket activity from one account touching SPNs it has never touched before (4769), process creation evidence of known enumeration tooling (4688), and PowerShell script block capture of the same tooling when it's PowerShell-based (4103/4104). If your environment has enabled Directory Service diagnostic logging or deployed Microsoft Defender for Identity / a similar identity-threat-detection sensor, cross-reference those alerts directly — they see the LDAP wire traffic that Windows Security auditing does not, and they are the highest-fidelity source for this specific playbook when available. Where they are not available, this playbook is explicitly a "secondary signature" detection, and analysts should expect more Insufficient Evidence closures than with a directly-instrumented technique.

## Required Log Sources & Event IDs
| Source | Event ID(s) | Purpose |
|---|---|---|
| Domain Controller Security log | 4798, 4799 | Local/security-group membership enumeration breadth — the closest native proxy for BloodHound/SharpHound-style collection |
| Domain Controller Security log | 4769 | Breadth of distinct SPNs/service names requested by one account — indicates SPN sweep, often paired with LDAP-based SPN discovery |
| Domain Controller Security log | 4768, 4771 | Confirms the enumerating account's own authentication context; pre-auth failures alongside enumeration suggest credential validation as part of the same tooling run |
| Endpoint Security log | 4688 | Process creation for `AdFind.exe`, `SharpHound.exe`, `dsquery.exe`, `csvde.exe`, `ldifde.exe`, `nltest.exe`, `PowerView.ps1`-invoking hosts |
| PowerShell Operational log | 4103, 4104 | Script block capture for PowerView (`Get-DomainUser`, `Get-DomainTrust`, `Get-DomainGroup`), ADRecon, or obfuscated LDAP-query wrappers |
| Domain Controller Security log | 4624, 4648 | Logon Type 3 volume to the DC, and explicit-credential logons, from the enumerating source |
| Domain Controller Security log | 1102 | Anti-forensics check — rare, but a cleared log immediately after a heavy enumeration burst is a serious escalation trigger |
| Identity threat detection sensor (if deployed) | vendor alert, not a Windows Event ID | Direct LDAP query/bind telemetry — treat as corroborating, not required |

## Key Fields to Inspect
**[ANALYST]**
- **4798/4799 — Subject Account Name / Domain**: the enumerating principal; count distinct target **Computer** values it touched within the window — breadth across dozens of hosts in minutes is the tell, not any single call
- **4769 — Account Name / Service Name**: watch for one account suddenly requesting tickets for SPNs spanning multiple unrelated services (SQL, HTTP, CIFS, LDAP) it has no operational reason to touch
- **4769 — Client Address**: source host of the enumerating traffic; cross-check against asset inventory — a print-shop workstation querying every SPN in the forest has no legitimate story
- **4688 — New Process Name / Command Line**: `AdFind.exe -f "(objectcategory=person)"`, `SharpHound.exe -c All`, `dsquery user -limit 0`, `nltest /domain_trusts /all_trusts`, `csvde -f dump.csv`
- **4104 — Script Block Text**: `Get-DomainUser`, `Get-DomainGroupMember`, `Get-DomainTrust`, `Get-DomainComputer`, `Invoke-BloodHound`, or de-obfuscated equivalents
- **4624 — Logon Type and Workstation Name**: repeated Logon Type 3 (network) hits against the DC from a single workstation, well above that account's historical baseline
- Timing regularity — human interactive LDAP browsing (e.g., an admin poking around in ADUC or ADSI Edit) is irregular and slow; tool-driven enumeration is fast, exhaustive, and evenly paced

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Helpdesk/IT admin queries a handful of specific users or one group via ADUC/PowerShell during a ticket investigation | Same account queries thousands of objects, every group, or every trust relationship in a single session |
| 4798/4799 activity concentrated on a handful of hosts an admin actually manages | 4798/4799 breadth spanning 20+ distinct hosts from one account inside a 10-30 minute window |
| Monitoring/inventory tool (SCCM, vulnerability scanner, CMDB sync) runs from a known service account, on a documented schedule, from a fixed source IP | Enumeration from a standard user workstation, a service account acting outside its documented job, or a host with no prior AD-querying history |
| 4769 SPN requests stay within the small set an app server actually calls | 4769 requests sweep across unrelated SPNs (mail, SQL, web, file) with no service dependency explaining the breadth |
| `nltest /domain_trusts` run occasionally by AD engineering during a migration project | Same command, or `Get-DomainTrust`, run from a workstation with no domain-engineering function, especially right after a phishing-linked logon |

## Investigation Steps
1. Identify the enumerating principal and source host from the 4798/4799 or 4769 cluster — pull the account's normal role (human, service, application) and its historical query volume for comparison.
2. Quantify breadth: distinct target hosts (4798/4799), distinct SPNs (4769), and distinct object types touched, within the burst window. A handful of related lookups is very different from thousands of objects touched in minutes.
3. Pull 4688/4104 from the source host for the same window — look specifically for AdFind, SharpHound, PowerView, ADRecon, dsquery, csvde, ldifde, or nltest invocations, and capture the full command line if available.
4. Check the account's authentication context — 4624/4648/4768 immediately preceding the enumeration burst. Was this account itself the product of a recent suspicious logon (unfamiliar source IP, new geography, off-hours), which would suggest a compromised-account chain rather than an authorized admin task?
5. Cross-reference against change/engagement records: scheduled AD health-check tools, CMDB sync jobs, and any active penetration test or red-team engagement covering the time window and source IP.
6. If a Defender for Identity or equivalent identity-sensor alert exists for the same window, pull it directly — it will usually name the LDAP filter or collection method used and removes most of the ambiguity native Windows logs leave behind.
7. Hunt forward for follow-on activity from any account or SPN that showed up in the enumeration results: new 4769 Kerberoasting-shaped bursts, 4771 AS-REP-style failures, or 4624/4672 logons from accounts that were clearly "interesting" targets in the enumerated data (privileged group members, trust accounts).
8. Determine scope and intent: reconnaissance breadth (whole domain/forest) versus narrow, job-relevant lookups, and whether this maps to an approved activity or an unscheduled, unexplained sweep.

## True Positive Indicators
- Confirmed execution of AdFind, SharpHound/BloodHound, PowerView, or ADRecon on the source host (4688 command line or 4104 script block)
- Enumeration breadth (hosts touched, SPNs queried, or objects returned) far exceeds anything the account's role justifies
- Source account was itself recently subject to a suspicious logon (phishing-linked, unfamiliar geography, credential-stuffing pattern) before the enumeration started
- Enumeration is followed within hours by a targeted Kerberoasting-shaped 4769 burst, an AS-REP roasting-shaped 4771 pattern, or a logon from a previously "quiet" privileged account
- Domain/forest trust enumeration (`nltest /domain_trusts`, `Get-DomainTrust`) from a host with no legitimate cross-domain administration function

## False Positive / Benign Positive Indicators
- Documented vulnerability scanner, CMDB/asset-management sync, or AD health-check tool running on schedule from a known service account and fixed source IP — should be allow-listed, not re-investigated every cycle
- Approved penetration test or red-team engagement with signed rules of engagement covering the exact window and source range
- IT/helpdesk staff performing legitimate, if broad, troubleshooting (e.g., auditing group membership ahead of an access review) — confirm via ticket reference and check the breadth is proportionate to the stated task
- New AD/identity engineer running discovery queries while onboarding to the environment — verify against HR/starter records and manager confirmation
- A single 4798/4799 event with no volume or breadth around it — one lookup is not a pattern; do not open an incident on a lone event without corroborating breadth

## Escalation Criteria
Escalate to Tier 2/IR immediately when confirmed enumeration tooling (SharpHound, AdFind, PowerView, Rubeus-adjacent scripts) is found on an unmanaged or unexpected host; when the enumerating account shows evidence of prior compromise (suspicious logon chain); when domain/forest trust enumeration is observed with no corresponding change record; or when enumeration is followed by any Kerberoasting/AS-REP-roasting-shaped ticket activity or an unexplained logon from a privileged account named in the likely enumeration scope. Treat log-clearing (1102) occurring during or immediately after the burst as a separate, higher-severity incident.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Immediate (Analyst/Tier 2, no approval needed)**: disable network logon capability for the enumerating account pending review if compromise is suspected; capture 4688/4104 evidence and preserve the source host for forensic review before any remediation touches it.
- **Endpoint isolation of the source host** — Tier 2/IR authority, standard SOC containment action once tooling is confirmed; no additional sign-off required under most IR playbooks.
- **Force password reset on the enumerating account, and on any high-value accounts named in the enumeration scope** (e.g., anything with `AdminSDHolder`/privileged group membership that surfaced in the query results) — requires Identity/AD team coordination; treat privileged-account resets as time-sensitive, not routine.
- **Review and tighten LDAP query permissions / enable LDAP channel binding and signing, or deploy directory-service query auditing/identity threat-detection sensor** — architectural remediation, owned by AD Engineering, tracked via Change Advisory Board as a hardening project rather than an incident action.
- SLA: initial triage and breadth assessment within 30 minutes of alert; escalation decision within 2 hours; privileged-account password rotation within 4 hours of confirmed compromise-linked enumeration.

## Example Query (Microsoft Sentinel — KQL)
```kql
SecurityEvent
| where EventID in (4798, 4799)
| where TimeGenerated > ago(1h)
| summarize HostsTouched = dcount(Computer), Calls = count()
    by SubjectUserName, SubjectDomainName, bin(TimeGenerated, 30m)
| where HostsTouched >= 20 and Calls >= 40
| order by HostsTouched desc
```

## Closure Criteria
Close as **True Positive - Contained** once the enumerating host/account is isolated or reset, confirmed enumeration tooling is remediated, and no follow-on credential-abuse activity (Kerberoasting-shaped ticket bursts, unexplained privileged logons) is observed in a 24-hour watch period. Close as **Benign Positive** when the source maps to a documented scanner, CMDB job, or approved engagement with matching account, IP and window. Close as **Insufficient Evidence** when only breadth-based secondary signals exist, command-line/script-block auditing was not enabled on the source host, and no identity-sensor alert corroborates the activity — note the LDAP audit-logging gap as a standing detection-coverage finding regardless of verdict.

**Example case note:** *"4799 breadth alert: acct jsmith.svc touched local group membership on 34 distinct hosts in 22 minutes from WKS-FIN-017 (10.40.12.88), no prior history of AD queries from this account. 4688 confirms SharpHound.exe execution at 09:14:02, command line `SharpHound.exe -c All --domain meridianfreight.local`. No approved engagement or change record found. Trust enumeration (nltest /domain_trusts) also observed same session. Account disabled 09:41, host isolated 09:44, no follow-on Kerberoasting activity in 24h watch. Domain Admins group membership review opened as a precaution. Closed True Positive - Contained."*
