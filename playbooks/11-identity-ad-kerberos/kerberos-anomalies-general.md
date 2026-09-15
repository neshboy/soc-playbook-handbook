# Kerberos Anomalies (General)

## Playbook ID & Name

**IAM-015 — Kerberos Anomalies (General)**

This is the triage-level playbook for the Kerberos ticket lifecycle. It does not replace the dedicated playbooks for Golden Ticket, Silver Ticket, Kerberoasting or AS-REP Roasting elsewhere in this handbook — it's the entry point an analyst lands on when a SIEM correlation rule flags "something is off with tickets" before it's clear which specific pattern applies. Use it to triage and route; use the specific-attack playbooks once the signature is confirmed.

## Business Risk

**[STAKEHOLDER]** - Kerberos is the trust fabric underneath Active Directory: every resource access, every "who is this user really," ultimately traces back to a ticket issued by a domain controller. When that trust chain is abused, an attacker can impersonate any account — including Domain Admins — without ever needing to guess a password, and the resulting access looks identical to a normal login on the wire. Left undetected, this is how a single compromised workstation becomes full domain compromise.

## Severity/Priority Default

**Medium**, auto-escalates to **High/Critical** when the anomaly touches the KRBTGT account, a Tier 0 admin account, or shows ticket lifetimes/encryption inconsistent with domain policy.

## MITRE ATT&CK Techniques

T1558 Steal or Forge Kerberos Tickets (.001 Golden Ticket, .002 Silver Ticket, .003 Kerberoasting, .004 AS-REP Roasting), T1550.002 Pass the Hash, T1550.003 Pass the Ticket, T1078.002 Valid Accounts: Domain Accounts, T1110.003 Password Spraying (visible via 4768/4771 failure bursts), T1003.006 OS Credential Dumping: DCSync (related escalation path, mention only — has its own playbook).

## Trigger / Detection Logic Summary

This rule set is a basket of behavioral tripwires around 4768/4769/4771, not a single signature:

- Ticket encryption type field showing RC4 (0x17) where the domain functional level and account should be issuing AES tickets — encryption downgrade.
- A 4769 service ticket request with no corresponding 4768 TGT request from the same Logon ID/session in a reasonable prior window — consistent with an injected/forged ticket bypassing normal AS-REQ.
- 4768 success (Result Code 0x0) with Pre-Authentication Type showing no pre-auth performed, for an account not intentionally configured that way — AS-REP Roasting signature.
- Ticket lifetime or renewal values exceeding the domain's configured maximum ticket lifetime (default golden tickets are notorious for absurd 10-year lifetimes).
- Client Address on a 4768/4769 changing rapidly between geographically or logically inconsistent hosts for the same account inside a short window.
- KRBTGT account generating 4768 activity outside its expected password-rotation cadence, or appearing as the "account name" context in unexpected places.
- Burst of 4771 pre-auth failures (0x18) across many accounts from one Client Address — spraying, not a single anomaly.

## Required Log Sources & Event IDs

| Source | Event IDs | Purpose |
|---|---|---|
| Domain Controller Security log | 4768, 4769, 4771 | Core Kerberos ticket lifecycle |
| Domain Controller Security log | 4776 | NTLM fallback correlation (attacker pivoting off Kerberos) |
| Domain Controller Security log | 4624, 4625, 4634, 4648, 4672 | Logon context tied to the Logon ID from the ticket |
| Domain Controller Security log | 4738, 4740 | Account changes/lockouts around the anomaly window |
| Domain Controller Security log | 1102 | Anti-forensics check — was the log cleared before/after |
| Workstation/server | 4103, 4104 | PowerShell tooling (Rubeus, Invoke-Kerberoast, etc.) if the anomaly traces to an endpoint |

## Key Fields to Inspect

**[ANALYST]**
- **Account Name / Supplied Realm** (4768) — does the realm match the actual domain, or is this a cross-realm/forged referral?
- **Client Address** (4768/4769/4771) — the true source; watch for it being blank, a DC's own IP (relay), or inconsistent with the account's normal workstation.
- **Ticket Encryption Type** — 0x17 (RC4) is the flag to chase down; compare against what that account/service normally negotiates.
- **Pre-Authentication Type** — absence of pre-auth on an account not deliberately configured for it.
- **Result Code / Failure Code** — 0x0 success, 0x6 client not found, 0x12 revoked/disabled, 0x18 bad password/pre-auth failed.
- **Service Name** (4769) — is this a real SPN, or a name that doesn't map to any known service account?
- **Logon ID** — thread the ticket event to the 4624/4672 logon session it fed, and from there to 4688 process activity if available.

## Normal vs Suspicious Pattern

| Signal | Normal | Suspicious |
|---|---|---|
| Encryption type | AES256 (0x12) across modern domain | RC4 (0x17) on an account that should be AES-capable |
| 4768→4769 sequence | TGT then service tickets from the same session, same source IP | 4769 with no matching prior 4768 in that session |
| Pre-auth on 4768 | Present for standard user accounts | Missing pre-auth on an account not intentionally exempted |
| Ticket lifetime | Matches domain Kerberos policy (commonly 10 hrs default) | Multi-year lifetime, or renewal well past max renewal window |
| Client Address stability | Same handful of workstations per user, day over day | Rapid flips between unrelated subnets for one account |
| KRBTGT activity | Quiet except scheduled rotation | Any unexpected reference outside rotation cadence |

## Investigation Steps

1. Pull the raw 4768/4769/4771 events for the flagged account across a ±24h window; establish the account's normal Client Address and encryption baseline from prior weeks for comparison.
2. Check whether the flagged 4769 has a matching 4768 from the same Logon ID/session — a missing parent TGT event is a strong forged-ticket indicator, not proof by itself (ingestion gaps and log rotation on the DC can also cause this).
3. Confirm domain Kerberos policy (max ticket lifetime, max renewal) against the observed ticket in the event, and against Group Policy if you have access, to rule out a stale or misapplied GPO rather than an attack.
4. Cross-reference 4624/4672 for the same Logon ID to see what resources the resulting logon actually touched — RDP session, SMB share, LDAP bind.
5. Check 1102 in the same window on the source DC and any DC in scope — a cleared log adjacent to a ticket anomaly changes this from Medium to Critical immediately.
6. If encryption downgrade is the trigger, identify the service/account and confirm with the app/service owner whether it's a known legacy integration (old Linux/Java client, EOL appliance) before assuming compromise.
7. If the anomaly points at a specific endpoint, pull 4103/4104 from that host for Rubeus-style command-line/module signatures (`asktgt`, `s4u`, `ptt`, `kerberoast` keywords in script block text).
8. Document the full ticket chain (source host → account → target service) and hand off to the matching specific playbook (Golden Ticket / Silver Ticket / Kerberoasting / AS-REP Roasting) once the pattern is confirmed, rather than closing this ticket as a standalone finding.

## True Positive Indicators

- Confirmed 4769 without a corresponding legitimate 4768, paired with known-attacker-tool artifacts (4104 script block referencing Rubeus/Mimikatz).
- Ticket lifetime values that don't match any configured domain policy.
- Encryption downgrade tied to an account that has no legitimate reason to use RC4, especially privileged accounts.
- KRBTGT-adjacent anomaly outside a documented rotation change window.
- 1102 log clear immediately before or after the anomalous ticket activity.

## False Positive / Benign Positive Indicators

- Legacy appliance, printer, or Linux/Java-based service account that has always negotiated RC4 — check the app inventory before escalating.
- Load balancer or NAT device masking Client Address, making source location look inconsistent across a session that's actually one user.
- Cross-realm trust referral tickets that look unusual purely because analyst is unfamiliar with trust topology — verify against `Get-ADTrust`/domain trust documentation.
- Clock skew between DC and client beyond Kerberos tolerance producing spurious pre-auth failures with no malicious intent.
- Scheduled KRBTGT rotation job landing inside the review window (check change calendar first).

## Escalation Criteria

Escalate to Tier 3 / IR immediately if: KRBTGT is implicated outside a scheduled rotation, a Tier 0/Domain Admin account is the subject of the anomaly, a 1102 log clear correlates in time, or the pattern matches a specific T1558 sub-technique with corroborating endpoint evidence (4104 tool signatures). Otherwise route to the matching specific-attack playbook for deeper analysis before escalating.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Disable the affected account and force logoff of active sessions — Tier 2 SOC lead approval, immediate for confirmed malicious use.
- Reset the account password (and for service accounts, rotate the SPN's keytab/credential) — service owner + SOC lead sign-off to avoid breaking production auth.
- KRBTGT password reset (must be done **twice**, spaced per Microsoft guidance, to invalidate forged TGTs) — requires AD architecture team + change advisory board approval; this is a domain-wide blast-radius action, not a unilateral SOC call.
- Isolate the originating endpoint from the network — standard EDR containment, SOC Tier 2 authority.
- Engage the incident response retainer / stand up a bridge — required once KRBTGT or Tier 0 accounts are confirmed in scope.

## Example Query (Microsoft Sentinel — KQL)

```kql
SecurityEvent
| where EventID in (4768, 4769)
| extend EncType = tostring(TicketEncryptionType)
| where EncType == "0x17" or isempty(EncType)
| summarize Requests = count(), DistinctServices = dcount(ServiceName),
    SourceIPs = make_set(IpAddress) by Account, bin(TimeGenerated, 1h)
| where DistinctServices > 10 or array_length(SourceIPs) > 3
| project TimeGenerated, Account, Requests, DistinctServices, SourceIPs
```

## Closure Criteria

Close as resolved once the ticket chain has been fully traced (source host, account, encryption type, lifetime, resulting logon), a root cause is documented (attack tooling confirmed, or legitimate legacy/service explanation validated with the system owner), and — if malicious — containment actions are verified complete and handed to the applicable specific-attack playbook for any follow-on remediation tracking. Valid closures include True Positive (escalated), Benign Positive (legacy service, documented), and Insufficient Evidence (log gaps prevented confirming the ticket chain — note the gap explicitly rather than defaulting to a clean bill of health).

**Example case note:**
`2026-09-15 14:32 UTC — Investigated 4769 RC4 anomaly for svc-printqueue@corp.example.com, 14 distinct SPNs in 40 min from 10.10.4.201. Confirmed with Infra team: legacy print server, RC4-only client library, no AES support planned until Q1 migration. No matching 4104/Rubeus artifacts on source host. Closed as Benign Positive — added svc-printqueue to RC4 baseline exception list to reduce future noise.`
