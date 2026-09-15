# Identity & Active Directory — Kerberos & Advanced Attacks

Everything in this category shares one property: the attacker isn't exploiting a vulnerability, they're abusing a protocol working exactly as designed. Kerberos delegation, ticket caching, NTLM fallback, LDAP queries, replication — all legitimate AD mechanics that a domain relies on every second of every day. The alerts in this folder exist because those same mechanics, used with stolen material or forged structures, look almost identical to normal traffic until you know which fields to distrust. This is the category where "it's probably a service account doing something weird" gets said a lot, and where that assumption is sometimes right and sometimes the whole reason an intrusion sat undetected for three weeks.

The common thread across Golden/Silver Tickets, Kerberoasting, AS-REP Roasting, DCSync, DCShadow, Pass the Hash and Pass the Ticket is that each one targets a different trust boundary inside authentication: the KDC's signing key, a service account's hash, a domain controller's replication trust, or a workstation's cached credential. Detection almost never comes from a single event — it comes from a mismatch between events that should agree and don't. A TGT with a lifetime that doesn't match domain policy. A service ticket request for an account nobody actually uses interactively. An NTLM authentication on a network that's supposed to be Kerberos-only. Individually these are noise. Together they're a pattern.

**[ANALYST]** - The core evidence chain runs through 4768 (TGT requested), 4769 (service ticket requested), 4771 (pre-auth failed), and 4776 (NTLM validation by the DC), cross-referenced against 4624/4648 for the logons that follow and 4672 for privilege level. Pre-authentication type, encryption type on 4769 (RC4 vs AES), Result/Failure Code, and Client Address are the fields that actually separate "user typed their password wrong" from "someone is requesting service tickets for every SPN in the domain." 4798/4799 matter for the recon phase that usually precedes the ticket abuse — enumeration rarely happens in isolation.

**[ENGINEERING]** - Native Security event volume on 4769 is the single biggest practical obstacle to building any of this reliably; most environments filter it at the collector before it reaches the SIEM, which means your Kerberoasting and Silver Ticket logic has to be designed around whatever subset actually survives ingestion. DCSync and DCShadow detection leans on directory service replication events and domain controller behavioral baselining rather than a clean single-event signature — expect to correlate against a known-DC allowlist. PowerShell-based tooling (Rubeus, Mimikatz wrappers) surfaces in 4103/4104 when script block logging is enabled, which is frequently the highest-fidelity evidence available when the Kerberos events themselves are ambiguous.

**[MANAGEMENT]** - These playbooks map to T1558 (Golden/Silver Ticket, Kerberoasting, AS-REP Roasting), T1003.001/.006 (LSASS dumping, DCSync), T1207 (DCShadow), T1550.002/.003 (Pass the Hash, Pass the Ticket), and T1110/T1078.002 for the brute-force and valid-account paths that often precede them. Ownership sits jointly between the SOC and the AD/Identity engineering team — ticket forgery and replication abuse frequently require privileged AD changes (krbtgt reset, SPN cleanup) that the SOC cannot execute unilaterally, so escalation paths and approval authority need to be pre-agreed, not negotiated mid-incident.

A short note on where this goes wrong in practice: clock skew between the DC and the collector will misalign 4768/4769 pairs just enough to break correlation logic that assumes tight timing windows, and nobody notices until a Golden Ticket investigation stalls on "which TGT issued this ticket." Encryption type on 4769 is a weaker signal than most detection content implies — plenty of legitimate legacy applications still request RC4 tickets, so alerting on encryption type alone produces a steady trickle of benign positives that erode analyst trust in the rule. DCSync detection is particularly prone to false positives from legitimate replication partners and Azure AD Connect accounts that were never added to the allowlist. And when someone clears the Security log (1102) mid-investigation, treat it as a separate incident in its own right, not as a reason to close out the original ticket as inconclusive.

## Playbooks in This Category

| # | Playbook | Primary MITRE ATT&CK Technique(s) |
|---|----------|------------------------------|
| 1 | Kerberos Anomalies (General) | T1558, T1078.002 |
| 2 | Golden Ticket Indicators | T1558.001 |
| 3 | Silver Ticket Indicators | T1558.002 |
| 4 | Kerberoasting | T1558.003 |
| 5 | AS-REP Roasting | T1558.004 |
| 6 | DCSync | T1003.006 |
| 7 | DCShadow | T1207 |
| 8 | Pass the Hash | T1550.002 |
| 9 | Pass the Ticket | T1550.003 |
| 10 | NTLM Abuse | T1550.002, T1110 |
| 11 | Suspicious LDAP Enumeration | T1087, T1069, T1482 |
