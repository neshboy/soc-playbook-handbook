# Endpoint – Persistence & Impact

Persistence and impact sit at opposite ends of the same kill chain, which is why they share a folder. Persistence techniques are how an adversary makes sure a reboot, a logoff, or an EDR restart doesn't cost them their foothold — a service, a scheduled task, a registry Run key, an injected process. Impact techniques are what happens once that foothold has been leveraged for something destructive or defense-degrading — credential theft from LSASS, mass file encryption, shadow copy deletion, or an EDR agent getting disabled outright. In practice these two phases blur together in a single incident timeline more often than the taxonomy suggests: a ransomware crew installs a scheduled task for re-entry, dumps credentials to move laterally, disables the EDR agent on the way through, and only then starts encrypting. Triaging one playbook in isolation without asking "what else in this category fired on this host in the last 24 hours" is how analysts miss the second and third stage of an intrusion that already announced itself once.

**[STAKEHOLDER]** - This category covers the alerts that most directly correlate with "this is no longer a phishing click, this is an operator on the box." Persistence mechanisms are the difference between a one-time cleanup and a re-infection three weeks later; impact alerts (LSASS access, mass file modification, VSS deletion, EDR tampering) are frequently the last clean signal before a ransomware detonation. Speed of triage here has a direct relationship to blast radius. This is also the category where a false negative is far more expensive than a false positive — over-alerting on service installs is a tuning annoyance, missing one is a rebuild.

Every playbook in this section leans on the same core telemetry, just pointed at different behaviors: Sysmon Event ID 1 (process creation with full command line and parent chain), Sysmon 3 (network connections tied to the responsible process), Sysmon 6/7 (driver and image loads, relevant to EDR-killers and injection), Sysmon 8 (CreateRemoteThread), Sysmon 10 (ProcessAccess, the backbone of LSASS-access detection), Sysmon 11/23 (file create/delete, for ransomware notes and anti-forensics cleanup), and Sysmon 12/13/14 (registry create/set/rename, for Run key and service-key persistence). On the native Windows side, Security log 4688 (process creation, command line if auditing is enabled), 4697 and System log 7045 (service installs), and 4698 (scheduled task creation, including the Task Content XML) do most of the load-bearing work. EDR telemetry — process tree, memory scan results, tamper-protection events — generally arrives faster and with more context than raw Windows logs, but the two should be cross-checked against each other rather than trusted in isolation; an EDR that's been tampered with is exactly the scenario where you need the Windows-native trail to still be intact.

Friction specific to this category: this is where logging gaps hurt the most, because the attacker's own playbook often includes turning your visibility off first. Don't assume a missing 4698 or a missing Sysmon 12 means nothing happened — check whether audit policy changed, whether the Sysmon service itself was stopped, or whether the EDR sensor shows a gap in its own heartbeat before concluding the technique wasn't used. Command-line auditing being disabled on a subset of hosts, config drift between Sysmon deployments, and EDR agents that silently failed to reinstall after a patch cycle are all extremely common, and each one will make a real persistence mechanism look like an Insufficient Evidence closure if you don't validate the sensor was even in a position to see it.

## Playbooks in This Category

| # | Playbook | Primary Technique(s) |
|---|---|---|
| 1 | New Service Creation | T1543.003 |
| 2 | Scheduled Task Persistence | T1053.005 |
| 3 | Registry Run Key Persistence | T1547.001 |
| 4 | Credential Dumping / LSASS Access / Mimikatz Indicators | T1003.001 |
| 5 | Process Injection | T1055 |
| 6 | Mass File Modification (Ransomware-Adjacent) | T1486 |
| 7 | Shadow Copy (VSS) Deletion | T1490 |
| 8 | Security Tool Tampering / EDR Disabled | T1562.001 |
