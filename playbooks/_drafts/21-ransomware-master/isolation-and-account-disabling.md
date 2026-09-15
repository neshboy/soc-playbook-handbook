# Response: Network Isolation and Account Disabling Decisions

The moment a ransomware event gets confirmed — a Sysmon Event ID 11 hit on a ransom note dropping across a dozen file shares, or a SOC analyst watching Volume Shadow Copies disappear (T1490 Inhibit System Recovery) in near real time — the incident commander has maybe fifteen minutes before the decision either gets made deliberately or gets made for them by the encryption process finishing. This section covers who gets to pull the isolation trigger, how fast to pull it, and how far account disabling should reach. Get this wrong in either direction and you either lose the whole estate or you torch evidence you needed to attribute the intrusion and negotiate credibly.

## Who Has Authority to Isolate

Isolation authority has to be pre-agreed before the incident, not negotiated during it. If your IR plan says "the SOC will isolate as needed," that's not an authority model, that's a hope.

**[MANAGEMENT]** - Authority should be tiered by blast radius, decided and signed off before an incident, not during one:

| Scope | Who can authorize | Escalation trigger |
|---|---|---|
| Single host/endpoint | On-shift analyst/handler, no approval needed | Immediate, log in IR ticket |
| VLAN/subnet segment | Incident Commander (IC) | Notify IT infra lead + site owner within 15 min |
| Site/building network | IC + IT Director or designated deputy | CISO notified immediately, business continuity plan activated |
| Core/WAN, DC isolation, internet egress cut | IC + CISO (or delegate) jointly | CEO/board bridge, legal and comms engaged same call |

The key failure mode we see repeatedly: the analyst who spots the ransom note has technical ability to isolate a switch port or disable a VLAN but no delegated authority to do it, and burns twenty minutes hunting for a human who can say yes while encryption continues. Pre-authorize host-level and single-segment isolation to on-shift staff explicitly, in writing, with a post-hoc notification requirement rather than a pre-approval gate.

**[STAKEHOLDER]** - The business risk of hesitating on isolation is almost always worse than the risk of an unnecessary cut. A severed VLAN is an outage you can explain to a customer. A second building encrypted because nobody had authority to act is not.

## Isolate Fast vs Preserve Evidence

This is the real tension, and there is no clean answer — only a documented, defensible tradeoff.

**[ANALYST]** - Before pulling network access, if there is any time at all (even 60-90 seconds), grab volatile evidence: a memory-resident process list, active network connections (Sysmon Event ID 3 data if the agent is still phoning telemetry home), and the encrypting process's PID/command line from Sysmon Event ID 1 or Windows Event ID 4688. Note the exact timestamp of isolation action taken and by whom — this becomes part of the root-cause timeline and, if litigation follows, part of the evidentiary record.

**[ENGINEERING]** - Preferred isolation order, fastest-to-slowest and least-to-most evidence-destructive:

1. **EDR network containment/quarantine** (agent-enforced host firewall) — near-instant, reversible, host stays powered and logging continues locally.
2. **Switch port shutdown / 802.1X quarantine VLAN** — fast, doesn't touch host state, kills lateral movement over SMB (T1021.002) and RDP (T1021.001) immediately.
3. **Firewall/ACL block at segment boundary** — slower to push at scale, good for isolating a whole site while keeping internal segment forensics collectible.
4. **Physical unplug / power-off** — last resort only. Powering off destroys memory-resident evidence (encryption keys sometimes recoverable from RAM, active C2 connections, injected code per Sysmon Event ID 8/10) and can trigger anti-forensic cleanup routines in some ransomware families that watch for shutdown signals. Never the default move for a live host still encrypting unless it's about to hit something irreplaceable (backup repository, domain controller).

**[MANAGEMENT]** - Set an explicit organizational default: *contain at the network layer, do not power off*, unless IC states a specific reason. Document that decision point every time — regulators and insurers will ask why a host was or wasn't powered down, and "we panicked" is not an answer that ages well.

## Scope of Precautionary Account Disabling

Ransomware crews with domain admin or a compromised service account (T1078.002 Valid Accounts – Domain Accounts) will keep using that access even after endpoints are isolated, pivoting to anything still reachable — backup consoles, hypervisor management, cloud admin portals.

**[ANALYST]** - Build the disable list from evidence, not guesswork: accounts seen in 4624/4672 privileged logons on affected hosts, any account tied to 4720/4728/4732 activity in the hours prior (attacker-created accounts or group adds), and service accounts tied to 4697/7045 service installs matching the ransomware binary or its deployment tooling (often abused for mass deployment via GPO or PsExec-style T1021.002).

**[ENGINEERING]** - Precautionary disable, in priority order: (1) any domain admin/enterprise admin account with recent activity, (2) the account(s) that authenticated to the encryption-source host, (3) all service accounts with logon rights on more than one server unless confirmed clean, (4) break-glass/emergency access accounts — reset, don't disable, since you'll need them. Do **not** blanket-disable every domain account; that turns a ransomware incident into a self-inflicted denial of service and destroys your ability to distinguish attacker activity from users locked out for unrelated reasons.

**[MANAGEMENT]** - Track disabled accounts on a single running list with owner, justification, and re-enable criteria — someone will need every one of them back, and "who approved re-enabling the CFO's account" needs an answer during the after-action review, not a guess.
