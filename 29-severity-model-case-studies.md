# Part 25 Companion: Playbook Severity Model — Case Studies

The core chapter gives you the nine factors, the weighted rubric, the bands, and the floor/cap overrides. This file runs that machinery against six situations that didn't arrive pre-labeled. Some score exactly the way the rubric predicts. A few fight it — stakeholder pressure, a scary-looking signature, an assumption baked into how "privilege" gets scored — and the interesting part is watching the discipline hold anyway. One case isn't a single incident at all; it's what happens once the same scoring mistake shows up across a dozen unrelated tickets and somebody finally notices the pattern instead of the individual fires.

## Case Study 1: The Floor Beats the Math — Ferrowest Manufacturing

**Organization:** Ferrowest Manufacturing (ferrowestmfg.example), industrial parts fabricator, three plants.

**Trigger:** 4688 on `SRV-FILE-02`, a Tier 2 production file server: command line `vssadmin.exe delete shadows /all /quiet`, parent process a renamed binary masquerading as a scheduling utility. Two minutes later, 7045 logs a new service, `WinCacheOptimizer`, image path in `C:\ProgramData\`, start type Automatic.

**Evidence gathered:** File-integrity monitoring shows mass extension renames across two departmental shares within six minutes of the vssadmin command. SMB write bursts appear from `SRV-FILE-02` toward `SRV-FILE-05`, a second file server on the same VLAN — consistent with T1021.002. No ransom note yet, no confirmed exfiltration.

**Reasoning and decision points:**

At minute two, scoring the raw rubric off the first slice of evidence: Asset Criticality Tier 2 (2×3=6), Identity Privilege none confirmed (0), Threat Confidence high given the vssadmin/service-install combo (3×2=6), Observed Impact conservative since only ~40 files were confirmed renamed at that point (1×3=3), Exploit Success confirmed code execution (3×3=9), Lateral Movement not yet confirmed (0), Persistence confirmed via the service install (2×2=4), Scope single host (1×1=1). Total = 29 → **Medium** on the math alone.

But T1490 (Inhibit System Recovery) and the in-progress T1486 (Data Encrypted for Impact) pattern are both confirmed the moment the shadow-copy deletion and mass rename correlate. The floor rule doesn't wait for lateral movement or scope to get scored — it fires **Critical** immediately.

**[ANALYST]** - that's the whole point of a floor: the ten to fifteen minutes it takes to properly score lateral movement and scope is exactly the window the encryption job keeps running in. By the time "Medium" finishes computing, the SMB writes toward `SRV-FILE-05` are already underway.

**Outcome:** Full IR activation triggered at minute two off the floor, not the math. Both file servers isolated within eleven minutes; two shares restored from backup; no ransom paid. `SRV-FILE-05` had received the encryptor payload but hadn't yet executed it — isolation landed before detonation on the second host.

**Without this discipline:** waiting for the weighted score to climb to Critical on its own holds the incident at Medium-level urgency for exactly the window the attacker needed to reach the second server.

## Case Study 2: Rescoring on Identity Privilege — Castellan Insurance Group

**Organization:** Castellan Insurance Group (castellaninsurance.example), commercial underwriting.

**Trigger:** Helpdesk reports a wave of 4740 lockouts — the side effect of a Password Spraying run (T1110.003): 4771 events (code 0x18) hit six accounts from `10.20.4.187` in under three minutes. Five lock out. One, `jrivera_helpdesk`, doesn't — the guessed password matches, and a 4624 logon (Logon Type 10, RDP) succeeds from the same address.

**Evidence gathered:** A 4648 explicit-credential logon follows within ninety seconds, reaching two more servers. On its face, a standard-privilege account caught in a lucky Password Spraying hit — until 4799 events show the account enumerating group memberships it has no ticket history touching, and a directory review turns up `jrivera_helpdesk` still sitting in `Tier0-Break-Glass-Support`, a domain-admin-equivalent global group left over from a migration two years earlier and never cleaned up.

**Reasoning and decision points:**

| Factor | Initial (min 15) | Revised (hour 24) |
|---|---|---|
| Asset Criticality | 2×3=6 | 3×3=9 (reaches underwriting DB) |
| Identity Privilege | 1×2=2 (assumed standard) | 4×2=8 (DA-equivalent group) |
| Threat Confidence | 3×2=6 | 4×2=8 (confirmed) |
| Observed Impact | 0 | 1×3=3 |
| Exploit Success | 2×3=6 | 4×3=12 (beacon confirmed running) |
| Lateral Movement | 2×2=4 | 3×2=6 (confirmed hop) |
| Data Exposure | 0 | 1×3=3 |
| Persistence | 0 | 3×2=6 (4698 task, elevated) |
| Scope | 1×1=1 | 2×1=2 |
| **Total** | **25 → Medium** | **57 → High** |

**[ANALYST]** - the account's job title never changed. What changed was what the account actually *grants*, which is the whole point of scoring Identity Privilege separately from asset criticality — a "helpdesk" account with a forgotten Tier 0 group membership isn't a Medium finding wearing a low-privilege costume; it's a High finding that hadn't been discovered yet.

**Outcome:** Access suspended, the legacy group membership removed domain-wide (two more orphaned members found on unrelated accounts during the audit), scheduled task removed, both reached servers rebuilt from known-good baselines. Escalated to IR lead per the High-band SLA once the revised score landed.

**Without this discipline:** anchored to its minute-15 score, the ticket sits at Medium urgency while a scheduled-task beacon runs, unattended, on a server holding underwriting data.

## Case Study 3: Holding the Cap Against Stakeholder Pressure — Bramwell Logistics

**Organization:** Bramwell Logistics (bramwelllogistics.example), freight brokerage with a customer-facing quoting portal.

**Trigger:** WAF/IDS alerts on exploit payloads matching a recently disclosed CVE against the quoting portal (T1190), sourced from an IP that threat intel flags as known exploitation infrastructure. Same week, a slower password-guessing run (T1110.001) hits the VPN gateway from a different address, producing a run of 4625 failures (0xC000006A) with no matching 4624 anywhere.

**Evidence gathered:** Every exploit attempt returns HTTP 403 at the WAF — none reach the application layer with a valid payload. The same pattern recurs three times over the week against three customer-facing apps in the same business unit. No lockout, no successful authentication, no follow-on activity anywhere.

**Reasoning and decision points:**

Scoring it straight: Asset Criticality Tier 2 (2×3=6), Identity Privilege none (0), Threat Confidence high given the correlated intel hit (4×2=8), Observed Impact none (0), Exploit Success — the WAF blocked every payload before it reached the application layer, which is the rubric's "blocked/failed pre-execution" tier, not "executed, no confirmed code execution" (1×3=3), Lateral/Data/Persistence all 0, Scope — recurring pattern across a business unit (3×1=3). Total = 20 → **Low**.

The portal's product owner, rattled after reading a competitor's breach writeup involving the same CVE two weeks earlier, pushes to have this declared High and pull in the IR lead. **[STAKEHOLDER]** - the answer given back: "This is the same technique that hit them, but nothing got through — the WAF blocked every attempt before code could run, and there's no follow-on activity anywhere. Escalating the label wouldn't change what we do next; it would just spend IR-lead attention on something already contained." The cap rule for failed exploit attempts against a Tier 2/3 asset with zero follow-on gives that answer a rule to point to, not just a judgment call — and it applies whether the pattern happened once or, as here, three times in a week.

**Outcome:** Closed at Low, formally capped rather than argued down informally. A separate, non-urgent ticket opened with engineering to confirm the underlying package is patched against the CVE regardless — closing the actual gap on its own timeline.

**Without this discipline:** an aggressive rubric, or an anxious stakeholder, inflates every blocked signature match into a Medium or High, and within a quarter every WAF block becomes a fire drill nobody reads carefully anymore.

## Case Study 4: Scope Escalation Across a Multi-Tenant Platform — Quillon Health Partners

**Organization:** Quillon Health Partners (quillonhealth.example), SaaS benefits-administration platform serving dozens of employer clients.

**Trigger:** Cloud IdP flags impossible travel on a platform admin account, immediately followed by a new client secret added to an existing application registration (T1098.001) already holding broad read access via the admin dashboard (T1538).

**Evidence gathered:** Initial review shows the secret used to pull records from what looks like a single client's workspace — T1580 (Cloud Infrastructure Discovery) followed by T1119 (Automated Collection). Thirty-six hours later, egress logs show a compressed archive uploaded to an external file-sharing link (T1567), and the admin role behind the account turns out to be scoped to the platform's shared administrative layer, not any single tenant.

**Reasoning and decision points:**

Initial score: Asset Criticality Tier 1 (3×3=9), Identity Privilege delegated, not yet confirmed platform-wide (3×2=6), Threat Confidence TTP match, unconfirmed intent (3×2=6), Exploit Success secret added and used (2×3=6), Data Exposure accessible-not-confirmed-touched (1×3=3), Persistence the secret itself, low scope pending confirmation (2×2=4), Scope assumed single tenant (1×1=1). Total = 35 → **Medium**.

Revised once the egress log and platform-wide role scope are confirmed: Asset Criticality (4×3=12), Identity Privilege now DA-equivalent for the platform (4×2=8), Threat Confidence confirmed (4×2=8), Observed Impact modest (1×3=3), Exploit Success confirmed with attacker-controlled follow-on (4×3=12), Data Exposure confirmed exfiltration off-network (4×3=12), Persistence a second, elevated OAuth registration found (3×2=6), Scope eleven client tenants touched (4×1=4). Total = 65 → **Critical**.

**[ENGINEERING]** - the mirror image of Case Study 1. There, the floor beat the math to Critical. Here, the confirmed-exfiltration override for regulated data on a Tier 0/1 asset (escalating to Critical given enterprise-wide scope) and the raw weighted total arrive at the same answer independently — the override just confirmed what the recomputed score was already saying.

**Outcome:** Both credentials revoked, both app registration secrets pulled, conditional access tightened to block rather than merely flag impossible-travel sign-ins. Legal notification scoped precisely to the eleven affected tenants, not all of them.

**Without this discipline:** anchoring to the minute-one "single tenant" assumption either delays notice to ten client organizations that should have been told, or — guessed wrong the other way — triggers a blanket notice to clients never touched.

## Case Study 5: Scoring Down Is a Real Outcome — Cobalt Ridge Credit Union

**Organization:** Cobalt Ridge Credit Union (cobaltridgecu.example).

**Trigger:** EDR heuristic flags process injection (T1055) on `SRV-BKUP-03`, a Tier 1 host running core-banking backup orchestration. A 4688 event shows the legitimate backup agent process spawning a child process using a name closely mimicking a system process, followed by an outbound connection to an IP address not previously seen from that host.

**Evidence gathered:** Memory analysis confirms a module loaded into the child process — but it's signed by the backup software vendor, and the "unfamiliar" outbound IP resolves inside the vendor's own published telemetry range. The patch management change log shows the agent received a vendor-pushed self-update two days earlier, and the vendor's knowledge base describes exactly this injection-and-callout behavior as part of that update's hotfix delivery.

**Reasoning and decision points:**

Minute-ten score, from the signature alone: Asset Criticality Tier 1 (3×3=9), Threat Confidence high — injection plus new outbound IP looks bad in isolation (3×2=6), Observed Impact a brief service blip (1×3=3), Exploit Success — injection observed, presumed real (3×3=9), Scope single host (1×1=1). Total = 28 → **Medium**, notification to the asset owner already in motion.

Revised once vendor documentation and the change log correlate: Threat Confidence drops to known-benign (0), Exploit Success drops to none — legitimate vendor code, not an exploit (0), Observed Impact drops to none — the blip was the update finishing on schedule (0). Total = 10 → **Low**.

**[ANALYST]** - note it doesn't drop to Informational, even though the finding is fully benign. Asset Criticality alone contributes 9 points the moment a real Tier 1 production system is in scope — Informational is reserved for events with essentially no real asset behind them, not "confirmed harmless activity on a system that matters." Closure category and severity band answer different questions: closure says what happened (Benign Positive), band says how much operational attention it earned along the way (Low, not zero).

**Outcome:** Closed as Benign Positive. EDR exception written narrowly, matched to the specific signed module hash and parent-process lineage — not a blanket exclusion for that process name — voided if the same signature fires without a corroborating change-log entry.

**Without this discipline:** either the ticket sits open at Medium indefinitely because nobody closes the loop with the vendor, or someone tunes the detection out on gut feel ("the backup agent does this sometimes") — building a blind spot a real injection technique could hide inside later.

## Case Study 6: Fixing the Rubric, Not the Analysts — Vantage Point MSSP

**Organization:** Vantage Point MSSP (vantagepointmssp.example), managed SOC service covering multiple mid-market clients.

**Trigger:** Not a live alert — a scheduled quarterly severity-model governance review, pulling ninety days of closed-incident data under the rubric's change-control process.

**Evidence gathered:** Fourteen incidents across three clients, all opening with a newly created inbox forwarding rule matching finance/wire keywords (T1114.003), all triaged at initial **Medium** because Identity Privilege was scored 1 — "standard user, no elevated rights" — based on directory role alone. Eleven of the fourteen were rescored to High or Critical within twenty-four hours once investigators found the "standard" accounts held delegated approval or payment-release authority inside a finance workflow application that never publishes entitlements into Active Directory.

**Reasoning and decision points:**

**[MANAGEMENT]** - the pattern isn't fourteen separate analyst misjudgments; it's one rubric gap repeating across unrelated clients and analysts — exactly the signal a quarterly review exists to catch. Root cause: the Identity Privilege guidance defines "elevated rights" in directory terms (group membership, admin flags) with no prompt for business-application authority that lives entirely outside the directory. An AP clerk with zero AD elevation can still be the single most consequential account in the company to compromise.

**Outcome:** Rubric revision issued under change control (v1.4), citing the fourteen incidents as the justifying data set. Identity Privilege guidance now includes a triage checklist prompt: confirm delegated financial-application authority, independent of AD role, before defaulting to a score of 1. Change logged with owner, rationale, and the incident IDs that drove it.

**Without this discipline:** the same underscoring recurs indefinitely — each ticket explainable on its own ("we didn't know about that finance permission yet") — until the lag between Medium-triage and High-rescore overlaps with a wire transfer that clears before anyone with IR-lead attention gets pulled in.

## What These Six Have in Common

| Case | Mechanic | Band shift | Without it |
|---|---|---|---|
| Ferrowest | Floor beats the math | → Critical, minute two | Response speed capped at arithmetic speed |
| Castellan | Rescoring on Identity Privilege | 25 → 57 (Medium → High) | Beacon runs unattended under a stale ticket |
| Bramwell | Cap resists stakeholder pressure | Held at 20 (Low) | Every blocked attempt becomes a fire drill |
| Quillon | Scope + override agree | 35 → 65 (Medium → Critical) | Wrong-sized breach notification |
| Cobalt Ridge | Downward rescore | 28 → 10 (Medium → Low) | Blind suppression or wasted attention |
| Vantage Point | Rubric fixed, not the ticket | Systemic, not one-off | Same underscoring recurs across clients |

The rubric was never meant to produce a number nobody argues with — it's meant to make sure the argument, when it comes, is about evidence and weighting, not who felt most alarmed in the moment.
