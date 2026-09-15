# Client Approval and GO/NO GO — Worked Case Studies

This companion file assumes you've already read the core chapter on client approval gates and GO/NO GO decision logic. What follows are five scenarios pulled from the kind of week a mid-size MSSP SOC actually has — not the tidy version. Each one shows the trigger, what was actually collected before anyone made a call, the specific decision points, what happened, and the one thing that breaks if you skip the discipline.

---

## Case Study 1: Emergency Isolation with an Unreachable Primary Contact

**Client:** Meridian Fabrication Ltd (contract manufacturer, mixed IT/OT environment)

**Trigger:** At 02:14 local time, EDR + SIEM correlation fires on `MER-WKS-114`: a `4688` process creation event shows `rundll32.exe` spawned from an Office document's parent process, immediately followed by LSASS memory access consistent with **T1003.001 (OS Credential Dumping: LSASS Memory)**. Ninety seconds later, `4104` PowerShell script block logging captures a heavily encoded command block containing `Invoke-` and `Mimikatz`-style string fragments (**T1027 Obfuscated Files or Information**). Within four minutes, a `7045` service-installed event appears on three additional hosts (`MER-SRV-02`, `MER-SRV-07`, `MER-OT-GATE`) — service name `WinSvcHealth`, image path pointing to a temp directory, start type auto (**T1543.003**).

**Evidence gathered:**

| Time (local) | Event | Host | Detail |
|---|---|---|---|
| 02:14:02 | 4688 | MER-WKS-114 | rundll32.exe, parent = WINWORD.EXE |
| 02:14:41 | 4104 | MER-WKS-114 | Base64 block decodes to Mimikatz-pattern strings |
| 02:16:55 | 4624 (Type 3) | MER-SRV-02, -07 | Source = MER-WKS-114, account = svc-backup (T1078.002) |
| 02:18:10 | 7045 | MER-SRV-02, -07, MER-OT-GATE | Service WinSvcHealth, temp image path |
| 02:19:30 | 4672 | MER-SRV-07 | Special privileges assigned to svc-backup logon |

`MER-OT-GATE` is the jump host sitting between the corporate network and the manufacturing floor's control systems — not itself a PLC, but the only path to them.

**Reasoning / decision points:**

The lateral movement pattern (**T1021.002**, SMB/admin shares, using a compromised backup service account) plus the credential-dump precursor is a strong ransomware-staging signature, not a one-off. The client's on-call tree lists the IT Director as primary; three calls and a text over eleven minutes get no response. The secondary contact, the CISO, answers but says she can't authorize isolating `MER-OT-GATE` without the plant manager's sign-off — an unplanned isolation there could blind a live production line, and that's not a call she owns alone.

**[MANAGEMENT]** - The MSA with Meridian includes a pre-negotiated emergency containment clause: the SOC may isolate any *non-OT-adjacent* host unilaterally when active lateral movement is observed, with mandatory notification within 15 minutes. OT-adjacent systems are explicitly carved out of that pre-authorization and require a named approver, precisely because an unplanned OT outage carries its own safety and liability profile that the security team isn't positioned to weigh alone.

Applying that split: the three IT-side hosts get isolated immediately under existing authority. `MER-OT-GATE` is not powered off or fully isolated — instead the analyst pushes a network ACL blocking outbound SMB/RDP from that host while leaving inbound OT traffic and visibility intact, and escalates for explicit sign-off rather than guessing.

**Outcome:** Four hosts contained within 14 minutes of first detection. The CISO reaches the plant manager at 02:41; full isolation of `MER-OT-GATE` is approved and executed at 02:47. No encryption events, no T1486-pattern impact activity ever observed — this was caught at the credential-access/staging phase.

*Without this discipline: an analyst working from a single "isolate everything now" instinct either freezes a live production line with zero authorization trail (real liability exposure for the MSSP), or waits for a callback that never comes fast enough and loses the 30-minute window before the actor pivots to domain admin and starts encrypting.*

---

## Case Study 2: Deliberately Delaying Containment to Protect a Fraud Recovery

**Client:** Harlow & Voss Logistics

**Trigger:** Cloud mailbox audit alert flags a new inbox rule on the CFO's mailbox (`j.pryce@harlowvoss.example.com`) forwarding any message containing "invoice," "wire," or "remittance" to an external Gmail address — a Business Email Compromise (BEC) pattern, consistent with **T1114.003 (Email Forwarding Rule)**. The rule was created nine minutes after a sign-in from an IP in a country the CFO has never traveled to or logged in from (**T1078.004**), no MFA challenge satisfied on record for that session's origin.

**Evidence gathered:** Sign-in logs show the anomalous session started at 08:03, the forwarding rule created at 08:12, and — critically — the client's own AP team ticket queue shows an "update banking details" request tied to a real vendor invoice was approved for payment at 07:50, before the observed compromise indicators even started. That ordering matters: the fraud may already be mid-flight.

**Reasoning / decision points:**

Standard instinct is contain-first: kill the session, disable the account, strip the rule. That's wrong here in a specific way. If the SOC forces the account offline immediately, the actor — who may still be watching that inbox for bank confirmation replies — sees the account go dark and has every reason to accelerate moving the stolen funds before the bank can claw the wire back.

**[STAKEHOLDER]** - This is a case where the security fix and the business's best financial outcome are briefly in tension, and it's not the SOC's call to resolve alone. The client's finance lead and legal counsel need to know *now* that a fraudulent payment redirection is likely in progress, because they own the relationship with the bank's fraud recovery desk and the decision of when it's safe to "spook" the account.

**Decision:** NO GO on immediate containment. The SOC documents this explicitly as a *deliberate delay*, not inaction — exports and preserves the mailbox audit log and rule content as evidence, keeps read-only monitoring live on the mailbox, and gives the client a hard two-hour window: either legal/finance confirms the bank recall is underway and gives the go-ahead, or the SOC forces containment regardless of fraud-recovery impact once the window lapses. Harlow & Voss's controller confirms at 09:40 that the receiving bank has frozen the funds pending recall.

**Outcome:** At 09:55 the SOC executes full containment — password reset, all sessions revoked, forwarding rule removed, MFA re-registration forced. Funds recovery succeeds in full two days later per the client's own confirmation.

*Without this discipline: reflexive immediate lockout at 08:20 tips the actor off before the bank recall request is even filed, and the client likely eats the full loss instead of recovering it.*

---

## Case Study 3: NO GO on Escalation — Expected Activity Confirmed, Not Assumed

**Client:** Delacroix Health Partners

**Trigger:** A correlation rule fires on a burst of `4769` Kerberos service ticket requests from a single workstation (`DEL-SCN-03`) requesting tickets for eleven distinct SPNs within ninety seconds, several using RC4 encryption (`0x17`) — the textbook shape of a **T1558.003 (Kerberoasting)** sweep.

**Evidence gathered:** The analyst does not close this on pattern-matching alone. Pulling `4688` process creation from `DEL-SCN-03` for the same window shows no `powershell.exe`, no `Rubeus`- or `Invoke-Kerberoast`-named binaries, and no `4104` script block activity at all in the preceding hour. The account driving the requests is `svc-vulnscan`, and the client's change calendar (checked, not assumed) shows an authorized Nessus scan window scheduled for that exact host and time slot, tied to change ticket CR-2291. The scanner's SPN-enumeration behavior during asset discovery legitimately triggers ticket requests that look identical to Kerberoasting at the event level — this is a known false-positive pattern for that tool, not a novel one.

**Reasoning / decision points:**

**[ANALYST]** - The absence of attacker tooling in the process tree is the key differentiator here, not the ticket burst itself — `4769` volume alone is too noisy to act on without it, which is exactly why this rule is usually filtered/tuned in mature environments and why the tuning gap itself is worth flagging.

The temptation on a health-sector client is to escalate anyway "to be safe." That instinct isn't wrong to have, but it isn't a substitute for evidence. The analyst still validates account ownership with the client's IT lead by phone (confirming `svc-vulnscan` hasn't been repurposed or its credentials stolen) before closing — GO/NO GO discipline applies to escalation decisions too, not only to containment actions.

**Decision:** NO GO on incident escalation. Closed as **Expected Activity**, logged with full evidence chain, and a tuning ticket filed to suppress `4769` alerts from the known scanner account while preserving detection for RC4 requests from any *other* source.

**Outcome:** No client-facing incident notification generated (would have been a false alarm at a client where trust in alert quality already needed rebuilding after two prior false escalations that quarter). Detection logic updated within the week.

*Without this discipline: either a costly false escalation damages the relationship further, or — if the analyst skips validation and closes it on gut feel without checking the process tree and the change calendar — an actual Kerberoasting run riding alongside the same scan window gets waved through unexamined.*

---

## Case Study 4: Insider Case Requiring Legal and HR Sign-Off Before Any Action

**Client:** Colby Ridge Utilities

**Trigger:** A network engineer, already under active HR investigation for a policy violation and informally told a decision on his employment is imminent, triggers a `4698` scheduled task creation on four servers within a six-minute window. Task Content XML shows a PowerShell action referencing an external IP (`203.0.113.44`) with a base64 payload; `4104` script block logging captures the decoded content (**T1027**), and the resulting `4688` shows `powershell.exe` spawned by the Task Scheduler service (**T1053.005**). A `4728` shortly afterward shows his own account re-added to the Domain Admins global group, from which he'd been quietly removed by IT two days earlier as a precaution (**T1098.007 Account Manipulation: Additional Local or Domain Groups**).

**Evidence gathered:** Task names are disguised as routine maintenance ("SysHealthCheck"). The decoded script establishes a reverse connection and includes a conditional branch referencing account deletion commands — read by the analyst as a plausible access-preservation / retaliation contingency, not yet executed.

**Reasoning / decision points:**

This is not a generic external-actor incident, and treating it like one is the mistake to avoid. It's an active HR matter with employment-law exposure on both sides: act too aggressively and the company risks a wrongful-action claim or a broken chain of custody; act too slowly and the employee may notice he's been re-removed from the group and trigger whatever the conditional branch was built for.

**[MANAGEMENT]** - GO/NO GO here explicitly routes through Legal and HR before any account-level action, per the client's insider-threat annex — one of the few categories in the contract *never* pre-authorized for unilateral SOC execution, because the legal exposure sits with the client's employment decisions, not the SOC's technical judgment.

**Decision:** NO GO on immediate account disablement. The SOC instead applies the narrowest technically defensible action — reverting the Domain Admins membership and removing the scheduled tasks (technical evidence preservation captured first via forensic export, per legal hold instructions received from the client's counsel) — while leaving the account itself active and closely monitored. HR and Legal are given the evidence package and coordinate a termination meeting time; the SOC pre-stages the full account disablement to execute the instant HR confirms the meeting has started.

**Outcome:** Account disabled at 14:32, synchronized to the minute with the termination meeting start. No further malicious activity observed after the scheduled tasks were pulled. Evidence package handed to Legal intact and properly chained.

*Without this discipline: disabling the account the moment the scheduled tasks were found tips the employee off hours before HR is ready, which is exactly the scenario that could trigger the destructive contingency the script was staged for in the first place.*

---

## Case Study 5: Pre-Authorized GO on a Cloud Identity Threat, No Real-Time Approver Available

**Client:** Bramwell & Cole LLP (legal services, Microsoft 365 tenant)

**Trigger:** Cloud audit log shows a user in the Litigation Support group approving an OAuth app consent grant with `Files.ReadWrite.All` and `Mail.Read` scopes for an app named "Quick PDF Convert," registered nine days earlier and never seen in the tenant before (**T1528 Steal Application Access Token** — the illicit consent-grant pattern, not a stolen password). Within twenty minutes, Graph API activity shows over 400 file reads/downloads across three client-matter SharePoint sites, all authenticated via the granted token — with zero corresponding interactive sign-in events for that access, which is the specific tell that this is token abuse (**T1530 Data from Cloud Storage**) rather than a credential-based logon.

**Evidence gathered:** The download pattern spans multiple unrelated client matters in alphabetical folder order — consistent with automated bulk collection, not a user retrieving something they actually need (**T1119**-flavored behavior, though the SOC doesn't need a technique ID to recognize "nobody browses case files this way").

**Reasoning / decision points:**

The client's IT administrator is on approved leave and unreachable; the listed secondary contact doesn't answer within the contracted 15-minute SLA. Ordinarily this is where things stall. It doesn't here, because during onboarding this client pre-authorized a narrow tier of cloud-identity actions for unilateral SOC execution: revoking a suspicious OAuth grant and forcing token/session invalidation. The reasoning at the time, documented in the approval matrix, was that this action is cheap to reverse (re-consenting a legitimate app takes minutes) against the cost of an open exfiltration window on privileged legal files — an asymmetry that wouldn't hold for something like isolating a production host.

**[ENGINEERING]** - The pre-authorization is scoped narrowly and by design: it covers OAuth grant revocation and forced re-authentication only, not account disablement, not mailbox deletion, not any action with a higher blast radius or lower reversibility. That scoping is what makes unilateral action defensible here in a way it wouldn't be for a broader action.

**Decision:** GO, executed without waiting on a live approver, per the pre-negotiated clause. The SOC revokes the OAuth grant, forces sign-out of all active sessions tenant-wide for the affected user, and files the mandatory retroactive notification (SMS + ticket) within the contracted 30-minute window.

**Outcome:** File access activity stops immediately upon revocation. Client's IT admin, reached the following morning, confirms the action and the affected user's credentials as compromised via a prior phishing click that had gone unreported.

*Without this discipline: waiting on an unreachable approver for something explicitly designed to be fast and reversible turns a five-minute fix into an open-ended exfiltration window over privileged legal matters — the wait itself becomes the incident.*

---

## Patterns Worth Extracting

A few things repeat across all five of these that are easy to miss if you only ever read the clean version of the playbook: the GO/NO GO call is rarely "act vs. don't act" — it's usually about scoping *which part* of the response is authorized right now versus which part needs a named human first. Pre-authorization only works when it's scoped narrowly to genuinely reversible, low-blast-radius actions (Case 5) — stretching it to cover something like OT isolation (Case 1) is how a pre-authorization clause turns into a liability instead of a safeguard. And a clean Expected Activity close (Case 3) is only earned by validation work — process tree, change calendar, a phone call to confirm the account itself hasn't been repurposed — not by pattern-matching a scary-looking alert and hoping.
