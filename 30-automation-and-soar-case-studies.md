# Part 25B — Automation and SOAR: Five Worked Case Studies

The core chapter covered SOAR architecture, playbook design, and where human approval gates belong in an automated response chain. This section puts five of those decisions under load — scenarios where the automation worked exactly as designed, and one where the design itself had a gap nobody caught until it broke something. Company names, hosts, and IPs are fictional; the failure modes are not. Duplicate-trigger rotation, criticality-blind isolation, unscoped auto-purge — every pattern below shows up in real post-incident reviews once a SOC has been running automated response long enough to accumulate scar tissue.

## Case Study 1 — Phishing: Auto-Contain the Mailbox, Gate the Org-Wide Purge

Environment: Brightwell Logistics, roughly 3,000 mailboxes on Microsoft 365, SOAR wired to the mail security connector and EDR.

**Trigger:** An accounts-payable clerk, K. Munroe (host `BRW-LT-58`), reports a suspicious invoice email via the "Report Phishing" button. The report auto-creates a SOAR case and kicks off the triage playbook before any analyst has looked at anything.

**Evidence gathered (automated, then analyst-reviewed):**
- Attachment is an HTML wrapper around an obfuscated script; sandbox detonation shows it drops a payload that launches `rundll32.exe` (T1218.011) with a base64-encoded argument.
- 4104 script block logging on `BRW-LT-58` captures the decoded second stage — a download-and-execute pattern pulling from `hxxps://cdn-assets-update[.]net`.
- 4103 module logging shows `Invoke-WebRequest` in the same pipeline.
- 4688 on the host has no populated command line — command-line auditing wasn't enabled there, a gap the analyst notes rather than assumes away — but the Creator Process relationship still ties `rundll32.exe` back to the mail client.
- Automated TI enrichment matches the callback domain to a loader family seen in three unrelated client environments over the past month.

**Decision points:** The playbook's first stage — quarantine the message from Munroe's mailbox, isolate `BRW-LT-58`, block the callback domain at the proxy — runs fully unattended, because the blast radius of being wrong is one mailbox and one laptop. The second stage — search-and-purge the same attachment hash across all 3,000 mailboxes — is gated behind analyst approval, because an org-wide purge is much harder to walk back than a re-delivered email, and an automated sandbox verdict alone isn't treated as sufficient grounds for a tenant-wide action without a second look.

**[STAKEHOLDER]** - The approval gate here isn't process for its own sake. It's the difference between "we cleared a phishing payload from 43 mailboxes in six minutes" and "the SOC deleted something without telling anyone," which is the kind of automation story that ends up in front of the CIO for the wrong reasons.

The analyst confirms the sandbox verdict against a second data point — hash reputation plus a domain registered nine days earlier with no hosting history — and approves the org-wide action. The purge finds and removes the attachment from 42 additional mailboxes; two users had already opened it before approval and go to IR for credential reset and reimage.

**Outcome:** Confirmed True Positive: phishing attachment (T1566.001) leading to user execution (T1204) of obfuscated PowerShell/rundll32 (T1059.001, T1027, T1218.011) with C2 callback (T1105, T1071). Full org-wide containment inside ten minutes of analyst sign-off.

**Without this discipline:** an unattended org-wide purge triggered off a single sandbox verdict is one bad detonation result away from mass-deleting something that wasn't actually malicious, and nobody notices until someone asks where their email went.

## Case Study 2 — Business Email Compromise: Automation That's Allowed to Move First

Environment: Halcyon Health Group, Microsoft 365 / Entra ID, SOAR wired to sign-in risk detection and Exchange Online, plus a secondary hook into the finance team's wire-approval workflow.

**Trigger:** A sign-in risk alert flags "atypical travel" on a finance controller's account — a successful authentication from an ASN in a different country roughly 40 minutes after a legitimate sign-in from Halcyon's own network, a gap no flight schedule explains.

**Evidence gathered:** The enrichment step, which runs before any analyst sees the case, queries the mail platform for recent changes and finds a new inbox rule created eleven minutes after the suspicious sign-in — forwards anything containing "invoice," "wire," or "payment" to an external address, marks it read, and files it away (T1114.003). A delegate permission grant to an external mail-enabled contact is also present (T1098.002).

**Decision points:** Unlike Case 1, this playbook is authorized to act before an analyst reviews it, because impossible-travel plus a keyword forwarding rule on a finance identity is treated as high-confidence BEC, and the cost of waiting is measured in wire fraud, not a re-sent email. It revokes active session tokens, disables the account (T1078.004), deletes the forwarding rule and delegate grant, and — the part leadership actually cares about — fires a second automated hook into the AP system that freezes any pending vendor banking-detail change tied to that user's approvals for 24 hours pending manual review.

**[STAKEHOLDER]** - Revoking a session protects the mailbox; freezing the wire workflow protects the money. That second hook has to exist before the incident, because by the time a human reads the ticket the wire can already be gone.

**Outcome:** Follow-up ties the credential theft to a fake Office 365 login page reported by a different employee two days earlier (T1566.002). No fraudulent payment went out; a pending banking-detail change for one vendor was held and, on manual callback to the vendor, confirmed fraudulent.

**Without this discipline:** a manual-only response usually finds the forwarding rule only after finance calls about a bounced or redirected invoice — by which point the wire has often already gone out, and recovery depends entirely on the receiving bank.

## Case Study 3 — Kerberoasting Auto-Remediation: When the Automation Duplicates Itself

Environment: Ashford Retail Group, on-prem AD across 340 stores, SIEM fed by both a Windows Event Forwarding subscription and a legacy syslog forwarder still pointed at the same domain controllers — a migration artifact nobody had fully decommissioned.

**Trigger:** A correlation rule fires on a burst of 4769 events with Ticket Encryption Type `0x17` (RC4) against 34 distinct SPNs, all requested within six minutes under the `svc_pos_sync` account from a host outside its normal footprint.

**Evidence gathered:** 34 4769 events across 34 SPNs, single source account, six-minute window — the Kerberoasting shape (T1558.003) covered in the false-positive engineering chapter's tuning discussion. Account discovery (T1087) on the same host in the preceding hour had built the SPN target list.

**Decision points:** Ashford's SOC had board sign-off on an aggressive runbook for exactly this pattern: auto-rotate the targeted service account's password through the PAM platform, no human gate, because RC4 tickets are crackable offline and every minute of delay is attacker time. That part worked. What broke was upstream — the same DC security log arrived twice, once via WEF and once via the leftover syslog path, and the correlation rule had no dedup key beyond a raw event count threshold. It fired the detection twice, ninety seconds apart, as two independent cases, and each one independently triggered the rotation playbook. The first rotation began propagating `svc_pos_sync`'s new password to the point-of-sale sync service's credential store; the second fired before that propagation finished. For about eleven minutes the account's live password and the value the sync service held didn't match, and transaction sync dropped across the store network during business hours.

**[ENGINEERING]** - the fix wasn't removing auto-rotation, it was making the action idempotent regardless of whether the trigger duplicates:

```text
on kerberoast_detection(account, spn_set, window):
    dedup_key = hash(account, sorted(spn_set), floor(window / 5min))
    if seen_recently(dedup_key, ttl=15min):
        merge_into_existing_case(dedup_key)
        return                                  # don't re-trigger the playbook

    if pam.rotation_lock(account) == "active":
        log("rotation already in-flight for this account, skipping duplicate action")
        return

    pam.set_rotation_lock(account, ttl=10min)
    pam.rotate_password(account)
    pam.release_rotation_lock(account)           # only after downstream propagation confirms
```

Two fixes went in: a dedup key on the correlation rule itself, and — as defense in depth, because upstream dedup will fail again someday for some other reason — a rotation lock inside the PAM action so the automation can't duplicate its own containment step even if the detection layer does.

**Outcome:** Detection-to-rotation speed stayed fast for real Kerberoasting going forward; the playbook now checks state before acting instead of assuming it's the only thing that ever calls it.

**Without this discipline:** any unattended containment action — disable, isolate, rotate, block — is exposed to the same failure the moment a log source gets ingested twice, and it rarely surfaces in testing because test environments don't usually have a decommissioning artifact quietly duplicating a feed.

## Case Study 4 — Ransomware Precursor: Auto-Isolate, Except When the Target Is Tier 0

Environment: Delacroix Manufacturing, EDR with an isolation API, CMDB-fed asset criticality tags (Tier 0 = domain controllers, ERP database, plant SCADA gateway; Tier 1/2 = everything else).

**Trigger:** EDR behavioral detection on `DEL-FS03` (file server, Tier 2): mass file rename with high-entropy output consistent with encryption, a shadow-copy deletion attempt (T1490), and a newly installed service (7045) whose binary matches a known ransomware loader.

**Evidence gathered:** 7045 shows the service installed under a name disguised as a Windows update helper; 4698 shows a scheduled task created minutes earlier to trigger the shadow-copy deletion at a set time (T1053.005, T1543.003); SMB connections from `FS03` reach two other segments, including domain controller `DEL-DC02`, consistent with spread over admin shares (T1021.002).

**Decision points:** The default runbook for confirmed ransomware behavior is unattended isolation — no waiting on an analyst, because every minute between detonation and isolation is more encrypted data. But the playbook checks the target's CMDB criticality tag first:

```text
on ransomware_behavior_confirmed(host):
    tier = cmdb.lookup_criticality(host)
    if tier == "Tier0":
        page_oncall_ir(host, severity="critical", sla_minutes=5)
        hold_isolation_pending_manual_confirm(host)
    else:
        edr.isolate(host)
        log_case(host, action="auto-isolated")
```

`FS03` (Tier 2) is isolated automatically in 40 seconds — no debate needed, it's patient zero. Twenty minutes later the same signature starts matching on `DC02` (Tier 0), because the loader had already reached it before `FS03` got cut off. The tier check catches this one: instead of auto-isolating a domain controller — which would drop Kerberos and LDAP authentication for the whole plant — it pages the on-call IR lead, who confirms active encryption processes via EDR live response in about four minutes and isolates `DC02` manually, with the plant floor systems team notified in the same window so the resulting authentication outage is expected rather than a surprise.

**[MANAGEMENT]** - this guardrail only works if the CMDB tag is accurate and owned by someone. A stale or missing criticality tag on a newly built server is functionally the same as having no guardrail at all — review the tagging feed on the same cadence as the exclusion list covered in the false-positive engineering chapter.

**Outcome:** Two hosts isolated — one automatically, one deliberately — with encryption limited to roughly 40 minutes of writes on a single file share instead of spreading domain-wide. Recovery came from backup for the affected share only; no full-domain DR failover was needed.

**Without this discipline:** logic that can't distinguish a file server from a domain controller either auto-isolates a DC the instant a false positive matches — a self-inflicted plant-wide outage for no containment benefit — or, if someone reacts to that risk by disabling auto-isolation everywhere, gives up the response speed that made the file-server containment work in the first place.

## Case Study 5 — Recon That Turns Out to Be a Contracted Pentest

Environment: Northgate Insurance, SOAR wired to both the SIEM and the SOC's engagement/change calendar — a system of record for approved pentest windows and signed rules of engagement.

**Trigger:** A correlation rule fires on a chain shaped exactly like the opening moves of a real intrusion: group membership enumeration (4798/4799) from a single host against dozens of accounts, followed by domain trust queries (T1482) and a burst of 4769 requests with RC4 encryption across 30+ SPNs. Default severity mapping would auto-escalate this to P1 and page the CISO.

**Evidence gathered:** All activity traces to host `FRP-ENG-04` authenticating as `t-pentest-fp`: enumeration events (T1087, T1069) plus RC4 ticket requests (T1558.003) plus domain trust discovery (T1482) — a textbook recon-to-Kerberoasting sequence.

**Decision points:** Before firing the auto-disable-and-page action, the playbook queries the engagement calendar for any active record matching the source account, host, and time window, and finds one: engagement `ENG-2026-0914`, contracted through an external pentest vendor, signed rules of engagement covering 2026-09-13 through 2026-09-20, explicitly scoping account enumeration and Kerberoasting-style testing against the designated account `t-pentest-fp`. The playbook suppresses the auto-disable step, downgrades the case to a logged validation record, and routes notification to the SOC lead for awareness rather than paging the CISO.

The calendar match is necessary but not sufficient. The analyst still checks that the account, host, and technique set actually fall inside what was scoped — not just that some engagement exists that week. If the same host had also touched the claims-payment system, which wasn't in scope, suppression would not apply and the case would escalate normally regardless of the calendar hit.

**[MANAGEMENT]** - this only holds together if someone owns keeping the calendar current and specific. A vague entry like "pentest this week, various systems" defeats the point — the automation needs account, host, and technique granularity to make a safe suppression decision, not just a date range.

**Outcome:** Disposition logged as Benign Positive — the attacker-pattern behavior was real, the actor was authorized. The tester's engagement continued uninterrupted, with the case and engagement record sitting in the audit trail in case anyone later asks why 30 SPNs got Kerberoasted that week and nothing happened.

**Without this discipline:** the automation disables the tester's account mid-engagement and pages the CISO over sanctioned, paid-for testing — at minimum wasted engagement hours, and if it happens more than once, exactly the kind of false alarm that trains a SOC to second-guess its own automation right when a real recon chain shows up looking identical.

## What These Five Have in Common

None of them needed a smarter correlation model or a bigger playbook library. Cases 1 and 2 needed a gate in the right place — and a recognition that "gate everything" and "gate nothing" are both wrong, just for different assets. Case 3 needed a state check the first version of the playbook never had. Case 4 needed a tag the automation was willing to trust, and a process to keep that tag honest. Case 5 needed a second system of record the SOAR was allowed to ask before acting, and an analyst willing to double-check the answer instead of rubber-stamping it. That's most of what separates automation that scales from automation that eventually breaks something on its own.
