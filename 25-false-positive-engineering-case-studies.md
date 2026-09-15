# False Positive Engineering — Worked Case Studies

The chapter covered the disposition taxonomy, the tuning lifecycle, and the cost model behind chasing (or not chasing) noise. This companion file skips past that and drops you into six alerts the way they'd actually land in a queue — partial evidence, a deadline, someone in Slack asking "is this real?" Each one closes with a disposition and a one-line gut-check on what happens if the discipline isn't there.

---

## Case Study 1: The Lockout Storm That Wasn't an Attack

**Alert:** "Distributed Account Lockout — Possible Password Spraying" (maps to T1110.001) fires when a single account locks out across more than five hosts inside ten minutes.

**Trigger account:** `svc-backup-01`, a domain service account used by a nightly backup job scheduled on 41 file servers.

### Evidence Gathered

| Source | Finding |
|---|---|
| 4740 (account locked out) | 41 separate lockout events, `Caller Computer Name` populated with 38 distinct hostnames — not one attacking source |
| 4625 (failed logon), Sub Status | All `0xC000006A` — bad password, none `0xC0000064` (unknown user), none from unrecognized accounts |
| 4776 (NTLM validation) | Failures cluster in a four-minute window matching the backup scheduler's start time, repeated exactly 24 hours later at the same minute mark |
| Password policy record | `svc-backup-01` password was rotated by the identity team nine hours before the first lockout |

### Reasoning

A real Password Spraying run usually comes from one or a small number of source IPs, hits at irregular intervals, and mixes in a few `0xC0000064` (unknown account) hits as the attacker tries variants. Here every failure is the same account, from hosts that legitimately run the backup job, timed to a cron-equivalent scheduler rather than attacker cadence. The tell that closed it fast: failures started *after* a scheduled credential rotation and stopped the moment the new password reached the Group Policy Preference item storing it. The rotation job updated the vault copy but not every server's cached scheduled-task credential.

**[ENGINEERING]** - The detection logic itself was sound; the gap was correlation. Adding a suppression join against the identity team's password-rotation change calendar (rotation event within the last 24 hours for the locked account) turns this from a ten-minute page into a zero-touch auto-close with a note.

### Outcome

**Benign Positive**, closed as expected activity tied to a credential rotation gap. Root cause ticket opened against the backup job owner to update the stored credential on all 41 hosts, not just the vault record.

**What goes wrong without this discipline:** the analyst either dismisses the storm as "just the backup job again" without checking sub-status codes — missing the one host with a `0xC0000064` from a nonexistent account, the real password-spraying attempt hiding in the noise — or escalates it as active brute force and forces an unscheduled reset on a production service account, breaking backups for a night over nothing.

---

## Case Study 2: Kerberoasting Alert on a Legacy Print Management Account

**Alert:** "High-Volume RC4 Service Ticket Requests" (T1558.003) fires when a single account requests service tickets for more than ten distinct SPNs within an hour using RC4 encryption.

**Trigger account:** `svc-print-mgr`, tied to a hospital's print release and job-accounting software running on `PRINTSRV02`.

### Evidence Gathered

- 4769 events: Account Name `svc-print-mgr`, Ticket Encryption Type `0x17` (RC4) on every request, Client Address consistently `10.40.12.15` (PRINTSRV02's own IP, not a workstation)
- SPN targets: 14 distinct printer-queue SPNs, all under the same naming convention (`HP-PrintSvc/*`), no SPNs outside the print environment
- Timing: requests spread evenly across the 08:00–18:00 shift, matching print volume, not a single burst
- Vendor documentation confirms the print accounting suite does not support AES for ticket encryption — it's a known limitation of the ten-year-old release still in use

**[ANALYST]** - An attacker harvesting tickets for offline cracking typically requests a wide, unrelated set of SPNs from a workstation with no business reason to touch most of them, often in a short burst. This account requested a narrow, topically consistent set of SPNs, from the service's own host, at a rate matching real business volume. RC4 alone is not the finding — RC4 plus broad, indiscriminate SPN enumeration from an atypical source is.

### Outcome

**Benign Positive**, logged as a known legacy exception. Engineering added the account to a tracked exception list scoped narrowly to *this account, this source host, this SPN prefix* — not a blanket suppression of RC4 ticket alerts.

**What goes wrong without this discipline:** a blanket "RC4 is old software, ignore it" rule gets written once, and six months later a real kerberoasting attempt against `svc-sql-reporting` — a different account, requesting SPNs it has no business touching — sails through under the same suppression because nobody scoped the exception tightly enough.

---

## Case Study 3: Obfuscated PowerShell From the Patch Management Tool

**Alert:** "Encoded PowerShell Execution" (T1059.001 / T1027) fires on 4104 script block content containing a base64 blob passed via `-EncodedCommand`.

### Evidence Gathered

- 4104 script block log: full decoded content is an application install routine referencing `Contoso-InventoryAgent-v4.2.1.msi`
- 4688 process creation: `New Process Name` = `powershell.exe`, `Creator Process Name` = `ccmexec.exe` (the SCCM client service), Subject = `NT AUTHORITY\SYSTEM`
- Change record: CAB-approved change ticket #CHG-11402 scheduled the same package for deployment to the Finance OU that night
- Timing: execution across 212 endpoints within a 40-minute deployment window, matching the SCCM collection's staggered rollout, not a single host

### Reasoning

The base64/`-EncodedCommand` pattern by itself says nothing about intent — plenty of legitimate deployment tooling encodes payloads to survive command-line length limits and quoting issues, not to evade detection. What separates this from a real obfuscation-for-evasion case is the parent process lineage and the corroborating change record. `ccmexec.exe` spawning PowerShell with a decodable, benign-content script block, matching an approved change, is a different animal from an encoded blob launched from `winword.exe` or `mshta.exe` decoding to a download-and-execute cradle.

**[ENGINEERING]** - The fix isn't "trust anything ccmexec.exe launches" — that would blind the SOC to an attacker who compromises the SCCM service account and reuses the same legitimate parent process to push a malicious package. The tuned rule requires known management parent process **and** decoded content hash matches an approved package **and** timing falls inside a logged change window. Any one of those three failing routes back to full review.

```text
// pseudo-detection logic, engineering reference only
4104 where ScriptBlockText contains "-EncodedCommand"
| decode base64 payload
| join ChangeRecords on TimeWindow, TargetOU
| where ParentProcess in (KnownMgmtAgents) 
      and DecodedContentHash in (ApprovedPackageHashes)
      and ChangeRecord.Status == "Approved"
| classify as ExpectedActivity, else escalate
```

### Outcome

**Expected Activity**, closed against the change ticket. No tuning suppression was applied to the base rule — only the layered logic above was added.

**What goes wrong without this discipline:** analysts get tired of the 2 a.m. pages and either whitelist the SCCM service account wholesale (removing visibility the day someone abuses it) or escalate a routine patch push as a live incident, waking a manager for nothing — twice a month, forever.

---

## Case Study 4: Impossible Travel on a Cloud Admin Account

**Alert:** "Impossible Travel — Concurrent Sign-Ins" (T1078.004) fires when a user authenticates successfully from two locations that can't be reconciled by normal travel time.

### Evidence Gathered

**[ANALYST]** - Two successful sign-ins for `j.ortega@contoso.example.com`, six minutes apart. First from an IP geolocating to Ashburn, Virginia, resolving to Contoso's corporate VPN egress range. Second from an IP geolocating to Reston, Virginia (roughly 15 miles away, but flagged because the platform's IP-to-location database placed it in a different metro bucket), resolving to a mobile carrier NAT gateway. Both used MFA push approval from the same enrolled device ID — one over the corporate VPN tunnel from a docked laptop, one over the phone's own carrier connection a few minutes later after the user undocked and walked to a meeting.

| Check | Result |
|---|---|
| Device ID on both sessions | Matches single enrolled corporate device (phone Authenticator app instance) |
| MFA method | Push, approved, no denials or fatigue pattern (single prompt each) |
| New mail forwarding rule (T1114.003) | None created |
| New app registration / OAuth consent | None |
| Session token anomalies | None — both are fresh interactive sign-ins, not token replay |

### Reasoning

The distinguishing question for impossible-travel alerts on VPN-heavy or carrier-NAT-heavy populations isn't "did two IPs disagree" — geolocation databases for VPN exit nodes and carrier NAT ranges are notoriously imprecise and shift metro attribution without any real distance traveled. The real question is whether the *authentication factors* tell a consistent story: same registered device, MFA approved without a fatigue pattern (no chain of denied-then-approved prompts, the actual red flag for MFA-bombing), and no follow-on account manipulation. All three came back clean.

**[MANAGEMENT]** - This account carries Global Administrator rights in the tenant, which is exactly why the alert fired at High severity and got a full review rather than an auto-close, even though the eventual finding was benign. That's the correct trade — the cost of one extra ten-minute review on a privileged account is cheap next to the cost of missing the one time it's real.

### Outcome

**Benign Positive** — attributed to VPN egress and mobile carrier NAT geolocation imprecision. A tuning ticket was raised to down-weight impossible-travel scoring specifically when both source IPs resolve to either the corporate VPN egress range or a small set of known carrier NAT ranges used by staff mobile plans, rather than suppressing the rule for the account.

**What goes wrong without this discipline:** the team gets three of these a week for VPN users and starts auto-dismissing "impossible travel" as a category — precisely the alert that would catch a stolen session cookie (T1550.004 Web Session Cookie) replayed from attacker infrastructure while the legitimate user is still at their desk.

---

## Case Study 5: New Service Installed Across an Entire OU

**Alert:** "Suspicious Service Installation" (T1543.003) fires on 7045 (System log) correlated with 4697 (Security log) for a service with a non-standard image path.

### Evidence Gathered

- 7045 across 89 workstations in the "Branch-Retail" OU within a 12-minute window: `Service Name = RemoteAssistAgent`, `Image Path = C:\ProgramData\RMMVendor\agent\rmm_svc.exe`
- 4697 on the same hosts: `Service Type = Win32OwnProcess`, `Start Type = Auto`, `Service Account = LocalSystem`
- Deployment source: all installs traced via 4688 parent process to `msiexec.exe` invoked by the existing RMM console under a change record for a vendor agent upgrade
- Binary check: `rmm_svc.exe` is signed with a valid certificate from the RMM vendor, hash matches the vendor's published release for the version in the change ticket

### Reasoning

**[ENGINEERING]** - The rule exists to catch exactly this shape of behavior when it's *not* sanctioned — a new auto-start service dropped simultaneously across many hosts is a classic mass-deployment persistence pattern, whether it's a legitimate RMM push or an attacker pushing an implant through a compromised management platform. The differentiator isn't the fan-out pattern itself; it's the combination of a valid vendor signature matching a known-good hash, a `LocalSystem` account consistent with documented install behavior, and an open change record naming this exact upgrade. Strip any one of those away — unsigned binary, unexpected service account, no change record — and this becomes a much more urgent conversation about whether the RMM platform itself has been compromised.

### Outcome

**Expected Activity**, closed against the change record. No suppression was applied to the base 7045/4697 correlation rule — mass service deployment stays a reviewed event every time; only the specific hash/signer combination for this vendor release was added to a time-boxed allowlist tied to the change ticket's window, expiring automatically after 48 hours.

**What goes wrong without this discipline:** a permanent allowlist entry for "any service signed by RMMVendor" would still be sitting there a year later, and it would wave through the day an attacker compromises the RMM vendor's supply chain and ships a signed-but-malicious update — a scenario the industry has seen play out for real with legitimate management tooling.

---

## Case Study 6: DNS Volume Spike Mistaken for Tunneling

**Alert:** "High-Entropy DNS Query Volume" (T1071.004) fires when a single host generates an unusual volume of DNS queries to high-entropy subdomains under one parent domain.

**Trigger host:** `WKSTN-FIN-22`, a finance department laptop.

### Evidence Gathered

| Field | Value |
|---|---|
| Query pattern | Thousands of queries per hour to subdomains like `a1f9c3e7.chunks.backupvendor-cdn.example.com` |
| Record types | Almost entirely A records resolving to a small, stable set of CDN IPs; no TXT or NULL record abuse, no oversized query names |
| Resolved IP ownership | ASN and IP ranges consistently attributed to the known backup vendor's published CDN infrastructure |
| Timing | Exact match to the nightly backup agent's scheduled dedup-and-sync job (4688 shows `backupagent.exe` as the querying process) |
| Direction of data | Steady bidirectional chunk-pull consistent with deduplicated backup sync, not the small-outbound/large-lookup asymmetry typical of DNS tunneling |

### Reasoning

High-entropy subdomains are a real tunneling and C2 beaconing indicator because attacker tooling frequently encodes data or commands into the subdomain label itself. The confusion here is that content-addressable storage systems — backup dedup engines, some CDN and package-manager clients — also generate high-entropy-looking subdomains because they're hashes of content chunks, not encoded payloads. The differentiator is what's *in* the query beyond the label: legitimate chunk-lookup traffic resolves to a small, stable, well-known set of IPs owned by an identifiable vendor ASN; tunneling traffic either resolves nowhere useful or shows record types and timing that don't match ordinary hostname resolution.

**[ANALYST]** - dont assume high entropy automatically means malicious — check what the query actually resolves to and who owns that infrastructure before writing this off either way. The volume alone got this escalated correctly; the resolution pattern is what closed it.

### Outcome

**Benign Positive**, identified as expected backup-agent chunk deduplication traffic. The rule was tuned to require volume **and** resolution to non-stable or unattributed IP ranges before firing at High severity — the base domain itself was deliberately *not* added to a blanket allowlist.

**What goes wrong without this discipline:** whitelisting the entire parent domain `backupvendor-cdn.example.com` instead of the narrow resolved-IP/ASN condition would let an attacker who registers a look-alike subdomain, or who tunnels traffic through an actually-compromised chunk within the same base domain, walk straight through the exception the SOC built for itself.

---

Six alerts, six different reasons they turned out clean — a rotation gap, a legacy protocol limitation, an approved change, a geolocation artifact, a sanctioned vendor push, a backup job that looks like C2 on paper. None were closed by gut feel, and none were closed by blanket suppression rules that would still be sitting in the rulebase, quietly hiding the next real thing.
