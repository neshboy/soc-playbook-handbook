# Part 19 — Playbook Queries Across SIEM Platforms

Every playbook earlier in this book was written in platform-neutral language on purpose — "alert when an account fails authentication several times then succeeds" reads the same whether you run Splunk, Sentinel, QRadar, or something homegrown. But someone has to turn that sentence into a query that a real engine will actually execute, and that translation is where a surprising amount of SOC time disappears. Field names differ, timestamp handling differs, aggregation syntax differs, and the same logical detection can look completely unrecognizable moving from one platform to another.

This part takes six of the signature detections referenced throughout the book and shows a worked query for each, deliberately spread across six different query languages: Microsoft Sentinel KQL, Splunk SPL, Google SecOps/Chronicle YARA-L, Elastic ES|QL, IBM QRadar AQL, and a vendor-neutral SQL example for teams running a log warehouse or a SIEM with a SQL-like query layer. None of these are drop-in production rules — every environment has different field mappings, retention, and noise profile — but each is close enough to real syntax that you can adapt it directly.

| # | Detection | Platform used here | Primary technique(s) |
|---|-----------|--------------------|------------------------|
| 1 | Failed-then-successful logon | Splunk SPL | T1110.001, T1078.002 |
| 2 | Encoded PowerShell from an Office app | Microsoft Sentinel KQL | T1204, T1059.001, T1027 |
| 3 | Impossible travel sign-in | Google SecOps / Chronicle YARA-L | T1078.004 |
| 4 | Kerberoasting-pattern ticket volume | IBM QRadar AQL | T1558.003 |
| 5 | Mass file rename (ransomware) | Elastic ES\|QL | T1486, T1490 |
| 6 | DNS-based beaconing | Generic SQL | T1071.004 |

## 1. Failed-Then-Successful Logon (Splunk SPL)

This is the bread-and-butter brute-force / password-spray detection most SOCs stand up in their first month. The logic sounds trivial — several 4625s followed by a 4624 for the same account — but the tuning is not: a help-desk password reset produces the exact same pattern as a successful spray, and the difference is context, not shape.

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval outcome=if(EventCode=4625,"fail","success")
| bin _time span=15m
| stats
    count(eval(outcome="fail")) as fail_count
    min(eval(if(outcome="fail",_time,null()))) as first_fail_time
    max(eval(if(outcome="success",_time,null()))) as success_time
    values(Source_Network_Address) as src_ips
    dc(Source_Network_Address) as src_ip_count
    values(Logon_Type) as logon_types
    by Account_Name, _time
| where fail_count >= 5 AND success_time > first_fail_time
| sort - fail_count
```

The query pulls both the failure event (4625, with its `Failure Reason` / sub status codes such as `0xC000006A` for bad password) and the success event (4624), tags each row, then buckets into 15-minute windows per account. `fail_count >= 5` with a success timestamp landing after the first failure inside the same window is the actual detection condition. `dc(Source_Network_Address)` matters more than it looks — five failures from one source IP followed by a success from that same IP reads very differently to an analyst than five failures spread across five source IPs (spray) followed by a success from a sixth. `Logon_Type` differentiates an interactive console logon (3389/RDP-style, type 10) from a network logon (type 3), which changes the response playbook entirely.

**[ANALYST]** - Before escalating, pull the account's normal logon behavior for the prior 30 days: does it normally authenticate from this source at this time of day? Check whether the failures carry sub status `0xC000006A` (wrong password — consistent with guessing/spray) versus `0xC0000064` (account doesn't exist — consistent with username enumeration hitting a real account by chance) versus `0xC0000234` (locked out — the "success" may actually be a 4767 unlock, not a real logon, so don't assume the pattern means what it looks like without reading the raw events). Also check `Caller Process Name` on the 4625s; automated scanning tools often show up as an unusual or unsigned process rather than `lsass.exe`/`winlogon.exe`.

**[ENGINEERING]** - Suppress or down-weight service accounts that legitimately fail and retry on password rotation, and exclude known VPN concentrators or NAT gateway IPs unless you can get the true client IP through XFF-equivalent headers upstream. Without that exclusion this rule turns into a permanent low-confidence firehose.

## 2. Encoded PowerShell Spawned by an Office Application (Microsoft Sentinel KQL)

Phishing → macro → encoded PowerShell is still one of the most common initial-access chains SOCs see, and it maps cleanly to logging most environments already have if command-line auditing is enabled: 4688 for the process creation itself, with a lookup to 4104 (PowerShell script block logging) if you need the deobfuscated payload as evidence.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell.exe"
| where ParentProcessName has_any ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE")
| where CommandLine has_any ("-enc", "-EncodedCommand", "-e ", "FromBase64String", "-w hidden", "-nop")
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine, NewProcessId, SubjectUserName
| order by TimeGenerated desc
```

This filters 4688 events down to PowerShell processes whose parent is an Office application — a parent/child relationship that essentially never happens in normal use, since Office documents don't legitimately spawn a shell. The `CommandLine` filter catches the common encoding switches attackers use to dodge simple string-matching detections and static AV signatures. `NewProcessId` and `Computer` are carried forward specifically so an analyst can pivot to the corresponding 4104 events on the same host to recover the actual decoded script content. That pivot query looks different from the one above, and it's worth knowing why: 4104 (PowerShell script block logging) is written to the `Microsoft-Windows-PowerShell/Operational` log, not the Security log, so it never lands in the `SecurityEvent` table at all — it comes in through a separate Windows Event data collection rule into the generic `Event` table (or a dedicated PowerShell-events table, depending on how the workspace is onboarded). Querying `SecurityEvent` for EventID 4104 will silently return nothing, which reads exactly like "no script block was logged" even when the real explanation is "wrong table." A closer-to-real version looks like:

```kql
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where Computer in ("fin-ws-0231.corp.example.com")
| where TimeGenerated between (datetime(2026-09-15T09:00:00Z) .. datetime(2026-09-15T09:10:00Z))
| extend ScriptBlockText = tostring(parse_xml(EventData).UserData.EventXML.ScriptBlockText)
| project TimeGenerated, Computer, ScriptBlockText
```

**[ANALYST]** - Command-line auditing has to be enabled group-policy-wide for `CommandLine` to populate on 4688 at all — if the field is consistently blank across an estate, that's a logging gap to raise, not evidence the activity didn't happen. Confirm PowerShell script block logging is separately enabled and actually being collected into the SIEM before relying on the 4104 pivot — it's a different group policy setting and a different ingestion path from the 4688 pipeline above, and it's common for one to be enabled without the other. Also confirm the parent Office process itself was launched from a document open event (email attachment, browser download) rather than, say, a legitimate internal macro-based tool your organization actually uses — some finance and reporting workflows still rely on VBA that shells out, and those need a documented exception rather than a daily false positive.

**[ENGINEERING]** - `-enc`/`-EncodedCommand` matching is trivially defeated by splitting the flag across variables or using alternate casing/abbreviation (`-e`, `-EnC`), so treat this as a first-pass filter, not a complete control — pair it with 4104 script block content inspection for `FromBase64String`, `IEX`, `DownloadString`, and similar patterns that survive minor obfuscation. This chain maps to Obfuscated Files or Information as the technique behind the evasion attempt, and User Execution as the technique that got the payload running in the first place.

## 3. Impossible Travel Sign-In (Google SecOps / Chronicle YARA-L)

Impossible travel lives in identity/cloud sign-in logs rather than Windows Security events, so this example runs against Chronicle's Unified Data Model instead. The core idea: the same user authenticates successfully from two locations that are geographically inconsistent with the time elapsed between them.

```yara-l
rule impossible_travel_signin {
  meta:
    author = "SOC Handbook"
    description = "Same user authenticates from two different countries within an implausible window"
    severity = "High"
    mitre_technique = "T1078.004"

  events:
    $login1.metadata.event_type = "USER_LOGIN"
    $login1.security_result.action = "ALLOW"
    $login1.principal.user.userid = $user
    $login1.principal.location.country_or_region = $country1
    $login1.metadata.event_timestamp.seconds = $t1

    $login2.metadata.event_type = "USER_LOGIN"
    $login2.security_result.action = "ALLOW"
    $login2.principal.user.userid = $user
    $login2.principal.location.country_or_region = $country2
    $login2.metadata.event_timestamp.seconds = $t2

    $country1 != $country2
    $t2 > $t1
    $t2 - $t1 < 3600

  match:
    $user over 1h

  outcome:
    $risk_score = max(65)

  condition:
    $login1 and $login2
}
```

The rule keys everything on `$user` and looks for a pair of successful `USER_LOGIN` events for that same principal where the recorded countries differ and the gap between them is under an hour (3600 seconds) — not enough time to physically travel between most country pairs, hence "impossible." This is a deliberately simplified version of impossible-travel logic; production implementations usually compute actual great-circle distance from lat/long and derive a required minimum travel speed, rather than a flat country-mismatch-plus-time-window rule, because a flat rule like this one will still fire on legitimate cases.

**[STAKEHOLDER]** - This detection exists because credential theft rarely announces itself — the attacker has a valid username and password and simply logs in like the real user would. Impossible travel is one of the few reliable ways to catch that without waiting for the attacker to do something destructive. The business risk it reduces is account takeover leading to data access or fraud under a legitimate identity, which is exactly the kind of incident that's hard to explain to a regulator after the fact. Decision on whether to require step-up MFA or an automatic session revocation on a match is a policy call for identity/security leadership, not something the SOC decides unilaterally mid-incident.

**[ANALYST]** - The most common false positive by far is corporate VPN or cloud proxy egress — a user in London whose traffic exits through a US data center will look like they signed in from the US a minute later. Check the egress IP against known corporate NAT/proxy ranges before treating this as travel at all. Mobile carrier IP reassignment and stale DNS-based geolocation on the identity provider's side are the next two most common causes. Genuine confirmed account takeover from this pattern is real but less common than the noise suggests — expect a fair number of closures as Benign Positive once the VPN egress is identified.

## 4. Abnormal Kerberos Service-Ticket Volume — Kerberoasting (IBM QRadar AQL)

Kerberoasting abuses the fact that any authenticated domain user can request a service ticket (event 4769) for any account with a Service Principal Name, then attempt offline cracking against the ticket's encrypted portion. The volume signal is the request pattern, not any single ticket.

```sql
SELECT
  "Account Name" AS requestor,
  "Client Address" AS source_ip,
  COUNT(*) AS ticket_requests,
  UNIQUECOUNT("Service Name") AS distinct_services
FROM events
WHERE "Event ID" = 4769
  AND "Ticket Encryption Type" = '0x17'
  AND "Service Name" NOT LIKE 'krbtgt%'
LAST 1 HOURS
GROUP BY requestor, source_ip
HAVING distinct_services >= 8
ORDER BY distinct_services DESC
```

This filters 4769 (Kerberos service ticket requested) down to `Ticket Encryption Type` `0x17` — RC4 — which is the encryption downgrade Kerberoasting tools rely on because RC4-encrypted tickets are far cheaper to brute-force offline than AES-encrypted ones. `krbtgt` requests are excluded because those are routine TGT-related renewal traffic, not service-ticket requests against real SPNs. Grouping by requesting account and source IP over a trailing hour, then filtering to accounts that touched eight or more distinct service names, catches the enumerate-every-SPN-in-the-domain behavior that tools like Rubeus or PowerView-style SPN sweeps produce — a normal user authenticates to two or three services a day at most, not eight-plus in an hour.

**[ENGINEERING]** - The threshold of eight distinct services in an hour is a starting point, not gospel — baseline it against your own directory first. Backup software, vulnerability scanners, and monitoring agents that walk service accounts across many SPNs for health checks are the classic false-positive source, and they need an explicit allowlist by account or source host rather than a blanket exclusion of RC4, since disabling RC4 detection wholesale blinds you to the exact technique you're trying to catch. If your domain has already moved to AES-only Kerberos encryption, this specific RC4 filter won't catch anything — watch for a shift to encryption type `0x11` (AES128) or `0x12` (AES256) combined with the same request-volume pattern instead, since attackers adapt to what the domain actually issues.

**[MANAGEMENT]** - This rule should have an explicit owner in the identity/AD engineering team as well as the SOC, because tuning it correctly requires visibility into which service accounts are supposed to be walked by legitimate tooling — that's directory knowledge the SOC doesn't own. Review the allowlist quarterly at minimum, and any SPN sweep alert against a Tier-0 service account (domain controllers, backup infrastructure, PKI) should carry an SLA tighter than the default, given how directly it feeds Steal or Forge Kerberos Tickets.

## 5. Mass File Rename Consistent With Ransomware (Elastic ES|QL)

By the time this fires, encryption may already be underway on the affected host — this detection is a damage-control tripwire, not a prevention control, and it should sit alongside earlier behavioral/EDR-based blocking rather than replace it. It works off endpoint file events rather than Windows Security log IDs, since file rename activity isn't captured by 4688.

```esql
FROM logs-endpoint.events.file-*
| WHERE event.action == "rename" AND file.extension IS NOT NULL AND user.name != "SYSTEM"
| EVAL minute_bucket = DATE_TRUNC(1 minute, @timestamp)
| STATS
    rename_count = COUNT(*),
    distinct_dirs = COUNT_DISTINCT(file.directory),
    extensions_seen = VALUES(file.extension)
  BY host.name, user.name, minute_bucket
| WHERE rename_count >= 50
| SORT rename_count DESC
```

The query buckets file rename events into one-minute windows per host and user, counting renames, distinct directories touched, and the set of resulting extensions. Fifty-plus renames in a single minute from one user session, spread across many directories, is well outside normal user or application behavior — even a bulk file operation a person triggers manually rarely produces that rate. `extensions_seen` gives the analyst an immediate look at whether a consistent new extension (a fabricated one like `.locked` or `.enc`, or a random-looking string many families use) is appearing across the renamed files, which is strong corroborating evidence over a coincidental spike from, say, a sync client or backup job doing legitimate bulk file operations.

**[ANALYST]** - Isolate the host from the network first and ask questions second — this is one of the few alert types where speed matters more than certainty, because the cost of a false positive (a legitimate bulk job gets interrupted) is much lower than the cost of a false negative (encryption completes across a file share). Collect the process holding file handles during the burst — that process is almost certainly the encryptor itself, and its full path, hash, and parent process are the evidence that drives containment of every other host that process touched. Also check for a preceding 4697 or 7045 service install event around the same time — many ransomware families install a service or disable shadow copies immediately before or during the encryption run, which corroborates Inhibit System Recovery and gives you a second host-level indicator beyond the file event burst itself.

**[MANAGEMENT]** - This detection should trigger an automated or one-click isolation action, not a queued alert reviewed on the analyst's normal cadence — the response SLA here should be measured in minutes, not the standard triage window used for lower-severity categories. Any tuning that raises the threshold above what a genuine incident would produce needs sign-off above analyst level, since the tradeoff is explicitly speed-of-detection against noise.

## 6. DNS-Based Beaconing (Generic SQL)

Malware calling home over DNS shows up as a steady drumbeat of queries to the same domain at a near-constant interval, which is a very different shape from how humans and normal applications generate DNS traffic — bursty, irregular, and driven by page loads or scheduled jobs rather than a fixed clock. This example runs against a plain DNS query log table, useful for any warehouse-backed SIEM or a log lake queried with standard SQL.

```sql
SELECT
    src_ip,
    query_name,
    COUNT(*) AS query_count,
    AVG(interval_to_next) AS avg_interval_seconds,
    STDDEV(interval_to_next) AS interval_stddev
FROM (
    SELECT
        src_ip,
        query_name,
        query_time,
        DATEDIFF(second, query_time,
            LEAD(query_time) OVER (PARTITION BY src_ip, query_name ORDER BY query_time)
        ) AS interval_to_next
    FROM dns_logs
    WHERE query_time >= DATEADD(hour, -24, GETUTCDATE())
) t
GROUP BY src_ip, query_name
HAVING COUNT(*) >= 100
   AND AVG(interval_to_next) BETWEEN 55 AND 65
   AND STDDEV(interval_to_next) < 5
ORDER BY query_count DESC;
```

The inner query uses a window function (`LEAD`) to compute the gap, in seconds, between each DNS query and the next one to the same domain from the same source host. The outer query aggregates that over a trailing 24-hour window and flags source/domain pairs with at least 100 queries where the average interval sits tightly around 60 seconds (`55`–`65`) with a low standard deviation — a signature of a beacon on a fixed sleep timer rather than organic traffic, where intervals would swing wildly. Adjust `DATEADD`/`GETUTCDATE` to your platform's date-function dialect — the logic is the same everywhere, the syntax for "give me the last 24 hours" is one of the more annoying inconsistencies between SQL engines.

**[ENGINEERING]** - Fixed-interval detection like this is easy for malware authors to defeat with jitter (randomizing sleep time by even ±20%), so don't rely on it alone — pair it with a rarity check against a passive DNS or threat-intel domain-age feed, and with NXDOMAIN ratio (a domain-generation-algorithm beacon burns through a lot of dead domains before landing on a live C2 hostname) or long/high-entropy subdomain labels, which point toward DNS tunneling rather than plain beaconing. Both variants fall under Application Layer Protocol: DNS as the covering technique; if the payload volume per query looks unusually large for a lookup, treat it as possible tunneling and escalate the analysis rather than closing it as routine beaconing.

**[ANALYST]** - Before opening a full investigation, rule out legitimate polling behavior — software update checks, telemetry clients, and some SaaS agents genuinely poll on a fixed interval and will trip this exact pattern. Cross-reference the queried domain against known-good vendor domains and internal asset inventory for what's installed on that host before assuming malicious C2; a fair number of these close as Expected Activity once the polling client is identified, and that's a normal, correct outcome, not a failure of the detection.

## Reading These Queries as a Set

None of these six examples are meant to be copy-pasted into production untouched — every one of them needs baseline tuning against your own environment's normal traffic before it goes anywhere near an analyst's queue. What's worth taking from the set as a whole is the pattern underneath the syntax: nearly every detection here reduces to the same three moves — filter to the events that matter, group by the entity you care about (account, host, source IP, domain), and set a threshold or window that separates the shape of an attack from the shape of normal use. That structure holds whether you're writing SPL, KQL, AQL, YARA-L, ES|QL, or plain SQL; only the verbs change. If you're building a new detection and you're stuck on syntax, start by writing the logic in plain English the way the playbook itself would state it, then translate — it's much easier to spot a wrong `GROUP BY` than to spot a wrong idea wearing correct syntax.
