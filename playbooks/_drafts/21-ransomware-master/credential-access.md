# Ransomware Master Playbook — Credential Access Stage

## Why This Stage Is the Hinge Point of the Incident

Every ransomware case has a moment where it stops being "a compromised laptop" and becomes "a domain-wide incident." That moment is almost always credential access. Initial access gets an attacker onto one host. Credential access is what lets them stop being a guest on that host and start being an administrator everywhere else. If you catch the incident before this stage, you're doing forensics on a workstation. If you catch it after, you're doing forensics on your entire Active Directory forest, and the clock on backup encryption and domain-wide lateral movement is already running.

This is the stage where an incident commander needs to make a hard call fast: is containment still "isolate the host" or has it already become "assume domain compromise and start planning a credential reset at scale"? Get that judgment wrong in either direction — over-scoping a contained incident or under-scoping a domain-wide one — and you either burn goodwill with the business or you miss the window to stop encryption entirely.

## LSASS Access — The Primary Signal

LSASS (Local Security Authority Subsystem Service) holds cached credential material in memory: NTLM hashes, Kerberos tickets, sometimes plaintext passwords depending on WDigest configuration. Dumping it is the single most common credential harvesting technique observed in ransomware intrusions ahead of domain-wide deployment, mapping to **T1003.001 OS Credential Dumping: LSASS Memory**.

**[ANALYST]** - The core telemetry here is Sysmon Event ID 10 (ProcessAccess) where the target image is `lsass.exe`. Legitimate processes that touch LSASS are a short, boring list (other Microsoft-signed system processes, some EDR agents, certain backup/auth tooling). What you're hunting for is an unusual source process — `taskmgr.exe` with `GrantedAccess` of `0x1410` or `0x1010`, `procdump.exe` (Sysinternals, LOLBin-adjacent), `rundll32.exe`, or a completely unsigned binary — requesting high-privilege access rights to LSASS. Pair this with Sysmon Event ID 1 (Process Creation) for the offending process's full command line and parent chain, and Sysmon Event ID 11 (FileCreate) for any `.dmp` file dropped afterward — attackers frequently dump LSASS to disk with `procdump -ma lsass.exe output.dmp` or via comsvcs.dll's MiniDump export, then exfil the dump for offline parsing rather than running Mimikatz live and tripping AV. Also watch Sysmon 7 (Image Loaded) for known credential-theft-adjacent DLLs loading into unexpected processes.

**[ENGINEERING]** - A workable Sysmon 10 detection filters on TargetImage `lsass.exe` and excludes a signed-process allowlist, then flags on GrantedAccess values associated with `PROCESS_VM_READ`/`PROCESS_QUERY_INFORMATION` combinations:

```
EventID=10
TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1410","0x1010","0x1438","0x143a","0x1fffff")
SourceImage NOT IN (known_good_signed_paths)
```

Correlate that hit against Sysmon 1 for the same ProcessGuid within a short window to pull CommandLine and ParentCommandLine — this is where you separate "EDR agent doing normal telemetry collection" from "unsigned binary staged in `C:\Users\Public` five minutes ago." Also alert on Sysmon 1 command lines matching known dumping tool syntax (`sekurlsa::`, `procdump.*lsass`, `comsvcs.dll.*MiniDump`) regardless of whether the ProcessAccess event fires cleanly — some tooling injects rather than opening a handle the naive way.

## Mimikatz-Style Indicators Beyond the LSASS Handle

Don't anchor detection purely on the LSASS touch — plenty of intrusions never run classic Mimikatz and instead go straight for **T1558.003 Kerberoasting** (mass 4769 requests with RC4 ticket encryption 0x17 against multiple SPNs from one source in a short window), **T1558.001 Golden Ticket**, or **T1003.006 DCSync**, which shows up as directory replication requests from a non-DC account context rather than anything touching LSASS on a workstation at all. If you're only watching for the LSASS handle, DCSync walks right past you.

**[ANALYST]** - For Kerberoasting, pull Event ID 4769 and look at ticket encryption type and request volume per source account — one workstation account requesting service tickets for a dozen SPNs in under a minute is not a normal help-desk pattern. 4104 (PowerShell script block logging) is your other high-value log here — most modern credential-theft tooling ships as an in-memory PowerShell loader before it ever touches disk, so obfuscated or Base64-heavy script blocks referencing reflection, memory patching, or LSASS-adjacent API names deserve a look even before the process-access event fires.

## Harvesting From Browsers and Config Files

**T1552.001 Unsecured Credentials: Credentials In Files** covers the other half of this stage — attackers grabbing saved browser passwords (Chrome/Edge SQLite credential stores), `.rdp` files with cached credentials, `web.config`/`unattend.xml` files, KeePass exports, and plaintext passwords left in scripts or scheduled task definitions. This doesn't need LSASS access at all, which is exactly why it's easy to miss if your detection strategy is LSASS-centric.

**[ANALYST]** - Sysmon 11 (FileCreate) and Sysmon 1 process creation showing access to `%LocalAppData%\Google\Chrome\User Data\Default\Login Data`, PowerShell or `findstr`/`Select-String` sweeps across network shares for strings like `password=`, `unattend.xml`, or `.rdp`, and any process copying browser profile directories to a staging folder are the practical evidence trail. This activity is quiet, doesn't trigger EDR credential-dumping heuristics tuned for Mimikatz, and is routinely the actual source of the domain admin credential that ends the single-host phase of the incident.

## Why This Turns One Host Into the Whole Domain

**[STAKEHOLDER]** - Up to this point the business risk is bounded — one machine, one user's blast radius. Once a credential with domain-wide reach (a cached admin session, a service account, a domain admin token) is harvested, the attacker can move to any system that credential can touch, including domain controllers and backup infrastructure. This is the decision point where "monitor and contain" needs to become "assume compromise across the estate" and where the business should expect scope, cost, and downtime estimates to change materially.

**[MANAGEMENT]** - This is the trigger for escalating to full incident status if not already there: mandate a forced credential reset scope decision (which accounts, in what order, Kerberos ticket invalidation via krbtgt reset where DCSync/Golden Ticket is suspected), assign an owner for the AD-wide password reset exercise, and set the expectation with leadership that "contained" and "eradicated" are not the same milestone — a harvested privileged credential that hasn't been rotated yet means the attacker can walk back in through a different door even after the original host is wiped.
