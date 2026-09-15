# Discovery: Network & AD Enumeration Preceding Lateral Movement

Between the moment a ransomware crew lands their first foothold and the moment they start pushing an encryptor to file servers, there's usually a window of hours to days where the operator is quietly mapping the environment. This is the discovery stage. Nobody's data has moved yet, nothing's encrypted, but the affiliate is building a target list: who are the domain admins, which host is the backup server, what talks to what over SMB and RDP. Miss this stage and you're triaging the encryption event instead of stopping it. Catch it, and you've bought yourself the single best chance to contain a ransomware intrusion before it becomes a headline.

The friction here is that almost everything an attacker runs in this phase has a legitimate twin. Help desk staff run `net user` all day. Vulnerability scanners hit every port on the subnet on a schedule. Backup software enumerates shares nightly. Discovery detection isn't about a single command line firing an alert — it's about context: which account, which parent process, which host, what volume, at what hour.

## LDAP / Active Directory Enumeration

**[ANALYST]** - AdFind (and its lookalikes — SharpHound, custom PowerShell LDAP wrappers) is still the most common tool seen in ransomware intrusions for bulk AD reconnaissance, because it's fast, static, and doesn't need .NET reflection tricks that some EDR products flag. Typical command lines seen in the wild:

```
adfind.exe -f "(objectcategory=person)" -csv > users.csv
adfind.exe -f "objectcategory=computer" -csv > computers.csv
adfind.exe -sc trustdmp
adfind.exe -f "(objectClass=group)" -csv > groups.csv
adfind.exe -subnets -f (objectCategory=subnet)
```

The `-sc trustdmp` shortcut is a strong tell — it dumps domain trust relationships, mapped to Domain Trust Discovery (T1482), and legitimate admins almost never run it interactively. Bulk user/computer/group dumps map to Account Discovery (T1087) and Permission Groups Discovery (T1069). Watch for the tool being copied to a temp path (`C:\Users\Public\`, `C:\PerfLogs\`, `C:\Windows\Temp\`) rather than run from an admin's normal toolset — that placement pattern, combined with a parent process of `cmd.exe` or `powershell.exe` spawned from something like a Cobalt Strike beacon or a PsExec session, is far more telling than the binary name alone, since the binary is trivially renamed.

**[ENGINEERING]** - Sysmon Event ID 1 (Process Creation) is the primary source here — it always captures the full command line regardless of whether Windows command-line auditing is enabled for 4688. Hunt on command-line substrings (`objectcategory=`, `trustdmp`, `-sc `) combined with hash allow-listing of known AdFind/SharpHound builds. Cross-reference against 4798 (user's local group membership enumerated) and 4799 (security-enabled local group membership enumerated) — a single source workstation generating dozens of 4798/4799 events against multiple target hosts in a short window is a strong recon signal, independent of tool attribution, because it catches PowerShell-native and .NET-reflected variants that never touch disk as adfind.exe.

## net.exe / net1.exe: The Living-Off-the-Land Workhorse

`net.exe` (and its lesser-known sibling `net1.exe`, which `net.exe` actually calls internally and which attackers sometimes invoke directly to dodge naive `net.exe` string-match rules) remains a staple for cheap, no-tooling-required discovery:

| Command | Purpose | ATT&CK |
|---|---|---|
| `net group "Domain Admins" /domain` | Enumerate privileged group membership | T1069 |
| `net localgroup administrators` | Local admin enumeration on target host | T1069 / T1087 |
| `net view` / `net view \\dc01.corp.example.com` | List shares/hosts visible from source | T1046 |
| `net accounts /domain` | Domain password/lockout policy | T1087 |
| `net use \\fileserver01\backup$` | Confirm share reachability ahead of staging | T1021.002 |

None of these require elevated logging config to see — the process creation event (Sysmon 1, or 4688 with command-line auditing enabled) carries the full argument string. The tell isn't the command, it's the chaining: `net group "Domain Admins" /domain` followed within seconds by `net localgroup administrators \\<host>` against a dozen different hostnames from one workstation Logon ID is a script, not a human typing.

## Port and Service Discovery

Before lateral movement via SMB (T1021.002), RDP (T1021.001), or WinRM, operators typically sweep for live services — SoftPerfect Network Scanner, Advanced IP Scanner, or raw PowerShell `Test-NetConnection` loops against 445, 3389, 5985/5986, and 22 across the subnet. This maps to Network Service Discovery (T1046) and occasionally broader Active Scanning (T1595) if the sweep originates from outside the perimeter (rare post-foothold, more common at initial recon).

**[ENGINEERING]** - Sysmon Event ID 3 (Network Connection) is the workhorse here: alert on a single source process making connections to port 445 or 3389 across more than a threshold of distinct destination IPs (e.g., >15 in 5 minutes) — that's a scan signature regardless of tool. Pair with Event ID 22 (DNS query) volume if the scanner resolves hostnames first from an AD-integrated DNS zone.

```
// pseudo-query, adapt to your SIEM
Sysmon EventID=3
| where DestinationPort in (445, 3389, 5985, 5986)
| summarize DistinctDest=dcount(DestinationIp) by SourceIp, Image, bin(TimeGenerated, 5m)
| where DistinctDest > 15
```

**[MANAGEMENT]** - This detection logic generates false positives against legitimate vulnerability scanners and backup agents; it needs an exception list maintained by IT operations and reviewed quarterly, with SOC owning the alert logic and IT confirming scanner IP ranges — not the reverse.
