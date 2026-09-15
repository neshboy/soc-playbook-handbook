# Linux Log Reference — Authentication & SSH Evidence

Every SOC playbook that touches a Linux fleet eventually runs into the same wall: analysts trained on Windows Security event logs open a Linux auth log for the first time and it just looks like a wall of text. No Event ID column, no neat XML, no Sysmon-style process trees. It's plain text, it's syslog-formatted, and half the useful context lives in a separate file (or a separate journal) that nobody remembers to check. This section is the field reference you actually pull up mid-incident: where the evidence lives per distro, what a normal line looks like versus a suspicious one, and how to read it for the three cases that come up constantly — brute force, unauthorized user creation, and sudo/SUID privilege escalation.

## Where the Evidence Actually Lives

Linux doesn't have one universal auth log path. It splits along distro family lines, and getting this wrong wastes the first ten minutes of an investigation.

| Distro family | Primary auth log path | Notes |
|---|---|---|
| Debian, Ubuntu, and derivatives | `/var/log/auth.log` | Rotated by `logrotate`, typically `auth.log.1`, `auth.log.2.gz`, etc. |
| RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux | `/var/log/secure` | Same rsyslog-style format, different filename by convention |
| SUSE (openSUSE, SLES) | `/var/log/messages` — no dedicated auth log by default | The default rsyslog config on SUSE-family distros doesn't split the `auth`/`authpriv` facility into its own file the way Debian and RHEL do; `sshd`/`sudo`/`su` lines sit mixed in with everything else unless someone has reconfigured rsyslog. Do not assume `/var/log/auth.log` or `/var/log/secure` exist here just because they exist on other families. |
| Any systemd-based distro (regardless of family) | journald (query via `journalctl`) | Auth events tagged under the `sshd`, `sudo`, `su`, `polkit` identifiers; binary format, not plain text |
| Containers / minimal images (Alpine, distroless) | Often **no persistent auth log at all** | BusyBox syslog or no syslog daemon running; SSH is frequently disabled entirely |

**[ANALYST]** - First thing to confirm on any Linux host: which family it belongs to (`cat /etc/os-release`) and whether the box uses rsyslog writing flat files, journald only, or both. A lot of modern distros run journald as the primary log store and then have rsyslog configured to also write `/var/log/auth.log` or `/var/log/secure` from the journal — so on those hosts the two sources should roughly agree. If they don't agree, or the flat file is suspiciously short or missing entries you can see in `journalctl`, that's a sign of log tampering, a misconfigured rsyslog rule, or an attacker who cleared the flat file but couldn't (or didn't bother to) touch the journal.

**[ENGINEERING]** - If you're shipping these logs to a SIEM, standardize on parsing `journalctl -o json` output where journald is present — it gives you structured fields (`_PID`, `_COMM`, `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`) instead of regexing free text. Fall back to flat-file syslog parsing only for hosts where journald isn't persistent (`Storage=volatile` in `journald.conf`, common on cloud images to save disk) or isn't installed at all.

## journalctl for Auth Investigation

On any systemd host, this is your fastest path to auth evidence, and it survives log rotation gaps that flat files don't.

```bash
# All SSH daemon activity
journalctl -u sshd --since "2026-09-14 00:00:00" --until "2026-09-15 06:00:00"

# All sudo activity for a specific user
journalctl _COMM=sudo | grep 'analyst_jsmith'

# Everything tagged as auth-facing, structured output for parsing
journalctl -t sshd -t sudo -t su -o json-pretty --since "-24h"

# Cross-reference by process ID once you have a suspicious PID
journalctl _PID=18422
```

**[ANALYST]** - `journalctl` retains history across log rotation in a way flat files sometimes don't (depends on `journald.conf` retention settings — `SystemMaxUse`, `MaxRetentionSec`). If `/var/log/auth.log.1.gz` has already rolled off disk under retention pressure, the journal may still have it, especially if it's persisted to `/var/log/journal/`. Always check `journalctl --disk-usage` and `journalctl --list-boots` early — if the host has rebooted since the suspected activity, you need to explicitly query across boots with `-b 0`, `-b -1`, etc., because the default view is often just the current boot.

## SSH Logs: What Normal and Suspicious Look Like

SSH auth events are written by `sshd` regardless of distro, so the line format is consistent even when the file path isn't.

**Normal successful login:**
```text
Sep 14 09:12:03 web01 sshd[14210]: Accepted publickey for deploy_svc from 10.20.4.15 port 51244 ssh2: RSA SHA256:AbCdEf...
Sep 14 09:12:03 web01 sshd[14210]: pam_unix(sshd:session): session opened for user deploy_svc(uid=1001) by (uid=0)
```

**Normal failed login (typo, expired key):**
```text
Sep 14 09:11:40 web01 sshd[14209]: Failed publickey for deploy_svc from 10.20.4.15 port 51201 ssh2: RSA SHA256:XyZ123...
```

**Brute-force pattern — same source, many usernames, password auth:**
```text
Sep 14 03:14:01 web01 sshd[22110]: Failed password for root from 203.0.113.77 port 41022 ssh2
Sep 14 03:14:02 web01 sshd[22112]: Failed password for admin from 203.0.113.77 port 41030 ssh2
Sep 14 03:14:04 web01 sshd[22114]: Failed password for oracle from 203.0.113.77 port 41041 ssh2
Sep 14 03:14:05 web01 sshd[22116]: Invalid user support from 203.0.113.77 port 41055
```

**[ANALYST]** - Distinguishing evidence to collect for an SSH brute-force case:

- Volume and rate: count `Failed password` / `Invalid user` lines per source IP per minute. A handful of failures over a day from a known admin's home IP is noise; dozens per minute from an unrecognized external IP is the pattern.
- Username diversity: real users mistype their own password. Attackers cycle through `root`, `admin`, `oracle`, `postgres`, `ubuntu`, `test` — usernames that were never provisioned on the host. `Invalid user` (as opposed to `Failed password for <valid_user>`) means the account doesn't exist at all, which is a strong brute-force / credential-stuffing indicator on its own.
- Outcome: did any `Failed password` sequence end in `Accepted password` or `Accepted publickey` from the same source? That's the line between "attempted" and "compromised" — pull it and treat the case as an active compromise, not a scan.
- Source reputation and geography: an internal jump-box IP hammering a host is very different from `203.0.113.77` doing it. Check whether the source IP maps to known infra (VPN gateway, monitoring scanner, CI runner) before escalating.

Don't assume every noisy source is malicious — vulnerability scanners, misconfigured monitoring agents, and a colleague's script with a hardcoded old password all produce the same shape of failures. This is a case where **Insufficient Evidence** or **Benign Positive** are legitimate closures if the source resolves to sanctioned scanning infrastructure and no `Accepted` line ever appears.

**[ENGINEERING]** - A workable correlation rule, expressed generically for a SIEM query language:

```text
source = auth_log OR journald(unit=sshd)
event_action IN ("Failed password", "Invalid user")
| stats count, dc(username) as distinct_users by src_ip, host, bin(time, 5m)
| where count >= 10 AND distinct_users >= 5
```

Tune the thresholds against your own baseline — a host with SSH exposed to a shared VPN range will have naturally higher failure noise than an internal-only jump box, and NAT/proxy egress can make many real users appear to share one source IP, flattening `distinct_users` in the wrong direction. Also account for fail2ban or similar tooling already banning after N attempts; if it's working, you'll see bursts capped at the ban threshold rather than sustained attacks, which is a different (better) picture than the raw auth log implies.

**[STAKEHOLDER]** - SSH brute force against internet-facing Linux hosts is one of the most common and least sophisticated attack patterns out there — it shows up in scan telemetry constantly. The business risk isn't the noise itself, it's the tail case where a weak or reused password lets one of those attempts succeed. The controls that actually move the needle are key-only auth, disabling root login over SSH, and MFA on jump hosts — decisions typically owned by infrastructure/platform engineering, with SOC providing the detection backstop.

## New User Creation

Account creation on Linux is driven by `useradd`/`adduser`, and it's logged through PAM and the audit trail, not just a single line.

```text
Sep 14 14:02:11 db02 useradd[30011]: new user: name=svc_backup, UID=1002, GID=1002, home=/home/svc_backup, shell=/bin/bash
Sep 14 14:02:11 db02 useradd[30011]: add 'svc_backup' to group 'sudo'
```

**[ANALYST]** - Evidence to collect: who invoked `useradd` (check the preceding `sudo` line for the invoking user and their session), whether the new UID falls in the expected range for human vs. service accounts on that host (site convention, but commonly system accounts stay under 1000), whether the account was immediately added to `sudo`/`wheel`, and whether a password or SSH key was set right after (`passwd` invocation, or a new `authorized_keys` write under the new home directory — check file integrity monitoring or `auditd` `path` records if enabled). A new user account created outside of change windows, added directly to an admin group, with a key pushed in the same minute, is the classic shape of an attacker establishing persistence after initial access. This maps to MITRE ATT&CK T1136.001 (Create Account: Local Account) — tag it in your case notes.

**[MANAGEMENT]** - Provisioning should run through an identity/config-management pipeline (Ansible, Terraform, IdP-driven), not ad hoc `useradd` on production hosts. Any manual account creation on a server outside that pipeline is worth a standing detection and a documented exception process — track it as a metric (manual account creations per month, by host tier) reviewed at the same cadence as privileged access reviews.

## Privilege Escalation: sudo Abuse and SUID Binaries

`sudo` logs every invocation whether it succeeds or fails, either to the auth log/secure log or its own `sudo.log` depending on configuration.

**Normal, expected sudo:**
```text
Sep 14 10:03:22 web01 sudo:   jsmith : TTY=pts/1 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
```

**Suspicious — enumeration and unusual command:**
```text
Sep 14 22:47:01 web01 sudo:   jsmith : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
Sep 14 22:47:03 web01 sudo:   jsmith : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/find / -perm -4000 -type f
```

**Failed sudo attempt (not authorized in sudoers):**
```text
Sep 14 22:41:55 web01 sudo:   contractor_amara : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/contractor_amara ; COMMAND=/usr/sbin/visudo
```

**[ANALYST]** - Read `sudo` lines for four things: the `TTY` and `PWD` (a sudo invocation from `/tmp` or `/dev/shm` is a lot more interesting than one from a home directory), the actual `COMMAND` (`sudo /bin/bash` or `sudo su -` grants a full interactive root shell — treat any account doing this outside documented break-glass procedure as a priority-one lead), repeated `user NOT in sudoers` failures (privilege escalation attempts against misconfigured or hopeful sudoers entries), and timing relative to the account's normal working pattern. A contractor account attempting `visudo` at 22:41 on a Tuesday, right after hours, is not a coincidence worth waving off.

SUID/SGID binary abuse is the other classic path and it doesn't always touch the auth log at all — the escalation itself (running `find` for SUID files, then exploiting a misconfigured one like a custom script with the setuid bit set) may only show up as process execution if you have `auditd` execve auditing or an EDR agent. What you can pull from auth-adjacent evidence:

- The `sudo` line showing `find / -perm -4000` or similar enumeration commands (shown above) — a legitimate hardening scan looks similar, so context (who ran it, was it authorized) matters more than the command alone.
- A subsequent `session opened` line for `root` immediately following execution of an unusual local binary, without a corresponding `Accepted` SSH login or normal `sudo` authorization line — a sign the escalation happened via the SUID bit rather than sudo policy, which won't generate a sudo log entry at all.
- File integrity monitoring or package-manager verification (`rpm -Va`, `dpkg --verify`) showing an unexpected SUID bit set on a binary that shouldn't have one — this is often the strongest piece of evidence when the log trail itself is thin.

**[ENGINEERING]** - If `auditd` is enabled, add rules to catch both vectors directly rather than relying on sudo log text parsing alone:

```bash
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -k root_escalation
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d -p wa -k sudoers_change
```

The `auid!=0` filter is the useful part — it flags processes that end up running as root (`euid=0`) but were launched by a session whose original login UID (`auid`) was not root, which catches both sudo escalation and SUID-binary escalation in one rule, regardless of which mechanism was used. Feed `ausearch -k root_escalation` output into your SIEM correlation alongside the sudo/auth log stream rather than treating them as separate cases.

**[MANAGEMENT]** - Sudoers changes and new SUID binaries on production hosts should both be change-controlled and alertable events, not just log lines waiting to be reviewed after the fact. Set an SLA for triage of any `root_escalation` or unauthorized-sudoers-change alert (same tier as a Windows admin-group-membership change) and review sudoers drift on a fixed cadence — monthly is reasonable for most fleets, tighter for anything internet-facing.

## Common Friction Worth Flagging Early

A few things routinely trip up analysts new to this evidence type. Timezone mismatches are constant — flat-file syslog timestamps are usually local host time with no offset printed, while `journalctl` output respects the querying shell's timezone by default (`journalctl --utc` fixes this, use it habitually when correlating across hosts). Log rotation compresses and eventually deletes old `auth.log`/`secure` files under disk pressure, so retention windows shorter than your detection-to-triage SLA will burn you — check the relevant `logrotate` config — `/etc/logrotate.d/rsyslog` on Debian/Ubuntu, `/etc/logrotate.d/syslog` on RHEL-family (the filename is a holdover from the old sysklogd package rsyslog replaced) — for rotation count against your actual investigation timelines. Service accounts running scheduled `sudo` jobs (backup scripts, cron-triggered deploys) generate volumes of legitimate `sudo` lines that look identical in shape to abuse — baseline them by command and schedule before treating deviation as signal. And containerized or ephemeral hosts frequently have no persistent auth log at all by design; if a host that should have SSH/sudo evidence has none, confirm first whether logging was ever enabled before treating the gap itself as an indicator of tampering.
