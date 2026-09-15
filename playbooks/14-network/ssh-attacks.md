# SSH Attacks

## Playbook ID & Name
**NW-019 — SSH Attacks (Brute Force, Credential Reuse & Abuse of Remote Access via Secure Shell)**

## Business Risk
**[STAKEHOLDER]** - SSH is how almost every Linux server, network appliance, container host, and a growing number of Windows boxes get administered. It's also internet-facing more often than anyone wants to admit — a forgotten jump box, a dev instance someone spun up in the cloud and never locked down, a vendor appliance with a default account. A successful SSH compromise doesn't just give an attacker a shell, it usually gives them a shell *with the same trust level as your own admins*, on a host that's often a stepping stone into everything else. The risk here isn't the noise (most SSH brute-force traffic is background radiation from the internet), it's the rare event where it actually lands, because when it does, the blast radius is "root on a production Linux host," not "a phishing click."

## Severity / Priority Default
**Low** for blocked/failed brute-force noise against a hardened, key-only, non-internet-facing host. **Medium** for sustained attempts against internet-facing SSH with password auth still enabled, or any spray pattern hitting multiple valid usernames. **High/Critical** for any confirmed successful authentication following a failure burst, any unrecognized public key accepted, or root/service-account compromise.

## MITRE ATT&CK Technique(s)
- **T1110 Brute Force** — `.001 Password Guessing` (repeated attempts against one account) and `.003 Password Spraying` (low-and-slow attempts across many accounts to dodge lockout thresholds).
- **T1021.004 Remote Services: SSH** — the technique this whole playbook exists to catch once the attacker actually gets in and uses SSH for lateral movement or interactive access.
- Adjacent techniques that frequently show up as the *next* step and belong in the same case, not a separate ticket: **T1078 Valid Accounts** (successful login using guessed/reused creds), **T1552.001 Unsecured Credentials: Credentials In Files** (an attacker finding a private key sitting in a home directory or CI config), **T1572 Protocol Tunneling** and **T1090 Proxy** (SSH port-forwarding or `-D` SOCKS proxy used to move data or reach otherwise-blocked segments), **T1105 Ingress Tool Transfer** (SCP/SFTP pulling tooling in post-compromise).

## Trigger / Detection Logic Summary
Alert fires on one of three shapes:
1. **Volume-based brute force** — one source IP against one account, failure count over threshold in a short window.
2. **Spray pattern** — one source (or a small rotating pool of sources) against many distinct accounts, each with only a handful of attempts, specifically to stay under a per-account lockout threshold.
3. **Anomalous success** — any successful authentication that follows a failure burst, comes from a new/unseen geography or ASN for that account, uses a public key never seen before for that account, or authenticates as root/a service account from a source that has no documented reason to be doing so.

**[ENGINEERING]** - Build this as two correlation searches, not one. Threshold-based brute force (fails > N in window) catches noisy attackers and 90% of internet scanning junk. Spray detection needs a *distinct account count per source* aggregation over a longer window (hours, not minutes) because spray attacks are deliberately paced to avoid the volume trigger. Both should join against an "any success in the same window for the same source/account" lookup — that join is where the actual signal lives; raw fail-count alerts on their own are close to worthless at internet scale.

## Required Log Sources & Event IDs
| Source | What it gives you |
|---|---|
| Linux `sshd` via syslog (`/var/log/auth.log`) or `/var/log/secure`, journald | `Failed password`, `Accepted password`, `Accepted publickey`, `Invalid user`, `Disconnecting: Too many authentication failures`, `PAM: Authentication failure` |
| `auditd` | `type=USER_AUTH` / `USER_LOGIN` records, useful when syslog forwarding drops or mangles sshd lines |
| `fail2ban` / `sshguard` | Ban/unban events — tells you if the host's own local control already handled it before it reached the SIEM |
| Zeek `ssh.log` / NDR | `auth_success` field, client/server version banner (automated tools often show non-standard banners like `SSH-2.0-libssh` or `SSH-2.0-Go`), negotiated cipher, session duration and byte counts |
| Sysmon (client-side, if SSH originates from a Windows host) | Event ID **3** (Network connection) for outbound SSH sessions; Event ID **1** (Process creation) capturing `ssh.exe`/`plink.exe`/`scp.exe` command lines — the `-L`, `-R`, `-D`, `-N` flags matter here |
| Windows Security log (hosts running Win32-OpenSSH Server) | Event ID **4624**/**4625** — logon type and provider behavior vary meaningfully by OpenSSH build and config, validate against your own baseline before treating this as authoritative on its own |
| Perimeter firewall / NetFlow | Session tuples on TCP 22 (and any non-standard SSH listener port) — source, destination, byte count, duration |
| Cloud (AWS) | VPC Flow Logs on port 22, GuardDuty finding `UnauthorizedAccess:EC2/SSHBruteForce`, CloudTrail for security-group changes opening 22 to `0.0.0.0/0` |

## Key Fields to Inspect
**[ANALYST]**
- Source IP, ASN, geo — and whether it matches a known bastion/VPN egress range or a documented admin location.
- Targeted username(s): one account hammered repeatedly vs. many accounts tried once or twice each (spray signature).
- Auth method — password vs. publickey. If publickey, get the **key fingerprint** that authenticated and check it against your authorized-key inventory. This is the single highest-value field in the whole investigation.
- Attempt count, window, and final outcome — still failing, or did one go through?
- Zeek `ssh.log` version-string banner — flags scripted/automated clients vs. interactive human sessions.
- Post-auth session shape: interactive shells are bursty and irregular; a tunnel or SOCKS proxy looks like a long, flat, sustained flow with steady small packets.
- Whether `PermitRootLogin` is in play — direct root SSH attempts (or successes) are a red flag in almost every hardened environment.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Known admin IP, publickey auth, accepted on first attempt | Dictionary-style sequential guesses, hundreds of failures in minutes from one source |
| CI/CD or automation account with a documented rotation schedule | Same account targeted from many rotating source IPs (credential-stuffing/distributed spray) |
| Occasional single failed login (mistyped password), then success | Root or a service account authenticated successfully with password auth, no ticket, no change record |
| SCP/SFTP transfer matching a known backup job window | New/never-seen public key accepted for an account with no onboarding record |
| `-L`/`-R` tunnel used by a documented engineering workflow (e.g., DB access via jump host) | Long-lived, low-and-slow SSH session with periodic small packets from a workstation that has no reason to hold an SSH session open |

## Investigation Steps
1. Pull the raw `sshd`/auth log entries for the alert window — confirm source IP(s), targeted username(s), auth method attempted, and the final outcome (still failing vs. one accepted).
2. Classify the shape: one source vs. one account repeatedly (T1110.001) or one/few sources vs. many accounts (T1110.003, spray). This changes what "success" would even look like and how you scope the search.
3. If **any** attempt succeeded, stop treating this as noise — pivot immediately to T1078 Valid Accounts and look at what that session did: commands run, files touched, outbound connections opened, before you do anything else.
4. Check source reputation/geo/ASN against known admin ranges and threat intel; flag matches to known scanning infrastructure or prior malicious sightings in your SIEM history.
5. For publickey auth, get the fingerprint that authenticated and check it against your CMDB/authorized_keys inventory — an unrecognized key that successfully authenticated is a hard escalate, not a "maybe."
6. Inspect the post-auth session for tunneling/proxy indicators (`-L`/`-R`/`-D`/`-N` flags in process telemetry, or a flow that looks like sustained SOCKS traffic) — this is T1572/T1090 territory and usually means SSH is being used to move around egress controls, not just for a shell.
7. Confirm whether MFA/PAM policy actually applies to this host and was enforced — a large share of real SSH compromises succeed specifically on a host that got missed in an MFA rollout.
8. Document scope (accounts and hosts targeted, success/fail), and if a service account or root was involved, check that account's activity across the *whole* estate — brute-forced service-account creds get reused wherever that account has access, not just on the host that alerted.

## True Positive Indicators
- Confirmed successful authentication following a failure burst from the same or a related source.
- Unrecognized public key accepted for an existing account.
- Root or service account authenticated via password from a source with no documented reason to be there.
- Post-auth tunneling/proxy behavior inconsistent with the account's normal role.
- Source IP/infrastructure matches known credential-stuffing or scanning campaigns in threat intel.

## False Positive / Benign Positive Indicators
- Automation/CI account failing during a documented credential-rotation window, then succeeding once the new secret propagates — expected, not malicious, but worth a note if it recurs (rotation timing is a process problem, not a security one).
- Authenticated vulnerability scanner performing a scheduled SSH check against inventoried hosts.
- Admin mistyped a password a couple of times below threshold, then authenticated normally from an expected location.
- IDS-flagged "SSH scan" that's actually a health-check/monitoring tool doing a banner grab on port 22 and closing without any auth attempt at all — a parsing/classification issue, not an attack.

## Escalation Criteria
Escalate to Tier 2/IR immediately when: any successful authentication follows a failure burst; an unrecognized public key is accepted; root or a service account is targeted successfully; tunneling/proxy behavior is found on a host with no business reason to run one; or the target host is Tier-0 (jump host, backup server, hypervisor management interface, domain-joined Linux/AD-bridge box). Distributed spray hitting more than a handful of valid usernames also warrants escalation even without a confirmed success — it means the attacker already has a valid username list, which is its own finding.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Block source IP/CIDR at perimeter firewall** — Tier 1 standing SOP for external sources with no legitimate business tie; no ticket approval required for this narrow action.
- **Disable/lock the targeted or compromised account** — Tier 1 can act directly under SOP once compromise is confirmed; otherwise requires account-owner/IAM notification first.
- **Force password reset and revoke/rotate SSH keys** for the affected account — owned by IAM/sysadmin team, tracked in ticket, and must include a check for any *new* authorized_keys entries the attacker may have planted (T1098.004 Account Manipulation: SSH Authorized Keys — persistence risk, not T1136 Create Account, since the attacker is modifying an existing account rather than creating a new one).
- **Isolate the host** — requires IR lead approval once there's evidence of a successful interactive session; treat as suspected-compromise, not routine brute-force closure.
- **Disable password auth in favor of key-only, enforce fail2ban/rate-limiting, restrict to bastion-only access** — change management plus network/sysadmin team; not a unilateral SOC action, but should be the standing recommendation on every ticket where password auth was even attempted successfully.

## Example Query (Splunk SPL — Linux auth index)
```spl
index=linux_secure sourcetype=linux_secure "sshd" earliest=-1h
| rex field=_raw "(?<sshd_action>Failed|Accepted)\s(?<auth_method>password|publickey)\sfor\s(?<user>\S+)\sfrom\s(?<src_ip>\S+)"
| stats count(eval(sshd_action="Failed")) as fails,
        count(eval(sshd_action="Accepted")) as success by src_ip, user
| where fails > 20 OR (success > 0 AND fails > 5)
| sort - fails
```

## Closure Criteria
Close as **True Positive** only after confirming which account(s) authenticated successfully, what the session did post-auth, and whether any new key/account persistence was planted — open a separate exposure ticket if the host had no business being reachable on 22 from the internet in the first place. Close as **Benign Positive** when the source is a verified scanner, automation account, or admin working from an expected location, all below threshold. Close as **Insufficient Evidence** when `auth.log`/`secure` has already rotated past retention and the source can't be attributed with confidence — note the log gap explicitly rather than defaulting to benign.

**Example case note:** *"Password-spray pattern, 4 accounts tried (svc-backup, root, admin, deploy) from rotating pool of 6 source IPs (AS-registered VPS range) against bastion01.example.com (10.30.2.11) over 3h, all password auth, all failed, PermitRootLogin already disabled. No successful auth in window. Closed Benign Positive — pending: escalated recommendation to disable password auth entirely on this host, currently key-only for 90% of accounts but svc-backup still password-enabled."*
