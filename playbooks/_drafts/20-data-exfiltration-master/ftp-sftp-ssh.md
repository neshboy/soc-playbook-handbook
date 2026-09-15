# Exfiltration via FTP/SFTP/SSH - Telemetry and Indicators

FTP, SFTP, and SSH-based transfer (`scp`, `rsync` over SSH, or an interactive SFTP subsystem session) rarely show up in ransomware-adjacent exfil chains anymore, but they are still the quiet default in EDI/B2B integrations, backup jobs, ICS/OT vendor drops, and DevOps pipelines. That's exactly why attackers like it: egress rules that were opened years ago for a partner feed on TCP/21 or a nightly `rsync` job on TCP/22 rarely get revisited, and an attacker riding those same ports blends into baseline noise instead of tripping a "new protocol seen on network" alert.

**[STAKEHOLDER]** - the risk here isn't exotic malware, it's a legacy transfer mechanism the business already trusts and rarely monitors closely. Closing this gap is usually a firewall-rule review and log-retention conversation, not a tooling purchase.

## Distinguishing the Three Channels

| Channel | Port(s) | Encryption | Payload Visible in Network Logs? | Common Legit Use |
|---|---|---|---|---|
| FTP | 21 (control), high ephemeral (data) | None | Yes - commands and filenames in cleartext | Legacy vendor/EDI drops, printer/scanner firmware, ICS file shares |
| FTPS | 21/990 | TLS wrapper | No (session encrypted after AUTH TLS) | Same as FTP, security-hardened variant |
| SFTP | 22 (SSH subsystem) | Full SSH encryption | No | Backup targets, DevOps artifact push, managed file transfer |
| SCP/SSH | 22 | Full SSH encryption | No | Ad-hoc admin file copy, `rsync` jobs, jump-box hops |

## Host-Based Telemetry (Windows Endpoint as Exfil Source)

**[ANALYST]** - the client tool launched is your best evidence. Look for **4688** (New Process Created) with `New Process Name` matching `ftp.exe`, `curl.exe` (URL with `ftp://` or `sftp://`), `winscp.exe`/`WinSCP.com`, `pscp.exe`/`psftp.exe` (PuTTY suite), `rclone.exe` (supports SFTP remotes), or PowerShell hosting the Posh-SSH module. Command Line only populates if command-line auditing is enabled - if it isn't, you're blind to arguments and can only infer intent from the binary itself plus network correlation, which is a gap worth flagging to the logging owner rather than assuming away.

A classic, still-seen trick: `ftp -s:script.txt` runs FTP non-interactively from a script file containing `open`, `user`, `bin`, `put`, `bye` commands - fully scriptable exfil with no interactive session to watch. Finding that script file on disk (staging directory, temp, user profile) is as strong an indicator as the process event itself. Same logic applies to WinSCP `.txt`/`.ini` batch scripts and saved-session credential files (`WinSCP.ini`, FileZilla `sitemanager.xml`/`recentservers.xml`, `.ssh/known_hosts` plus private key files) - these map to **T1552.001** (Credentials In Files) and often explain how the attacker got valid transfer creds in the first place, tying back to **T1078**.

Also pull **4624**/**4625** for the session that launched the transfer (Logon Type, Source Network Address) and check **1102** around the same timeframe - clearing the Security log right after a bulk FTP/SFTP push is a well-worn anti-forensics move, not a coincidence.

## Network and Server-Side Telemetry

**[ANALYST]** - for FTP, flow-aware monitoring (Zeek's `ftp.log` or equivalent) is genuinely decisive: because the control channel is cleartext, you can see the actual `STOR` (upload/exfil direction) versus `RETR` (download) command and the filename being transferred. For SFTP/SSH, the payload is encrypted end-to-end, so you're working metadata only: sustained outbound byte volume with a strong client-to-server skew, session duration, low packet-timing variance (scripted/batch transfer vs. an interactive shell), and SSH client banner/version string anomalies (e.g., a `paramiko`- or `libssh2`-based client where the host normally only ever uses OpenSSH or PuTTY).

If the org runs its own SFTP/SSH server (DMZ drop box, jump host), correlate `sshd` authentication logs (Accepted publickey/password, source IP, account) against expected partner IP ranges. One environment-specific gotcha worth validating rather than assuming: on Windows OpenSSH Server deployments, password auth generally surfaces via **4624**/**4625**, but public-key auth doesn't reliably generate the same Security-log coverage on every build - confirm this in your own estate before relying on it for detection.

**[ENGINEERING]** - a practical correlation rule: flag hosts where a **4688** event for an FTP/SFTP/SSH client binary occurs within a tight window (e.g., 10 minutes) of a network flow record showing outbound TCP/21, 22, or 990 with upload-direction byte count exceeding the host's 30-day baseline, especially to a destination IP/ASN with no prior connection history from that host. Separately, treat `-L`/`-R`/`-D` flags on `ssh.exe`/`plink.exe` command lines as **T1572**/**T1090** (tunneling/proxy) rather than direct file transfer - both ride TCP/22, but the investigative path and evidence differ.

## Enrichment Pivots

Check destination IP/ASN reputation (bulletproof hosting and generic VPS ranges are common for throwaway SFTP drop servers), look for staging activity immediately preceding the transfer (**4688** for `rar.exe`/`7z.exe` archiving sensitive files minutes before the FTP/SFTP client launches), and cross-reference file names/hashes against DLP-tagged sensitive documents if available. Not every hit resolves to confirmed exfil - a lot of these connections turn out to be Benign Positive (the scheduled EDI job) or Expected Activity (a sanctioned backup run); the differentiator is whether the account, timing, destination, and volume match the known-good baseline for that specific transfer job. Relevant techniques for this channel overall: **T1048** (Exfiltration Over Alternative Protocol) as the primary classification, with **T1021** (Remote Services, SSH) when stolen creds are reused for both lateral movement and exfil, and **T1552.001**/**T1078** explaining credential provenance.

**[MANAGEMENT]** - command-line process auditing and egress logging on ports 21/22 are prerequisites, not nice-to-haves, for this channel to be investigable at all; if they're not enabled org-wide, that's a gap to raise with the logging/engineering owner before the next tabletop, not something to discover mid-incident.
