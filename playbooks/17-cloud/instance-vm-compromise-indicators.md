# Instance / VM Compromise Indicators

**Playbook ID & Name:** CLD-017 — Instance/VM Compromise Indicators (AWS EC2, Azure Virtual Machine, GCP Compute Engine)

**[STAKEHOLDER]** - A compute instance is not just "a server" anymore - in AWS, Azure, and GCP it's an identity with a badge (an instance profile, managed identity, or service account) that can call your control plane. If someone gets code execution on a VM, they don't just have that VM - they potentially have whatever that VM's cloud role is trusted to do: read S3 buckets, enumerate other resources, spin up new infrastructure, or pivot straight into the identity layer with credentials that never touch a password. This playbook exists because "the box got popped" in cloud is rarely the end of the story - it's usually the beginning of one.

**Severity/Priority default:** High, escalates to Critical if the instance holds a privileged instance profile/managed identity/service account, sits in a production VPC/VNet, is internet-facing, or shows any sign of encryption/destructive activity or outbound data movement.

**MITRE ATT&CK Techniques:** T1190 (Exploit Public-Facing Application) and T1078.004 (Valid Accounts: Cloud Accounts) as the two dominant initial-access vectors; T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) and T1552.001 (Credentials In Files) for the credential-theft pivot that turns "compromised VM" into "compromised cloud account"; T1021.004 (SSH) / T1021.001 (RDP) for lateral movement onto and between instances; T1059.001 (PowerShell) / T1059.003 (Windows Command Shell), T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files or Information), T1543.003 (Windows Service), T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task), T1055 (Process Injection), and T1003.001 (OS Credential Dumping: LSASS Memory) for on-host execution/persistence/credential access; T1562.001 (Impair Defenses: Disable or Modify Tools) for AV/EDR/agent tampering; T1046 (Network Service Discovery), T1580 (Cloud Infrastructure Discovery), and T1538 (Cloud Service Dashboard) for post-compromise recon; T1071.004 (Application Layer Protocol: DNS), T1572 (Protocol Tunneling), and T1090 (Proxy) for C2; and T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1567 (Exfiltration Over Web Service), T1048 (Exfiltration Over Alternative Protocol), and T1530 (Data from Cloud Storage) as impact-stage outcomes once an instance compromise has run its course.

## Trigger / Detection Logic Summary

This playbook fires from several independent trigger paths that all converge on the same investigation - treat any one of these as sufficient to open the case, and treat two or more firing together as a near-automatic escalation:

- A cloud-native threat detection service raises a compute-specific finding: AWS GuardDuty (`Backdoor:EC2/*`, `CryptoCurrency:EC2/BitcoinTool.B`, `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/MetadataDNSRebind`, `PenTest:EC2/*`, `InstanceCredentialExfiltration.*`), Microsoft Defender for Cloud VM alerts, or GCP Security Command Center findings against a Compute Engine resource.
- EDR/host telemetry on the instance shows execution consistent with the on-host technique cluster above (unmanaged process spawning a shell, LSASS access attempt, new autostart entry, defense-tooling service stopped).
- VPC/VNet/Subnet flow logs show the instance originating traffic that doesn't fit its role: outbound connections to known C2/mining pool infrastructure, high-volume egress, DNS query volume spikes consistent with tunneling, or connections on non-standard ports to a large number of internal hosts (scanning behavior).
- CloudTrail/Activity Log/Cloud Audit Logs show the instance's *own* role/managed identity/service account being used to call the control plane from a source that isn't the instance's IMDS/metadata endpoint pattern - the classic signature of a stolen instance credential being replayed off-box.
- SSH/RDP authentication logs on the instance show a sudden burst of failed logons followed by a success, or a success from a source IP/geography the instance has never authenticated from before.

**[ENGINEERING]** - The single highest-value correlation in this whole playbook is tying an *on-host* signal (EDR alert, auth log anomaly, GuardDuty finding tied to the instance ID) to a *control-plane* signal (that instance's role/identity being used to call APIs). Most SOCs investigate these as two separate alerts in two separate tools and miss that they're the same incident 20 minutes apart. If your SIEM can join VPC Flow Logs / GuardDuty by `instanceId` against CloudTrail `userIdentity.arn` containing that instance's role name (or the Azure managed identity's object ID, or the GCP service account email tied to the VM), build that join now - it is worth more than any single detection rule in this category.

## Required Log Sources & Event IDs

| Platform | Log Source | Event / Finding / Operation Name |
|---|---|---|
| AWS | GuardDuty | `Backdoor:EC2/C2Activity`, `CryptoCurrency:EC2/BitcoinTool.B`, `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/RDPBruteForce`, `InstanceCredentialExfiltration.OutsideAWS`, `Trojan:EC2/*`, `Impact:EC2/WinRMBruteForce` |
| AWS | CloudTrail (management events) | `AssumeRole` / `GetCallerIdentity` calls where `userIdentity.arn` maps to an instance role but `sourceIPAddress` is not the instance's known egress IP; `RunInstances`, `StopInstances`, `TerminateInstances`, `ModifyInstanceAttribute`, `CreateSnapshot` (recon/tampering/exfil staging) |
| AWS | VPC Flow Logs | Flow records keyed on the instance's ENI - egress volume, destination ASN/IP reputation, port/protocol distribution |
| AWS | SSM / Session Manager logs | `StartSession`, command history - legitimate admin access vs. unexpected session origin |
| Azure | Defender for Cloud | VM alerts: suspicious process execution, brute-force success, digital-currency mining behavior, suspicious outbound network activity |
| Azure | Activity Log / Entra ID Sign-in Logs | Managed identity token requests, `Microsoft.Compute/virtualMachines/*` operations, sign-ins attributable to the VM's managed identity from unexpected context |
| Azure | NSG Flow Logs | Same role as AWS VPC Flow Logs - egress anomalies, lateral scanning on the VNet |
| GCP | Security Command Center | Findings against `compute.googleapis.com` resources: brute force, malware, C2, crypto-mining |
| GCP | Cloud Audit Logs | `google.iam.credentials.v1.GenerateAccessToken`, `compute.instances.*` operations, service-account token use inconsistent with the VM's normal call pattern |
| GCP | VPC Flow Logs | Egress and internal scanning patterns on the instance's network interface |
| Host (any provider) | OS authentication logs | Linux `sshd`/`auth.log`/`secure` - Accepted/Failed publickey or password entries; Windows Security auditing - logon success/failure and process-creation auditing (if your EDR or Windows audit policy captures it) |
| Host (any provider) | EDR/antivirus agent telemetry | Process creation, LSASS access attempts, service/scheduled-task creation, autostart registry modification, defense-tooling stop/uninstall events |

Retention and coverage gaps to expect going in: GuardDuty and Defender for Cloud findings typically have a shorter default retention than your SIEM's ingested copy - if this is a retrospective hunt, confirm what's actually still queryable before concluding "no finding" means "no activity." Host-level OS/EDR logs are frequently *missing entirely* on instances that predate your agent rollout, on instances built from an unmanaged AMI/image, or on short-lived autoscaled instances that got terminated before the agent checked in - don't assume the absence of host telemetry means the instance is clean; it may just mean nobody's watching it.

## Key Fields to Inspect

**[ANALYST]**

| Field | What to check |
|---|---|
| `instanceId` / VM resource ID | Anchor for joining GuardDuty/Defender/SCC findings to flow logs and CloudTrail/Activity Log/Cloud Audit Log entries |
| `userIdentity.arn` (AWS) / managed identity object ID (Azure) / service account email (GCP) | Is the instance's own cloud identity being used to call APIs from somewhere other than the instance itself? |
| `sourceIPAddress` on control-plane calls | Compare against the instance's actual public/NAT egress IP - a mismatch means the credential left the box |
| IMDS/metadata endpoint access pattern | On AWS, check IMDSv1 vs IMDSv2 enforcement and any unusual volume of `169.254.169.254` requests from a process that shouldn't be pulling credentials (a strong T1552.005 signal, especially paired with SSRF-style web app logs if the instance runs one) |
| VPC/NSG flow log 5-tuple + byte counts | Destination IP/ASN reputation, port (22/3389/4444/8080/random-high), sustained high-byte-count sessions (exfil or mining pool keep-alive) |
| SSH auth log source IP and key fingerprint | New key never seen authenticating to this host before; password auth succeeding on a host that should be key-only |
| Windows/Linux new local account or added SSH authorized key | Attacker-created backdoor account (T1136) or persistence via `authorized_keys` |
| Process ancestry / command line (EDR) | Web server or app process spawning a shell, `curl`/`wget`/`certutil` pulling a second-stage payload, base64/PowerShell-encoded command blocks |
| Scheduled task / cron / systemd timer entries | New, unexplained recurring job - classic persistence, often disguised with a legitimate-sounding name |
| Security group / NSG / firewall rule changes tied to the instance | Attacker opening additional inbound ports for re-entry, or disabling egress restrictions before exfil |
| Snapshot/AMI/image creation calls tied to the instance | Recon or data-staging step before exfil, or destructive-actor prep before a wipe |

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| Instance calls its own instance profile/managed identity credentials only from the IMDS/metadata endpoint on-box | Same role/identity's credentials used to call APIs from a source IP that isn't the instance |
| SSH/RDP access from known bastion/jump host or VPN range, matching change/maintenance window | SSH/RDP success following a burst of failed attempts, or success from a new country/ASN |
| Outbound traffic consistent with the application's known dependencies (package repos, license servers, internal services) | Sustained connections to mining pool ports, known C2 ranges, or DNS query volume/entropy spike consistent with tunneling |
| Scheduled tasks/cron jobs match configuration management inventory (Ansible, Chef, SSM State Manager) | New scheduled task/cron entry with no corresponding IaC/config-management record |
| Security group/NSG changes tied to a ticket or IaC pipeline run | Security group/NSG opened to `0.0.0.0/0` on an unusual port shortly after other suspicious activity |
| EDR/agent heartbeat continuous, no tamper events | EDR/AV agent service stopped, uninstalled, or heartbeat gap coinciding with the incident window |
| Snapshot/AMI creation matches backup schedule | Ad hoc snapshot/AMI creation with no backup job attribution, especially right before a `TerminateInstances`/deletion |

## Investigation Steps

1. Anchor the case on the instance/resource ID and pull every finding tied to it across the last 24-72 hours - GuardDuty/Defender/SCC findings, EDR alerts, and any manual reports (app team noticing high CPU, unexpected outbound traffic tickets from network team).
2. Confirm initial access vector: check for an internet-facing service on the instance (T1190 - review web server/app logs for exploit attempts, unusual request patterns, known CVE exploitation signatures around the time window) versus a valid-credential login (T1078.004 - check SSH/RDP auth logs and any preceding IAM/Entra sign-in anomaly on the account used to reach the instance).
3. Determine whether the instance's cloud identity has been used off-box: pull CloudTrail/Activity Log/Cloud Audit Log entries for that role/managed identity/service account and compare every `sourceIPAddress`/caller context against the instance's actual egress IP. Any mismatch means treat this as a cloud-account-compromise case, not just a host incident - go pull the related IAM/Entra/IAM(GCP) playbooks for the identity side.
4. Pull EDR/host telemetry (where present) for process ancestry, new persistence artifacts (scheduled task, service, registry run key, cron/systemd entry, new SSH key or local account), and any credential-access attempt (LSASS access, credential file access) - this tells you what the actor actually *did* on the box, not just that they got in.
5. Review VPC/NSG flow logs for the instance's network interface across the incident window: egress volume and destination reputation, internal scanning behavior toward other hosts (T1046), and any protocol anomalies consistent with tunneling or proxying (DNS query volume, non-standard ports carrying HTTP-like traffic).
6. Check for lateral movement: did this instance's credentials, SSH keys, or network position get used to reach other instances or services? Correlate SSH/RDP sessions *originating from* the compromised instance against other hosts' auth logs.
7. Assess impact-stage indicators before closing: any file encryption/ransom-note activity, deleted/disabled backups or snapshots (inhibit-recovery behavior), large outbound transfers to storage/web services, or cloud storage bucket access using the instance's identity.
8. Build the full timeline (initial access -> execution -> persistence -> credential access -> discovery -> lateral movement/impact) before deciding containment scope - a partial timeline leads to partial containment and a second call three days later.

## True Positive Indicators

- Instance's own role/managed identity/service account credentials used from a source outside the instance (confirmed off-box replay).
- Confirmed exploit attempt against an internet-facing service on the instance immediately preceding anomalous process execution.
- New, unexplained persistence artifact (scheduled task, service, autostart entry, SSH key, local account) with no configuration-management record.
- EDR/AV agent tampering (stopped, uninstalled, or tamper-protection bypass event) coinciding with the incident window.
- Outbound traffic to confirmed C2/mining-pool infrastructure or threat-intel-flagged IPs/domains.
- File encryption, snapshot/backup deletion, or other destructive activity originating from the instance.

## False Positive / Benign Positive Indicators

- GuardDuty/Defender/SCC "brute force" finding where all authentication attempts failed and no successful logon followed - noisy internet scanning, no compromise.
- Legitimate configuration-management job (Ansible/Chef/Puppet run, SSM Automation, cloud-init) creating what looks like a new scheduled task or service, matching the platform's known change window.
- Security scanner or vulnerability-assessment tool (internally sanctioned) generating IMDS access or port-scanning-like flow log patterns - check the source against your approved scanner inventory (T1595 findings against your own infra are common false alarms if your vuln-management tool isn't allowlisted).
- High outbound byte count explained by a legitimate large data transfer, backup job, or software update matching a known maintenance window.
- EDR alert on a process that's a known, recently deployed internal tool not yet added to the allowlist.

## Escalation Criteria

Escalate to full Incident Response immediately if: the instance's cloud identity is confirmed used off-box (this is now a cloud account compromise, not just a host incident, and the blast radius includes everything that identity can touch); there's any confirmed encryption, backup/snapshot deletion, or ransom note (T1486/T1490); confirmed lateral movement to additional instances or to production data stores; or confirmed exfiltration via cloud storage APIs, web services, or DNS tunneling. Escalate to the platform/infrastructure owning team without full IR when the finding is a benign scanner false positive that needs allowlisting, or a configuration-management artifact that needs documentation.

## Containment Options & Approval Authority

**[MANAGEMENT]**

| Action | Who approves |
|---|---|
| Isolate the instance at the network layer (quarantine security group/NSG, deny all egress except forensic collection path) | SOC Tier 2 can act immediately on confirmed non-production; production requires app/platform owner sign-off or pre-agreed emergency-isolation authority |
| Revoke/rotate the instance's role credentials (detach instance profile, revoke STS session, rotate managed identity/service account key) | SOC Tier 2 immediately if the identity is confirmed compromised off-box - this takes priority over host-level containment since it caps the control-plane blast radius fastest |
| Snapshot the disk/volume for forensics before any remediation reboot or termination | Standard IR procedure, no additional approval, but must happen before step below |
| Terminate/rebuild the instance from a known-good image | Application/platform owner approval for production workloads; SOC can act unilaterally on clearly disposable/dev resources |
| Force-disable the affected internet-facing service pending patch | Application owner, expedited approval given active exploitation |
| Emergency rotation of any credentials the instance's identity had access to (downstream secrets, database creds it could reach) | Identity/platform team lead, given wider blast-radius implications |

Target SLA: acknowledge within 15 minutes for confirmed off-box credential use or destructive-activity indicators; network isolation within 30 minutes of confirmation; full containment (identity rotated + instance isolated/rebuilt) within 2 hours.

## Example Query (Splunk SPL - AWS GuardDuty + CloudTrail correlation)

```spl
index=guardduty type=Backdoor:EC2* OR type=CryptoCurrency:EC2* OR type=UnauthorizedAccess:EC2*
| rename resource.instanceDetails.instanceId as instanceId
| join instanceId
    [ search index=cloudtrail eventName=AssumeRole OR eventName=GetCallerIdentity
      | eval roleInstanceId=mvindex(split(userIdentity.arn,"/"),1)
      | rename roleInstanceId as instanceId ]
| where sourceIPAddress!=instanceDetails.networkInterfaces.publicIp
| table _time, instanceId, type, sourceIPAddress, userIdentity.arn
```

## Closure Criteria

Close as **True Positive** once the initial access vector is identified, all persistence/lateral-movement artifacts are inventoried and removed (or the instance is rebuilt from clean image), the instance's cloud identity is rotated/revoked, and no further anomalous activity is observed from either the host or the identity across a defined monitoring window (minimum 24-48 hours post-containment). Close as **Benign Positive** when the finding traces to an approved scanner, sanctioned configuration-management job, or documented maintenance activity. Close as **Insufficient Evidence** when the instance predates EDR/host-log coverage, was terminated (autoscaling) before host telemetry could be pulled, and the available control-plane/flow-log data can't confirm or rule out off-box credential use - document the coverage gap and flag the missing agent/logging baseline to the platform team rather than guessing at a verdict.

**Example case note:** *"GuardDuty finding InstanceCredentialExfiltration.OutsideAWS on i-0a1b2c3d4e5f67890 (prod-web-03, us-east-1). CloudTrail shows role prod-web-instance-role used to call ec2:DescribeInstances and s3:ListBuckets from source IP 198.51.100.77 (VPS hosting range), while the instance's own known egress is 203.0.113.20. Apache access log on the instance shows a Log4j-pattern exploit string 11 minutes prior to first anomalous IMDS access volume, consistent with T1190 leading to T1552.005 credential theft. No lateral movement to other instances confirmed via SSH auth logs on adjacent hosts. Classified True Positive - instance isolated (quarantine security group applied), instance role credentials revoked and role detached, instance snapshotted for forensics and scheduled for rebuild from patched AMI, escalated to IR for full cloud-identity blast-radius review given the S3 ListBuckets call."*
