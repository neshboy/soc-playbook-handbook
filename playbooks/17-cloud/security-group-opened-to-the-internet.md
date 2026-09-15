# Security Group Opened to the Internet

## Playbook ID & Name
**CLD-005 — Security Group / NSG Ingress Rule Opened to 0.0.0.0/0 (or ::/0)**

Covers AWS Security Groups, Azure Network Security Groups (NSGs), and GCP Firewall Rules where an inbound rule is created or modified to allow traffic from any source address, on any port range, but with particular attention to management ports (SSH/22, RDP/3389, WinRM/5985-5986), database ports (1433, 3306, 5432, 6379, 9200, 27017), and "ALL traffic/ALL ports" rules.

## Business Risk
**[STAKEHOLDER]** - An open security group is one misconfiguration away from an internet-wide invitation. Mass-scanning botnets find newly exposed ports in minutes, not days — this is one of the few cloud misconfigurations where the exploit window is measured in single-digit minutes on a bad day. A database or RDP port left open to the world routinely ends in ransomware, cryptomining, or straight-up data theft, and it's the single most common root cause we see in post-incident reviews for "how did they get in."

## Severity / Priority Default
**High** if the rule exposes a management port (22/3389/5985-5986), a database/cache port, or "all ports/all protocols" from 0.0.0.0/0 or ::/0.
**Medium** if it exposes a narrow, expected web port (80/443) on a resource that is intentionally internet-facing (e.g., a public ALB, a CDN origin) — still requires validation that this was the intended design, not drift.
**Critical** if the resource behind the rule also has a public IP/public endpoint attached and telemetry shows inbound connections already occurring from non-corporate ranges within the detection window.

## MITRE ATT&CK Technique(s)
- T1190 Exploit Public-Facing Application (the likely follow-on if the exposed service has a known vuln)
- T1595 Active Scanning (mass internet scanners will find the rule almost immediately)
- T1046 Network Service Discovery
- T1580 Cloud Infrastructure Discovery (if the change itself was made by an actor already inside the tenant, doing recon before widening access)
- T1538 Cloud Service Dashboard (if the change was made via console by a compromised identity)
- T1110 Brute Force (.001 Password Guessing, .003 Password Spraying) — common next step against exposed RDP/SSH
- T1078.004 Valid Accounts: Cloud Accounts — if the change itself was performed by a legitimate-looking but compromised principal

## Trigger / Detection Logic Summary
Alert fires on a cloud control-plane event that creates or modifies an ingress rule where:
- `CidrIp` / `sourceAddressPrefix` / `sourceRanges` = `0.0.0.0/0` or `::/0`, AND
- the rule is not tagged/labeled as an approved exception (see false-positive section), AND
- the destination port falls in a watchlist (22, 3389, 1433, 3306, 5432, 6379, 9200, 27017, 5985-5986, or `*`/ALL).

Secondary trigger: cloud-native posture tools (AWS Security Hub / GuardDuty, Azure Defender for Cloud, GCP Security Command Center) natively flag this as a finding — ingest their finding as an alternate detection path in case the raw control-plane event was missed due to log delay.

## Required Log Sources & Event IDs
| Platform | Log Source | Key Event/API Name |
|---|---|---|
| AWS | CloudTrail (management events) | `AuthorizeSecurityGroupIngress`, `ModifySecurityGroupRules`, `CreateSecurityGroup` |
| AWS | VPC Flow Logs | ACCEPT records against the newly opened port, from external source IPs |
| AWS | Security Hub / GuardDuty | `EC2SecurityGroupOpenPort` / finding type variants |
| Azure | Azure Activity Log | `Microsoft.Network/networkSecurityGroups/securityRules/write` |
| Azure | NSG Flow Logs / Traffic Analytics | Allowed flows on the affected rule |
| Azure | Defender for Cloud | Recommendation: "Management ports should be closed" / "Internet-facing VM ... unrestricted access" |
| GCP | Cloud Audit Logs (Admin Activity) | `v1.compute.firewalls.insert`, `v1.compute.firewalls.patch` |
| GCP | VPC Flow Logs | Allowed connections on the new rule, external source |
| GCP | Security Command Center | `OPEN_FIREWALL` finding |

## Key Fields to Inspect
**[ANALYST]**
- Actor identity: `userIdentity.arn` (AWS), `caller` / `identity/claims` (Azure), `authenticationInfo.principalEmail` (GCP)
- Source IP and user agent of the API call that made the change — console vs CLI vs Terraform/CI service principal vs unknown IP
- MFA presence on the session (`userIdentity.sessionContext.attributes.mfaAuthenticated` in AWS; conditional access result in Azure sign-in log correlated to the same session)
- Exact rule delta: previous CIDR/port vs new CIDR/port (need the "before" state — check the prior `DescribeSecurityGroups` or resource config history, e.g., AWS Config timeline, Azure Resource Graph history)
- Resource attached to the SG/NSG: instance name, whether it has a public IP, what workload runs on it (check tags: `Environment`, `Owner`, `DataClassification`)
- Time of change vs. time of first inbound hit in flow logs — gap tells you how fast scanners found it
- Whether the change came from IaC pipeline (Terraform/CloudFormation/ARM) — check for a corresponding CI/CD run ID, commit hash, or change-ticket reference in the event's session tags

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Rule scoped to corporate CIDR, VPN egress range, or a named peer VPC | Rule scoped to 0.0.0.0/0 or ::/0 |
| Change made by known IaC service principal during a scheduled deploy window, matching a merged PR | Change made via console/CLI by a human principal outside change windows, no ticket |
| Port is 80/443 on a resource explicitly designed as public (load balancer, CDN origin, public API gateway) | Port is 22, 3389, or a database/cache port |
| MFA-authenticated session, known source IP (corporate egress or known jump host) | Session with no MFA claim, or from a geography/IP never seen for that principal |
| Rule immediately reviewed/reverted by the same engineer within minutes (fat-finger caught fast) | Rule persists, and flow logs show inbound SYNs from many unrelated /24s within the hour — classic mass-scanner fingerprint |

## Investigation Steps
1. Pull the exact control-plane event (`AuthorizeSecurityGroupIngress` / NSG rule write / firewall insert) and confirm actor, source IP, MFA status, and whether it originated from a known IaC pipeline identity.
2. Identify the "before" state of the rule — was this net-new, or a widening of an existing scoped rule? Check resource history (AWS Config, Azure Resource Graph, GCP asset inventory) for the prior CIDR/port.
3. Enumerate every resource attached to the affected SG/NSG and confirm whether any of them has a public IP or public endpoint actually bound. A rule change on a security group with no publicly-addressable member is lower urgency but still needs closing.

   ```bash
   # AWS - list ENIs/instances using the security group and whether each has a public IP
   aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg-id> \
     --query 'NetworkInterfaces[].{ENI:NetworkInterfaceId,Instance:Attachment.InstanceId,PublicIP:Association.PublicIp,PrivateIP:PrivateIpAddress}'
   ```
   ```bash
   # Azure - list NICs associated with the NSG, then check each for a public IP config
   az network nic list --query "[?networkSecurityGroup.id=='<nsg-resource-id>'].{Name:name,IPConfigs:ipConfigurations}"
   ```
   ```bash
   # GCP - list instances the firewall rule's target tags/service account apply to
   gcloud compute instances list --filter="tags.items=<target-tag>" \
     --format="table(name,networkInterfaces[].accessConfigs[].natIP)"
   ```
4. Check flow logs (VPC Flow Logs / NSG Flow Logs) for any inbound ACCEPT traffic on the newly opened port from non-corporate source ranges since the rule change. Note source IP diversity — a handful of IPs might be legit testing; dozens of unrelated /24s in a short window is scanner traffic.
5. If inbound traffic is confirmed, pivot to host-level telemetry (auth logs, EDR process/network events) on the affected instance for signs of successful logon, brute-force attempts, or anomalous process execution correlating with the exposure window.
6. Correlate the identity that made the change against recent sign-in risk signals (impossible travel, new device, failed MFA) to rule out (or confirm) that the change itself was made by a compromised account rather than a careless engineer.
7. Check for a linked change ticket, PR, or CAB approval. Absence of any paper trail combined with an unscoped CIDR is a strong indicator this was not a sanctioned change.
8. If the resource is a domain-joined server, jump host, or database holding regulated data, treat as high-severity regardless of whether exploitation is confirmed yet — the exposure window itself is the incident.

## True Positive Indicators
- Rule confirmed unscoped (0.0.0.0/0 or ::/0) on a management or database port, no linked change ticket.
- Flow logs show inbound connection attempts from IP ranges with no legitimate business reason to reach the resource (e.g., unrelated cloud provider ranges, Tor exit nodes, known scanner ASNs like Shodan/Censys/mass-scan infrastructure).
- Change made by a principal whose session shows other suspicious activity (new IAM key creation, privilege escalation attempts, disabled logging) around the same time — consistent with an attacker widening access post-compromise.
- Host-level evidence of brute-force attempts (repeated failed auths) or a successful anomalous logon shortly after the exposure window opened.

## False Positive / Benign Positive Indicators
- Resource is intentionally public (public-facing web app, API gateway, bastion with just-in-time access controls) and the port/CIDR combination matches its documented design — Expected Activity, close with note referencing the architecture doc.
- Change originated from an approved IaC pipeline run tied to a merged, reviewed PR, and the rule was reverted or scoped down within the maintenance window before any external traffic hit it — Benign Positive, but still worth a config-drift ticket if the "temporary" broad rule pattern repeats.
- Lab/sandbox/dev account explicitly exempted from production security baselines under a documented exception (check the exception register, don't just take the analyst's word for it) — Expected Activity.
- Duplicate alert from both the raw CloudTrail-based detection and the vendor posture-tool finding for the same rule change — dedupe, do not double-count as two separate incidents.

## Escalation Criteria
- Confirmed inbound connections from external, non-scanner-attributable sources with signs of interactive access (successful auth, shell execution, lateral movement attempts) — escalate to IR lead immediately, treat as active intrusion.
- Resource holds regulated/customer data (PCI, PII, PHI) — escalate to IR + notify compliance/legal per breach-notification runbook regardless of confirmed exploitation, since exposure window alone may trigger notification obligations.
- Change was made by a principal without a plausible business reason for that permission (e.g., a read-only reporting service account suddenly modifying network config) — escalate as probable account compromise, pull in identity/IAM team.
- Same pattern (unscoped rule, same account/subscription) recurs more than twice in 30 days — escalate to cloud engineering management as a systemic guardrail gap, not just repeated one-off incidents.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Immediate revert/scope-down of the rule to a known-good CIDR** — SOC/on-call engineer can execute without prior approval when severity is High/Critical and a legitimate owner cannot be reached within 15 minutes; document and notify owner post-action.
- **Isolate the affected instance (remove from load balancer, quarantine security group) if active exploitation is confirmed** — requires IR lead sign-off given availability impact; coordinate with resource owner if reachable. When asking the resource owner for sign-off, give them exactly this in one message, not a narrative: **What happened** (rule `<name>` on `<resource>` allowed `<port>/tcp` from `0.0.0.0/0` starting `<time>`); **Evidence** (`<N>` inbound connection attempts from `<N>` distinct source ranges since exposure, consistent with mass scanning/attack traffic - or confirmed successful auth if applicable); **Decision needed** (approve isolating `<resource>` now, yes/no, within the next 15 minutes); **Consequences** - GO: service interruption for `<resource>` until rebuilt/cleared, but the exposure and any active access stop immediately; NO-GO: `<resource>` stays reachable and in service, but the attack surface and any in-progress access continue while only the rule itself is reverted - acceptable only if the owner explicitly accepts that residual risk in writing/ticket.
- **Rotate credentials/keys on the affected host** if any successful authentication occurred during the exposure window — required, not optional, once TP is confirmed; owned by IAM/platform team.
- **Suspend the principal that made the change** if account compromise is suspected — requires IR lead + IAM team approval; business-hours changes need app owner notification, off-hours emergency suspension is pre-approved under the cloud incident response policy.
- **Preventive control**: deploy/verify a Service Control Policy (AWS), Azure Policy, or GCP Org Policy that denies 0.0.0.0/0 on watchlisted ports tenant-wide — cloud engineering owns implementation, CISO/cloud governance board owns exception approval.

## Example Query
AWS CloudTrail via Athena/SIEM (Sigma-style logic adapted to SQL-ish pseudocode):

```sql
SELECT eventTime, userIdentity.arn, sourceIPAddress,
       requestParameters.groupId,
       requestParameters.ipPermissions.items
FROM cloudtrail_logs
WHERE eventName IN ('AuthorizeSecurityGroupIngress')
  AND requestParameters.ipPermissions.items.ipRanges.items.cidrIp = '0.0.0.0/0'
  AND requestParameters.ipPermissions.items.toPort IN (22,3389,1433,3306,5432,6379,9200,27017,5985,5986)
ORDER BY eventTime DESC
```

Azure equivalent (KQL against AzureActivity + Resource Graph delta), for reference in the Azure-specific version of this control: filter `OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"` and inspect the properties payload for `sourceAddressPrefix == "*"` or `"0.0.0.0/0"`.

## Closure Criteria
Close as **True Positive** once the rule has been scoped down or removed, any confirmed inbound access has been investigated to completion (host isolated/rebuilt or cleared), affected credentials rotated, and root cause (human error vs pipeline defect vs compromised identity) is documented with a corrective action assigned.

Close as **Expected Activity** when the exposure matches a documented, approved architecture (e.g., a tagged public-facing resource) and no unexpected inbound activity is present. Close as **Benign Positive** when the exposure was not pre-documented as intentional, but investigation confirms no malicious actor and no harmful access occurred.

Close as **Insufficient Evidence** only if flow logs for the exposure window are unavailable (retention gap, logging not enabled at time of event) and no host-level corroboration exists — in that case still force the rule closed and flag the missing-flow-logs gap as a separate logging-coverage finding.

**Example case-note line:** *"NSG rule 'allow-rdp-temp' on rg-prod-eastus/vm-fin-app02 was modified 2026-09-15 03:12 UTC by svc-deploy-pipeline (no linked PR found) to allow 3389/tcp from Any. NSG flow logs show 47 inbound SYNs from 19 distinct /24 ranges (consistent with mass RDP scanning) between 03:14-04:02 UTC, no successful auth in Windows Security log. Rule reverted to corporate CIDR at 04:10 UTC by on-call. No evidence of successful access. Closed as True Positive (unauthorized exposure), host credentials rotated as precaution, ticket CLOUD-4471 opened with cloud engineering to require CAB approval on all NSG rule changes to RDP/SSH ports."*
