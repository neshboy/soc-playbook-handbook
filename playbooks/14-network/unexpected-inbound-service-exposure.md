# Unexpected Inbound Service Exposure

## Playbook ID & Name
**NW-015 — Unexpected Inbound Service Exposure (Attack Surface / Exposure Management)**

## Business Risk
**[STAKEHOLDER]** - This playbook covers the moment you find out a door was left open, not the moment someone walked through it. A firewall rule change, a cloud security group with a typo in the CIDR, a new VM that inherited a permissive default template — any of these can put a database, an admin interface, or a management port directly on the internet without anyone deciding that should happen. The business risk isn't the alert itself, it's the gap between "the exposure existed" and "someone found it and closed it." Internet-wide scanning services re-index changes within hours, sometimes minutes, so the window between misconfiguration and discovery-by-attacker is often shorter than most change-management processes assume. This is also one of the few network findings where "nothing bad happened yet" is still a real finding — the exposure itself is the incident, independent of whether anyone exploited it.

## Severity / Priority Default
**High** for internet-facing exposure of an administrative, database, or hypervisor-management service on a production asset, regardless of whether exploitation is confirmed. **Medium** for exposure of a less sensitive service, or exposure limited to an internal segment that shouldn't have reachability but isn't internet-facing. **Low** for exposure on a documented dev/sandbox asset with no sensitive data, pending confirmation of intent. Any confirmed successful connection, authentication, or data return against the exposed service escalates automatically regardless of starting severity.

## MITRE ATT&CK Technique(s)
- **T1046 Network Service Discovery** — this is frequently how the exposure gets found in the first place, either by your own attack-surface-management tooling or by someone else's internal recon after an unrelated foothold.
- **T1595 Active Scanning** — internet-wide scanners (both legitimate research/ASM infrastructure and attacker-run reconnaissance) will find and fingerprint a newly opened port, often within hours of it going live.
- **T1190 Exploit Public-Facing Application** — the natural next step if the exposed service is vulnerable, default-credentialed, or otherwise attackable. This playbook closes before that point in most cases; if there's evidence exploitation was attempted or succeeded, pivot to an incident workflow rather than closing this as a routine exposure finding.

## Trigger / Detection Logic Summary
Alerts fire from two directions and both matter:
- **Configuration-side detection** — a cloud security group, NSG, or perimeter firewall rule change opens a previously closed inbound path (new allow rule, widened CIDR, port added to an existing rule), picked up via cloud audit/change logs or firewall rule-diff monitoring.
- **Observation-side detection** — continuous external attack-surface scanning (your own ASM tooling scanning your own IP ranges) or an internal authenticated/unauthenticated vulnerability scan reports a listening service on a host/port that isn't in the asset baseline, or that the baseline explicitly marks as should-not-be-reachable from that direction.

Either path can fire first; a config-side alert with no observation-side confirmation yet just means the scanner hasn't caught up — don't treat "we haven't seen a scan hit it" as evidence the exposure isn't real.

**[ENGINEERING]** - The reliable version of this detection is a diff, not a single event: compare current listening/reachable state against a known-good baseline (CMDB expected-ports list, prior scan result, or Infrastructure-as-Code desired state) and alert on drift, rather than trying to hand-write a rule for every possible bad port/CIDR combination.

## Required Log Sources
| Source | What it gives you |
|---|---|
| Cloud audit/activity logs (AWS CloudTrail, Azure Activity Log, GCP Audit Logs) | Security group / NSG / firewall rule change events — who changed what, when, from where |
| Cloud provider flow logs (VPC Flow Logs, NSG flow logs) | Actual inbound connection tuples hitting the newly permitted port/CIDR |
| Perimeter firewall allow logs (NGFW) | Confirms whether traffic is reaching the host through the on-prem/hybrid path, not just the cloud-native path |
| Attack-surface-management / external scanning tool (Censys, Shodan-monitoring, internal ASM platform) | First-seen banner, port, and service fingerprint on your own IP ranges |
| Internal vulnerability scanner (Nessus/Qualys/Rapid7) scan-diff | Baseline drift between scheduled scans — this port wasn't open last cycle |
| Host firewall allow log (Windows Filtering Platform / Linux iptables/nftables) | Confirms the host itself is permitting and completing the connection, not just the network ACL |
| EDR network-connection telemetry | Confirms an actual listening process and which binary/service accepted the connection |
| CMDB / asset inventory | Expected-port baseline per asset — the thing you're diffing against |
| Change management ticketing | Correlates the rule change to an approved window, or shows there is none |

## Key Fields to Inspect
**[ANALYST]**
- Asset identity — hostname/IP or cloud resource ID (instance ID, security group ID), owner, environment tag (prod/dev/test), Tier classification.
- Exposed port, protocol, and service/version (banner grab) — and whether the service requires authentication at all.
- Scope of exposure — allowed CIDR (`0.0.0.0/0` / `::/0` vs a specific partner range), and direction (internet-facing vs cross-segment internal reachability that also shouldn't exist).
- First-effective timestamp of the rule/listener vs. detection timestamp — the gap between "it became true" and "we noticed" tells you how long the window of exposure actually was.
- Change actor — IAM user/role, admin account, or IaC pipeline (Terraform/CloudFormation apply, CI/CD job) that made the change, and whether that identity's activity otherwise looks normal.
- Source IPs already connecting since exposure began — geo/ASN, and whether they match known scanner infrastructure (Censys, Shodan, Shadowserver, your own vuln-scanner ranges) vs. unattributed or known-hostile infrastructure.
- Any successful authentication, banner exchange, or data returned — this is the line between "exposure" and "exploitation," and it changes the closure category entirely.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Change ticket exists matching the exact rule, scope, and timing | No change record for the rule at all, or the ticket describes something narrower than what was actually opened |
| CIDR scoped to a specific partner/vendor range for a documented integration | CIDR is `0.0.0.0/0` on an administrative, database, or hypervisor-management port |
| Dev/sandbox asset intentionally internet-reachable per a logged exception | Production, Tier-0, or PCI-scoped asset newly reachable with no exception on file |
| Only known scanner-infrastructure traffic observed against the new opening | Unattributed or known-hostile source IPs hitting the port within minutes to hours of it going live |
| Rule change made by a recognized platform-engineering identity during a normal change window | Rule change made by an unfamiliar service account/role, outside business hours, or immediately following an unrelated suspicious sign-in |

## Investigation Steps
1. Validate the exposure independently before doing anything else — run your own scan/banner grab against the reported port. Stale ASM cache entries and load-balancer health-check ports masquerading as application ports both produce false reads.
2. Identify the asset and its business context from CMDB — owner, environment, Tier, and what the baseline says should be listening there.
3. Establish the timeline: pull the rule/config change history (cloud audit log or firewall rule versioning) to find exactly when the exposure became effective, and check it against the change-ticket calendar.
4. Identify the change actor and mechanism — manual console/CLI change, IaC pipeline apply, or automation — and sanity-check that identity's broader activity for signs of compromise rather than just legitimate misconfiguration.
5. Check what's already hit the port since exposure began — flow logs, firewall allow logs, IDS signature matches — and look specifically for any successful authentication or protocol handshake beyond a bare connect.
6. Assess exploitability of the exposed service itself: version, known vulnerabilities, default or weak credentials, and what else is reachable from it if it were compromised (blast radius).
7. Coordinate remediation with the asset/platform owner — restrict or remove the rule, confirm the fix with a fresh independent scan, and don't close the ticket on the owner's word alone.
8. If this traces back to a template, AMI, or IaC module default rather than a one-off human error, flag it to platform/cloud-security engineering — a single fix here doesn't stop the next instance from launching the same way.

## True Positive Indicators
- Administrative, database, or management-plane service exposed to `0.0.0.0/0` (or an equivalently broad range) with no matching change record.
- Exposure traced to an IaC template or launch default that will recur on every new instance until fixed.
- Unattributed or hostile source IPs connecting shortly after the exposure appeared, particularly with more than a bare TCP handshake.
- Successful authentication, banner interaction, or data return against the exposed service.
- Exposed service is unpatched or uses default/weak credentials and is genuinely reachable end to end.

## False Positive / Benign Positive Indicators
- Approved change ticket matches the rule, scope, and timing exactly (Benign Positive — confirm and close, still worth a note if the CIDR was broader than the ticket described).
- Documented dev/sandbox exception on file for the asset.
- ASM/scanner reporting a result that's already been remediated — the underlying rule was reverted before the scan re-ran, this is a stale-cache artifact, not a live exposure.
- The "open port" is actually a load balancer, CDN edge, or health-check listener misclassified by the scanning tool as the application itself.
- Only known scanner-infrastructure traffic observed, no unattributed connections — real exposure finding, but not an active-targeting escalation.

## Escalation Criteria
Escalate to Tier 2/IR immediately when: a Tier-0 asset (domain controller, hypervisor management interface, core database, PKI, backup infrastructure) is internet-reachable; there's evidence of successful authentication or data returned from the exposed service; the change traces to a likely-compromised identity or an unauthorized modification to an IaC pipeline; default or weak credentials are confirmed reachable; or the pattern indicates a systemic misconfiguration affecting multiple assets rather than an isolated rule change — that last case goes to detection engineering/cloud platform team as well as IR, because closing one instance doesn't fix the template producing the rest.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Emergency restriction or rollback of the firewall/security-group rule** — Tier 1 can action directly under standing SOP when the asset is not Tier-0 and there's clearly no legitimate business tie to the exposure; Tier-0 assets require IR lead or network engineering sign-off even for an emergency change, given outage risk on production infrastructure.
- **Full host/instance isolation** — requires IR lead approval; treat as a suspected-compromise workflow if any successful connection or authentication was observed, not a routine misconfiguration closure.
- **Credential rotation for the exposed service** — owned by the asset/application owner; SOC raises the requirement and tracks it, doesn't own the rotation itself.
- **Reversion of an unauthorized IaC/pipeline change** — owned by platform engineering, actioned through an emergency-change record even when done same-day; SOC doesn't push infrastructure code changes directly.
- **Guardrail/policy update to prevent recurrence** (e.g., an org-wide deny on `0.0.0.0/0` for administrative ports) — owned by cloud security/platform engineering; SOC supplies the finding as the driver, not a unilateral SOC control change.

## Example Query (Microsoft Sentinel — KQL, cloud audit log)
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| where ActivityStatusValue == "Success"
| extend RuleBody = tostring(parse_json(Properties).requestbody)
| where RuleBody has "0.0.0.0/0"
    and (RuleBody has "3389" or RuleBody has "22" or RuleBody has "1433")
| project TimeGenerated, Caller, ResourceGroup, RuleBody
```

## Closure Criteria
Close as **True Positive** (exposure confirmed) once the rule/listener is verified real, unauthorized, and remediated — regardless of whether exploitation occurred; open a separate confirmed-incident workflow only if evidence shows successful exploitation or credential compromise. Close as **Benign Positive** when the exposure matches an approved change ticket or a documented exception, even if the scope was slightly broader than ideal (note the gap for follow-up hardening). Close as **Insufficient Evidence** when cloud audit or firewall change logs have already rolled off retention and neither the timeline nor the change actor can be established — say so explicitly rather than defaulting to benign because the trail went cold.

**Example case note:** *"sqldb02.example.com (10.20.6.41) — TCP/1433 exposed via AWS security group sg-0fa29c1d4e, ingress rule permitting 0.0.0.0/0 added 2026-09-12 03:14 UTC by IAM role terraform-deploy-prod; no matching change ticket found. Independent scan confirmed reachable and unauthenticated banner responded. VPC Flow Logs show 6 connection attempts from a known Censys scanning range, no unattributed sources, no successful auth observed. Engine version patched, no default-credential exposure. SG rule reverted 2026-09-15 10:02 UTC by platform-eng under emergency change CHG-4471; re-scan confirms closed. Closed True Positive (exposure confirmed, no exploitation) — DB owner notified to rotate the SQL admin credential as precaution and flagged terraform-deploy-prod module to platform-eng for default-CIDR review."*
