# Cloud Audit Logging Disabled

## Playbook ID & Name
**CLD-010** — Cloud Audit Logging Disabled / Modified (AWS CloudTrail, Azure/Entra ID Diagnostic Settings, GCP Cloud Audit Logs, M365 Unified Audit Log / Microsoft Purview Audit)

## Business Risk
**[STAKEHOLDER]** - When audit logging goes dark, we lose the ability to see what an attacker (or a careless admin) does next in the tenant — every subsequent action becomes unprovable, which breaks incident response, breach notification obligations, insurance claims, and regulatory attestations (SOC 2, PCI, ISO 27001) that depend on continuous audit trails. This is treated as a blinding event, not a config drift event, which is why it pages the on-call SOC lead immediately rather than waiting for business hours: restoring logging is a "fix now, explain after" call the SOC lead can make alone, but deciding whether the gap itself is reportable (a compliance question, independent of whether anything malicious happened during it) sits with the Cloud Platform lead and Legal/Compliance, who must hear about any gap within 4 hours of confirmation regardless of how it resolves.

## Severity / Priority Default
**Critical / P1** — auto-escalate on detection, regardless of who made the change, pending confirmation of intent. Logging gaps have a way of aging badly; the "we'll check it tomorrow" version of this ticket is how six-month-old compromises get discovered.

## MITRE ATT&CK Technique(s)
- **T1562.001** — Impair Defenses: Disable or Modify Tools (primary — this is the textbook example of the technique in a cloud control plane)
- **T1078.004** — Valid Accounts: Cloud Accounts (the credential/identity used to make the change)
- **T1098.001** — Additional Cloud Credentials (frequently paired follow-on: attacker adds a persistent access key or app credential once logging is suppressed)

## Trigger / Detection Logic Summary
Alert fires on any control-plane event that disables, deletes, suspends, or materially narrows the scope of audit/diagnostic logging: stopping or deleting a trail/sink, disabling the unified audit log, removing a diagnostic setting that fed a SIEM, shrinking event selectors to exclude data events, or disabling mailbox/Entra audit at the tenant level. The rule should also catch *retention* changes (e.g., dropping retention to 1 day) and *routing* changes (log export target quietly redirected to an attacker-controlled or unmonitored destination), since those achieve the same blinding effect without an outright "disable."

## Required Log Sources & Event IDs
| Platform | Log Source | Key Event / API Call |
|---|---|---|
| AWS | CloudTrail (management events, ideally cross-account/org trail) | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`, `DeleteEventDataStore` |
| Azure | Activity Log | `Microsoft.Insights/diagnosticSettings/delete`, `Microsoft.Insights/diagnosticSettings/write` (scope narrowed), `Microsoft.Network/networkWatchers/...FlowLogs/delete` |
| Entra ID | Entra Diagnostic Settings / Directory Audit | Diagnostic setting deletion for `AuditLogs`/`SignInLogs` category; `Update AuditLogsRetentionPolicy` |
| M365 | Unified Audit Log / Microsoft Purview Audit (via Microsoft 365 admin/PowerShell) | `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false`; mailbox audit disabled (`Set-Mailbox -AuditEnabled $false`) |
| GCP | Cloud Audit Logs / Logging sinks | `google.logging.v2.ConfigServiceV2.DeleteSink`, `UpdateSink` (filter narrowed), Data Access log toggle off |
| SIEM/collector side | Ingestion health | Sudden drop-to-zero in EPS from a specific cloud source; missing heartbeat from a log forwarder |

## Key Fields to Inspect
**[ANALYST]**
- Actor identity: `userIdentity.arn` / `userIdentity.principalId` (AWS), `caller` / `identity.claims.upn` (Azure), `InitiatedBy.user.userPrincipalName` (Entra), `actor.email` (GCP), `UserId` (M365 UAL)
- Source IP and whether it resolves to a known corporate egress, VPN, or a cloud provider/Tor/VPS range
- User-agent / calling application — console UI vs `aws-cli`, `az cli`, PowerShell module, or an unfamiliar SDK signature
- MFA presence on the session (`additionalEventData.MFAUsed` in AWS, `authenticationRequirement` in Entra sign-in log correlated to the same session)
- Target resource: which trail/sink/diagnostic setting/mailbox was touched, and its prior scope (all regions? all subscriptions? which log categories?)
- Time delta between the account's last successful sign-in/MFA challenge and the disable action — attackers move fast after landing
- Whether the same session subsequently created an access key, app registration, or federated credential (T1098.001 chaining)

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| Change made by a named cloud/platform engineer during a documented maintenance window, tied to a change ticket | Change made by a service account, break-glass account, or an identity with no prior history of touching logging config |
| Logging paused briefly for a *migration* (old sink deleted, new sink created within minutes, same or broader scope) | Logging disabled with no replacement sink/trail created, or scope narrowed to exclude the exact region/subscription/mailbox relevant to other suspicious activity |
| Action originates from known admin workstation IP / expected CI-CD pipeline identity | Action from anonymized VPN, unfamiliar geography, or immediately after a password reset / MFA registration change |
| Retention shortened as part of a cost-review project (documented, gradual) | Retention dropped to the platform minimum abruptly, same day as other defense-evasion indicators |

## Investigation Steps
1. Confirm the event is real and not a collector-side artifact — check ingestion pipeline health first; a "logging disabled" alert can be a false alarm if it's actually a broken forwarder or expired API token on the SIEM side.
2. Identify exactly what was disabled/changed: trail vs event selector vs sink vs retention vs UAL toggle. Pull the full "before" configuration from a recent baseline or CMDB/IaC state (Terraform/CloudFormation state file) if available.
3. Identify the actor and authenticate the session: cross-reference sign-in logs (Entra sign-in, AWS `ConsoleLogin`/`AssumeRole`, GCP IAM) for MFA status, source IP, device, and session token age.
4. Check for a paired persistence action in the same session or within the following hour: new access key (`CreateAccessKey`), new app secret/federated credential, new admin role assignment, new mailbox delegate/forwarding rule (T1098.001, T1136).
5. Determine blast radius of the gap: which resources, subscriptions, or mailboxes lost coverage, and for how long (from disable timestamp to detection/re-enable timestamp).
6. Pull whatever telemetry survived from adjacent sources not affected by the change (VPC Flow Logs, EDR on any workload identities involved, DNS logs, M365 Defender if UAL only was disabled) to reconstruct activity during the gap.
7. Interview the actor's team/manager if it's an internal identity — legitimate maintenance is common; get the change ticket number before escalating further.
8. If no legitimate explanation surfaces within the SLA window, treat as confirmed compromise and pivot to full incident response, including credential rotation for the actor and anyone who shares that role.

## True Positive Indicators
- No corresponding change ticket, and the identity has no history of managing logging infrastructure
- Disable action immediately preceded by a suspicious sign-in (new geography, impossible travel, failed MFA attempts beforehand)
- Scope of disabled logging maps precisely onto where other alerts (privilege escalation, mass download, new external forwarding rule) are firing
- Logging re-enabled by the attacker briefly to avoid tripping "logging disabled" health alerts, then disabled again (flapping pattern)
- Persistence artifact created in the same session (new key, new OAuth app consent, new global admin)

## False Positive / Benign Positive Indicators
- Scheduled Terraform/Pulumi apply that recreates the trail/sink as part of normal IaC drift correction (old resource deleted, new one created with matching or broader scope)
- Vendor-run security tool (CSPM/CNAPP) performing a documented remediation test
- Cost-optimization project narrowing data-event logging on a low-value bucket, with a linked Jira/change ticket
- Regional trail consolidation where a per-region trail is intentionally deleted in favor of an organization trail — verify the org trail actually covers the region before closing

## Escalation Criteria
Escalate to IR/CSIRT immediately if: the actor cannot be reached or denies making the change; MFA was not present on the session; the change coincides with any other active alert in the same tenant/subscription; or the affected scope includes production financial, healthcare, or customer PII systems. Notify the data protection/compliance owner in parallel — a sustained logging gap may itself be a reportable control failure independent of whether compromise is confirmed.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- Immediate: re-enable logging/restore prior configuration — Tier 2 analyst can execute with on-call Cloud Platform lead notification, no approval delay (this is a "fix now, explain after" action)
- Suspend/disable the actor's credentials and revoke active sessions — requires Incident Commander or IAM team lead sign-off; do this before the actor can re-disable logging a second time
- Rotate any access keys/app secrets created during the suspected gap — Cloud Security Engineering, same-day
- Enable a break-glass alert on future `StopLogging`/`DeleteSink`/diagnostic-setting-delete calls with no auto-remediation delay — CSIRT + Cloud Platform, standing control, review quarterly
- Legal/Compliance notification for any gap exceeding the org's defined logging-availability SLA — SOC Manager escalates within 4 hours of confirmation

## Example Query (Splunk SPL, multi-source)
```spl
index=cloud_audit (sourcetype=aws:cloudtrail eventName IN ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors"))
   OR (sourcetype=azure:activitylog operationName="*diagnosticSettings/delete*")
   OR (sourcetype=gcp:audit protoPayload.methodName="*ConfigServiceV2.DeleteSink*")
   OR (sourcetype=o365:management operation="Set-AdminAuditLogConfig")
| eval actor=coalesce(userIdentity.arn, caller, protoPayload.authenticationInfo.principalEmail, UserId)
| table _time, actor, src_ip, eventName, operationName
| sort -_time
```

## Closure Criteria
Close only once: the prior logging configuration is confirmed restored (screenshot/config export attached to ticket), the actor's identity and intent are validated against a change record or interview, no correlated malicious activity is found during the gap window across surviving telemetry, and — if the actor was internal — the change process gap that allowed an undocumented logging change is fed back to the Cloud Platform team.

**Example case note:** "2026-09-15 14:02 UTC — AWS org trail `mgmt-org-trail` stopped via StopLogging by role `svc-terraform-ci` from CI runner IP 10.4.12.9, session had valid MFA-exempt service credential; confirmed against change ticket CHG-40217 (trail migration to CloudTrail Lake). New event data store confirmed capturing events from 14:06 UTC, 4-minute gap. VPC Flow Logs and GuardDuty show no anomalous activity in gap window. Closed as Expected Activity."
