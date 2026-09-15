# Cloud (AWS / Azure / M365 / Entra ID / GCP)

Every playbook in this category is really the same story wearing a different provider's logo: someone's identity did something it shouldn't have, or a control-plane setting got changed in a way that widens the blast radius. There's no perimeter to defend here in the traditional sense — the "network" is an API, and the API doesn't care whether the caller is a human at a laptop, a CI/CD pipeline, a Lambda function, or an attacker replaying a stolen session token. That's the throughline across this whole section: identity is the perimeter, and almost every alert here ultimately reduces to "was this API call/sign-in/config change expected, from this principal, at this time, from this location, doing this action." Root/global-admin misuse, new access keys, IAM policy drift, public buckets, open security groups, disabled MFA, impossible travel, rogue OAuth grants, privilege escalation via role chaining, audit logging tampering — these all map back to a small cluster of ATT&CK techniques you'll see repeated with minor variations across the folder: Valid Accounts: Cloud Accounts (T1078.004), Additional Cloud Credentials (T1098.001), Account Manipulation (T1098), Create Account (T1136), Account Access Removal (T1531), Impair Defenses: Disable or Modify Tools (T1562.001), Cloud Infrastructure Discovery (T1580), Cloud Service Dashboard (T1538), Data from Cloud Storage (T1530), and Unsecured Credentials: Cloud Instance Metadata API (T1552.005). It's identity abuse and control-plane manipulation, not exotic malware, that dominates this category.

**[ENGINEERING]** - Practically, that means detection here leans on control-plane/management-plane logs far more than payload inspection: AWS CloudTrail (management and data events), Config, GuardDuty and VPC Flow Logs; Azure/Entra ID Sign-in and Audit logs, the unified Activity Log, and Defender for Cloud/NSG flow logs; M365's Unified Audit Log (Microsoft Purview Audit) plus Defender for Office 365 and Defender for Cloud Apps (MCAS) for OAuth/mailbox activity; GCP's Admin Activity and Data Access audit logs plus Security Command Center. Correlating identity actions against a CSPM/CIEM view (who *can* do this vs. who *did* do this) is what separates a real finding from noise, and most of the playbooks in this folder assume you've got at least one of those wired into the SIEM.

**[ANALYST]** - The friction is real and specific to this category. CloudTrail delivery can lag several minutes behind the actual API call, Entra ID sign-in logs run on their own ingestion delay, and if your SIEM connector pulls on a schedule you're often investigating a "live" incident that's already 20-30 minutes stale. Timestamps arrive in UTC while the ticket, the stakeholder, and the analyst's shift are all on local time — get this wrong and your timeline is wrong. Cross-account/cross-tenant visibility usually requires an assumed role or app registration that someone forgot to scope correctly, so half your "missing telemetry" tickets are really permissions tickets. Microsoft 365 and Google Workspace egress traffic routinely comes from the provider's own shared IP ranges, which makes impossible-travel and geo-anomaly detections noisy by default — don't assume the alert is wrong just because the "second" location resolves to a Microsoft datacenter. And break-glass/emergency-access accounts, third-party OAuth consents nobody reviewed, and forgotten service principals will keep showing up as false positives until someone actualy inventories them.

## Playbooks in This Category

| # | Playbook |
|---|---|
| 1 | Root / Global-Admin Account Usage |
| 2 | New Access Key Creation |
| 3 | Suspicious IAM Policy Changes |
| 4 | Public Storage Bucket Exposure |
| 5 | Security Group Opened to the Internet |
| 6 | MFA Disabled on an Account |
| 7 | Impossible Travel (Cloud Sign-In) |
| 8 | New OAuth Application Registered/Consented |
| 9 | Privilege Escalation via Role/Policy Chaining |
| 10 | Cloud Audit Logging Disabled |
| 11 | New Admin/Global-Admin Granted |
| 12 | Access from Unusual Geography |
| 13 | Mass Object Download from Storage |
| 14 | Storage-Based Exfiltration |
| 15 | Suspicious API Call Sequences |
| 16 | Cloud Shell Abuse |
| 17 | Instance/VM Compromise Indicators |
| 18 | Credential Leakage (Keys in Code/Logs) |
