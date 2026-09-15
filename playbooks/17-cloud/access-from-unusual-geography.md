# CLD-012: Access from Unusual Geography

**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)

## Business Risk

**[STAKEHOLDER]** - An account authenticating or acting from a country it has never operated from, or from a country the business has no footprint in at all, is one of the cheapest tells that credentials have leaked - cheaper than waiting for the attacker to do something obviously destructive. This playbook is broader than impossible travel: it doesn't need two conflicting sign-ins to compare, it needs one sign-in (or one API call) that doesn't fit where this identity, or the organization as a whole, normally operates from. That matters because plenty of real account takeovers never produce a neat "impossible travel" pair - the attacker logs in once from a foreign IP, sets up persistence, and the legitimate user doesn't sign in again for hours. Waiting for a second data point to correlate against means giving up the head start. Who decides how aggressively to gate on geography (block outright vs. alert-and-review) is a joint call between IAM/identity engineering and the business unit, because a real remote workforce, contractor base, or M&A-in-progress subsidiary can make "unusual" genuinely normal.

## Severity / Priority Default

**Medium / P3** for a first-time country with no other risk signal on a standard user account. Escalates to **High / P2** if the source country is on the organization's sanctioned/high-risk watchlist, the IP resolves to hosting/VPS or known anonymizing infrastructure, or the account holds elevated privilege. Escalates to **Critical / P1** if post-access activity shows credential/key creation, mailbox delegation, mass data access, or if multiple unrelated accounts show the same anomalous-geography pattern in a short window (spray/stuffing campaign, not an isolated case).

## MITRE ATT&CK Techniques

T1078.004 (Valid Accounts: Cloud Accounts) is the core technique represented. Commonly preceded by T1110.001 (Password Guessing) or T1110.003 (Password Spraying) originating from the same foreign infrastructure, and frequently masked by T1090 (Proxy) - VPN, residential proxy, or hosting-provider relays specifically chosen to blend in or to hop around geo-fencing rules. If the access is confirmed malicious, expect follow-on activity mapping to T1538 (Cloud Service Dashboard) and T1580 (Cloud Infrastructure Discovery) as the attacker orients themselves, T1098.001 (Additional Cloud Credentials) or T1114.003 (Email Forwarding Rule) as they entrench, and T1530 (Data from Cloud Storage) or T1119 (Automated Collection) if the objective is data theft.

## Trigger / Detection Logic Summary

Fires on a single successful authentication event, or a burst of API/data-plane activity, where the resolved source country/region falls outside an established baseline. Two baselines matter and should both be checked, not just one:

- **Per-identity baseline** - countries this specific user/service principal has authenticated from historically (rolling 30-90 day window is typical).
- **Per-tenant baseline** - countries the organization has any legitimate presence in at all (offices, remote staff, contractors, approved SaaS vendors calling in via API).

A hit against either baseline is worth a look; a hit against both (never seen for this user, and the organization has zero business reason to have traffic from that country) is the higher-confidence case.

- **Entra ID / M365** - Identity Protection risk detections `unfamiliarFeatures` / atypical location signals in `AADUserRiskEvents`, cross-referenced with `SigninLogs.Location`; Conditional Access named-location/country policies can also emit block or MFA-challenge events worth alerting on even when they succeed.
- **AWS** - CloudTrail `ConsoleLogin`/`AssumeRole`/`GetSessionToken` events geo-resolved by `sourceIPAddress`, compared against a per-`userIdentity.arn` history table you maintain in the SIEM (AWS has no native per-identity geo-baseline); GuardDuty's anomalous-API-caller findings for IAM users can supplement this.
- **GCP** - Cloud Identity/Workspace login audit `ipAddress` geo-resolved and compared the same way; Security Command Center anomalous-location findings where licensed.
- **General** - a maintained watchlist of sanctioned/high-risk countries (aligned to OFAC and internal risk policy) that auto-elevates severity regardless of whether it's a "first" for that user.

## Required Log Sources & Event Data

| Platform | Source | Key Fields / Identifiers |
|---|---|---|
| Entra ID / M365 | Sign-in logs, Identity Protection, Conditional Access logs, Unified Audit Log (Purview) | `SigninLogs` (`Location`, `IPAddress`, `ResultType`, `ConditionalAccessStatus`), `AADUserRiskEvents.RiskEventType`, UAL `UserLoggedIn` |
| AWS | CloudTrail (management + data events), GuardDuty | `eventName` (`ConsoleLogin`, `AssumeRole`, `GetSessionToken`), `sourceIPAddress`, `userIdentity.arn`, `additionalEventData.MFAUsed`, GuardDuty finding type/severity |
| GCP | Cloud Identity login audit, Cloud Audit Logs, Security Command Center | `protoPayload.authenticationInfo.principalEmail`, login `ipAddress`, SCC finding category |
| Threat intel / geo-IP enrichment | Internal SIEM enrichment or third-party feed | ASN owner, hosting/VPS classification, sanctioned-country list membership - this is where most disputes get settled |
| HR / travel / contractor roster | Internal system, referenced not ingested | Confirms whether a country is a legitimate business presence for that identity |

## Key Fields to Inspect

**[ANALYST]**
- `userPrincipalName` / `userIdentity.arn` - rule out shared, break-glass, or federated identity-provider service accounts up front; those legitimately originate from unexpected ranges and should already be excluded from this detection, but check the exclusion list is current.
- `location` (country/region as resolved by the platform) and a **second independent geo-IP lookup** - platform-native resolution and third-party feeds disagree often enough that this step alone resolves a chunk of false positives.
- ASN/IP ownership - residential ISP vs. datacenter/hosting/VPS vs. known commercial VPN provider vs. mobile carrier. A hosting-provider ASN in an unusual country is a materially stronger signal than a residential ISP in an unusual country.
- `isInteractive` / `clientAppUsed` - non-interactive, backend service-to-service traffic through provider infrastructure routes across regions constantly and is a leading false-positive source.
- `deviceDetail` (`deviceId`, `isCompliant`, `isManaged`, `trustType`) - known managed device from an unusual country carries a different weight than an unmanaged/unknown device.
- `authenticationRequirement` / MFA method and satisfaction - and whether the MFA method was registered recently, from where.
- Whether the country appears on the sanctioned/high-risk watchlist independent of whether it's "new" for this user - a returning pattern from a sanctioned jurisdiction is still worth escalating.
- Volume and scope of activity after the sign-in - one login that goes nowhere is a different animal than a login followed by enumeration or bulk data access.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| First-time country matches a known business trip, new remote hire, or contractor onboarding with HR/roster confirmation | First-time country with zero business relationship, no travel record, no calendar entry, denied by the user |
| Source ASN is a recognized corporate VPN/SASE egress or known mobile carrier CGNAT pool | Source ASN is a bare hosting/VPS provider or a commercial VPN/anonymizer with prior abuse history |
| Non-interactive/background sign-in relayed through provider infrastructure across regions | Interactive sign-in, human-driven console/API session, immediately followed by discovery or data-access activity |
| Country is on an approved list for a specific role (e.g., offshore support team with documented geography) | Country is on the sanctioned/high-risk watchlist or has no documented business reason to appear |
| Isolated, single event with no follow-on activity, account returns to baseline pattern | Repeated access from the same anomalous country/ASN across multiple unrelated accounts in a short window |

## Investigation Steps

1. Pull the full sign-in/API event: source IP, ASN, resolved country/region, device, client app, MFA method and result, and any correlation ID linking related events.
2. Run a second, independent geo-IP/ASN lookup - don't accept the platform's label at face value, especially for newly assigned or carrier-grade NAT ranges.
3. Check the identity's 30-90 day authentication history for this country/ASN - genuinely first-time, or an established-but-infrequent pattern (e.g., a consultant splitting time between two countries)?
4. Cross-reference the country against the sanctioned/high-risk watchlist and against the organization's documented business presence (offices, remote staff roster, approved contractor/vendor list).
5. Contact the user or the account owner (service principal → engineering owner) through an out-of-band channel - do not rely on email if the mailbox itself could be compromised.
6. Review activity immediately following the access: role/permission enumeration, new credential or additional cloud credential creation, mailbox rule/delegation changes, bulk storage access, or console navigation consistent with reconnaissance.
7. If the source ASN is hosting/VPS or a known anonymizer, check whether the same infrastructure touched other accounts in the tenant in the same window - this is frequently how a single detection turns into a campaign-level finding.
8. Document findings and assign a disposition; if any credential-theft or post-access tampering indicator is present, move directly into containment rather than waiting on user confirmation.

## True Positive Indicators

- User or system owner denies the access, or has no explanation for presence in that country.
- Source IP resolves to hosting/VPS infrastructure or a commercial anonymizer with prior abuse reports, and no legitimate business use of a VPN explains it.
- Post-access activity includes new credential/access key creation, mailbox forwarding rule, permission enumeration, or bulk data access.
- Country is on the sanctioned/high-risk watchlist with no documented business relationship.
- Same anomalous country/ASN touching multiple unrelated accounts in a short window - indicates a coordinated spray/stuffing campaign rather than an isolated event.

## False Positive / Benign Positive Indicators

- Confirmed legitimate travel, relocation, or new remote-work arrangement, corroborated by HR/travel records or a documented calendar entry.
- Corporate VPN/SASE egress node or mobile carrier CGNAT reassigning apparent location - resolves cleanly once ASN is checked.
- Non-interactive backend service traffic relayed through the cloud provider's own multi-region infrastructure (very common with Exchange Online/Teams/Workspace background sync).
- Newly onboarded offshore contractor, support team, or acquired-company staff whose geography simply hasn't been added to the baseline/roster yet - a detection engineering gap, not a security incident.
- Stale or inaccurate geo-IP database entry for a recently reassigned IP block, resolved by a second-source lookup.

## Escalation Criteria

Escalate to IR/CIRT immediately if: the user denies the access, the source infrastructure is hosting/anonymizer-class with abuse history, any credential/permission/mailbox-rule change followed the access, the country is on the sanctioned watchlist, or the same anomalous pattern spans multiple accounts. Notify identity engineering regardless of disposition if the same "new" country recurs after being marked benign once - either the baseline needs updating or the account is being re-targeted.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Revoke active sessions/refresh tokens for the affected identity - SOC analyst executes immediately on confirmed or high-confidence suspected compromise under standing authorization.
- Force password reset and MFA re-registration - SOC lead authorizes, IAM/helpdesk executes; contact the user out-of-band, not via corporate email.
- Apply or tighten a Conditional Access / IAM policy country-block or MFA-challenge rule for the anomalous location - IAM engineering executes; SOC lead can request emergency application during an active campaign, standing change process otherwise.
- Suspend the account pending investigation - SOC lead can execute for standard users; VIP/executive or production-service-account suspension requires IAM manager or business-owner sign-off unless active malicious activity is confirmed, in which case emergency authority applies.
- Add a legitimate new country/ASN to the identity or tenant baseline once confirmed benign - requires a detection engineering change ticket referencing HR/roster confirmation, not an ad hoc analyst suppression.

## Example Query (Microsoft Sentinel - KQL)

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize FirstSeen = min(TimeGenerated), Count = count() by UserPrincipalName, Country, IPAddress
| join kind=leftanti (
    SigninLogs
    | where TimeGenerated between (ago(90d) .. ago(7d))
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | distinct UserPrincipalName, Country
) on UserPrincipalName, Country
```

## Closure Criteria

Close only after: the source IP/ASN has been independently geo-verified, the identity's history has been checked for prior visibility into that country, the user or system owner has been reached through an out-of-band channel, and post-access activity has been reviewed for tampering. Record a disposition of True Positive, Benign Positive (travel/new-hire/VPN explained), Expected Activity (documented business presence, baseline just needs updating), or Insufficient Evidence (owner unreachable, geo data inconclusive) - do not force a verdict just to close the ticket.

**Example case note:**
"2026-09-15 11:20 UTC - Unusual geography alert for svc-reports@example.com (service principal, AWS `userIdentity.arn` ending `role/ReportingAutomation`): `AssumeRole` from 203.0.113.44 resolving to Lagos, NG, ASN registered to a commercial VPS provider. No prior activity from Nigeria in 90-day baseline; organization has no offices, staff, or contractors in-country. Engineering owner confirmed no scheduled maintenance from that region. Follow-on CloudTrail shows `ListBuckets` and `GetObject` calls against the `example-reports-prod` bucket within 4 minutes of the AssumeRole event - inconsistent with the role's normal daily-batch pattern. Disposition: True Positive (T1078.004 via leaked long-lived access key, T1530 attempted). Key deactivated, role trust policy reviewed, bucket access logs pulled for full scope, IAM engineering notified to rotate and migrate to short-lived credentials."
