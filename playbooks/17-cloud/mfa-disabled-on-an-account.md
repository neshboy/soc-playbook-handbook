# CLD-006: MFA Disabled on an Account

**Category:** Cloud (AWS / Azure / M365 / Entra ID / GCP)

## Business Risk

**[STAKEHOLDER]** - Multi-factor authentication is the single control that stands between a leaked or guessed password and full account takeover. When MFA gets turned off on an account - whether by an admin, by the user themselves, or by an attacker who's already inside - that account drops back to password-only strength, and passwords get phished, sprayed, and reused constantly. The dangerous version of this event is an attacker who has already stolen a password, logs in with it, and then disables MFA (or registers their own MFA method) so they don't have to fight the control again on the next login. That turns a one-time credential theft into standing, renewable access. This is why the removal of the control is treated as the alert - not just misuse after the fact.

## Severity / Priority Default

**High / P2** by default, escalating to **Critical / P1** if the account is privileged (Global Admin, IAM admin, billing, break-glass) or if the disable action was performed by someone other than the account owner and cannot be immediately tied to an approved helpdesk/IT ticket.

## MITRE ATT&CK Techniques

T1562.001 (Impair Defenses: Disable or Modify Tools) - disabling the MFA requirement itself is a defense-impairment action against an identity control. T1098.001 (Account Manipulation: Additional Cloud Credentials) - commonly paired: attacker registers a new authenticator method/phone number they control, sometimes before removing the legitimate one. T1078.004 (Valid Accounts: Cloud Accounts) - the account is then used with password-only or attacker-controlled MFA to maintain access. T1538 (Cloud Service Dashboard) - admin portal used to review/change the account's security settings. Where the disable is followed by locking the legitimate owner out entirely, treat as a possible pivot into T1531 (Account Access Removal) and re-scope the investigation accordingly.

## Trigger / Detection Logic Summary

Fires on any event where an account's MFA/strong-authentication requirement is removed, an existing MFA method is deleted, or MFA enforcement is bypassed at the policy level for that account - regardless of who performed it. Three sub-patterns matter and should be distinguished in the alert:

1. **Self-service removal** - the account holder deletes their own authenticator app/phone method (Entra ID: "Delete registered security info" initiated by the user themselves).
2. **Admin-initiated removal** - a help desk or IT admin disables MFA or resets authentication methods for another user (legitimate password-reset workflow, but also a common social-engineering target: an attacker calls the help desk impersonating the employee to talk an agent into resetting MFA without proper caller verification).
3. **Policy-level bypass** - a Conditional Access policy, per-user MFA setting, or AWS IAM/STS session policy is modified to exclude the account from an MFA requirement entirely, rather than touching the method itself.

Correlate the disable event against sign-in activity in the surrounding ±30 minutes on both sides - a legitimate self-service device swap looks very different from "new session from unfamiliar ASN, then MFA method deleted 4 minutes later."

## Required Log Sources & Event Data

| Platform | Source | Key Event Identifiers |
|---|---|---|
| Entra ID / M365 | Entra ID Audit Logs, Sign-in Logs, Unified Audit Log (Purview, UAL) | Audit activities: `Delete registered security info`, `Admin deleted security info`, `Disable Strong Authentication` (legacy per-user MFA), `Update policy` (Conditional Access), `Update user` with `StrongAuthenticationRequirements` in `ModifiedProperties` |
| AWS | CloudTrail (management events) | `eventName`: `DeactivateMFADevice`, `DeleteVirtualMFADevice`, `UpdateLoginProfile`, `PutUserPolicy` (if used to strip an MFA-required condition from an IAM policy) |
| GCP / Google Workspace | Admin console audit log, Cloud Identity audit log | Event category `2SV Enrollment` / `ENFORCE_STRONG_AUTHENTICATION` toggles at org-unit or user level |
| Identity/helpdesk | ITSM ticketing system, helpdesk call logs | Correlate every admin-initiated MFA reset against an open, verified ticket with caller-identity verification recorded |

## Key Fields to Inspect

**[ANALYST]**
- `initiatedBy` (Entra audit log) - is this the account owner's own session, or a different admin/service principal? A self-triggered removal from a device the user has never signed in from before is itself suspicious.
- `TargetResources` / `modifiedProperties` - which specific authentication method was deleted (Authenticator app, SMS, phone call, FIDO2 key) and whether a new method was registered in the same window.
- `IPAddress` / `ipAddress` and ASN of the session that performed the disable - compare to the account's normal login footprint (corporate egress range vs. residential ISP or VPN/proxy exit).
- `userAgent` and client app - a browser session on an unmanaged device performing a security-setting change is a different risk profile than the same action from a managed, compliant endpoint.
- Time gap between the most recent successful sign-in and the MFA method deletion - near-immediate action after a suspicious login is the classic takeover-then-entrench pattern.
- For admin-initiated resets: identity of the admin, whether they have a legitimate service-desk role, and whether the reset matches a logged, verified support ticket.
- Any immediately following activity: new mail forwarding rule, new OAuth app consent, new registered device, or added MFA method under attacker control - these confirm intent rather than accident.

## Normal vs Suspicious Pattern

| Normal | Suspicious |
|---|---|
| User swaps phone/authenticator app themselves, from their usual device and location, then re-registers a new method within minutes | MFA method deleted with no new method registered, or a new method added from an unfamiliar IP immediately before/after the old one is removed |
| Admin performs MFA reset tied to an open helpdesk ticket, caller identity verified per policy | Admin reset with no matching ticket, or ticket exists but caller-verification step was skipped/rushed |
| Conditional Access policy change made during a planned migration window, documented in change management | Conditional Access policy silently modified to exclude a specific privileged account, outside any change window |
| MFA disable followed by normal day-to-day account use | MFA disable followed immediately by mailbox rule creation, OAuth app consent, or access to sensitive resources the account doesn't normally touch |

## Investigation Steps

1. Identify exactly what happened: method deletion, per-user MFA toggle, or Conditional Access/policy-level exclusion - the response differs for each.
2. Identify who performed the action - pull `initiatedBy`/actor identity, and confirm whether it's the account owner, an admin, or a service principal/automation.
3. Pull the account's sign-in timeline for the two hours before and one hour after the disable event - look for an unfamiliar IP/ASN, impossible travel, or a legacy-auth sign-in immediately preceding the change.
4. If admin-initiated, verify against the ITSM ticket: does a matching, approved ticket exist, and was caller/requestor identity actually verified per the documented helpdesk procedure (not just "they knew the employee ID")?
5. Check whether a new MFA method was registered around the same time, and if so, whether its associated phone number/device fingerprint matches anything previously seen for this user.
6. Review post-disable account activity: new inbox rules, OAuth app consents, file/mailbox access outside normal pattern, or use of the account from the same suspicious IP as the disable event.
7. If the account is privileged, immediately check for downstream changes - new role assignments, new access keys, or additional accounts created - since a privileged account with MFA down is a direct path to broader compromise.
8. Interview the account owner directly (out-of-band, not via email if the mailbox itself is in question) to confirm whether they performed or requested the change.

## True Positive Indicators

- MFA method deleted or bypassed with no corresponding user request, ticket, or self-service action the owner can confirm.
- Disable event immediately preceded by a sign-in from an unfamiliar IP/ASN or via legacy authentication.
- New MFA method registered under a device/phone number the user does not recognize.
- Admin-initiated reset with no matching ticket, or a ticket created after the fact to paper over an unverified request.
- Follow-on activity (mail rule, OAuth consent, new credentials, privileged role changes) consistent with entrenchment rather than routine use.

## False Positive / Benign Positive Indicators

- User self-service device swap (lost phone, new phone, reinstalled authenticator app) with a new method registered promptly and confirmed by the user.
- Verified helpdesk reset tied to a legitimate, fully-verified support ticket - standard "employee locked out, verified via manager callback" workflow.
- Planned Conditional Access policy change during an approved migration or pilot rollout, documented in change management with no unexpected accounts included.
- Service account or break-glass identity intentionally excluded from MFA per a documented, reviewed exception (should still be flagged for periodic access review even though it's benign here).

## Escalation Criteria

Escalate to IR/CIRT immediately if: the disable cannot be tied to the account owner or a verified ticket, it follows a suspicious sign-in, a new attacker-controlled MFA method was registered, or the account is privileged. Notify the account owner's manager and, for privileged accounts, the CISO within the hour of a confirmed unauthorized disable - this event class frequently precedes business email compromise or lateral movement into other cloud services.

## Containment Options & Approval Authority

**[MANAGEMENT]**
- Immediately re-enable/restore MFA enforcement for the account and revoke all active sessions/refresh tokens - Tier 2 SOC analyst can execute for confirmed unauthorized disable under standing IR authorization, no further sign-off needed.
- Remove any attacker-registered MFA method and force re-registration through the verified enrollment process - IT identity team executes, SOC lead authorizes.
- Force password reset in addition to MFA restoration if the disable followed a suspicious sign-in (password compromise should be assumed until ruled out).
- Suspend the account entirely if privileged and active malicious use is confirmed - requires SOC lead or IR manager approval; business/account owner notified concurrently, not after the fact.
- Review and tighten the helpdesk MFA-reset procedure (stronger caller verification, ticket-mandatory workflow) if the root cause was social engineering of the service desk - IT service management owner approves the process change.

## Example Query (Microsoft Sentinel - KQL)

```kql
AuditLogs
| where OperationName in ("Delete registered security info", "Admin deleted security info",
                           "Disable Strong Authentication", "Update policy")
| where Result == "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Actor, Target, InitiatedBy
| sort by TimeGenerated desc
```

## Closure Criteria

Close only when: the actor performing the disable is confirmed, the reason is validated against a ticket or direct owner confirmation, sign-in activity around the event has been reviewed for signs of prior takeover, and any new MFA method registered in the window has been verified as belonging to the legitimate user. Disposition should be recorded as True Positive (confirmed malicious/unauthorized disable), Policy Violation (internal actor, no attacker involvement confirmed, but procedure wasn't followed - e.g., an unverified helpdesk reset), Benign Positive (verified self-service or approved change), or Insufficient Evidence where sign-in telemetry has already aged out of retention.

**Example case note:**
"2026-09-15 09:52 UTC - Authenticator app method deleted for m.reyes@example.com via 'Delete registered security info'. Preceding sign-in at 09:41 UTC from 198.51.100.77 (unrecognized ASN, legacy IMAP auth, no prior history for this user) succeeded on first password attempt. No new MFA method registered afterward; account effectively left MFA-less. User confirmed via phone callback she did not initiate this and was not travelling. Password reset forced, all sessions revoked, MFA re-enrollment required at next login. Escalated to IR as confirmed account takeover; manager notified 10:10 UTC."
