# Defense Evasion

By the time a ransomware operator starts tampering with logging and security tooling, they've usually already got a foothold and domain-level access. Defense Evasion isn't the flashy part of the intrusion, but it's the stage that decides whether you catch this at 2am on day one or whether you find out from the ransom note on day twelve. If you only have budget to tune detections for one stage of the ransomware lifecycle, tune it here.

## Why this stage is disproportionately high-signal

Most of what a legitimate admin does looks like Defense Evasion telemetry noise on a bad day - a service restart, a GPO change, a log rollover. What almost never happens legitimately is an *endpoint security agent* getting disabled, uninstalled, or unloaded from kernel space, followed within minutes by the Security event log going quiet. Legitimate admins do not clear the Security log as a troubleshooting step. This combination of low false-positive rate and high true-positive severity is rare in the kill chain - most other stages (recon, initial access) generate far more noise per genuine hit.

## Security tool tampering and EDR/AV disabling (T1562.001)

Operators go after security tooling through a handful of repeatable mechanisms:

- **Service-level kill**: `sc.exe stop`, `net stop`, or direct registry edits to a security service's `Start` value (disabled = 4). Look for Sysmon Event ID 1 process creation with command lines referencing known AV/EDR service names, and Sysmon 12/13 registry events touching `HKLM\SYSTEM\CurrentControlSet\Services\<vendor-agent>`.
- **BYOVD (Bring Your Own Vulnerable Driver)**: a signed-but-vulnerable driver is loaded to get kernel privileges and rip the EDR's hooks out from underneath it. This is what Sysmon Event ID 6 (Driver Loaded) exists to catch - flag unsigned drivers outright, and treat signed-but-unrecognized drivers loading outside a patch window as suspect.
- **Uninstall via installer/service abuse**: watch for 7045 (System log, new service installed) and 4697 (Security log, same event, different log) where the Service File Name references an uninstaller, a management-agent binary being invoked out of context, or a renamed copy of a legitimate removal tool.
- **PowerShell-driven tampering**: `Set-MpPreference -DisableRealtimeMonitoring $true`, exclusion-path additions, tamper-protection toggles. 4104 (script block logging) is where you catch this even when the operator base64-encodes or string-splits the cmdlet name - the de-obfuscated block usually still shows up in 4104 content. 4103 gives you the module/pipeline execution context around it.

**[ANALYST]** - Baseline what "normal" looks like for your EDR/AV vendor's service and driver footprint on gold-image hosts. When you see a 7045/4697 pair for a security-relevant service where the Service File Name doesn't match your known-good binary path or hash, treat it as a tampering candidate until proven otherwise - don't wait for the encryption to start to escalate.

**[ENGINEERING]** - Correlate Sysmon 1 command lines matching a security-product denylist (`*mpcmdrun* /remove*`, `*sc*stop*<agentsvc>*`, `*Set-MpPreference*Disable*`) with a drop in that same host's EDR heartbeat/telemetry volume within a 5-10 minute window. The heartbeat gap is your ground truth that the disable attempt actually succeeded, since the command line alone doesn't prove outcome.

## Audit policy tampering (4719) and log clearing (1102)

4719 (System audit policy changed) fires when a subcategory - most tellingly *Process Creation* auditing or *Security State Change* - gets flipped off. An attacker doing this is trying to go dark on the exact telemetry that would otherwise catch everything they do next. It's a blinding move, not a cleanup move.

1102 (audit log cleared) is the cleanup move, and it's about as close to a smoking gun as Windows Security auditing produces. The Subject field tells you who cleared it - if that account isn't your logging/SIEM service account or a documented maintenance window, this is an incident, full stop.

```
// Pseudocode correlation - not vendor-specific KQL/SPL
alert when:
  EventID == 1102
  AND Subject.AccountName NOT IN (approved_log_admin_accounts)
  WITHIN 15m OF (EventID IN (4719, 7045, 4697) ON SAME Host)
```

The pairing matters more than either event alone. 4719 followed by 1102 on the same host, close together, outside change windows, is a near-certain precursor to encryption - get eyes on that host and its lateral-movement neighbors immediately, don't wait for corroborating alerts.

**[MANAGEMENT]** - 1102 and 4719 should page someone, always, with no dedupe/suppression window longer than a few minutes and no auto-close. Track mean time from first 4719/1102 to containment action as a core ransomware-readiness metric; review any suppression rule touching these two IDs quarterly and require CISO sign-off to add one.

**[STAKEHOLDER]** - These are the cheapest, highest-value detections you can buy: nobody legitimately needs to turn off their own security cameras and burn the tapes. Wiring these straight to a 24/7 page, rather than a daily digest, is a small SOC engineering investment that materially shortens ransomware dwell time.
