# Response: Recovery Sequencing

Recovery is where incident commanders get hurt politically. The encryption event is over, the room wants "back to normal," and every hour of downtime has a dollar figure attached to it that someone in finance is calculating in real time. The IC's job in this phase is to slow that instinct down just enough to avoid a second detonation, without becoming the reason the business bled out waiting.

## Validate Backup Integrity Before Anything Touches Production

Restoring from a compromised or already-encrypted backup set is a documented failure mode, not a hypothetical. Ransomware operators that deploy T1486 (Data Encrypted for Impact) routinely precede it with T1490 (Inhibit System Recovery) - deleting shadow copies, disabling Windows Server Backup, tampering with VSS, or pivoting into backup infrastructure specifically because backups are the thing standing between the victim and payment.

**[ANALYST]** - Before you trust any backup set, confirm three things independently, not from the backup console's own status page:
- **Timestamp relative to compromise window.** Pull the earliest confirmed indicator of compromise from your timeline (first suspicious Sysmon Event ID 1 process creation, first 4624/4648 anomalous logon, first 4720/4728 account or group manipulation) and discard any backup image created after that point minus a safety margin - attacker dwell time is usually longer than it looks.
- **Backup infrastructure itself wasn't touched.** Check the backup server/appliance for 4624 Logon Type 10 (RDP) or Type 3 from unexpected sources, 4648 explicit-credential logons, 7045/4697 service installs, and Sysmon Event ID 1 for backup-agent processes spawning unusual children. If the backup server shows up anywhere in the lateral movement graph (T1021.002 SMB/Windows Admin Shares, T1021.001 RDP), treat every image from it as suspect until proven otherwise.
- **Sample-restore before mass-restore.** Restore one non-critical host to an isolated VLAN and run it through the same detection stack (EDR, Sysmon FileCreate/FileDelete Event ID 11/23 for ransom-note or mass-encryption behavior, network telemetry for beaconing) before you trust the image for anything business-facing.

**[ENGINEERING]** - Immutable/air-gapped backups (object-lock, offline tape, replicated to an account the production domain has no write path to) get restore priority. Anything that was reachable from a domain-joined credential during the incident window gets the sample-restore treatment regardless of vendor assurances.

## Rebuild vs. Restore

This isn't a technical coin-flip, it's a risk/cost trade decided per asset class, and the IC should push for a written decision matrix rather than relitigating it host by host at 2 a.m.

| Factor | Favors Restore | Favors Rebuild |
|---|---|---|
| Domain Controllers, PKI, identity infra | Rarely - if attacker had DA (evidenced by 4728/4732 group changes, DCSync-pattern 4662-adjacent replication abuse) | Almost always - rebuild from clean media, restore data only |
| Backup image age vs. dwell time | Image predates first IOC by comfortable margin | Image falls inside or near the compromise window |
| Golden image / IaC availability | N/A | Rebuild is fast and cheap - prefer it |
| Custom, undocumented legacy app | Restore, with compensating monitoring | Rebuild not realistic short-term |

**[MANAGEMENT]** - Domain Controllers, CA servers, and anything that issued or validated authentication during the incident should default to rebuild-from-clean, not restore, unless forensics can affirmatively clear them. Restoring a DC that was in scope for credential theft (T1003.006 DCSync, T1558.001 Golden Ticket) without a full krbtgt reset and trust re-establishment reintroduces the exact persistence mechanism you're trying to remove.

## Order of Restoration

Sequence by business-criticality tier agreed with the business continuity owner *before* the incident, not during it - if that mapping doesn't exist yet, build it now as a gap finding. Typical tiering: Tier 0 (identity, DNS, backup infrastructure itself) → Tier 1 (revenue-generating and safety systems) → Tier 2 (internal productivity) → Tier 3 (everything else). Never restore a downstream tier onto a Tier 0 system that hasn't been independently validated clean - you'll re-establish trust relationships against a still-compromised foundation.

## Reinfection Risk - the Gate Before Go-Live

**[ANALYST]** - Before any restored or rebuilt host reconnects to the production network, confirm eradication of every persistence mechanism found during the investigation: scheduled tasks (4698), services (4697/7045), Run-key registry entries (Sysmon 12/13), rogue accounts (4720/4722/4728), and audit-tampering (1102, 4719) that may have blinded logging mid-incident. A single missed scheduled task or a credential that wasn't rotated (especially service accounts) turns a clean restore into a same-day repeat encryption event - this happens more often than anyone likes admitting in the after-action review.
