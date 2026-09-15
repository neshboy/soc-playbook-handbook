# INS-008: Unusual Database Access

## Playbook ID & Name
**INS-008 — Unusual Database Access (Anomalous Query, Table, or Volume Pattern Against Production Data)**

## Business Risk
**[STAKEHOLDER]** - Someone with legitimate database credentials pulls data they don't need for their job, at a scale or from tables that don't match their role. There's no malware here and usually no alert from an EDR product — the person is authenticated, authorized at the platform level, and doing something a database engine will happily let them do. The exposure is direct: customer PII, payment data, payroll records, or M&A financials leaving through the one door most companies forget to lock — the database itself, not the application sitting in front of it. Decision owner for any personnel or legal action is HR + Legal + the data owner; SOC's job is detection, evidence, and a clean referral, not adjudicating intent.

## Severity / Priority Default
**Medium** by default. Escalates to **High** when the tables/columns touched are regulated (PII, PCI, PHI) or the access bypasses the normal application layer entirely (direct client connection instead of the sanctioned app service account). Escalates to **Critical** when export/local-file evidence exists (BULK EXPORT, `mysqldump`, `pg_dump`, `bcp`, `INTO OUTFILE`), when the account is tied to a resignation/termination within 30 days, or when the access pattern was previously blocked by application-layer controls and is now occurring via a direct database connection instead.

## MITRE ATT&CK Techniques
- **T1078.002** — Valid Accounts: Domain Accounts (on-prem SQL Server/Oracle/MySQL/Postgres access via a legitimate domain-joined identity, used outside its normal scope)
- **T1078.004** — Valid Accounts: Cloud Accounts (RDS, Azure SQL, Cloud SQL access via a legitimate cloud identity or IAM role)
- **T1119** — Automated Collection (scripted/looped queries pulling far more rows or tables than a manual session would)
- **T1552.001** — Unsecured Credentials in Files (shared or hardcoded DB credentials found in a script, notebook, or config the insider used to bypass normal app-layer authentication)
- **T1530** — Data from Cloud Storage (cloud-native export/snapshot pulled to an object store the insider then accesses)
- **T1567** — Exfiltration Over Web Service (query results or an export file uploaded to personal cloud storage/webmail as the next stage)
- **T1048** — Exfiltration Over Alternative Protocol (bulk export tunneled out over a protocol other than the expected app/DB path)

This playbook owns detection of the **query/access** itself. If a confirmed external upload follows, hand off evidence to the corresponding exfiltration playbook rather than duplicating that logic here.

## Trigger / Detection Logic Summary
Fires on database audit telemetry when an identity's query pattern deviates from its own historical baseline: row-count or table-count spike, access to tables/schemas the identity has never touched, a query with no `WHERE` clause against a large or sensitive table, or a connection using a client tool (SSMS, DBeaver, `sqlplus`, `mysql` CLI, `psql`) where the historical norm for that identity is application-layer access only. Also fires on direct use of a shared/generic DB login by a human session, and on export-statement signatures (`BULK INSERT`, `SELECT ... INTO OUTFILE`, `COPY TO`, `mysqldump`/`pg_dump` process launch) correlated to a database session.

## Required Log Sources & Event IDs
| Source | Event ID / Field Source | Purpose |
|---|---|---|
| SQL Server Audit / Extended Events | `AUDIT_SUCCESS`, statement class, `server_principal_name`, `application_name` | Query text, principal, client app string |
| Oracle Unified Audit Trail | `DBUSERNAME`, `SQL_TEXT`, `ACTION_NAME` | Statement-level access record |
| MySQL / MariaDB audit log (or general query log) | `command_type`, `argument`, `user` | Query and connecting user |
| PostgreSQL (pgAudit) | `session_id`, `command_tag`, `object_name` | Statement and object accessed |
| MongoDB audit log | `atype: authCheck`, `param.ns` | Collection-level access on NoSQL stores |
| Cloud provider audit logs | AWS CloudTrail (`rds:ExecuteStatement`, Redshift Data API `GetClusterCredentials`), Azure SQL Audit Logs, GCP Cloud SQL audit logs | Cloud-native DB access via IAM/service identity |
| Windows Security (app/DB host) | **4624** (logon type 3/10), **4648** (explicit credential use), **4769** (Kerberos service ticket for SQL service principal) | Host-level authentication context to the DB server |
| Sysmon | **Event ID 1** (process creation — `sqlcmd.exe`, `mysqldump.exe`, `pg_dump.exe`, `dbeaver.exe`); **Event ID 3** (network connection to DB port 1433/1521/3306/5432/27017); **Event ID 11** (export file created on disk) | Client-tool use and local export staging |
| DLP / CASB, proxy/firewall | Upload events, bytes-out per session | Corroborates any next-stage exfil |

## Key Fields to Inspect
**[ANALYST]**
- Database principal/role used vs. the underlying human identity (linked login, service account impersonation, or shared credential)
- `application_name` / client program string in the audit record — a query claiming to come from the reporting app but sourced from a developer laptop IP is a mismatch worth chasing
- Exact query text: statement type, `WHERE` clause presence/absence, columns selected (`SELECT *` vs targeted fields), joins across tables outside the user's normal scope
- Row count returned/affected, and how that compares to the identity's own 30/60/90-day baseline for that table
- Source host/IP and whether it matches the identity's normal workstation, a jump box, or an unexpected app server
- Time of access — business hours vs. off-hours, and whether it clusters immediately before/after a resignation, PIP, or role change
- Table/column sensitivity per the data classification catalog — PII, PCI, PHI, source, financials
- Export or client-tool process evidence on the connecting host (Sysmon 1/3/11) correlated to the same time window as the audit event

## Normal vs Suspicious Pattern
**Normal:** A service account running parameterized, high-volume queries around the clock as part of the application it backs; a DBA running a scoped `SELECT` against a specific table tied to an open change ticket; a business analyst pulling a few hundred rows from a report view within their own business unit's data, consistent with their historical pattern.

**Suspicious:** A named human account connecting directly to production with SSMS/DBeaver/`psql` when their role is normally app-layer only; a query with no `WHERE` clause against an entire customer or payroll table; access to tables the identity has never queried before, especially outside their department's data domain; use of a shared or generic DB login traceable to one individual via host/IP; an export statement or dump utility launched immediately after a large `SELECT`; access timed to a resignation notice, a denied access request, or right after being removed from a project that used to justify that access.

## Investigation Steps
1. Pull the full database audit record — principal, `application_name`, source host/IP, exact statement, table/columns, and row count. Don't work from a summary alert; get the raw statement text.
2. Baseline the identity's own historical access to that table and that access method over 30/60/90 days — compare against themselves, not a flat org-wide threshold.
3. Determine access path: sanctioned application/service account vs. a direct client-tool connection from a human endpoint (Sysmon Event ID 1/3 on the source host confirms tool and destination port).
4. Cross-reference with HR/IT context — current role, recent role or team change, resignation/termination date, active PIP, or an access request/change ticket that would justify this specific query.
5. Classify the sensitivity of the data touched with the data owner — PII/PCI/PHI/financials carries privacy-office and possibly breach-notification implications separate from the HR/insider angle.
6. Check for export or staging evidence: dump-utility process launch, export-statement syntax, a file written to disk (Sysmon 11) matching the query's timing and approximate row count.
7. Review authentication context for compromise indicators (impossible travel, new device, concurrent sessions, MFA anomalies) to distinguish misuse-by-the-account-owner (T1078) from a compromised credential being used the same way.
8. Document the exact table/query set and timeline precisely — HR/Legal will need the specifics, not "accessed sensitive data," to make a personnel or breach-notification decision.

## True Positive Indicators
- Human account bypassing the application layer to query production directly, with no change ticket or business justification
- Access to tables/columns clearly outside job function, especially after a role change removed the justification
- `SELECT *` or unfiltered bulk query against a sensitive table followed by an export or dump-utility launch
- Shared/generic DB credential traced to one individual via host, IP, or badge/VPN correlation
- Timing aligned with resignation, termination notice, denied access request, or a known workplace dispute

## False Positive / Benign Positive Indicators
- DBA or platform team activity tied to an open maintenance, migration, or patching change ticket
- Approved ad hoc reporting request signed off by the data owner, just not yet reflected in the peer-group baseline
- New BI/reporting tool or ETL job whose `application_name`/connection signature hasn't been added to the known-good list yet
- Legitimate onboarding into a new role where access is correct but the historical baseline hasn't caught up
- Scheduled batch/backup job misclassified as a human session due to a poorly labeled service account

## Escalation Criteria
Escalate to Insider Threat/HR/Legal when regulated or sensitive data was accessed outside job scope with no ticket and export evidence exists. Escalate to the privacy/compliance office in parallel if PII/PHI/PCI access is confirmed — this may trigger a breach-assessment workstream independent of the personnel question. Escalate to IR if authentication context suggests the credential is compromised rather than misused by its owner — that changes this from an insider case to an account-compromise case.

## Containment Options & Approval Authority
**[MANAGEMENT]**
- **Preserve DB audit logs, query cache, and session records** before any account action — approval: SOC lead + Legal.
- **Revoke or restrict the specific DB role/permission** (not full account disable) to stop the bleeding while HR/Legal review — approval: DBA lead + data owner; can move same-day if export evidence exists.
- **Disable the account entirely** — approval: HR + Legal + CISO or designee, given employment-law exposure.
- **Block the network path from the source host to the database (firewall/DB firewall rule)** — lower-friction, can be applied without singling out the individual — approval: SOC lead.
- **Rotate shared/service credentials implicated in the access** — approval: SOC lead, notify IR and the application owner to avoid breaking production.
- SLA: same-business-day decision on role restriction for active-export cases; routine baseline-anomaly cases sit in a 3-5 business day review queue pending HR/data-owner input.

## Example Query

**[ENGINEERING]** - Splunk SPL flagging direct-client DB access with an unfiltered SELECT against a sensitive schema:

```spl
index=db_audit sourcetype=sqlserver_audit application_name!="ReportingApp*"
| regex query="(?i)select\s+\*"
| lookup sensitive_tables.csv table_name AS object_name OUTPUT is_sensitive
| where is_sensitive="true"
| stats count as query_count, sum(rows_returned) as total_rows by user, src_ip, application_name, object_name
| where query_count>0
| sort - total_rows
```

## Closure Criteria
Close as **True Positive** (insider threat referred) once HR/Legal has taken ownership of the personnel action and the evidence package (audit records, query text, export artifacts) has been handed off — SOC's part ends at detection, preservation, and referral. Close as **Benign Positive** when the data owner or manager confirms a legitimate, ticketed business need. Close as **Insufficient Evidence** if the account owner and manager can't be reached within SLA and no export/destination risk corroborates the access — reopen if the pattern recurs.

**Example case note:** *"DB principal `svc_reporting` was used from workstation 10.20.4.87 (user pchandran, Business Analyst, Claims) to run an unfiltered SELECT against `dbo.PolicyHolder_PII` (312,904 rows) via SSMS at 2026-09-12 23:14 UTC — outside pchandran's historical access to this table and 11 days after a denied request for expanded Claims-data access. Sysmon Event ID 11 confirms a 480 MB CSV export written to Downloads at 23:19 UTC; no external upload observed on proxy logs as of case open. Table classified PII by data catalog. Referred to HR/Legal and Privacy Office with full audit trail and endpoint export preserved; DB role access-restricted pending review."*
