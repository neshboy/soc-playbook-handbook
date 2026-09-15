# Insider Threat

Every playbook in this category shares one uncomfortable trait: the account doing the thing is usually the account that's *supposed* to be doing something adjacent to it. There's no exploit, no malware hash, no C2 beacon to pivot from. A finance analyst pulling customer records isn't tripping an IDS signature - they're using an application exactly the way it was designed to be used, just at a scale, time, or destination that doesn't fit their normal pattern. That's the core difficulty across this entire category: you're not hunting for something that shouldn't exist, you're hunting for something that shouldn't exist *at this volume, from this person, right now*.

Because of that, insider threat detections lean heavily on baselining and behavioral deltas rather than static signatures. A single file download means nothing. Ten thousand files touched in an hour by someone who normally touches forty means something - maybe. The alerts in this folder cover the common exfiltration and misuse channels an employee (or a compromised employee account acting the same way, which is a real ambiguity you have to hold onto during triage) can use to move data out or access things they shouldn't: bulk file and database access, removable media, cloud storage uploads, personal webmail, code repository cloning, printing, and privileged account abuse. A meaningful chunk of these also cluster around the departing-employee lifecycle, because notice periods are historically when this behavior spikes - not because everyone who quits is dishonest, but because the ones who were already planning something tend to accelerate once the exit date is set.

Tooling-wise, you're pulling from a wider spread of sources than most other categories in this book. DLP (endpoint and network/CASB) is the backbone for anything touching upload, email, or removable media. EDR/Sysmon telemetry on the endpoint (process creation, file access, USB/removable-storage events) covers local behavior. Proxy and firewall logs matter for destination - is the upload going to a sanctioned tenant or a personal one. Identity provider and directory logs (Entra ID / Azure AD sign-in logs, on-prem AD security logs) cover the account lifecycle and privilege side: T1078 Valid Accounts, T1136 Create Account, T1098 Account Manipulation, T1531 Account Access Removal. Cloud audit logs (M365 audit log, Google Workspace, AWS CloudTrail, Salesforce event monitoring) matter for T1530 Data from Cloud Storage and T1098.001 Additional Cloud Credentials scenarios. HR system integration - or at minimum a reliable feed of resignation/termination dates and role changes - is not optional here; without it you're baselining blind. Database audit logs and print server logs round out two of the more commonly under-instrumented sources in this list.

**[ANALYST]** - Expect to spend real time correlating across systems that don't share a timeline cleanly. DLP says a file left; you still have to confirm what the file actually contained, whether the user had legitimate access to it (check T1078 vs. genuine entitlement), and whether this matches their role. Don't assume access was scoped correctly just because the ticket says it was - RBAC drift is common and you should verify current group membership (T1069 Permission Groups Discovery is relevant on the attacker side, but on the insider side it's usually just stale provisioning nobody cleaned up).

A quick word on friction, because this category produces more of it than most: HR and Legal involvement changes the tempo of everything, and you will frequently be blocked from full investigation until they clear you to proceed - which can mean sitting on a live data-loss event for hours while approvals happen. Personal device and BYOD activity routinely falls outside EDR/DLP visibility entirely, so "no alert fired" does not mean "nothing happened." Encrypted personal cloud storage and messaging apps blind you to content even when you can see that an upload occurred. And a large fraction of these cases resolve as Benign Positive - a manager doing a legitimate mass export before a reorg, a departing employee backing up their own prior work product per company policy - so build your write-ups to support "Expected Activity" and "Insufficient Evidence" as first-class outcomes, not failures to find something worse.

## Playbooks in This Category

| # | Playbook | File |
|---|----------|------|
| 1 | Mass File Access | `01-mass-file-access.md` |
| 2 | Large Download | `02-large-download.md` |
| 3 | USB Copying | `03-usb-copying.md` |
| 4 | Cloud Storage Upload of Sensitive Data | `04-cloud-storage-upload.md` |
| 5 | Personal Email Transfer of Company Data | `05-personal-email-transfer.md` |
| 6 | Sensitive Repository Cloning | `06-sensitive-repo-cloning.md` |
| 7 | Printing of Sensitive Files | `07-printing-sensitive-files.md` |
| 8 | Unusual Database Access | `08-unusual-database-access.md` |
| 9 | Departing-Employee Activity | `09-departing-employee-activity.md` |
| 10 | Privileged Access Misuse | `10-privileged-access-misuse.md` |
| 11 | Access Outside Job Role / Need-to-Know | `11-access-outside-job-role.md` |
| 12 | Bulk Deletion of Data | `12-bulk-deletion-of-data.md` |

*File names above reflect this folder's convention; confirm exact filenames against the directory listing if referencing programmatically.*
