# Appendix 37A — Templates Cluster A: Master Playbook, Stakeholder Summary, Investigation, Escalation

These are the four templates analysts and playbook owners reach for most. Copy them into your playbook management tool (wiki, SOAR case template, Git-tracked Markdown, whatever your shop actually uses) and strip the guidance text in *italics* once you understand what belongs in each field. Leave the field names alone — consistency across playbooks is what lets you build metrics later without reformatting three years of backlog.

A blank template is only useful if people actually fill in the boring fields (Owner, Next Review Date, Approver) and not just the exciting ones (Detection Logic, Containment Options). A playbook with a brilliant investigation section and no listed owner is an orphan the day its author changes teams.

---

## 1. Master Playbook Template (Full Field List)

*Use this version for a full treatment playbook — a detection with real investigative depth, decision points, and containment authority attached to it. Lighter-weight variants (tuning-only playbooks, informational-alert playbooks) can drop some fields, but this is the canonical full set. Fill every field; write "N/A — not applicable because..." rather than leaving it blank, so a reviewer can tell "blank" from "considered and excluded."*

```
Playbook ID:                 [e.g., PB-EDR-0042]
Playbook Name:                
Version:                      [semantic version, e.g., 1.3.0]
Status:                       [Draft / In Review / Active / Deprecated / Retired]
Owner:                         [name/role accountable for the playbook overall]
Technical Owner:              [engineer responsible for detection logic & automation]
Business Owner:                [stakeholder accountable for risk decisions this playbook informs]
Approver:                     [name/role who signed off current version]
Last Updated:                  [YYYY-MM-DD]
Next Review Date:              [YYYY-MM-DD]

Detection Source:              [SIEM rule / EDR analytic / cloud-native detection / vendor alert / threat intel feed / manual hunt]
Alert Name:                    [exact alert/rule name as it appears in the tool]
Description:                    

Objective:                     [what this playbook exists to determine or achieve]
Business Risk:                  [what happens if this activity goes unnoticed, in business terms]
Severity:                       [Informational / Low / Medium / High / Critical]
Priority:                       [P1-P4 or your org's SLA priority scale]
MITRE ATT&CK:                  [tactic/technique IDs — leave blank rather than guess]

Applicable Systems:             [OS, platform, cloud provider, app tier this playbook covers]
Data Sources:                   [category-level, e.g., authentication logs, endpoint telemetry, network flow]
Log Sources:                    [specific systems, e.g., Windows Security log via WEC, EDR API, firewall syslog]
Required Fields:                [specific log fields the analyst must have to run this playbook]

Prerequisites:                  [access, tooling, log retention, or licensing needed before this playbook can run]
Dependencies:                   [other playbooks, feeds, or systems this one relies on]

Trigger Condition:              [the exact condition that fires the alert]
Detection Logic Summary:        [plain-language summary of the underlying query/rule logic]
Known Limitations:              [blind spots, log gaps, timing issues, coverage caveats]
Known False Positives:          [specific, named sources of noise for this detection]

Initial Triage:                 [first 5-10 minutes: what to check before anything else]
Enrichment:                     [context to pull in — asset criticality, user role, threat intel, prior alerts]
Investigation:                  [step-by-step investigative path — reference the Investigation Template below]
Validation:                     [how the analyst confirms the finding is real before deciding severity]

Decision Points:                 [explicit branch points — "if X, go to escalation; if Y, close as benign"]
True Positive Indicators:       [concrete evidence that confirms malicious/unauthorized activity]
False Positive Indicators:       [concrete evidence that this is noise, misconfiguration, or tooling artifact]
Benign Positive Conditions:      [activity that is real and matches the alert logic, but authorized/expected]

Escalation Criteria:             [conditions requiring escalation — reference Escalation Template below]
Containment Options:             [available actions — isolate host, disable account, block indicator, etc.]
Containment Approval:            [who must approve which containment action, and how fast]

Recovery Steps:                  [how affected systems/accounts are restored to normal operation]
Evidence Collection:             [what must be preserved — logs, memory, disk image, chain-of-custody notes]
Case Documentation:              [minimum documentation standard for the case record]
Communication Requirements:      [who gets notified, at what stage, via what channel]

SLA:                             [time to acknowledge / time to triage / time to escalate, by priority]
Closure Criteria:                [conditions that must be true before a case can be closed]
Post Incident Tasks:             [follow-up actions after closure — ticket handoffs, comms, lessons learned]

Detection Feedback:              [process for reporting detection gaps/noise back to engineering]
Tuning Opportunities:            [known candidates for suppression, threshold changes, or logic changes]
Metrics:                         [what this playbook's performance is measured against]
Automation Potential:            [which steps are/could be automated, and current automation state]

Related Rules:                   [other detections that commonly fire alongside this one]
Related Playbooks:               [playbooks this one hands off to or receives from]
References:                       [MITRE ATT&CK, vendor docs, internal wiki pages, prior incident reports]

Revision History:
  | Version | Date       | Author | Summary of Change |
  |---------|------------|--------|--------------------|
  |         |            |        |                    |
```

**[MANAGEMENT]** - Owner, Technical Owner, and Business Owner are deliberately three separate fields. In practice they're often three different people, and playbooks that collapse them into one "Owner" field tend to rot the moment that person moves teams — nobody left has both the technical context and the risk authority to update it. Next Review Date should be a real calendar entry, not an aspiration; a quarterly review cadence is reasonable for anything above Medium severity.

---

## 2. Stakeholder Summary Template

*Written for people who were not on the incident call and don't need the raw log lines. One page, no jargon that hasn't been defined. This is the version that goes to a business unit lead, legal, or an executive sponsor — not the SOC lead, who gets the full investigation record.*

```
Incident Reference:            [ticket/case ID]
Date/Time of Summary:          [YYYY-MM-DD HH:MM, timezone]
Prepared By:                    

WHAT HAPPENED
  [2-4 plain-language sentences: what was detected, on what system/account, roughly when]

WHAT WE KNOW
  [Confirmed facts only — no speculation. State current confidence level:
   True Positive (confirmed) / True Positive (suspected — validation still in progress) /
   Benign Positive / Insufficient Evidence]

WHAT WE DON'T KNOW YET
  [Open questions still under investigation, if any]

BUSINESS IMPACT
  Systems/Data Affected:        
  Users/Customers Affected:      [number/scope, or "none identified"]
  Service Disruption:            [Yes/No — describe]
  Regulatory/Contractual Exposure: [if applicable — flag for legal/compliance, don't self-assess]

ACTIONS TAKEN
  [Containment/remediation steps already executed, in plain terms]

ACTIONS PLANNED / IN PROGRESS
  [Next steps and rough timeline]

WHAT WE NEED FROM YOU
  [Decision, approval, or information requested from this stakeholder, with a deadline if time-sensitive]

NEXT UPDATE EXPECTED
  [Date/time, or "on closure" / "on material change"]

Contact for Questions:          
```

**[STAKEHOLDER]** - The "What We Don't Know Yet" section is the one people most want to skip and the one that prevents the most damage. A stakeholder who's told "contained, low confidence it spread" and later learns it did spread trusts the SOC a lot less than one who was told upfront that lateral movement was still being ruled out. Silence on uncertainty reads as confidence you didn't earn.

**[MANAGEMENT]** - Set a standing rule for cadence: e.g., every 4 hours for a Critical incident, every 24 hours for High, on closure only for Medium/Low unless the stakeholder asks otherwise. Put that rule in the playbook's Communication Requirements field, not just in someone's head.

---

## 3. Investigation Template

*The analyst's working record. This is the artifact that gets reviewed in QA, cited in the post-incident review, and occasionally subpoenaed. Write it as you go, not from memory after the fact — reconstructed timelines are where inconsistencies creep in.*

```
Case ID:                        
Playbook Applied:               [Playbook ID + Version]
Analyst:                        
Investigation Start:            [YYYY-MM-DD HH:MM TZ]
Investigation End:              [YYYY-MM-DD HH:MM TZ]

ALERT DETAILS
  Alert Name:                   
  Alert Timestamp:               [note source timezone explicitly]
  Source System:                  
  Raw Alert Reference:            [link/ID to original alert in SIEM/EDR/case tool]

SCOPE
  Host(s):                      
  Account(s):                    
  IP Address(es):                
  Process/File/Hash (if applicable): 

TIMELINE OF EVENTS
  | Timestamp (TZ noted) | Source | Event | Notes |
  |-----------------------|--------|-------|-------|
  |                       |        |       |       |

INITIAL TRIAGE NOTES
  [What was checked first, and result — normal-vs-suspicious call at this stage]

ENRICHMENT PERFORMED
  Asset Criticality:              
  User Context (role, normal behavior baseline): 
  Threat Intel Lookups:           [source checked, result — e.g., "IP not in any feed as of check time"]
  Related/Prior Alerts:            

INVESTIGATIVE STEPS TAKEN
  | Step | Action | Data Source Queried | Result |
  |------|--------|----------------------|--------|
  |      |        |                      |        |

EVIDENCE COLLECTED
  [Log excerpts, artifact hashes, screenshots, memory/disk capture references — note where stored and
   who has access, for chain-of-custody purposes if this could become a formal investigation]

GAPS / LIMITATIONS ENCOUNTERED
  [Missing logs, retention expired, log source offline, parsing issue, timezone mismatch, etc. — 
   state plainly rather than omitting; "we couldn't confirm X because Y" is a valid and useful line]

ANALYSIS / REASONING
  [Why the evidence points where it does — this is the section a reviewer reads to judge the call,
   not just the conclusion]

CONCLUSION
  Verdict:                        [True Positive / False Positive / Benign Positive / Insufficient Evidence]
  Confidence Level:                [High / Medium / Low]
  Justification:                   

ACTIONS TAKEN
  [Containment, remediation, or explicit decision to take no action, with rationale]

FOLLOW-UP ITEMS
  [Tuning suggestion, escalation raised, ticket handed off elsewhere, etc.]

Reviewed By (QA/peer, if applicable): 
Review Date:                     
```

**[ANALYST]** - Note the timezone on every timestamp you write down, every time, even if it feels repetitive. The single most common thing that quietly wrecks a timeline reconstruction three weeks later isn't a missing log — it's someone assuming a timestamp was local when it was UTC, or vice versa, and building a sequence of events that's off by anywhere from one to twelve hours depending on the source system. If your SIEM normalizes to UTC but the raw EDR console shows local time, write both.

**[ANALYST]** - "Insufficient Evidence" is a legitimate, complete verdict. Don't let a case sit open indefinitely because you can't reach True Positive or False Positive with confidence — document what you checked, what you couldn't get (expired retention, offline log source, encrypted traffic you have no visibility into), and close it at the confidence level the evidence actually supports. A reviewer can always reopen if new evidence surfaces.

---

## 4. Escalation Template

*Used the moment a case crosses the escalation criteria defined in the playbook — moving from analyst-level triage to IR lead, secondary SOC, threat hunt team, or outside the SOC entirely (legal, executive, third-party IR retainer). Fill this out at the point of escalation, not after the fact.*

```
Case ID:                        
Escalating Analyst:              
Escalation Timestamp:             [YYYY-MM-DD HH:MM TZ]
Escalated To:                     [name/role/team]
Escalation Channel:               [phone/page/Slack/ticket — note if primary channel failed and backup was used]

ESCALATION TRIGGER
  Playbook Criterion Met:          [quote the specific Escalation Criteria field from the playbook]
  Severity/Priority at Escalation: 

SUMMARY FOR RECEIVING TEAM
  [3-6 sentences: what's confirmed, what's suspected, why this exceeds analyst-level authority or scope —
   assume the reader hasn't seen the case yet]

CURRENT STATE
  Scope (hosts/accounts/systems affected): 
  Containment Actions Already Taken:        
  Containment Actions Awaiting Approval:     [and from whom]

EVIDENCE SUMMARY
  [Pointer to full Investigation Template record — don't duplicate the whole timeline here, link it]

RISK IF NO FURTHER ACTION TAKEN
  [Plain statement of what could happen if this sits, e.g., "credential likely usable for lateral movement,
   account has domain admin group membership"]

REQUESTED ACTION / DECISION NEEDED
  [Specific ask — approve isolation, approve account disable, engage legal, activate IR retainer, etc.]
  Deadline for Decision:           [if time-sensitive, state why]

ACKNOWLEDGEMENT
  Received By:                     
  Acknowledged Timestamp:           
  Handoff Accepted? (Y/N):          [if N, note reason and next escalation path]

OUTCOME OF ESCALATION
  [Filled in after resolution — decision made, action taken, by whom]
```

**[ENGINEERING]** - If your SOAR platform supports it, wire the Escalation Criteria field from the Master Playbook directly to an automated case-priority bump and notification, rather than relying on the analyst to remember the threshold under pressure. The template above still gets filled out by a human — automation should trigger the page, not write the judgment call.

**[MANAGEMENT]** - Acknowledgement timestamp matters for SLA measurement independent of resolution time. "Time to escalate" and "time to acknowledge escalation" are two different metrics with two different owners (SOC vs. receiving team), and conflating them in your reporting hides whichever side is actually slow. Track them separately.
