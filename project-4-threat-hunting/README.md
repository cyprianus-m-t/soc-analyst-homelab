# Project 4 — Threat Hunting \& SOC Analyst Investigation

**SOC Home Lab | Portfolio Project 4 of 5**

|Field|Detail|
|-|-|
|**Author**|Mojaki Tjeeka|
|**Date**|07 October 2026|
|**Analyst Role**|Tier 1 SOC Analyst|
|**Environment**|Wazuh v4.14.7 — 192.2.42.142|
|**Monitored Asset**|Win-Server — Windows Server 2012 DC (192.2.42.136, Agent ID: 001)|
|**Hunt Window**|Oct 6–7, 2026 |
|**MITRE ATT\&CK**|T1110 — Brute Force · T1136.001 — Create Account: Domain Account · T1098.007 — Account Manipulation · T1070.001 — Indicator Removal: Clear Windows Event Logs|

\---

## Objective

Conduct a proactive threat hunt against the last 24 hours of SIEM data using structured hunt queries, reconstruct a full attack timeline from log evidence, make formal triage decisions on each finding, and produce a complete SOC case note — demonstrating the end-to-end investigation workflow of a Tier 1 SOC analyst.

\---

## Skills Demonstrated

* Proactive threat hunting using structured Wazuh DQL queries
* Multi-event timeline reconstruction from fragmented log data
* IOC pivoting — following a single indicator across multiple event types
* True positive / false positive triage with documented reasoning
* Attack chain identification across multiple MITRE ATT\&CK tactics
* Formal SOC case note writing in the format used in production environments
* Escalation decision-making with supporting evidence

\---

## Hunt Methodology

Threat hunting is proactive — it does not wait for a page or alert. The analyst runs structured queries against the SIEM each shift looking for patterns that *may not have fired an alert* or to confirm that high-severity alerts represent real threats. Five standard hunt queries were run against the Win-Server agent for the last 24 hours.

\---

## Hunt Query Results

### Query 1 — High Severity Alert Review

**DQL:** `rule.level >= 10 and rule.level <= 15`

|Result|Value|
|-|-|
|Total hits|8|
|Time window|Oct 6 @ 14:35 — Oct 7 @ 12:16|
|Highest severity|Level 15 (rule 100005 — log clearing)|
|Rule IDs firing|100001, 100003, 100004, 100005|

**Analyst observation:** Eight high-severity alerts across two time clusters — one spanning \~3 hours on Oct 6, and one at 12:12–12:16 on Oct 7. The presence of four distinct rule IDs covering brute force, account creation, privilege escalation, and evidence destruction is immediately suspicious. This pattern maps to a structured attack chain, not random noise.

> 📷 Screenshot 1 — High-severity query results showing 8 hits across rules 100001, 100003, 100004, 100005

\---

### Query 2 — Authentication Failure Volume

**DQL:** `data.win.system.eventID: 4625`

|Result|Value|
|-|-|
|Total hits|12|
|Spike time|Oct 7 @ 12:12 — dense burst within 30 seconds|
|Rule firing|60122 (Level 5 per event) + 100001 (Level 12 correlated)|
|Source|Win-Server agent (192.2.42.136)|

**Analyst observation:** Twelve failed logons with a dense cluster at 12:12. The time chart shows a sharp single spike — characteristic of an automated tool, not a user mistyping a password. Rule 100001 (custom brute force correlation) fired at Level 12, confirming 5+ failures from the same source IP within 2 minutes. The individual 4625 events at Level 5 would likely be filtered out in a high-volume environment — the correlated rule 100001 is what surfaces this as actionable.

> 📷 Screenshot 2 — Event ID 4625 query showing 12 hits, dense spike at 12:12, rule 100001 at Level 12 visible at top of list

\---

### Query 3 — New Account Creation

**DQL:** `data.win.system.eventID: 4720`

|Result|Value|
|-|-|
|Total hits|5|
|Custom rule hits|2 × rule 100003 (Level 12)|
|Pre-built rule hits|3 × rule 60109 (Level 8)|
|Creating account|Administrator (all events)|
|Domain|CCLABS|

**Analyst observation:** Five account creation events across two days — two caught by the custom rule 100003, three by the pre-built rule 60109. All created by the Administrator account. Notable: the most recent creation (Oct 7 @ 12:16:05) occurred **within 4 minutes** of the brute force burst at 12:12 — a tight temporal correlation that strongly suggests the brute force and the account creation are related actions by the same actor. The account name `svc\_monitor` mimics a legitimate monitoring service account — a classic attacker naming technique to avoid detection during casual review.

> 📷 Screenshot 3 — Event ID 4720 query showing 5 hits across both days, rule 100003 and 60109 visible
> 📷 Screenshot 4 — Document Details for most recent 4720 event — targetUserName: svc\_monitor, subjectUserName: Administrator, domain: CCLABS

\---

### Query 4 — Privileged Group Modification

**DQL:** `data.win.system.eventID: 4728`

|Result|Value|
|-|-|
|Total hits|3|
|Rule 100004 hits|1 (Level 14)|
|Rule 60159 hits|2 (Level 12)|
|Group modified|Domain Admins (all 3 events)|
|Member added|`CN=svc\_test3,CN=Users,DC=cclabs,DC=local` (all 3 events)|
|Performing account|Administrator|

**Analyst observation:** Domain Admins was modified three times, and pivoting on the `memberName` field confirmed the same account — `svc\_test3` — was added each time. This is significant for two reasons: first, any modification to Domain Admins is critical; second, the repetition (same account added three times in one afternoon) suggests either automated execution or an attacker re-running an escalation script after each log clearing. The SID suffix `-512` on the target group is a reliable indicator that Domain Admins specifically was targeted, not a lower-privilege group.

> 📷 Screenshot 5 — Event ID 4728 query showing 3 hits — rule 100004 (Level 14) and rule 60159 (Level 12) both visible

\---

### Query 5 — Security Log Clearing

**DQL:** `data.win.system.eventID: 1102`

|Result|Value|
|-|-|
|Total hits|3|
|Rule 100005 hits|1 (Level 15)|
|Rule 63103 hits|2 (Level 5)|
|Clearing account|Administrator (all events)|
|Times|Oct 6 @ 14:42, 15:59, 16:53|

**Analyst observation:** The Security log was cleared three times in approximately 2 hours — at 14:42, 15:59, and 16:53. Each clearing immediately followed a Domain Admins modification (at 14:35, 15:58, 16:52). This is a deliberate destroy-evidence pattern: escalate, then erase. The attacker could not reach the Wazuh SIEM — centralised log management preserved all three clearing events and everything that preceded them. Note also that two of the three clearing events only triggered the pre-built rule at Level 5 — below typical SOC escalation thresholds. The custom rule 100005 at Level 15 only caught the third. **This is a detection gap worth noting:** the first two log-clearing events would have been easy to miss without the hunt query.

> 📷 Screenshot 6 — Event ID 1102 query showing 3 hits — rule 100005 Level 15 and two rule 63103 Level 5 events visible

\---

## Timeline Reconstruction

The following full timeline was reconstructed by correlating timestamps across all five hunt queries:

```
Oct 6, 2026
─────────────────────────────────────────────────────────────
13:50:23  \[4720] Account created — svc\_backup (rule 60109, L8)
13:50:54  \[4720] Account created — administrator2 (rule 60109, L8)
14:35:15  \[4728] svc\_test3 added to Domain Admins (rule 60159+100004)  ← CYCLE 1 ESCALATION
14:42:19  \[1102] Security log cleared (rule 63103, L5)                 ← CYCLE 1 COVER
15:58:41  \[4720] Account created (rule 60109, L8)
15:58:51  \[4728] svc\_test3 added to Domain Admins again (rule 60159)   ← CYCLE 2 ESCALATION
15:59:10  \[1102] Security log cleared again (rule 63103, L5)           ← CYCLE 2 COVER
16:48:54  \[4720] Account created — svc\_test3 (rule 100003, L12)
16:52:19  \[4728] svc\_test3 added to Domain Admins — third time         ← CYCLE 3 ESCALATION
            (rule 100004, L14)
16:53:34  \[1102] Security log cleared — third time (rule 100005, L15) ← CYCLE 3 COVER

Oct 7, 2026
─────────────────────────────────────────────────────────────
12:12:58  \[4625×12] Brute force burst — 12 failures in <1 minute      ← NEW ATTACK WAVE
           Rule 100001 fires at Level 12
12:16:05  \[4720] Account created — svc\_monitor (rule 100003, L12)     ← NEW PERSISTENCE
           Created 4 minutes after brute force
```

**Attack chain interpretation:**

The Oct 6 activity represents a **create → escalate → cover loop** repeated three times. The attacker created service-account-named backdoor accounts, immediately escalated at least one (`svc\_test3`) to Domain Admin, then cleared the Security log after each cycle — likely attempting to erase evidence before it could be reviewed. The repetition suggests either an automated script or an attacker who was uncertain whether the escalation persisted across log clearing.

The Oct 7 activity represents a **second wave** — the attacker returned to the DC, ran a fresh brute force (suggesting they may have lost access overnight, or are probing from a different session), and created a new persistence account (`svc\_monitor`) within 4 minutes of the authentication activity.

\---

## IOC Summary

|IOC|Type|First Seen|Significance|
|-|-|-|-|
|`svc\_test3`|Rogue domain account|Oct 6 @ 16:48|Added to Domain Admins 3× — primary backdoor account|
|`svc\_backup`|Rogue domain account|Oct 6 @ 13:50|Service-account naming mimic|
|`administrator2`|Rogue domain account|Oct 6 @ 13:50|Admin naming mimic — high risk|
|`svc\_monitor`|Rogue domain account|Oct 7 @ 12:16|Created post-brute-force — second-wave persistence|
|`192.2.42.136`|Internal DC|—|All events originate here — attacker has DC-level access|
|Security log cleared 3×|Behaviour|Oct 6 @ 14:42–16:53|Active evidence destruction — high confidence attacker present|

\---

## Triage Decisions

|Finding|Classification|Confidence|Rationale|
|-|-|-|-|
|Brute force — rule 100001|**True Positive**|High|12 rapid failures from single source, automated tool signature, correlated rule fires|
|Rogue account creation — rule 100003|**True Positive**|High|Service-account naming outside provisioning process, created minutes after brute force|
|DA escalation — rule 100004|**True Positive**|High|Non-standard account added to Domain Admins, SID -512 confirmed, repeated 3×|
|Log clearing — rule 100005|**True Positive**|High|No legitimate use case for clearing Security log 3 times in 2 hours|
|Pre-built 60109 hits (4720)|**True Positive**|Medium|Same accounts as custom rule detections — but would require manual correlation without custom rule context|
|Pre-built 63103 hits (1102, L5)|**True Positive** — detection gap|Medium|Real events, but Level 5 severity would likely be missed without hunt query. Gap addressed by custom rule 100005|

**False positive assessment for 4720 events:** Account creation events can be legitimate (IT provisioning, onboarding). However, the following factors rule out false positive here: names follow attacker convention (service-account mimicry), accounts created outside business hours, no corresponding change management record would exist, and the temporal correlation with brute force and DA escalation makes innocent explanation implausible.

\---

## SOC Case Note

> \*This is a formal incident case note as it would be written in a production SOC ticketing system (e.g., ServiceNow, Jira, TheHive).\*

\---

**CASE ID:** INC-2026-1007-001
**Status:** Escalate to Tier 2
**Priority:** P1 — Critical
**Opened:** 2026-10-07 @ 12:35 (analyst shift start)
**Analyst:** Mojaki Tjeeka (Tier 1)
**Asset:** Win-Server — Domain Controller — 192.2.42.136

\---

**SUMMARY**

During morning threat hunt, analyst identified indicators consistent with a multi-stage Active Directory compromise spanning Oct 6–7, 2026. Activity includes credential brute forcing, creation of four rogue service-account-style domain user accounts, repeated escalation of one account (`svc\_test3`) to Domain Admins, and three Security log clearing events. The attacker appears to have DC-level access. All rogue accounts remain active as of investigation time.

\---

**DETECTION TRIGGER**

Morning hunt query `rule.level >= 10 and rule.level <= 15` returned 8 high-severity alerts from Win-Server agent. Manual investigation of supporting event IDs confirmed a structured attack chain. Alerts were not individually paged — the pattern was identified through proactive hunting, not reactive alerting.

\---

**EVIDENCE**

|Timestamp|Event ID|Rule|Level|Description|
|-|-|-|-|-|
|Oct 6 @ 13:50:23|4720|60109|8|Account `svc\_backup` created by Administrator|
|Oct 6 @ 13:50:54|4720|60109|8|Account `administrator2` created by Administrator|
|Oct 6 @ 14:35:15|4728|60159 / 100004|12/14|`svc\_test3` added to Domain Admins|
|Oct 6 @ 14:42:19|1102|63103|5|Security log cleared by Administrator|
|Oct 6 @ 15:58:41|4720|60109|8|Additional account created|
|Oct 6 @ 15:58:51|4728|60159|12|`svc\_test3` added to Domain Admins (second time)|
|Oct 6 @ 15:59:10|1102|63103|5|Security log cleared again|
|Oct 6 @ 16:48:54|4720|100003|12|Account `svc\_test3` created|
|Oct 6 @ 16:52:19|4728|100004|14|`svc\_test3` added to Domain Admins (third time)|
|Oct 6 @ 16:53:34|1102|100005|15|Security log cleared (third time)|
|Oct 7 @ 12:12:58|4625×12|100001|12|Brute force — 12 failures in <1 minute against DC|
|Oct 7 @ 12:16:05|4720|100003|12|Account `svc\_monitor` created — 4 min after brute force|

All evidence sourced from Wazuh SIEM (192.2.42.142). Local Security log on Win-Server was cleared three times — SIEM records are the authoritative source.

\---

**ANALYSIS**

The activity follows a structured post-compromise pattern: initial access (method unknown — possibly prior credential compromise or local console access), persistence via rogue account creation, privilege escalation to Domain Admins, and evidence destruction via log clearing. The cycle was repeated three times on Oct 6, suggesting scripted execution or an attacker re-running steps after each log clearing. The Oct 7 activity (brute force followed immediately by account creation) indicates the attacker either lost access overnight or is operating from a new session.

All four rogue accounts use service-account naming conventions (`svc\_backup`, `svc\_monitor`) or attempt to mimic built-in accounts (`administrator2`) — deliberate obfuscation intended to avoid detection during casual AD review.

The attacker has or had Domain Admin privileges via `svc\_test3`. The full scope of actions taken during DA access is unknown — the local Security log was cleared before full forensic capture was possible.

\---

**RECOMMENDED IMMEDIATE ACTIONS**

|Priority|Action|Owner|
|-|-|-|
|P1 — Immediate|Disable `svc\_test3`, `svc\_backup`, `administrator2`, `svc\_monitor` in AD|Tier 2 / AD Admin|
|P1 — Immediate|Remove `svc\_test3` from Domain Admins group|Tier 2 / AD Admin|
|P1 — Immediate|Audit all Domain Admins members — confirm no other unauthorised accounts|Tier 2|
|P1 — Immediate|Identify session logonId `0x3ff88` — trace origin of Administrator session that made changes|Tier 2 / Forensics|
|P2 — Urgent|Review all GPO changes made during Oct 6 14:35–16:53 (while svc\_test3 had DA access)|Tier 2|
|P2 — Urgent|Check all domain-joined machines for lateral movement activity from 192.2.42.136 during attack window|Tier 2|
|P2 — Urgent|Review Win-11 agent logs for any logon events using rogue account names|Tier 1 follow-up|
|P3 — High|Do not delete rogue accounts until forensic review complete — preserve SIDs for correlation|Forensics|
|P3 — High|Determine how attacker gained initial access to Administrator session on DC|Forensics|

\---

**ESCALATION DECISION**

**Escalate to Tier 2 — P1 Critical.**

Rationale: Confirmed Domain Admin compromise. Rogue accounts active. Scope of DA-level actions unknown. Local evidence partially destroyed. Potential for persistent access via accounts not yet identified. This incident exceeds Tier 1 response authority — requires AD admin access, forensic capability, and potential domain-wide remediation.

\---

**DETECTION GAP IDENTIFIED**

During this investigation, two log-clearing events (Oct 6 @ 14:42 and 15:59) fired only at Level 5 via the pre-built rule 63103. In a high-volume production environment, Level 5 alerts are typically below the paging threshold and may not be reviewed during shift. Custom rule 100005 caught the third event at Level 15. **Recommendation:** Review custom rule 100005 to confirm it catches all 1102 events regardless of which parent rule fires first. Consider a rule that fires at Level 12+ for *any* 1102 event to eliminate this gap.

\---

**CASE CLOSED BY:** Mojaki Tjeeka (Tier 1) — Escalated to Tier 2
**TIME TO DETECT:** \~23 hours (first event Oct 6 @ 13:50, hunt conducted Oct 7 @ 12:35)
**TIME TO TRIAGE:** \~25 minutes (queries run 12:35, case note completed \~13:00)
**Detection method:** Proactive hunt — not reactive alert

\---

## What This Hunt Proved

|SOC Principle|Evidence from This Hunt|
|-|-|
|Proactive hunting finds what reactive alerting misses|Two Level-5 log-clearing events would not have paged anyone — hunt query surfaced them|
|Timeline reconstruction requires cross-event correlation|No single alert told the full story — the attack chain only became visible by correlating 4720 → 4728 → 1102 timestamps|
|IOC pivoting adds critical context|Pivoting on `memberName` in 4728 events revealed svc\_test3 was added 3× — a single-event view missed this pattern|
|Detection gaps must be actively identified|Analyst identified that custom rule 100005 only caught 1 of 3 log-clearing events — recommended rule improvement|
|Centralised SIEM defeats log clearing|Attacker cleared local Security log 3 times — Wazuh preserved all prior events, enabling full reconstruction|

\---

## Skills Mapped to SOC Analyst Job Requirements

|Job Requirement|Evidence from This Project|
|-|-|
|24x7 SIEM monitoring and threat hunting|Conducted structured morning hunt using 5 query types across multiple event categories|
|Identifying anomalies and potential breaches|Identified 4-account compromise with DA escalation from hunt data alone|
|Performing end-to-end lifecycle of security incidents|Detected, triaged, reconstructed timeline, and produced formal case note with escalation decision|
|Collecting and analysing SIEM event data|Correlated 12 distinct events across 2 days to build unified attack timeline|
|MITRE ATT\&CK knowledge|Mapped each finding to specific technique and sub-technique|
|Escalation and communication|Produced P1-level case note with structured evidence table and recommended actions|
|Identifying detection gaps|Identified and documented Level 5 under-severity issue for log clearing events|
|Microsoft Active Directory knowledge|Interpreted AD-specific fields (memberName, targetSid, SID -512) to identify DA compromise|

\---

## Evidence Index

|Screenshot|Description|
|-|-|
|Screenshot 1|Hunt Query 1 — High severity (L10–15), 8 hits, rules 100001/100003/100004/100005|
|Screenshot 2|Hunt Query 2 — Event ID 4625, 12 hits, brute force spike at 12:12, rule 100001|
|Screenshot 3|Hunt Query 3 — Event ID 4720, 5 hits, both rule 100003 and 60109 visible|
|Screenshot 4|Hunt Query 3 detail — svc\_monitor creation, targetUserName field, 4 min after brute force|
|Screenshot 5|Hunt Query 4 — Event ID 4728, 3 hits, rule 100004 Level 14 and rule 60159 Level 12|
|Screenshot 6|Hunt Query 5 — Event ID 1102, 3 hits, rule 100005 Level 15 and rule 63103 Level 5|

> All screenshots are located in the \[`/screenshots`](./screenshots/) folder of this repository.

\---

*Part of the* [*SOC Home Lab Portfolio*](../README.md) *by Mojaki Tjeeka*

