# Project 2 — Brute Force Attack Detection \& Custom Rule Development

**SOC Home Lab | Portfolio Project 2 of 5**

|Field|Detail|
|-|-|
|**Author**|Mojaki Tjeeka|
|**Date**|02 October 2026|
|**Environment**|Wazuh v4.14.7 · Kali Linux · Windows Server (AD/DC) · Windows 11|
|**Objective**|Simulate a credential brute force attack against both the Domain Controller and a domain-joined Windows 11 endpoint, confirm detection via Wazuh's built-in ruleset, and develop custom correlation rules for high-severity alerting|
|**MITRE ATT\&CK**|T1110 — Brute Force · T1110.001 — Password Guessing|

\---

## Skills Demonstrated

* Offensive simulation using industry-standard tooling (Hydra)
* SMB and RDP protocol attack execution and analysis
* Windows Security Event log analysis (Event IDs 4625, 4624, 4634, 4673)
* SIEM alert triage and event field interpretation
* Custom Wazuh detection rule development with frequency correlation
* MITRE ATT\&CK framework mapping at technique and sub-technique level
* Critical evaluation of SIEM enrichment output (GeoIP anomaly)

\---

## Network Environment

|Component|Role|IP Address|Agent ID|
|-|-|-|-|
|Kali Linux|Attacker — simulated threat actor|192.2.42.156|N/A (no agent)|
|Win-Server|Windows Server AD/DC|192.2.42.136|Agent-001|
|Win-11|Windows 11 domain-joined endpoint|192.2.42.137|Agent-002|
|Ubuntu Server|Wazuh Manager v4.14.7|192.2.42.142|N/A (Manager)|

> All machines are on a bridged VMware LAN (`192.2.42.0/24`). Kali has no Wazuh agent installed — all detections are defender-side only, matching real-world SOC visibility constraints.

\---

## Steps Taken

### Step 1 — Attack Preparation

Built a custom 8-entry password wordlist on Kali with the correct credential for the account `jay` embedded at position 6, to simulate a realistic (not instant) brute force against a single targeted account rather than a password spray.

```bash
cat ~/lab-wordlist.txt
```

\---

### Step 2 — SMB Brute Force Against the Domain Controller

Ran Hydra from Kali against the DC over SMB (port 445):

```bash
hydra -l jay -P ~/lab-wordlist.txt smb://192.2.42.136
```

Confirmed the attack landed on both sides:

**Host side (Windows Event Viewer, DC):** filtered the Security log to Event ID 4625 and confirmed 42 matching events, Task Category *Logon*, Keywords *Audit Failure*, Subject `NULL SID`, Computer `win-server.cclabs.local`.

!\[Windows Event Viewer filtered to Event ID 4625 on the Domain Controller](./screenshots/b-f-a-004.png)

**SIEM side (Wazuh, Win-Server agent):** observed a dense burst of paired **60122** (*Logon Failure — Unknown user or bad password*) and **60104** (*Windows audit failure event*) alerts at Level 5, followed by **60106** (*Windows Logon Success*) and **60137** (*Windows User Logoff*) within \~2.3 seconds of the last failure.

!\[Wazuh event list showing the 4625 failure burst followed by logon success and logoff](./screenshots/b-f-a-001.png)

> ⚠️ \*\*Note:\*\* the Event Viewer timestamp (2:29:12 PM) is one minute behind the matching Wazuh burst (14:30:12). This is either an earlier manual attempt or a clock offset between the DC and the Wazuh manager — flagged for follow-up rather than assumed.

Expanded a 4625 event to confirm field-level parsing:

|Field|Value|Significance|
|-|-|-|
|`system.eventID`|`4625`|Failed logon|
|`targetUserName`|`jay`|Account under attack|
|`ipAddress`|`192.2.42.156`|Kali attacker machine|
|`workstationName`|`192.2.42.156`|Raw IP, no hostname supplied by attacker|
|`ipPort`|`46364` / `46384`|Ephemeral source port — one connection per attempt|
|`authenticationPackageName` / `logonProcessName`|`NTLM` / `NtLmSsp`|SMB uses NTLM auth|
|`logonType`|`3`|Network logon — confirms SMB|
|`status` / `subStatus`|`0xc000006d` / `0xc0000064`|General failure / **user name does not exist**|
|`failureReason`|`%%2313`|Unknown user name or bad password|
|`subjectUserSid` / `targetUserSid`|`S-1-0-0`|Null SID — pre-authentication failure|

!\[Expanded Event ID 4625 detail showing full field breakdown](./screenshots/b-f-a-002.png)

> ⚠️ \*\*Note:\*\* `subStatus 0xc0000064` means the account name itself was not found (a wrong password for an existing account returns `0xc000006a`). The Win-11 evidence in Step 4 shows the real domain account is `CCLABS\\jay.reed`, so the 4624 success event should be opened and its `targetUserName`/`ipAddress` confirmed before describing the password as "recovered."

Also observed follow-on activity in the same window — network share access (`67017`) and SQL-style database attach/detach events (`60798`/`60797`) — which do not appear to be attacker-driven and should be scoped out before being counted as part of the attack.

!\[Wazuh showing network share access and database attach/detach events after the logon](./screenshots/b-f-a-003.png)

\---

### Step 3 — Wazuh Built-In Correlation Confirmation

Before any custom rule was written, Wazuh's own correlation engine detected the repeated failure pattern and fired **rule 60204** — *Multiple Windows Logon Failures* — at **Level 10**, with `frequency: 8` (eight parent-rule matches counted), mapped to **MITRE T1110** / Credential Access, and to NIST 800-53 (AU.14, AC.7, SI.4) and GDPR (IV.35.7.d, IV.32.2).

!\[Wazuh alert detail for rule 60204, Multiple Windows Logon Failures, Level 10, MITRE T1110](./screenshots/b-f-a-multi-.png)

This confirmed Wazuh's built-in ruleset alone was sufficient to flag the brute force pattern — the custom rules in Step 6 exist to raise the severity and correlate across both hosts into a single higher-fidelity alert.

\---

### Step 4 — RDP Enablement and Attack Against the Windows 11 Endpoint

Enabled Remote Desktop on the Windows 11 machine so it could be targeted the same way as the DC:

```powershell
# Enable Remote Desktop
Settings → System → Remote Desktop → On

# Allow through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Ran Hydra against the endpoint over RDP and SMB:

```bash
hydra -l jay -P \~/lab-wordlist.txt rdp://<192.2.42.137>

```

Confirmed in Wazuh (Win-11 agent) a burst of **rule 60107** — *Failed attempt to perform a privileged operation* (Event ID 4673) — at Level 4, immediately followed by **67027** (*A process was created*):

!\[Wazuh event list on Win-11 showing repeated rule 60107 alerts followed by process creation](./screenshots/b-f-a-005.png)

Expanded one alert to confirm the account and privilege context:

|Field|Value|
|-|-|
|`rule.id` / `rule.level` / `rule.firedtimes`|`60107` / `4` / `84`|
|`message`|"A privileged service was called." (Event ID 4673)|
|`win.eventdata.privilegeList`|`SeTcbPrivilege`|
|`win.eventdata.processName` / `processId`|`C:\\Windows\\System32\\svchost.exe` / `0x390`|
|`win.eventdata.subjectUserName` / `subjectDomainName`|`jay.reed` / `CCLABS`|
|`rule.mitre.id` / `tactic`|`T1078` / Defense Evasion, Persistence, Privilege Escalation, Initial Access|

!\[Wazuh document detail showing subjectUserName jay.reed, processName svchost.exe](./screenshots/b-f-a-006.png)
!\[Wazuh document detail showing systemTime, providerName and severityValue AUDIT\_FAILURE](./screenshots/b-f-a-007.png)
!\[Wazuh document detail showing rule 60107, firedtimes 84, MITRE T1078 Valid Accounts](./screenshots/b-f-a-008.png)

> ⚠️ \*\*Note:\*\* this evidence shows Event 4673 / rule 60107, which maps to \*\*T1078 (Valid Accounts)\*\* rather than T1110. The Event ID 4776 (local credential validation, `workstation: kali`) and Win-11 Event 4625 referenced in earlier planning notes were not captured in this evidence set and should either be re-captured or removed from the write-up. On a domain-joined Windows 11 host, NTLM validation attempts can log as 4776 in addition to 4625, which would give a second detection surface not present on the DC — but this needs its own screenshot before being presented as a finding.

\---

### Step 5 — GeoIP Enrichment Review

While triaging the DC alerts, reviewed Wazuh's GeoLocation enrichment for the attacker IP. Wazuh resolved `192.2.42.156` — a private RFC 1918 address — to a geolocation of **lat 37.751, lon -97.822 (United States)**.

> ⚠️ \*\*Finding:\*\* this is a false enrichment. Private IP ranges cannot be accurately geolocated and should never resolve to a real-world geography. In a production SOC this would constitute misleading threat intelligence and could cause an analyst to misclassify an internal lateral-movement event as an external attack. GeoIP output must be corroborated with DHCP logs and asset inventory before being used as evidence.

*(Screenshot of the GeoLocation field was not captured in this evidence set — flagged for re-capture.)*

\---

### Step 6 — Custom Detection Rule Development

Wrote two correlation rules in `/var/ossec/etc/rules/local\_rules.xml` to raise the DC/endpoint failure patterns to a single high-severity, MITRE-tagged alert:

```xml


<group name="local\_rules,">



 <!-- Repeated failed Windows logons from the same IP -->

 <rule id="100001" level="12" frequency="5" timeframe="120">

   <if\_matched\_sid>60122</if\_matched\_sid>

   <same\_field>win.eventdata.ipAddress</same\_field>

   <description>Brute Force Attack: Repeated failed Windows logons from the same IP within 2 minutes</description>

   <mitre>

     <id>T1110</id>

   </mitre>

   <group>authentication\_failures,brute\_force,</group>

 </rule>



 <!-- Identify an individual failed RDP logon -->

 <rule id="100010" level="5">

   <if\_sid>60105</if\_sid>

   <field name="win.system.eventID">^4625$</field>

   <field name="win.eventdata.logonType">^10$</field>

   <description>Windows RDP Logon Failure</description>

   <group>authentication\_failures,rdp,</group>

 </rule>



 <!-- Repeated failed RDP logons from the same IP -->

 <rule id="100002" level="12" frequency="5" timeframe="120">

   <if\_matched\_sid>100010</if\_matched\_sid>

   <same\_field>win.eventdata.ipAddress</same\_field>

   <description>Brute Force Attack: Repeated RDP failures from the same IP within 2 minutes</description>

   <mitre>

     <id>T1110.001</id>

   </mitre>

   <group>authentication\_failures,brute\_force,rdp,</group>

 </rule>



</group>
```

|Parameter|Value|Meaning|
|-|-|-|
|`id`|100001 / 100002|Custom rules start at 100000|
|`level`|12|High severity (Wazuh scale 0–15); triggers `mail: true`|
|`frequency`|5|Triggers after 5 parent rule matches|
|`timeframe`|120|Within a 120-second window|
|`if\_matched\_sid`|60122 / 60104|Parent rules to correlate against|
|`same\_source\_ip`|—|Only counts failures from identical source IP|
|`mitre id`|T1110 / T1110.001|MITRE ATT\&CK technique and sub-technique|

> \*\*Design note:\*\* rule 100001 (`if\_matched\_sid: 60122`) fires on either host, since both Win-Server and Win-11 raise rule 60122 on failed logons — a single rule gives domain-wide coverage.

```bash
# Validate rule syntax
sudo /var/ossec/bin/wazuh-logtest

# Restart manager to load new rules
sudo systemctl restart wazuh-manager

# Confirm running
sudo systemctl status wazuh-manager
```
!\[Screenshot of `local_rules.xml` open in nano](./screenshots/b-f-a-003.png)

\---

### Step 7 — Custom Rule Validation

Re-ran the SMB attack against the DC and confirmed rule **100001** fired at **Level 12**:

|Field|Value|
|-|-|
|`rule.id` / `rule.level`|`100001` / `12`|
|`rule.firedtimes`|`2`|
|`rule.mail`|`true`|
|`rule.groups`|`local\_rules`, `authentication\_failures`, `brute\_force`|
|`rule.mitre`|T1110 — Brute Force, Credential Access|

!\[Wazuh alert list showing custom rule 100001 firing at Level 12, with 24-hour histogram](./screenshots/b-f-a-009.png)
!\[Wazuh document detail for rule 100001 showing groups, MITRE T1110, Credential Access tactic](./screenshots/b-f-a-010.png)

The 24-hour view for the Win-Server agent showed 1,565 hits with volume ramping sharply from midday onward — consistent with repeated attack runs during rule testing.

*(Screenshot of rule 100002 firing was not captured in this evidence set — flagged for re-capture.)*

\---

## Troubleshooting Log

No blocking technical issues were encountered during this project. Two analytical gaps were identified during evidence review and are tracked as open follow-ups rather than resolved issues:

|||
|-|-|
|**Issue**|One-minute discrepancy between the DC's local Event Viewer timestamp (2:29:12 PM) and the matching Wazuh alert timestamp (14:30:12) for the same attack burst.|
|**Status**|Not yet root-caused. Candidate explanations: an earlier manual Hydra run, or clock drift between the DC and the Wazuh manager.|
|**Next step**|Compare `systemTime` in the raw Windows event JSON against the Wazuh manager's system clock.|

|||
|-|-|
|**Issue**|Rule 100002 is scoped to SID 60104, which fires on all Windows audit failures, not RDP specifically — so its "RDP credential failures" description is currently inaccurate.|
|**Status**|Open.|
|**Next step**|Add an `eventID` or `logonType` condition scoped to RDP-originated failures (e.g. Event 4776) and re-test.|

\---

## Findings \& Results

### ✅ Objectives Met

* Brute force attack successfully simulated against both the Domain Controller and a domain-joined Windows 11 endpoint over SMB and RDP
* Attack signature (4625 failure burst, NTLM, single source IP) confirmed end-to-end in both Windows Event Viewer and Wazuh
* Wazuh's built-in ruleset detected the pattern without any custom configuration (rule 60204, Level 10, MITRE T1110)
* Two custom correlation rules developed, deployed, and validated — rule 100001 confirmed firing at Level 12 against live traffic
* GeoIP enrichment critically evaluated and a false-positive enrichment identified and documented

### Key Observations

* All observed failures originated from a single source IP (192.2.42.156), consistent with a single-actor targeted brute force rather than a distributed attack
* NTLM over SMB from a workstation presenting only a raw IP (no hostname) is itself an anomaly worth baselining against normal DC traffic
* The Domain Controller and the Windows 11 endpoint surface different event types for the same style of attack (4625/60122 on the DC vs. 4673/60107 on the endpoint) — detection coverage needs to account for both
* GeoIP enrichment is unreliable for RFC 1918 addresses and must be corroborated with DHCP logs and asset inventory, not trusted as standalone evidence
* Several items of evidence referenced in the attack plan (Win-11 Event 4776, rule 100002 firing, the `local\_rules.xml` file itself, the GeoLocation field) were not present in the screenshots reviewed and are tracked above rather than claimed without evidence

### Wazuh Alerts Generated

|Rule ID|Rule Description|Severity|Triggered By|
|-|-|-|-|
|60104 / 60122|Windows audit failure / Logon Failure — Unknown user or bad password|Low (5)|Each 4625 event on DC and Win-11|
|60204|Multiple Windows Logon Failures|Medium (10)|8 correlated failures from 192.2.42.156|
|60107|Failed attempt to perform a privileged operation|Medium (4)|Event 4673 on Win-11, account `jay.reed`|
|**100001** (custom)|Brute Force Attack: Repeated failed Windows logons from the same IP within 2 minutes|**High (12)**|5+ rule-60122 matches from the same source IP within 120s|
|**100002** (custom)|Brute Force Attack: 5+ RDP credential failures from same source within 2 minutes|**High (12)**|5+ rule-60104 matches from the same source IP within 120s *(scoping gap noted above)*|

\---

## Skills Mapped to SOC Analyst Job Requirements

|Job Requirement|Evidence from This Project|
|-|-|
|Monitoring security systems — SIEM, EDR, XDR|Monitored Wazuh in real time during live attacks, triaged hundreds of correlated events|
|Identifying anomalies and potential breaches|Identified brute force pattern from event volume, speed, source IP consistency, and an anomalous workstation name|
|Performing end-to-end lifecycle of security incidents|Detected, analysed, correlated, and documented a full attack sequence across two targets|
|Proactively detecting and responding to threats|Wrote and validated custom Wazuh correlation rules to flag future attacks before they succeed|
|SIEM log collection and analysis|Parsed Windows event fields (`targetUserName`, `ipAddress`, `logonType`, status/substatus codes) and cross-checked Wazuh against Windows Event Viewer|
|Scripting — PowerShell|Used PowerShell to enable RDP and the associated firewall rule on Windows 11|
|MITRE ATT\&CK knowledge|Mapped detections to T1110 and T1110.001 at sub-technique level; identified an additional T1078 surface on Win-11|
|Applying expertise and advanced technologies|Deployed and validated custom Wazuh correlation rules against live attack traffic|

\---

## Evidence Index

|#|Filename|Description|
|-|-|-|
|1|`b-f-a-004.png`|Windows Event Viewer — 4625 entries filtered on the DC|
|2|`b-f-a-001.png`|Wazuh — 4625 failure burst → Logon Success → Logoff (DC)|
|3|`b-f-a-002.png`|Wazuh — expanded 4625 detail, field breakdown (DC)|
|4|`b-f-a-003.png`|Wazuh — network share access and DB attach/detach events (DC)|
|5|`b-f-a-multi-.png`|Wazuh — rule 60204 detail, Level 10, MITRE T1110, NIST/GDPR mappings|
|6|`b-f-a-005.png`|Wazuh — rule 60107 / 67027 burst on Win-11|
|7|`b-f-a-006.png`|Wazuh — document detail, `jay.reed`, `svchost.exe`, `SeTcbPrivilege`|
|8|`b-f-a-007.png`|Wazuh — document detail, `systemTime`, provider fields, `AUDIT\_FAILURE`|
|9|`b-f-a-008.png`|Wazuh — rule 60107 detail, `firedtimes 84`, MITRE T1078|
|10|`b-f-a-009.png`|Wazuh — custom rule 100001 firing at Level 12, 24-hour histogram|
|11|`b-f-a-010.png`|Wazuh — custom rule 100001 JSON detail, groups, MITRE T1110|

> Not yet captured: `local\_rules.xml` in nano, rule 100002 firing, Win-11 Event 4776/4625, DC Event 4624 detail, GeoLocation field. See Troubleshooting Log and Step notes above.

> All screenshots are in the \[`/screenshots`](./screenshots/) folder of this repository.

\---

*Part of the* [*SOC Home Lab Portfolio*](../README.md) *by Mojaki Tjeeka*

