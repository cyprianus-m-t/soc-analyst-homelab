# Project 3 — Active Directory Attack Detection

**SOC Home Lab | Portfolio Project 3 of 5**

| Field | Detail |
|---|---|
| **Author** | Mojaki Tjeeka |
| **Date** | 06 October 2026 |
| **Target Machine** | Windows Server 2022 — Domain Controller (192.2.42.136) |
| **SIEM** | Wazuh v4.14.7 — 192.2.42.135 |
| **Domain** | CCLABS (cclabs.local) |
| **MITRE ATT&CK** | T1136.001 — Create Account: Domain Account · T1098.007 — Account Manipulation: Add Office 365 Global Administrator Role (used here for Domain Admins escalation) · T1070.001 — Indicator Removal: Clear Windows Event Logs |

---

## Objective

Simulate three high-impact Active Directory attack techniques on the Domain Controller, observe the specific Windows Security Event IDs they generate in Wazuh, then develop custom detection rules that fire targeted alerts for each technique. These attacks represent the post-compromise persistence and privilege escalation phase of a domain attack — the stage most likely to result in full domain takeover.

---

## Skills Demonstrated

- Active Directory attack simulation using PowerShell
- AD-specific Windows Security Event log analysis (Event IDs 4720, 4728, 1102)
- SIEM alert triage and AD event field interpretation
- Custom Wazuh detection rule development for account management events
- MITRE ATT&CK framework mapping for persistence, privilege escalation, and defense evasion
- Critical evaluation of pre-built vs. custom rule coverage gaps
- Evidence destruction detection and its SOC implications

---

## Network Environment

| Component | Role | IP |
|---|---|---|
| Windows Server 2022 | Target — Domain Controller | 192.2.42.136 |
| Ubuntu / Wazuh | SIEM — defender visibility | 192.2.42.135 |
| Windows 11 | Domain-joined endpoint (monitored) | 192.2.42.137 |

> All attacks simulated from an Administrator PowerShell session on the DC — representing an attacker who has already achieved initial access and is operating with elevated privileges.

---

## Attack Context — The Simulated Threat Scenario

All three attacks form a logical attack chain:

```
[Phase 1] Attacker creates backdoor accounts → persistence established
[Phase 2] Backdoor account escalated to Domain Admins → full domain control
[Phase 3] Security log cleared → evidence of phases 1 & 2 destroyed
```

This mirrors the attack pattern used in real ransomware incidents targeting financial institutions: gain initial foothold, establish persistence with a hidden admin account, escalate to Domain Admin for maximum access, then clear logs to delay detection.

---

## Attack 1 — Rogue Account Creation (Event ID 4720)

### Method

Simulated an attacker creating two backdoor user accounts via PowerShell on the DC. Both accounts use names designed to blend into a legitimate environment:

- `svc_backup` — mimics a legitimate service account name
- `administrator2` — mimics the built-in Administrator account

```powershell
# Create service-account style backdoor
New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true

# Create admin-mimic account
New-ADUser -Name "administrator2" -SamAccountName "administrator2" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true

# Verify both accounts exist and are enabled
Get-ADUser -Filter {SamAccountName -like "svc_backup" -or SamAccountName -like "administrator2"} `
  | Select Name, SamAccountName, Enabled
```

### Attack Outcome

Both accounts were created successfully and confirmed enabled in Active Directory.

> 📷 **Screenshot 1** — PowerShell Get-ADUser output confirming both `svc_backup` and `administrator2` exist with Enabled: True.

### Key Event Fields Observed (Event ID 4720)

Wazuh ingested two Event ID 4720 events from Win-Server — one per account created.

| Field | Value | Significance |
|---|---|---|
| `data.win.system.eventID` | `4720` | User account created in AD |
| `data.win.eventdata.targetUserName` | `administrator2` / `svc_backup` | Name of the new backdoor account |
| `data.win.eventdata.subjectUserName` | `Administrator` | Account that performed the creation |
| `data.win.eventdata.subjectDomainName` | `CCLABS` | Domain where account was created |
| `data.win.system.computer` | `win-server.cclabs.local` | DC where action occurred |
| `data.win.system.severityValue` | `AUDIT_SUCCESS` | Account creation succeeded |

> 📷 **Screenshot 2** — Wazuh event list filtered to `eventID:4720` showing 2 hits — both account creation events timestamped within seconds of each other.

> 📷 **Screenshot 3** — Wazuh Document Details for Event ID 4720 — showing `targetUserName: administrator2`, `subjectUserName: Administrator`, `data.win.system.message: "A user account was created"`.

> 📷 **Screenshot 4** — Wazuh Document Details for second 4720 event — showing `samAccountName: svc_test3` (from second run), `subjectUserName: Administrator`, domain CCLABS.

---

## Attack 2 — Privilege Escalation to Domain Admins (Event ID 4728)

### Method

Escalated the `svc_backup` backdoor account to the **Domain Admins** group — granting it full administrative control over the entire domain.

```powershell
# Escalate backdoor account to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_backup"

# Verify escalation succeeded
Get-ADGroupMember -Identity "Domain Admins" | Select Name, SamAccountName
```

### Attack Outcome

`svc_backup` was confirmed as a member of Domain Admins alongside the built-in Administrator account. At this point, the attacker has full domain control through a non-obvious account.

> 📷 **Screenshot 5** — PowerShell Get-ADGroupMember output showing both `Administrator` and `svc_backup` listed as Domain Admins members.

### Key Event Fields Observed (Event ID 4728)

| Field | Value | Significance |
|---|---|---|
| `data.win.system.eventID` | `4728` | Member added to security-enabled global group |
| `data.win.eventdata.memberName` | `CN=svc_backup,CN=Users,DC=cclabs,DC=local` | Full DN of the account added |
| `data.win.eventdata.targetUserName` | `Domain Admins` | The group that was modified |
| `data.win.eventdata.targetDomainName` | `CCLABS` | Domain where change occurred |
| `data.win.eventdata.subjectUserName` | `Administrator` | Account that made the change |
| `data.win.eventdata.targetSid` | `S-1-5-21-...-512` | SID ending -512 = Domain Admins (well-known) |

> **Note on SID -512:** The Domain Admins group always ends in SID suffix `-512`. Any event adding a member to a group with this SID suffix is automatically high priority — it represents the highest privilege in a Windows domain.

> 📷 **Screenshot 6** — Wazuh Document Details for Event ID 4728 — showing `memberName: CN=svc_backup`, `targetUserName: Domain Admins`, `subjectUserName: Administrator`, `targetSid` ending -512.

> 📷 **Screenshot 7** — Wazuh event list filtered to `eventID:4728` showing 1 hit — rule 60159 "Domain Admins Group Changed" at Level 12.

---

## Attack 3 — Security Log Clearing (Event ID 1102)

### Method

Cleared the Windows Security event log to destroy evidence of phases 1 and 2.

```powershell
Clear-EventLog -LogName Security
```

### Attack Outcome

The Security log was cleared. Windows immediately generated Event ID 1102 — the log clearing event — which was captured by Wazuh before any local evidence could be destroyed.

> 📷 **Screenshot 8** — Windows Server Event Viewer showing Security log with Event ID 1102 "Log clear" at the top, timestamped Oct 6, 2026 @ 14:42 PM. Only 35 events remain after clearing.

### Key Event Fields Observed (Event ID 1102)

| Field | Value | Significance |
|---|---|---|
| `data.win.system.eventID` | `1102` | Security audit log cleared |
| `data.win.logFileCleared.subjectUserName` | `Administrator` | Account that cleared the log |
| `data.win.logFileCleared.subjectDomainName` | `CCLABS` | Domain of the account |
| `data.win.logFileCleared.subjectLogonId` | `0x3ff88` | Session that performed the action |
| `data.win.system.channel` | `Security` | Confirms Security log was cleared |
| `data.win.system.message` | `"The audit log was cleared."` | Windows-generated message |

> **Critical observation:** Despite the attacker clearing the Security log on the DC, Wazuh had already forwarded all prior events to the centralised SIEM. The attacker destroyed local evidence but could not reach the SIEM. This is the core value proposition of centralised log management.

> 📷 **Screenshot 9** — Wazuh event list filtered to `eventID:1102` showing the "The audit log was cleared" alert (rule 63103, Level 5) firing with full field detail.

> 📷 **Screenshot 10** — Wazuh Document Details for Event ID 1102 — showing `subjectUserName: Administrator`, `subjectDomainName: CCLABS`, message: "The audit log was cleared."

---

## SIEM Analysis — Wazuh Pre-Built Rules Observed

Before custom rules were deployed, Wazuh's built-in ruleset detected the following:

| Rule ID | Description | Level | Event ID | Notes |
|---|---|---|---|---|
| 60109 | User account enabled or created | 8 | 4720 | Both account creations detected |
| 60159 | Domain Admins Group Changed | 12 | 4728 | Already at high severity — DA change is a critical signal |
| 63103 | The audit log was cleared | 5 | 1102 | Only Level 5 — this is too low for a SOC response threshold |

**Key finding:** Rule 63103 fires at Level 5 for log clearing — which is below most SOC alert thresholds and could be missed in a high-volume environment. This justifies writing custom rule 100005 at Level 15.

---

## Custom Detection Rules Developed

### Rule File Location
`/var/ossec/etc/rules/local_rules.xml`

> 📷 **Screenshot 11** — local_rules.xml in nano showing all five custom rules (100001–100005) correctly formatted and deployed.

### Rule XML (AD-Specific Rules)

```xml
<!-- New domain user account created — potential rogue account -->
<rule id="100003" level="12">
  <if_sid>60144</if_sid>
  <field name="win.system.eventID">^4720$</field>
  <description>AD Attack: new domain user account created (possible rogue account)</description>
  <mitre>
    <id>T1136.001</id>
  </mitre>
  <group>account_management,ad_attack,</group>
</rule>

<!-- Account added to privileged security group — possible privilege escalation -->
<rule id="100004" level="14">
  <if_sid>60144</if_sid>
  <field name="win.system.eventID">^4728$</field>
  <description>AD Attack: Account added to privileged security group (possible privilege escalation)</description>
  <mitre>
    <id>T1098.007</id>
  </mitre>
  <group>account_management,privilege_escalation,ad_attack,</group>
</rule>

<!-- Windows Security event log cleared — evidence destruction -->
<rule id="100005" level="15">
  <if_sid>60145</if_sid>
  <field name="win.system.eventID">^1102$</field>
  <description>AD Attack: Windows Security event log cleared (possible evidence destruction)</description>
  <mitre>
    <id>T1070.001</id>
  </mitre>
  <group>log_tempering,defense_evasion,ad_attack,</group>
</rule>
```

### Rule Logic Explained

| Rule | Level | Rationale for Level |
|---|---|---|
| 100003 | 12 | Any new domain account creation outside a change-management window should be treated as high severity |
| 100004 | 14 | Adding any account to Domain Admins is near-critical — this grants full domain control |
| 100005 | 15 (maximum) | Log clearing is the highest-confidence indicator of active attacker presence — a legitimate administrator clearing logs is rare and should always be investigated |

### Validation & Deployment

```bash
# Validate rule syntax
sudo /var/ossec/bin/wazuh-logtest -t

# Reload rules
sudo systemctl restart wazuh-manager

# Confirm running
sudo systemctl status wazuh-manager
```

### Custom Rules Firing

> 📷 **Screenshot 12** — Wazuh alert — rule **100003** firing at Level 12, description "AD Attack: new domain user account created", Event ID 4720, Win-Server, Oct 6 @ 16:48.

> 📷 **Screenshot 13** — Wazuh alert — rule **100004** firing at Level 14, description "AD Attack: Account added to pri...", Event ID 4728, Win-Server, Oct 6 @ 16:52.

> 📷 **Screenshot 14** — Wazuh alert — rule **100005** firing at Level 15, description "AD Attack: Windows Security event log cleared (possible evidence dest...", Event ID 1102, Win-Server, Oct 6 @ 16:53.

---

## Findings & Analysis

### Attack Chain Summary

| Phase | Action | Event ID | Time | Wazuh Alert |
|---|---|---|---|---|
| 1a | Created `svc_backup` (service account mimic) | 4720 | 13:50:23 | Rule 100003 — Level 12 |
| 1b | Created `administrator2` (admin name mimic) | 4720 | 13:50:54 | Rule 100003 — Level 12 |
| 2 | Added `svc_backup` to Domain Admins | 4728 | 14:35:15 | Rule 100004 — Level 14 |
| 3 | Cleared Security event log | 1102 | 14:42:19 | Rule 100005 — Level 15 |

### What Made These Attacks Detectable

**Account Creation (4720):**
- Creating user accounts at non-business hours is anomalous
- Account names mimicking service accounts or built-ins are a strong indicator
- Two accounts created within 1 second of each other is an automated action signature

**Privilege Escalation (4728):**
- Any modification to Domain Admins is abnormal in a well-governed environment
- The `targetSid` ending in `-512` is a reliable programmatic indicator that a DA-level change occurred
- SID `-512` should be in every SOC's watchlist as an automatic high-priority trigger

**Log Clearing (1102):**
- Legitimate administrators almost never clear the Security log
- The event is self-documenting — it proves someone tried to hide their activity
- The fact that Wazuh still has all prior events demonstrates that centralised SIEM defeats this technique entirely

### Pre-Built vs Custom Rule Coverage Gap

| Attack | Pre-Built Rule | Level | Custom Rule | Level | Gap Closed |
|---|---|---|---|---|---|
| Account creation | 60109 | 8 | 100003 | 12 | ✅ Raised severity threshold |
| DA group change | 60159 | 12 | 100004 | 14 | ✅ Raised severity, added MITRE tag |
| Log clearing | 63103 | 5 | 100005 | 15 | ✅ Critical — pre-built level was far too low |

The most important gap closed was rule 100005. A Level 5 alert for log clearing would likely be drowned out in alert noise in a production SOC. Elevating it to Level 15 ensures it bypasses alert fatigue and demands immediate analyst attention.

### What This Attack Chain Could Lead To (Real-World Impact)

Had this been a real incident in a banking environment:

- **Phase 1** — `svc_backup` provides persistent access even if the initial intrusion vector is closed
- **Phase 2** — Domain Admin access enables password hash extraction (DCSync attack), GPO modification, and deployment of malicious scripts to all domain-joined machines
- **Phase 3** — Log clearing delays detection, buys the attacker more time, and complicates forensic reconstruction
- **Combined** — This is the exact pattern preceding ransomware deployment: establish DA access, deploy ransomware via GPO to all endpoints simultaneously

---

## Recommended Response Actions

| Priority | Action |
|---|---|
| **Immediate** | Disable `svc_backup` and `administrator2` — do not delete yet (preserve forensic evidence) |
| **Immediate** | Remove `svc_backup` from Domain Admins group |
| **Immediate** | Identify the session (logonId `0x3ff88`) that cleared the log and trace its origin |
| **Urgent** | Check for any GPO modifications made while `svc_backup` had DA rights |
| **Urgent** | Review all privileged actions performed by `Administrator` account during the attack window |
| **High** | Check Wazuh for any Event ID 4624 logons using `svc_backup` or `administrator2` credentials |
| **High** | Audit all Domain Admins group membership changes over the last 30 days |
| **Medium** | Implement an alert rule that fires on any modification to tier-0 groups (Domain Admins, Enterprise Admins, Schema Admins) |
| **Medium** | Enforce change management controls — require a change ticket before any AD account creation |
| **Post-incident** | Review whether the initial compromise that gave Administrator-level access can be identified |

---

## Skills Mapped to SOC Analyst Job Requirements

| Job Requirement | Evidence from This Project |
|---|---|
| Monitoring security systems — SIEM, EDR, XDR | Monitored Wazuh in real time across a three-phase AD attack chain |
| Identifying anomalies and potential breaches | Identified rogue account names, DA escalation, and log clearing as high-confidence IOCs |
| Performing end-to-end lifecycle of security incidents | Simulated, detected, analysed, and documented a full post-compromise attack chain |
| Microsoft Active Directory knowledge | Demonstrated deep understanding of AD event IDs, group structures, SID conventions, and DC audit events |
| Custom detection rule writing | Wrote three targeted rules at appropriate severity levels, closing gaps in pre-built coverage |
| MITRE ATT&CK framework | Mapped attacks to T1136.001, T1098.007, and T1070.001 at sub-technique level |
| Scripting — PowerShell | Used PowerShell AD cmdlets to simulate all three attack phases |
| Proactively detecting and responding to threats | Identified and documented that the pre-built Level 5 log-clearing rule was dangerously under-severity |

---

## Evidence Index

| Screenshot | Description |
|---|---|
| Screenshot 1 | PowerShell — Get-ADUser confirming svc_backup and administrator2 both Enabled: True |
| Screenshot 2 | Wazuh — Event ID 4720 list, 2 hits, rule 60109 Level 8 |
| Screenshot 3 | Wazuh Document Details — 4720, targetUserName: administrator2, message: "A user account was created" |
| Screenshot 4 | Wazuh Document Details — 4720, samAccountName: svc_test3, subjectUserName: Administrator |
| Screenshot 5 | local_rules.xml — rules 100003, 100004, 100005 visible in nano |
| Screenshot 6 | Wazuh Document Details — 1102, subjectUserName: Administrator, "The audit log was cleared" |
| Screenshot 7 | Wazuh — Event ID 1102 list, rule 63103 "The audit log was cleared" Level 5 |
| Screenshot 8 | Windows Server Event Viewer — Security log showing Event ID 1102 Log clear |
| Screenshot 9 | Wazuh Document Details — 4728, memberName: CN=svc_backup, targetUserName: Domain Admins |
| Screenshot 10 | Wazuh — Event ID 4728 list, rule 60159 "Domain Admins Group Changed" Level 12 |
| Screenshot 11 | PowerShell — Get-ADGroupMember showing svc_backup in Domain Admins alongside Administrator |
| Screenshot 12 | Wazuh — custom rule 100003 firing, Level 12, Event ID 4720 |
| Screenshot 13 | Wazuh — custom rule 100004 firing, Level 14, Event ID 4728 |
| Screenshot 14 | Wazuh — custom rule 100005 firing, Level 15, Event ID 1102 |

> All screenshots are located in the [`/screenshots`](./screenshots/) folder of this repository.

---

*Part of the [SOC Home Lab Portfolio](../README.md) by Mojaki Tjeeka*
