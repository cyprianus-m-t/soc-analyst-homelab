# Project 2 — Brute Force Attack Detection & Custom Rule Development

**SOC Home Lab | Portfolio Project 2 of 5**

| Field | Detail |
|---|---|
| **Author** | Mojaki Tjeeka |
| **Date** | 02 October 2026 |
| **Attacker Machine** | Kali Linux — 192.2.42.156 |
| **Targets** | Windows Server DC (192.2.42.136) · Windows 11 Endpoint (192.2.42.137) |
| **SIEM** | Wazuh v4.14.7 — 192.2.42.135 |
| **MITRE ATT&CK** | T1110 — Brute Force · T1110.001 — Password Guessing |

---

## Objective

Simulate a real-world credential brute force attack from a dedicated Kali Linux attacker machine against both the Domain Controller and a domain-joined Windows 11 endpoint. Observe the attack signature in Wazuh, analyse event-level detail, and develop custom detection rules that fire high-severity alerts correlated across both targets.

---

## Skills Demonstrated

- Offensive simulation using industry-standard tooling (Hydra)
- SMB and RDP protocol attack execution and analysis
- Windows Security Event log analysis (Event IDs 4625, 4776)
- SIEM alert triage and event field interpretation
- Custom Wazuh detection rule development with frequency correlation
- MITRE ATT&CK framework mapping at technique and sub-technique level
- Critical evaluation of SIEM enrichment output (GeoIP anomaly)

---

## Network Environment

| Component | Role | IP |
|---|---|---|
| Kali Linux | Attacker — simulated threat actor | 192.2.42.156 |
| Windows Server 2022 | Target 1 — Domain Controller | 192.2.42.136 |
| Windows 11 | Target 2 — Domain-joined endpoint | 192.2.42.137 |
| Ubuntu / Wazuh | SIEM — defender visibility | 192.2.42.135 |

> All machines on bridged VMware LAN `192.2.42.0/24`. Kali has no Wazuh agent — all detections are defender-side only, matching real-world SOC visibility constraints.

---

## Attack 1 — SMB Brute Force Against Domain Controller

### Tool & Method

**Tool:** Hydra — pre-installed on Kali Linux  
**Protocol:** SMB (port 445)  
**Target:** 192.2.42.136 (Windows Server DC)  
**Account targeted:** `jay`  
**Wordlist:** Custom 8-entry list with correct credential embedded at position 6

```bash
hydra -l jay -P ~/lab-wordlist.txt smb://192.2.42.136
```

### Attack Outcome

Hydra attempted each password sequentially over SMB. Five consecutive failures were generated before the correct credential was discovered, producing a clear brute force pattern in Wazuh:

- **5 × Event ID 4625** — Failed logon (Unknown user or bad password)
- **1 × Event ID 4624** — Successful logon after correct credential found
- **1 × Event ID 4634** — User logoff

### Key Event Fields Observed (Event ID 4625 — DC)

| Field | Value | Significance |
|---|---|---|
| `eventID` | `4625` | Failed network logon |
| `targetUserName` | `jay` | Account under attack |
| `ipAddress` | `192.2.42.156` | Kali attacker machine |
| `workstationName` | `kali` | Attacker hostname visible |
| `authenticationPackageName` | `NTLM` | SMB uses NTLM auth |
| `logonType` | `3` | Network logon — confirms SMB |
| `status` | `0xc000006d` | General logon failure |
| `subStatus` | `0xc0000064` | Username does not exist / bad password |
| `failureReason` | `%%2313` | Unknown username or bad password |

> 📷 **Screenshot 1** — Wazuh event list showing flood of 4625 events from Win-Server agent, source IP 192.2.42.156, rule IDs 60104 and 60122 firing at Level 5.

> 📷 **Screenshot 2** — Expanded event detail — Event ID 4625 on DC showing full field breakdown including targetUserName, ipAddress, logonType, status codes.

> 📷 **Screenshot 3** — Wazuh showing Event ID 4624 (Logon Success) appearing after the 4625 flood — confirming Hydra recovered the credential.

---

## Attack 2 — SMB/RDP Brute Force Against Windows 11 Endpoint

### Tool & Method

**Protocol:** SMB + RDP (port 3389)  
**Target:** 192.2.42.137 (Windows 11)  
**Account targeted:** `jay`

RDP was enabled on the Windows 11 machine via:
```powershell
# Enable Remote Desktop
Settings → System → Remote Desktop → On

# Allow through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

```bash
hydra -l jay -P ~/lab-wordlist.txt rdp://192.2.42.137
hydra -l jay -P ~/lab-wordlist.txt smb://192.2.42.137
```

### Key Event Fields Observed (Event ID 4776 — Win-11)

A distinct event type appeared on Win-11 not seen on the DC:

| Field | Value | Significance |
|---|---|---|
| `eventID` | `4776` | Local credential validation attempt |
| `targetUserName` | `jay` | Same account targeted |
| `workstation` | `kali` | Attacker identified by hostname |
| `packageName` | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` | Local NTLM validation |
| `status` | `0xc0000064` | Bad username or password |
| `rule.firedtimes` | `19` | 19 attempts at time of screenshot |

> **Note:** Event ID 4776 differs from 4625. On a domain-joined Windows 11 machine, RDP attacks trigger local credential validation events (4776) before escalating to the DC. This provides an additional detection surface not present on the DC itself.

> 📷 **Screenshot 4** — Wazuh alert showing Event ID 4776 on Win-11 agent, workstation field showing "kali", firedtimes: 19.

### Key Event Fields Observed (Event ID 4625 — Win-11)

SMB attack against Win-11 also generated 4625 events identical in structure to the DC attack, with `firedtimes: 28` confirming sustained attack volume.

> 📷 **Screenshot 5** — Wazuh event detail showing Event ID 4625 on Win-11, ipAddress 192.2.42.156, logonType 3, rule 60122 at firedtimes 28.

---

## SIEM Analysis — Wazuh Pre-Built Rules Observed

Before custom rules were written, Wazuh's built-in ruleset detected the following across both attacks:

| Rule ID | Description | Level | Trigger |
|---|---|---|---|
| 60104 | Windows audit failure event | 5 | Every 4625 / 4776 event |
| 60122 | Logon Failure — Unknown user or bad password | 5 | Every 4625 event |
| 60204 | Multiple Windows Logon Failures | **10** | Correlation of repeated failures |
| 60106 | Windows Logon Success | 3 | 4624 after credential found |
| 60137 | Windows User Logoff | 3 | 4634 post-session |

Rule 60204 (Level 10, MITRE T1110, Credential Access tactic) fired automatically — confirming Wazuh's built-in correlation engine detected the brute force pattern without any custom configuration.

> 📷 **Screenshot 6** — Wazuh event list showing rule 60204 "Multiple Windows Logon Failures" at Level 10 firing within the attack sequence, with MITRE T1110 and NIST 800-53 mappings visible.

---

## GeoIP Anomaly — Critical Observation

Wazuh's GeoLocation enrichment flagged source IP `192.2.42.156` (a private RFC 1918-range address) as geolocating to the **United States** (lat: 37.751, lon: -97.822).

This is a false enrichment — private IP ranges cannot be accurately geolocated and should never resolve to a real-world geography. In a production SOC environment this would constitute misleading threat intelligence and could cause an analyst to incorrectly classify an internal lateral movement event as an external attack.

**Lesson:** SIEM enrichment output must always be critically evaluated. GeoIP data is unreliable for RFC 1918 addresses and should be corroborated with DHCP logs and asset inventory before being used as evidence.

---

## Custom Detection Rules Developed

### Rule File Location
`/var/ossec/etc/rules/local_rules.xml`

### Rule XML

```xml
<!-- Local rules -->
<group name="local_rules,">

  <rule id="100001" level="12" frequency="5" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_source_ip />
    <description>Brute Force Attack: 5+ failed Windows logons from same IP within 2 minutes</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,brute_force,</group>
  </rule>

  <rule id="100002" level="12" frequency="5" timeframe="120">
    <if_matched_sid>60104</if_matched_sid>
    <same_source_ip />
    <description>Brute Force Attack: 5+ RDP credential failures from same source within 2 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,brute_force,</group>
  </rule>

</group>
```

### Rule Logic Explained

| Parameter | Value | Meaning |
|---|---|---|
| `id` | 100001 / 100002 | Custom rules start at 100000 |
| `level` | 12 | High severity (Wazuh scale 0–15) |
| `frequency` | 5 | Triggers after 5 parent rule matches |
| `timeframe` | 120 | Within a 120-second window |
| `if_matched_sid` | 60122 / 60104 | Parent rules to correlate against |
| `same_source_ip` | — | Only counts failures from identical source IP |
| `mitre id` | T1110 / T1110.001 | MITRE ATT&CK technique and sub-technique |

> **Note:** Rule 100001 (`if_matched_sid: 60122`) catches both DC and Win-11 SMB attacks because both machines generate rule 60122 on failed logons. A single rule provides coverage across the entire domain.

### Validation & Deployment

```bash
# Validate rule syntax
sudo /var/ossec/bin/wazuh-logtest -t

# Restart manager to load new rules
sudo systemctl restart wazuh-manager

# Confirm running
sudo systemctl status wazuh-manager
```

> 📷 **Screenshot 7** — `local_rules.xml` open in nano showing both rules 100001 and 100002 correctly formatted.

> 📷 **Screenshot 8** — Wazuh Alerts view showing rule **100001** firing at Level 12 with description "Brute Force Attack: 5+ failed Windows logons from same IP within 2 minutes" and MITRE T1110 tag.

> 📷 **Screenshot 9** — Wazuh Alerts view showing rule **100002** firing at Level 12 with MITRE T1110.001 tag.

---

## Findings & Analysis

### Attack Pattern Summary

| Indicator | Value | Significance |
|---|---|---|
| Total events generated | 579 (Sep 24 session) | High-volume attack clearly distinguishable |
| Attack duration | ~17 seconds (14:02:27 – 14:02:44) | Automated tool — human attacker would be slower |
| Source IP consistency | 100% from 192.2.42.156 | Classic single-source brute force |
| Protocols targeted | SMB (445) + RDP (3389) | Common ransomware entry vectors |
| Accounts targeted | Single account (jay) | Targeted brute force vs password spray |
| Authentication method | NTLM | Legacy protocol — should be restricted in production |

### What Made This Attack Detectable

1. **Volume** — 579 events in one day, with a dense cluster within 17 seconds, is anomalous against any normal baseline
2. **Speed** — Sub-second intervals between failures are impossible for a human — automated tool signature
3. **Source IP consistency** — All failures from the same IP within a tight timeframe
4. **Protocol** — NTLM over SMB from a non-server workstation is unusual in a modern domain environment
5. **Workstation name** — `kali` appearing as a workstation name is itself suspicious in a corporate environment

### What This Attack Could Lead To (Real-World Impact)

Had the attacker successfully authenticated in a real environment:
- **Lateral movement** via SMB using recovered credentials (PsExec, WMI)
- **Ransomware deployment** — RDP and SMB are the two most common ransomware entry vectors
- **Data exfiltration** using domain account access
- **Privilege escalation** if `jay` had elevated AD group membership

---

## Recommended Response Actions

| Priority | Action |
|---|---|
| **Immediate** | Block source IP 192.2.42.156 at perimeter firewall |
| **Immediate** | Disable account `jay` pending investigation |
| **Urgent** | Check Event ID 4624 — did attacker achieve successful logon? |
| **Urgent** | Review all systems for lateral movement from 192.2.42.156 |
| **High** | Force password reset on `jay` and all accounts in same OU |
| **High** | Check for account lockout (Event ID 4740) — determine lockout policy threshold |
| **Medium** | Review whether NTLM should be restricted via Group Policy |
| **Medium** | Restrict RDP access to approved management IPs only |
| **Follow-up** | Escalate to Tier 2 if successful logon (4624) confirmed |
| **Post-incident** | Update firewall rules to rate-limit SMB and RDP from non-server IPs |

---

## Skills Mapped to SOC Analyst Job Requirements

| Job Requirement | Evidence from This Project |
|---|---|
| Monitoring security systems — SIEM, EDR, XDR | Monitored Wazuh in real time during live attack, triaged 579 events |
| Identifying anomalies and potential breaches | Identified brute force pattern from event volume, speed, and source IP consistency |
| Performing end-to-end lifecycle of security incidents | Detected, analysed, correlated, and documented a full attack sequence |
| Proactively detecting and responding to threats | Wrote custom rules to detect future attacks before they succeed |
| SIEM log collection and analysis | Parsed Windows event fields (targetUserName, ipAddress, logonType, status codes) |
| Scripting — PowerShell | Used PowerShell to enable RDP and firewall rules on Windows 11 |
| MITRE ATT&CK knowledge | Mapped detections to T1110 and T1110.001 at sub-technique level |
| Applying expertise and advanced technologies | Deployed and validated custom Wazuh correlation rules in production config |

---

## Evidence Index

| Screenshot | Description |
|---|---|
| Screenshot 1 | Wazuh event list — 4625 flood on Win-Server, rules 60104 and 60122 |
| Screenshot 2 | Expanded 4625 event detail — DC, full field breakdown |
| Screenshot 3 | Event ID 4624 (Logon Success) appearing after credential recovered |
| Screenshot 4 | Event ID 4776 on Win-11 — RDP local credential validation |
| Screenshot 5 | Event ID 4625 on Win-11 — SMB failure, firedtimes 28 |
| Screenshot 6 | Rule 60204 "Multiple Windows Logon Failures" Level 10 — MITRE T1110 |
| Screenshot 7 | `local_rules.xml` in nano — both custom rules visible |
| Screenshot 8 | Wazuh alert — custom rule 100001 firing at Level 12 |
| Screenshot 9 | Wazuh alert — custom rule 100002 firing at Level 12 |

> All screenshots are located in the [`/screenshots`](./screenshots/) folder of this repository.

---

*Part of the [SOC Home Lab Portfolio](../README.md) by Mojaki Tjeeka*
