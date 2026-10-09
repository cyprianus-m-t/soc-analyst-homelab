# Project 6 — File Integrity Monitoring (FIM)

> **Status:** Complete ✅
> **Difficulty:** Intermediate
> **Duration:** ~1 day (09 Oct 2026)
> **Framework:** NIST SP 800-53 SI-7 (Software, Firmware, and Information Integrity)
> **Tool:** Wazuh syscheck module

---

## Overview

This project configures and validates **File Integrity Monitoring** on the Windows Server domain controller using Wazuh's built-in syscheck module. FIM is a core detective control in any SOC environment — it detects unauthorised file modifications, deletions, and suspicious files dropped into sensitive directories in real time.

Three violation scenarios were simulated to produce realistic alert data for analyst triage:

- **Scenario A** — Sensitive financial file modified (data tampering)
- **Scenario B** — Database configuration file deleted (data destruction / credential exposure)
- **Scenario C** — Malicious script dropped in System32 (malware staging)

Each alert was triaged using a structured analyst workflow: false positive vs. true positive decision, severity rating, MITRE mapping, and documented remediation action.

---

## Environment

| Component | Details |
|---|---|
| SIEM / FIM Engine | Wazuh 4.x — 192.2.42.142 (Ubuntu Server) |
| Monitored Host | WIN-SERVER — 192.2.42.136 (Windows Server 2012 R2) |
| Domain | cclabs.local |
| Monitored Directories | C:\SensitiveData, C:\Windows\System32, C:\Windows\SysWOW64, C:\Program Files |

---

## FIM Configuration

Wazuh syscheck was configured on WIN-SERVER by editing `ossec.conf` (C:\Program Files (x86)\ossec-agent\ossec.conf):

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <directories check_all="yes" report_changes="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">C:\Windows\SysWOW64</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">C:\Program Files</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">C:\SensitiveData</directories>
</syscheck>
```

Key options:
- `check_all="yes"` — computes and stores MD5, SHA1, SHA256 hashes plus file metadata (size, permissions, owner, mtime) for all monitored files
- `report_changes="yes"` — captures a diff of file content changes (visible in `syscheck.diff` field in Wazuh)
- `realtime="yes"` — uses Windows inotify-equivalent to alert within seconds of a change, rather than waiting for the next scheduled scan

After config change: `Restart-Service -Name "Wazuh"` confirmed agent status: **Running**.

---

## Baseline Establishment

Three baseline files created in `C:\SensitiveData` (09 Oct 2026, 11:16–11:18 UTC+2):

```powershell
New-Item -ItemType Directory -Path "C:\SensitiveData"
"CONFIDENTIAL: Employee salary data - DO NOT MODIFY"  | Out-File "C:\SensitiveData\salary_data.txt"
"CONFIDENTIAL: Customer account list - DO NOT MODIFY" | Out-File "C:\SensitiveData\customer_accounts.txt"
"Configuration: DB_HOST=192.2.42.136 DB_PASS=P@ssw0rd123" | Out-File "C:\SensitiveData\db_config.txt"
```

| File | Size at Baseline | Purpose |
|---|---|---|
| salary_data.txt | 106 bytes | Simulated HR payroll data |
| customer_accounts.txt | 108 bytes | Simulated customer PII |
| db_config.txt | 116 bytes | Simulated plaintext database credentials |

Wazuh's first scheduled scan (frequency: 300s) indexed these files and stored their baseline hashes. Two Rule 594 "Registry Key Integrity Checksum Changed" events fired during baseline — these are expected Windows DFSR registry activity (see Alert Triage section).

---

## Violation Simulations

### Scenario A — File Modification (Data Tampering)

```powershell
Add-Content "C:\SensitiveData\salary_data.txt" "`nACCOUNT MODIFIED BY ATTACKER - SALARY INFLATED"
```

Simulates an insider threat or compromised account modifying payroll data.

**Wazuh detection:** Rule 550 — "Integrity checksum changed" — Level 7  
**Mode:** realtime (alert within seconds)  
**MITRE:** T1565.001 — Stored Data Manipulation

### Scenario B — File Deletion (Data Destruction / Credential Exposure)

```powershell
Remove-Item "C:\SensitiveData\db_config.txt" -Force
```

Simulates an attacker deleting a config file containing database credentials — both destroying operational data and covering their access to the credentials.

**Wazuh detection:** Rule 553 — "File deleted" — Level 7  
**Mode:** realtime  
**MITRE:** T1070.004 (File Deletion) + T1485 (Data Destruction)

### Scenario C — Malicious File Dropped in System32

```powershell
"powershell -enc JABjAGwAaQBlAG4AdA..." | Out-File "C:\Windows\System32\svchost_helper.ps1"
```

Simulates a threat actor staging a Base64-encoded PowerShell payload in System32, masquerading as a legitimate system process component.

**Wazuh detection:** Rule 550/554 — "Integrity checksum changed" / "File added" — Level 7  
**Mode:** realtime  
**MITRE:** T1036.005 (Masquerading — Match Legitimate Name or Location)

---

## Alert Triage

| Alert | File | Rule | Level | Decision | Severity |
|---|---|---|---|---|---|
| Integrity checksum changed | c:\sensitivedata\salary_data.txt | 550 | 7 | ✅ TRUE POSITIVE | P2 — HIGH |
| File deleted | c:\sensitivedata\db_config.txt | 553 | 7 | ✅ TRUE POSITIVE | P1 — CRITICAL |
| Registry Key Integrity Checksum Changed | HKLM\...\DFSR\... | 594 | 5 | ❌ FALSE POSITIVE | Noise |
| File added / checksum changed | C:\Windows\System32\svchost_helper.ps1 | 550/554 | 7 | ✅ TRUE POSITIVE | P1 — CRITICAL |

### Alert A — salary_data.txt (P2 HIGH — TRUE POSITIVE)

**Evidence from Wazuh:**
- `syscheck.event`: modified
- `syscheck.size_before`: 204 | `syscheck.size_after`: 302 (98 bytes appended)
- `syscheck.md5_before`: `7fd1809c30276ba2802a92eec854f755`
- `syscheck.md5_after`: `1327336c0e8f8f703b1623f37dd7880f`
- `syscheck.diff`: diff output confirms new line appended
- `syscheck.changed_attributes`: size, mtime, md5, sha1, sha256

**Analyst reasoning:** All five integrity attributes changed simultaneously — this is a genuine file modification, not a metadata-only timestamp update. The file content diff confirms new data was appended. No change management ticket exists for payroll data at this time. The file owner field (Administrators) does not narrow down which account performed the write — further investigation would query Windows Security logs for Event ID 4663 (file access audit) on this file at the time of modification.

**Remediation:**
```powershell
# Restore from backup (simulated)
Set-Content "C:\SensitiveData\salary_data.txt" "CONFIDENTIAL: Employee salary data - DO NOT MODIFY"
```

### Alert B — db_config.txt (P1 CRITICAL — TRUE POSITIVE)

**Evidence from Wazuh:**
- `syscheck.event`: deleted
- `decoder.name`: syscheck_deleted
- `full_log`: `File 'c:\sensitivedata\db_config.txt' deleted Mode: realtime`
- `syscheck.md5_after`: `c3c5ba7b36cba6766f99f5a556aad629` (hash of deleted file preserved)
- `syscheck.path`: c:\sensitivedata\db_config.txt
- MITRE: T1070.004 + T1485

**Analyst reasoning:** Two MITRE tactics present simultaneously: the attacker deleted both evidence of the credential file AND the operational data itself. Because the file contained `DB_HOST` and `DB_PASS` in plaintext, the database credentials must be treated as compromised regardless of whether the file was read before deletion. Wazuh preserved the final file hash — this could be used to confirm file identity if a copy were found elsewhere on the network.

**Remediation:**
```powershell
# Recreate from backup (simulated); rotate DB credentials immediately
"Configuration: DB_HOST=192.2.42.136 DB_PASS=<NEW_PASSWORD>" | Out-File "C:\SensitiveData\db_config.txt"
# In a real environment: change database password, audit all services using old credentials
```

### Alert C — DFSR Registry Key (FALSE POSITIVE — EXPECTED NOISE)

**Evidence from Wazuh:**
- Rule 594, Level 5
- `decoder.name`: syscheck_registry_key_modified
- `syscheck.changed_attributes`: mtime (only — no data change)
- Key: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DFSR\Access Checks\Replication Groups\...`
- Mode: scheduled (not realtime)

**Analyst reasoning:** Only the `mtime` attribute changed — no content modification. This registry key belongs to the Windows Distributed File System Replication service, which updates its internal access-check registry entries as part of normal AD domain replication. This is expected background activity that Wazuh monitors as part of the broad `%WINDIR%\System32` directory scope. A dedicated ignore rule would suppress this noise.

**Recommended suppression:**
```xml
<!-- Add to ossec.conf syscheck block on Win-Server -->
<ignore type="sregex">HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\DFSR</ignore>
```

### Alert D — svchost_helper.ps1 in System32 (P1 CRITICAL — TRUE POSITIVE)

- Malicious script staging in System32 to blend with legitimate Windows binaries
- Name `svchost_helper.ps1` mimics the legitimate `svchost.exe` process
- Base64-encoded payload indicates obfuscated command intent
- MITRE: T1036.005 — Masquerading (Match Legitimate Name or Location)

**Remediation:**
```powershell
Remove-Item "C:\Windows\System32\svchost_helper.ps1" -Force
Test-Path "C:\Windows\System32\svchost_helper.ps1"
# Expected: False
```

---

## Remediation Results

### Post-remediation verification

```powershell
# Confirm SensitiveData is restored to baseline state
Get-ChildItem "C:\SensitiveData" | Select Name, Length, LastWriteTime

# Confirm malicious file removed
Test-Path "C:\Windows\System32\svchost_helper.ps1"
```

Expected output:
- `salary_data.txt` — restored
- `customer_accounts.txt` — unchanged (not modified in simulation)
- `db_config.txt` — recreated
- `Test-Path` → `False`

---

## Deliverables

| File | Description |
|---|---|
| `FIM-ALERT-ANALYSIS.md` | Full analyst triage write-up — the primary document |
| `screenshots/001-ossec-conf-syscheck.png` | ossec.conf with syscheck block configured |
| `screenshots/002-baseline-creation.png` | C:\SensitiveData created; 3 baseline files confirmed |
| `screenshots/003-agent-restart.png` | Wazuh agent restarted; Status: Running |
| `screenshots/004-wazuh-baseline-scan.png` | Wazuh — initial 2 registry hits; baseline scan in progress |
| `screenshots/005-wazuh-scenario-a-fires.png` | Wazuh — rule 550 fires; Scenario A (salary_data modified) detected |
| `screenshots/006-wazuh-scenario-b-fires.png` | Wazuh — rule 553 fires; Scenario B (db_config deleted) detected |
| `screenshots/007-wazuh-5hits.png` | Wazuh — 5 hits; all scenarios accumulating |
| `screenshots/008-wazuh-7hits-full-feed.png` | Wazuh — 7 hits; complete FIM event feed |
| `screenshots/009-detail-registry-event.png` | Document Details — registry key modified (Rule 594; DFSR key) |
| `screenshots/010-detail-registry-mitre.png` | Document Details — MITRE T1565.001 + T1112 for registry event |
| `screenshots/011-detail-file-deleted.png` | Document Details — db_config.txt deleted (Rule 553; realtime; T1070.004 + T1485) |
| `screenshots/012-detail-file-deleted-hashes.png` | Document Details — deleted file hashes preserved (md5/sha1/sha256) |
| `screenshots/013-detail-salary-modified.png` | Document Details — salary_data.txt modified; size 204→302; diff visible |
| `screenshots/014-detail-salary-hashes.png` | Document Details — salary_data hash comparison (md5/sha1/sha256 before/after) |
| `screenshots/015-detail-salary-path.png` | Document Details — salary_data.txt path and timestamp confirmed |
| `screenshots/016-remediation-system32.png` | PowerShell — svchost_helper.ps1 removed; Test-Path: False |
| `screenshots/017-remediation-sensitivedata.png` | PowerShell — C:\SensitiveData restored to 3-file baseline |

---

## Key Skills Demonstrated

- **FIM configuration** — enabling realtime monitoring with check_all and report_changes on Windows via Wazuh syscheck
- **Baseline establishment** — creating a known-good file state before testing for deviations
- **Alert triage** — distinguishing true positives (data tamper, deletion, malware staging) from false positives (DFSR registry noise)
- **Hash-based evidence** — using before/after MD5/SHA1/SHA256 to prove file integrity violation
- **MITRE ATT&CK mapping** — T1565.001, T1070.004, T1485, T1036.005
- **Remediation documentation** — structured response actions for each confirmed incident
- **Noise reduction** — identifying false positive patterns and writing targeted ignore rules

---

## Detection Engineering Insight

The DFSR registry alert (Rule 594, Level 5) demonstrates a real SOC challenge: FIM generates high volumes of **expected** system-change events that analysts must separate from genuine violations. In production, a Wazuh analyst would:

1. Run FIM for 1–2 weeks in **monitoring-only mode** before alerting on Level 5 events
2. Build a suppression list of known-noisy registry paths (DFSR, Windows Update, COM registration)
3. Tune Level thresholds so that Level 5 FIM events route to a low-priority queue, while Level 7+ (file modified/deleted) page the SOC

This project validates that **realtime FIM on sensitive directories (Level 7+)** provides actionable alerts with minimal tuning, while broad registry monitoring benefits from a noise-reduction phase first.

---

## Connection to Previous Projects

```
Projects 3–4 → Custom rules + threat hunting → AD compromise detected
    ↓
Project 5 → Full IR lifecycle → attacker created rogue accounts, modified AD
    ↓
Project 6 → FIM deployed → would have caught any file modifications made
             during the Project 5 compromise (e.g. config file tampering,
             persistence scripts dropped to disk)
```

FIM is the layer that catches **what the attacker touches after they land** — complementing the AD event monitoring in Projects 3–5.

---

*CCLabs SOC Portfolio | Mojaki Tjeeka | 2026*
