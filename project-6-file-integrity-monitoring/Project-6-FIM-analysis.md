# FIM ALERT ANALYSIS
## File Integrity Monitoring — Violation Detection and Analyst Response
### Incident Reference: FIM-2026-1009-001
### Report Classification: INTERNAL — RESTRICTED
### Report Version: 1.0 FINAL

---

| Field | Detail |
|---|---|
| **Reference** | FIM-2026-1009-001 |
| **Report Date** | 2026-10-09 |
| **Report Author** | Mojaki Tjeeka, SOC Analyst L1 |
| **Monitored Asset** | WIN-SERVER (192.2.42.136) — Windows Server 2012 R2 |
| **FIM Tool** | Wazuh syscheck module |
| **Directories Monitored** | C:\SensitiveData, C:\Windows\System32, C:\Windows\SysWOW64, C:\Program Files |
| **Framework** | NIST SP 800-53 SI-7 |
| **Status** | CLOSED — REMEDIATED |

---

## 1. EXECUTIVE SUMMARY

On **09 October 2026**, Wazuh's File Integrity Monitoring (syscheck) module detected three file system violations on the WIN-SERVER domain controller across a 30-minute window (11:35–12:08 UTC+2). Two violations were confirmed as P1 Critical incidents; one was confirmed as a false positive.

| # | Alert | Verdict | Severity |
|---|---|---|---|
| A | salary_data.txt content modified | TRUE POSITIVE | P2 — HIGH |
| B | db_config.txt deleted | TRUE POSITIVE | P1 — CRITICAL |
| C | DFSR registry key mtime updated | FALSE POSITIVE | Noise (L5) |
| D | svchost_helper.ps1 dropped in System32 | TRUE POSITIVE | P1 — CRITICAL |

All confirmed violations were remediated on the same day. The database credentials contained in the deleted `db_config.txt` were treated as compromised and rotated. The malicious script was removed and a hash was preserved as evidence.

---

## 2. FIM CONFIGURATION SUMMARY

Syscheck was enabled in `ossec.conf` on the Wazuh agent running on WIN-SERVER with the following key parameters:

| Parameter | Value | Effect |
|---|---|---|
| `disabled` | no | FIM active |
| `frequency` | 300 | Scheduled scan every 5 minutes |
| `check_all` | yes | MD5, SHA1, SHA256, size, permissions, owner, mtime all monitored |
| `report_changes` | yes | File content diff stored in syscheck.diff field |
| `realtime` | yes | Windows filesystem events trigger immediate alerts (vs. scheduled-only) |

**Monitored paths:**
- `C:\Windows\System32` — catch malicious files masquerading as system components
- `C:\Windows\SysWOW64` — 32-bit system directory (same risk surface)
- `C:\Program Files` — catch unauthorised software installation
- `C:\SensitiveData` — custom path for simulated high-value data files

---

## 3. BASELINE ESTABLISHMENT

**Date/Time:** 09 October 2026, 11:16–11:18 UTC+2

Three files were created in `C:\SensitiveData` to represent sensitive organisational data:

| File | Size (bytes) | MD5 (baseline) | Content |
|---|---|---|---|
| salary_data.txt | 106 | 7fd1809c30276ba2802a92eec854f755 | Employee payroll — CONFIDENTIAL |
| customer_accounts.txt | 108 | (not modified in simulation) | Customer PII — CONFIDENTIAL |
| db_config.txt | 116 | (captured at deletion) | DB credentials — CONFIDENTIAL |

Wazuh's first scheduled scan indexed these files. Two Rule 594 registry events fired at 11:35 and 11:41 — these were baseline registry activity (see Section 5.C).

---

## 4. ALERT TIMELINE

All timestamps UTC+2 (Africa/Johannesburg).

| Time | Rule | Level | Description | Verdict |
|------|------|-------|-------------|---------|
| 11:35:11 | 594 | 5 | Registry Key Integrity Checksum Changed (DFSR) | FALSE POSITIVE |
| 11:41:32 | 594 | 5 | Registry Key Integrity Checksum Changed (DFSR) | FALSE POSITIVE |
| 11:53:32 | 550 | 7 | Integrity checksum changed — salary_data.txt | TRUE POSITIVE (A) |
| 11:53:53 | 594 | 5 | Registry Key Integrity Checksum Changed (DFSR) | FALSE POSITIVE |
| 11:56:42 | 550 | 7 | Integrity checksum changed — salary_data.txt (2nd detection) | TRUE POSITIVE (A) |
| 11:58:00 | 553 | 7 | File deleted — db_config.txt | TRUE POSITIVE (B) |
| 12:00:38 | 594 | 5 | Registry Key Integrity Checksum Changed | FALSE POSITIVE |
| 12:08:05 | 594 | 5 | Registry Key Integrity Checksum Changed | FALSE POSITIVE |

*Note: Scenario C (svchost_helper.ps1 dropped in System32) aligns with the file-added events in the feed — confirmed by the 7-hit view.*

---

## 5. ALERT TRIAGE — DETAILED ANALYSIS

### 5.A — salary_data.txt Modified (TRUE POSITIVE — P2 HIGH)

**Wazuh event fields (from Document Details):**

| Field | Value |
|---|---|
| rule.description | Integrity checksum changed. |
| rule.id | 550 |
| rule.level | 7 |
| decoder.name | syscheck_integrity_changed |
| syscheck.event | modified |
| syscheck.mode | realtime |
| syscheck.path | c:\sensitivedata\salary_data.txt |
| syscheck.size_before | 204 |
| syscheck.size_after | 302 |
| syscheck.changed_attributes | size, mtime, md5, sha1, sha256 |
| syscheck.md5_before | 7fd1809c30276ba2802a92eec854f755 |
| syscheck.md5_after | 1327336c0e8f8f703b1623f37dd7880f |
| syscheck.sha1_before | 636ba72c6f52525bcf9a9221dd850e799f362538 |
| syscheck.sha1_after | 722e1ed7a9aaea67e4c2267b055596b212b3466a |
| syscheck.diff | diff output confirming new line appended |
| rule.mitre.id | T1565.001 |
| rule.mitre.tactic | Impact |
| rule.mitre.technique | Stored Data Manipulation |

**Analysis:**

Five independent integrity attributes changed simultaneously (size, mtime, md5, sha1, sha256) — this eliminates any metadata-only explanation. The `syscheck.diff` field shows the appended content, and the file grew by 98 bytes (204 → 302). In a real environment, the next step would be to query Windows Security Event ID 4663 (file object access audit) on this file at 11:53 UTC+2 to identify which account performed the write.

**False positive check:** Could this be a legitimate admin action? No authorised change request exists for payroll data at this time. The content added (`ACCOUNT MODIFIED BY ATTACKER - SALARY INFLATED`) is clearly unauthorised. TRUE POSITIVE confirmed.

**MITRE mapping:** T1565.001 — Stored Data Manipulation. An attacker modifying financial records could be attempting fraud, inflating their own salary, or planting false evidence.

**Remediation action:**
```powershell
Set-Content "C:\SensitiveData\salary_data.txt" "CONFIDENTIAL: Employee salary data - DO NOT MODIFY"
```
File restored to original content. Recommend implementing file access auditing (Event ID 4663) on C:\SensitiveData to identify the writing account in future.

---

### 5.B — db_config.txt Deleted (TRUE POSITIVE — P1 CRITICAL)

**Wazuh event fields (from Document Details):**

| Field | Value |
|---|---|
| rule.description | File deleted. |
| rule.id | 553 |
| rule.level | 7 |
| decoder.name | syscheck_deleted |
| syscheck.event | deleted |
| syscheck.mode | realtime |
| syscheck.path | c:\sensitivedata\db_config.txt |
| syscheck.md5_after | c3c5ba7b36cba6766f99f5a556aad629 |
| syscheck.sha1_after | 88987bfec065ec7f8d8fc2e796ad8c3110563a80 |
| syscheck.sha256_after | 98b91c6cdcd72597018f9fce371369446571eefa53948e351a326ec2d3df5f40 |
| syscheck.size_after | 116 |
| syscheck.uname_after | Administrators |
| syscheck.attrs_after | ARCHIVE |
| rule.mitre.id | T1070.004, T1485 |
| rule.mitre.tactic | Defense Evasion, Impact |
| rule.mitre.technique | File Deletion, Data Destruction |

**Analysis:**

Two separate MITRE tactics present in a single event:

- **T1070.004 — File Deletion (Defence Evasion):** The attacker deleted the config file to remove evidence of the credentials they accessed or exfiltrated.
- **T1485 — Data Destruction (Impact):** Deleting an operational configuration file disrupts the service depending on those database credentials.

Wazuh preserved the final MD5/SHA1/SHA256 hashes of the deleted file. In a real investigation, these hashes could be used to:
- Confirm the file was not modified before deletion (i.e., original content was accessed)
- Search for copies of the file on other hosts (lateral movement evidence)
- Match the file against known malicious hash databases

**Credential exposure assessment:** The file contained `DB_PASS=P@ssw0rd123` in plaintext. Regardless of whether the attacker read the file before deleting it, the credentials must be treated as compromised.

**Remediation action:**
```powershell
# Immediate: rotate database credentials
# Recreate config with new credentials
"Configuration: DB_HOST=192.2.42.136 DB_PASS=<ROTATED>" | Out-File "C:\SensitiveData\db_config.txt"
```
Credential rotation should be completed before service restoration.

---

### 5.C — DFSR Registry Key Modified (FALSE POSITIVE — NOISE)

**Wazuh event fields:**

| Field | Value |
|---|---|
| rule.description | Registry Key Integrity Checksum Changed |
| rule.id | 594 |
| rule.level | 5 |
| decoder.name | syscheck_registry_key_modified |
| syscheck.event | modified |
| syscheck.mode | scheduled |
| syscheck.changed_attributes | mtime (only) |
| syscheck.path | HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DFSR\Access Checks\Replication Groups\342E0399-835D-4308-924D-67D5C0FB17C4 |

**Analysis:**

Only the `mtime` attribute changed — there is no data modification. The key belongs to the Windows **Distributed File System Replication (DFSR)** service, which is responsible for replicating SYSVOL and other shared content across domain controllers. DFSR updates its internal access-check registry entries as part of normal AD replication heartbeat activity.

This is expected background noise that Wazuh captures because we configured broad monitoring of `%WINDIR%\SysNative` and `%WINDIR%\System32` (which includes registry paths under HKLM\System\...). It is not malicious.

**Analyst action — noise suppression recommendation:**
```xml
<!-- Add to ossec.conf syscheck block -->
<ignore type="sregex">HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\DFSR</ignore>
```

This false positive illustrates a key FIM tuning principle: **broad monitoring generates noise; targeted monitoring generates signal.** The DFSR alert fired five times during the session — in production, this would create alert fatigue. Suppressing known-benign registry paths after a baseline observation period is standard FIM hygiene.

---

### 5.D — svchost_helper.ps1 Dropped in System32 (TRUE POSITIVE — P1 CRITICAL)

**Simulated attack:**
```powershell
"powershell -enc JABjAGwAaQBlAG4AdA..." | Out-File "C:\Windows\System32\svchost_helper.ps1"
```

**Analysis:**

The threat actor dropped a script named `svchost_helper.ps1` into `C:\Windows\System32`. Two evasion techniques are in play:

1. **T1036.005 — Masquerading (Match Legitimate Name):** The name `svchost_helper` mimics `svchost.exe`, the legitimate Windows Service Host process. A cursory inspection of running processes or file listings might overlook it.

2. **Base64-encoded payload:** The `powershell -enc` prefix indicates the script's content is Base64-encoded, which is a common obfuscation technique to bypass signature-based detection and make the payload less readable to human analysts.

FIM detected this because `C:\Windows\System32` is in our monitored directory list. The alert generated a "file added" or "integrity checksum changed" event — confirming that new file creation in System32 is caught in near-real time.

**Remediation action:**
```powershell
Remove-Item "C:\Windows\System32\svchost_helper.ps1" -Force
Test-Path "C:\Windows\System32\svchost_helper.ps1"
# Expected: False
```

**Additional recommended action:** Decode the Base64 content for malware analysis:
```powershell
$encoded = "JABjAGwAaQBlAG4AdA..."
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```
In a real incident, the decoded payload would be submitted to a malware sandbox (Any.run, VirusTotal) and the hash added to the SIEM as a threat intelligence IOC.

---

## 6. MITRE ATT&CK MAPPING

| Tactic | Technique | Sub-technique | Alert |
|---|---|---|---|
| Impact | T1565 — Data Manipulation | T1565.001 — Stored Data Manipulation | salary_data.txt modified |
| Defence Evasion | T1070 — Indicator Removal | T1070.004 — File Deletion | db_config.txt deleted |
| Impact | T1485 — Data Destruction | — | db_config.txt deleted |
| Defence Evasion | T1036 — Masquerading | T1036.005 — Match Legitimate Name | svchost_helper.ps1 in System32 |

---

## 7. INDICATORS OF COMPROMISE (IOCs)

| IOC Type | Value | Context |
|---|---|---|
| File path | c:\sensitivedata\salary_data.txt | Modified — size 204→302 bytes |
| File hash (modified) | MD5: 1327336c0e8f8f703b1623f37dd7880f | Post-tamper hash of salary file |
| File path | c:\sensitivedata\db_config.txt | Deleted — credentials exposed |
| File hash (deleted) | MD5: c3c5ba7b36cba6766f99f5a556aad629 | Final hash before deletion |
| File path | C:\Windows\System32\svchost_helper.ps1 | Malicious script staged |
| File content | `powershell -enc JABjAGwAaQBlAG4AdA...` | Base64-encoded PowerShell payload |

---

## 8. RESPONSE ACTIONS TAKEN

| Action | Status |
|---|---|
| salary_data.txt restored to original content via Set-Content | ✅ Complete |
| db_config.txt recreated; database credentials rotated | ✅ Complete |
| svchost_helper.ps1 removed from System32; Test-Path confirms False | ✅ Complete |
| C:\SensitiveData verified at 3-file baseline state | ✅ Complete |
| DFSR ignore rule recommended for ossec.conf | ⚠️ Recommended (pending implementation) |
| Windows file access auditing (Event 4663) recommended for C:\SensitiveData | ⚠️ Recommended (pending implementation) |

---

## 9. LESSONS LEARNED

### What FIM caught immediately

All three true-positive violations were detected **within seconds** using realtime mode. The `report_changes` option provided file content diffs that removed ambiguity — the analyst could confirm exactly what changed without needing access to the original file. Hash preservation at deletion time (db_config.txt) is particularly valuable: even after the file is gone, Wazuh retains the forensic fingerprint.

### What required tuning

The Level 5 DFSR registry alerts (Rule 594) generated five events during the session. In production with hundreds of endpoints, this would scale to thousands of events per day — creating alert fatigue that could cause analysts to miss genuine violations buried in the noise. A post-baseline suppression phase is essential for production FIM deployments.

### Detection gaps

**No alerting on who made the change.** Wazuh FIM tells you *what* changed, not *who* changed it. To close this gap, Windows file object auditing (System ACL — SACL) must be enabled on monitored directories so that Event ID 4663 (file access) is generated and forwarded to Wazuh alongside the FIM events. Correlating the 4663 logon account with the FIM syscheck.path provides a full who-what-when picture.

### Recommended improvements

| Gap | Recommendation | Priority |
|---|---|---|
| DFSR registry noise | Add sregex ignore rule for DFSR registry paths | HIGH |
| No file access attribution | Enable SACL auditing on C:\SensitiveData; forward Event 4663 to Wazuh | HIGH |
| FIM Level 7 not paging SOC | Confirm Wazuh manager alert threshold is ≤ 7 for file modified/deleted events | MEDIUM |
| No automated response | Add active response playbook: FIM alert on SensitiveData → auto-disable writing account pending review | LOW |

---

## 10. CLOSURE STATEMENT

FIM case **FIM-2026-1009-001** is hereby **CLOSED**.

All confirmed violations have been remediated. Database credentials have been rotated. The malicious script has been removed. The `C:\SensitiveData` directory has been restored to its known-good baseline state.

This exercise validates that Wazuh's realtime FIM provides rapid, hash-accurate detection of sensitive file changes with actionable alert context (content diffs, before/after hashes, MITRE mapping). The false positive analysis demonstrates the analyst judgment required to separate genuine incidents from expected system activity.

---

**Signed:** Mojaki Tjeeka, SOC Analyst L1  
**Date:** 2026-10-09  
**Report Status:** FINAL

---

*Generated as part of CCLabs SOC Portfolio — Project 6: File Integrity Monitoring*
