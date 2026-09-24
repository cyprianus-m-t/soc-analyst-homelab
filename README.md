# soc-analyst-homelab

## Overview
A hands-on Security Operations Centre (SOC) home lab built to simulate 
real-world threat detection, analysis, and incident response scenarios. 
All attacks are performed in an isolated VMware environment.

## Lab Environment

| Machine | Role | IP |
|---|---|---|
| Ubuntu Server | Wazuh SIEM/XDR | 192.2.42.141 |
| Windows Server 2022 | Domain Controller (AD DS) | 192.2.42.136 |
| Windows 11 | Monitored Endpoint (domain-joined) | 192.2.42.137 |
| Kali Linux | Attacker Machine (on a seperate host)| 192.2.42.156 |

**Network:** VMware bridged — 192.2.42.0/24  
**SIEM:** Wazuh (open-source XDR/SIEM)  
**Detection method:** Defender-side only — no agent on attacker machine, 
mirroring real SOC visibility constraints

## Projects

| # | Project | Skills Demonstrated |
|---|---|---|
| 1 | [SIEM Setup & Log Ingestion](./project-1-siem-setup/) | SIEM deployment, log pipeline validation, audit policy |
| 2 | [Brute Force Detection](./project-2-brute-force/) | Attack simulation, custom rule writing, MITRE ATT&CK mapping |
| 3 | [Active Directory Attack Detection](./project-3-ad-attacks/) | AD security, privilege escalation detection, log analysis |
| 4 | [Threat Hunting](./project-4-threat-hunting/) | Proactive hunting, Wazuh queries, lateral movement detection |
| 5 | [Incident Response Simulation](./project-5-incident-response/) | Full IR lifecycle, forensic preservation, IR report writing |

## Tools & Technologies
- Wazuh SIEM/XDR
- Windows Server 2012 / Active Directory
- Kali Linux / Hydra / Nmap
- VMware Workstation
- MITRE ATT&CK Framework
- NIST SP 800-61 Incident Response Framework

## Author
**Mojaki Tjeeka**  
BSc (Hons) Computing — Networking & Infrastructure Management  
Certified in — Cyber Threat Management , Junior Cybersecurity Analyst Career Path Exam

mojakitjeeka@gmail.com
