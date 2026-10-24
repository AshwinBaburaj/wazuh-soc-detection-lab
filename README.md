# Wazuh SOC Detection Lab

A personal homelab built to simulate a real-world SOC environment — covering SIEM deployment, log ingestion, custom detection engineering, and end-to-end attack simulation with full Wazuh alert validation.

---

## Lab Overview

| Component | Details |
|---|---|
| SIEM | Wazuh v4.14.7 (OVA — manager + indexer + dashboard) |
| Attacker | Kali Linux |
| Target | Metasploitable2 (vsftpd, Apache/DVWA, MySQL) |
| Monitored Host | Windows 11 (Wazuh agent) |
| Log Forwarding | rsyslog UDP/514 from Linux VMs → Wazuh manager |
| Anomaly Detection | OpenSearch anomaly detector (soc-lab-anomaly-detector) |

All IPs in documentation are masked (10.0.2.xxx / 192.168.56.xxx).

---

## Repository Structure

```
wazuh-soc-detection-lab/
├── README.md
├── reports/
│   ├── 01_Wazuh_SIEM_Setup_and_Configuration.pdf
│   ├── 02_Attack_Simulation_FTP_Brute_Force.pdf
│   ├── 03_Attack_Simulation_SQL_Injection_DVWA.pdf
│   └── 04_Attack_Simulation_URL_Fuzzing_Gobuster.pdf
└── rules/
    └── local_rules.xml
```

---

## Part 1 — SIEM Setup & Configuration

**Report:** `reports/01_Wazuh_SIEM_Setup_and_Configuration.pdf`

Covers the full deployment and tuning of the Wazuh homelab:

- OVA import and network configuration (NAT + Host-Only adapters)
- rsyslog UDP/514 forwarding from Kali and Metasploitable2
- Windows 11 agent enrollment and log collection
- Custom detection rules (IDs 100010–100016) covering SSH brute force, SSH compromise, and sudo privilege escalation
- MITRE ATT&CK tagging (T1110, T1078, T1548, T1021)
- OpenSearch anomaly detection configuration

---

## Part 2 — Attack Simulations

Each simulation follows the same structure: pre-attack baseline → attack execution → raw log verification → detection gap analysis → custom rule authoring → alert validation.

### 2.1 FTP Brute Force — Hydra vs Metasploitable2

**Report:** `reports/02_Attack_Simulation_FTP_Brute_Force.pdf`

| Field | Detail |
|---|---|
| Tool | Hydra v9.7 |
| Target | Metasploitable2 vsftpd (port 21) |
| Wordlist | rockyou.txt |
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Detection rule added | 100017 |

**Key finding:** The default Wazuh ruleset had no frequency-based FTP brute-force rule — raw PAM failures were captured but never escalated to a high-severity alert. Custom rule 100017 was written (frequency=5 in 120s, scoped to vsftpd via `program_name`) and validated by re-running Hydra against a non-existent account to guarantee sustained failures.

```xml
<rule id="100017" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5503</if_matched_sid>
  <program_name>vsftpd</program_name>
  <same_source_ip />
  <description>FTP brute force: 5 failed logins in 2 minutes</description>
</rule>
```

---

### 2.2 SQL Injection — DVWA via Burp Suite

**Report:** `reports/03_Attack_Simulation_SQL_Injection_DVWA.pdf`

| Field | Detail |
|---|---|
| Tool | Burp Suite Community Edition (Proxy + Repeater) |
| Target | DVWA on Metasploitable2 Apache/MySQL (SQLi module, security: Low) |
| Injection point | `id` GET parameter — `/dvwa/vulnerabilities/sqli/` |
| MITRE ATT&CK | T1190 — Exploit Public-Facing Application |
| Detection rule added | 100018 |

**Key finding:** Apache logs on Metasploitable2 could not be forwarded via rsyslog's `imfile` module (the module was missing from this build). Workaround: Apache's built-in piped-logging feature (`CustomLog`/`ErrorLog` piped through `logger`) routed traffic directly into the existing rsyslog forwarding chain — no Wazuh-side changes needed. Raw SQL injection payloads were confirmed in `wazuh-archives-*` before any custom rule was written.

---

### 2.3 URL/Directory Fuzzing — Gobuster vs Metasploitable2

**Report:** `reports/04_Attack_Simulation_URL_Fuzzing_Gobuster.pdf`

| Field | Detail |
|---|---|
| Tool | Gobuster v3.8.2 |
| Target | Metasploitable2 Apache web root |
| Wordlist | `/usr/share/wordlists/dirb/common.txt` (~4,600 entries + `.php` extension → 9,226 requests) |
| MITRE ATT&CK | T1595 — Active Scanning |
| Detection rule added | 100019 |

**Key finding:** Wazuh's built-in rule 31101 classifies individual 404s at level 5 — enough to capture events, but not enough to surface the volume signature of an automated scan as a high-severity alert. Custom rule 100019 (frequency=20 in 60s — tighter than the FTP/SSH rules to match fuzzing tool speed) escalated the volume to level 10. Gobuster's own user-agent string (`gobuster/3.8.2`) was also visible in raw request logs, providing an additional fingerprint.

```xml
<rule id="100019" level="10" frequency="20" timeframe="60">
  <if_matched_sid>31101</if_matched_sid>
  <same_source_ip />
  <description>Possible web directory/URL fuzzing: high-volume 404s from single source</description>
  <group>web,attack,recon,</group>
  <mitre>
    <id>T1595</id>
  </mitre>
</rule>
```

---

## Custom Detection Rules Summary

All rules live in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager.

| Rule ID | Description | MITRE | Level | Base Rule |
|---|---|---|---|---|
| 100010 | SSH brute force (5 failures in 120s) | T1110 | 10 | 5760 |
| 100011–100016 | SSH compromise, sudo escalation variants | T1078, T1548 | 10 | various |
| 100017 | FTP brute force — vsftpd (5 failures in 120s) | T1110.001 | 10 | 5503 |
| 100018 | SQL injection pattern in Apache access log | T1190 | 10 | 31108 |
| 100019 | URL fuzzing — high-volume 404s from single IP (20 in 60s) | T1595 | 10 | 31101 |

---

## What This Lab Demonstrates

- End-to-end SIEM deployment from OVA to production-ready monitoring
- Log pipeline engineering — including a non-standard workaround when standard log forwarding wasn't available
- Detection gap identification: running a real attack, observing what Wazuh *doesn't* alert on, then closing the gap
- Custom rule authoring following Wazuh's frequency/timeframe/same_source_ip pattern
- MITRE ATT&CK mapping across credential access (T1110), web exploitation (T1190), and reconnaissance (T1595)
- Alert validation methodology — re-running attacks against controlled conditions to confirm rules fire deterministically

---

## Tools & Technologies

`Wazuh v4.14.7` `OpenSearch` `Kali Linux` `Metasploitable2` `Windows 11`  
`Hydra` `Burp Suite` `Gobuster` `rsyslog` `vsftpd` `Apache` `MySQL/DVWA`

---

*Built as a personal SOC homelab project. All attack simulations were conducted in an isolated virtual environment against intentionally vulnerable targets.*
