# Detection Lab Journey

My cybersecurity homelab documenting my path to Detection Engineer.

## Lab Setup (January 2026)
- **Hypervisor:** Proxmox on Dell R720
- **SIEM:** Wazuh v4.14.2
- **Target Systems:**
  - Windows 11 with Sysmon (Custom Configuration from SwiftOnSecurity)
  - Debian Linux
- **Attack Simulation:** Atomic Red Team
- **AD Environment:** GOAD-Light (Game of Active Directory)
  - **Domain:** `sevenkingdoms.local`
  - **Child Domain:** `north.sevenkingdoms.local`

## Infrastructure

| Hostname | Role | OS | IP | Status | Agent Name |
|----------|------|----|----|--------|------------|
| **Wazuh-Server** | SIEM / Manager | Amazon Linux 2023 | `10.10.0.154` | 🟢 Active | `wazuh-server` |
| **Win11-Target** | Workstation Target | Windows 11 | `10.10.0.156` | 🟢 Active | `win11-agent` |
| **Debian-Target** | Attack Box / Target | Debian 12 | `DHCP` | 🟢 Active | `debian-agent` |
| **DC01** | Forest Root DC (KingsLanding) | Windows Server 2019 | `10.10.0.61` | 🟢 Active | `DC01-KingsLanding` |
| **DC02** | Child Domain DC (Winterfell) | Windows Server 2019 | `10.10.0.56` | 🟢 Active | `DC02-Winterfell` |
| **SRV02** | Member Server (CastelBlack) | Windows Server 2019 | `10.10.0.64` | 🟢 Active | `SRV02-CastelBlack` |

## Detection Rules

| Rule ID | Name | MITRE ATT&CK | Status |
|---------|------|--------------|--------|
| 100001 | Mimikatz Detection (filename) | T1003 | ✅ Tested |
| 100002 | Mimikatz Detection (cmdline) | T1003 | ✅ Tested |
| 100003 | Encoded PowerShell Commands | T1059.001 | ✅ Tested |
| 100004 | PowerShell Download Cradle | T1059.001 | ⬜ Untested |
| 100005 | Local Account Creation | T1136.001 | ✅ Tested |
| 100006 | Scheduled Task Creation | T1053.005 | ✅ Tested |
| 100007 | Disable Windows Defender | T1562.001 | ⬜ Untested |
| 100008 | Stop Security Services | T1562.001 | ⬜ Untested |
| 100009 | Kerberoasting Detection (RC4) | T1558.003 | ✅ Tested |
| 100010 | AS-REP Roasting (No Pre-Auth) | T1558.004 | ✅ Tested |
| 100011 | Malware File Drop (FIM) | T1105 | ✅ Tested |

### Rule 92652: Pass-the-Hash (Administrator)
**Description:** Detects NTLM authentication for Administrative accounts over the network (Logon Type 3), which is often indicative of Pass-the-Hash lateral movement.
**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/)
**Severity:** High (Level 6-12 depending on frequency)
**Status:** ✅ Detected via Built-in Rule 92652

## Progress
- [x] Deploy Wazuh SIEM
- [x] Configure Windows 11 + Sysmon
- [x] Configure Debian Linux agent
- [x] Write custom detection rules
- [x] Install Atomic Red Team
- [x] Test detections with attack simulations
- [x] Deploy Active Directory lab (GOAD)
- [ ] Integrate Shuffle SOAR

## Progress Log

### Day 1: Lab Foundation & Wazuh Deployment
* **Infrastructure:** Set up Proxmox hypervisor on Dell R720 with dedicated VLAN for isolated lab traffic.
* **Configuration:**
    * Deployed Wazuh v4.14.2 using all-in-one installation (`wazuh-install.sh -a`).
    * Stack includes: Wazuh Manager, Wazuh Indexer, and Wazuh Dashboard.
    * Allocated 8GB RAM to Wazuh VM after initial memory issues.
    * Opened firewall ports: 1514 (agent), 1515 (enrollment), 443 (dashboard).
* **Key Learnings:**
    * Wazuh uses OSSEC-style rule syntax with XML format.
    * Alert structure available at `/var/ossec/logs/alerts/alerts.json`.
    * Custom rules go in `/var/ossec/etc/rules/` (defaults in `/var/ossec/ruleset/rules/`).

### Day 2: Windows Agent & First Detection Rules
* **Infrastructure:** Deployed Windows 11 VM with Sysmon (SwiftOnSecurity configuration).
* **Configuration:**
    * Installed and enrolled Wazuh agent to manager.
    * Configured Sysmon log ingestion via `ossec.conf` (`Microsoft-Windows-Sysmon/Operational`).
* **Detection Engineering:**
    * Created custom Wazuh rules for Mimikatz detection:
        * Rule 100001: Filename-based detection (`(?i)mimikatz`).
        * Rule 100002: Command-line argument detection (`sekurlsa|lsadump|kerberos::`).
    * Both rules mapped to MITRE ATT&CK T1003 (Credential Dumping).
    * **Result:** Rules deployed to `/var/ossec/etc/rules/`.

### Day 3: Active Directory & Kerberoasting
* **Infrastructure:** Deployed GOAD-Light AD Lab (DC01, DC02, SRV02) on Proxmox.
* **Configuration:**
    * Corrected Audit Policy on DC02 to log `Kerberos Service Ticket Operations`.
    * Troubleshot and fixed Wazuh Agent naming conventions.
* **Attack Simulation:** Executed Kerberoasting against `sql_svc` using Impacket `GetUserSPNs.py`.
* **Detection Engineering:**
    * Identified Event ID 4769 with Ticket Encryption `0x17` (RC4).
    * Created custom Wazuh rule (ID 100009) to alert on this activity.
    * **Result:** Validated detection in Wazuh Dashboard.

### Day 4: Identity Attacks (AS-REP Roasting)
* **Attack Simulation:** Executed AS-REP Roasting attack against accounts with Kerberos pre-authentication disabled.
* **Detection Engineering:**
    * Identified Event ID 4768 with pre-authentication type `0` indicating no pre-auth.
    * Created custom Wazuh rule (ID 100010) to detect AS-REP Roasting attempts.
    * **Result:** Successfully detected and validated in Wazuh Dashboard.

### Day 5: Endpoint Detection (File Integrity Monitoring)
* **Configuration:** Enabled Wazuh FIM (File Integrity Monitoring) on target endpoints.
* **Attack Simulation:** Simulated malware file drops in monitored directories.
* **Detection Engineering:**
    * Created custom Wazuh rule (ID 100011) to alert on suspicious file creation events.
    * **Result:** Successfully detected malware file drops via FIM alerts.

### Day 6: Automated Active Response (SOAR "Plan B")
* **Objective:** Automate the blocking of malicious actors detected by Suricata without relying on external SOAR platforms (Native Wazuh).
* **Challenge:** The default Wazuh `firewall-drop` script expects the field `srcip`, but Suricata logs use `src_ip`, causing the automation to fail silently.
* **Solution:**
    * **Manager Side:** Configured a custom `<command>` entry in `ossec.conf` to map the `src_ip` field correctly.
    * **Agent Side:** Engineered a custom "Universal Wrapper" script for `iptables` that captures raw STDIN data, extracts the IP using regex, and executes the block regardless of input format.
* **Result:** Successfully automated the blocking of the "BlackSun" C2 User-Agent. Attacks are now dropped at the firewall level instantly upon detection.

### Day 7: Advanced Detection Engineering (Sysmon Debugging)
* **Objective:** Validate custom rules for PowerShell download cradles and security service tampering.
* **Challenge:** Custom rules failed to fire despite Sysmon logs being present.
* **Root Cause Analysis:**
    * Used Wazuh Archives (`logall_json`) to inspect raw logs.
    * Discovered logs were decoded as generic `json` instead of `windows_eventchannel`, causing standard `<if_sid>61603</if_sid>` dependencies to fail.
* **Solution:** Engineered "Self-Sufficient" rules that manually match `win.system.providerName` and `win.system.eventID` (Regex `^1$`), decoupling detection logic from decoder quirks.
* **Result:** Verified successful detection of PowerShell Download Cradles (Rule 100004).