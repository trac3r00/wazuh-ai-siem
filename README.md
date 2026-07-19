# 🛡️ Wazuh AI-Powered SIEM & Detection Engineering Lab

> An end-to-end security operations project I designed, built, and operate on my own homelab — combining a production-grade **Wazuh SIEM** with **local-LLM threat analysis**, **automated response (SOAR)**, and a full **detection engineering lab** validated against real attack simulations.

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.2-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-12+%20techniques-red)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

---

## 📌 What This Project Demonstrates

| Area | What I Did |
|------|-----------|
| **SIEM Engineering** | Deployed and tuned Wazuh 4.14 (Manager + Indexer + Dashboard) from scratch; ingested logs from Windows (Sysmon), Linux, pfSense firewall, and AdGuard DNS |
| **Detection Engineering** | Wrote 11+ custom detection rules mapped to MITRE ATT&CK, validated each with real attack simulations (Atomic Red Team, Impacket, Mimikatz) |
| **AI Integration** | Built Python integrations that pipe security events through a locally-hosted LLM (Qwen 14B) for threat triage, plus a natural-language log search service (FAISS vector store + REST API) |
| **SOAR / Automated Response** | One-click quarantine from Discord alerts → n8n workflows → pfSense firewall blocks; native Wazuh active response with a custom universal iptables wrapper |
| **Adversary Simulation** | Deployed GOAD Active Directory lab and executed Kerberoasting, AS-REP Roasting, Pass-the-Hash, credential dumping — then engineered the detections to catch them |
| **Alert Engineering** | Noise-reduction ruleset that suppresses routine events while escalating real attacks — the difference between a dashboard nobody reads and alerts that matter |

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              WAZUH SERVER                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Wazuh     │  │   Threat    │  │    MCP      │  │   Discord   │    │
│  │   Manager   │  │   Hunter    │  │   Server    │  │   Alerts    │    │
│  │   :55000    │  │   :8080     │  │   :8081     │  │             │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │                │           │
│         └────────────────┴────────────────┴────────────────┘           │
│                                   │                                     │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│   AdGuard     │          │   pfSense     │          │   Local LLM   │
│   DNS Agent   │          │   Firewall    │          │   Server      │
│   (Agent)     │          │   (Syslog)    │          │   (Qwen 14B)  │
└───────────────┘          └───────────────┘          └───────────────┘
                                    │
                                    ▼
                           ┌───────────────┐
                           │     n8n       │
                           │  Automation   │
                           │  (Webhooks)   │
                           └───────────────┘
```

**Stack:** Proxmox VE on Dell R720 · Wazuh 4.14.2 · Python 3.10 · LMStudio (Qwen 14B) · n8n · pfSense · AdGuard Home · Discord

---

## 🎯 Detection Engineering Highlights

All rules are custom-written, mapped to MITRE ATT&CK, and **validated by actually executing the attack** in an isolated lab — not just copied from a blog post.

| Rule ID | Detection | MITRE ATT&CK | Validation |
|---------|-----------|--------------|------------|
| 100001–2 | Mimikatz (filename + command-line) | [T1003](https://attack.mitre.org/techniques/T1003/) | ✅ Executed Mimikatz |
| 100003 | Encoded PowerShell commands | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | ✅ Atomic Red Team |
| 100004 | PowerShell download cradles | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | ✅ Live simulation |
| 100005 | Local account creation | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | ✅ Atomic Red Team |
| 100006 | Scheduled task persistence | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | ✅ Atomic Red Team |
| 100007–8 | Defender tampering / security service kill | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | ✅ Live simulation |
| 100009 | Kerberoasting (RC4 ticket requests) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | ✅ Impacket GetUserSPNs |
| 100010 | AS-REP Roasting (no pre-auth) | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | ✅ Impacket GetNPUsers |
| 100011 | Malware file drop (FIM) | [T1105](https://attack.mitre.org/techniques/T1105/) | ✅ Live simulation |
| 92652* | Pass-the-Hash (NTLM Logon Type 3) | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | ✅ Lateral movement sim |

*\*Built-in rule, validated against live Pass-the-Hash execution in the AD lab.*

**Notable engineering work:**
- **Sysmon decoder debugging** — custom rules initially failed silently because logs were decoded as generic `json` instead of `windows_eventchannel`. Root-caused via Wazuh archives (`logall_json`) and engineered *self-sufficient rules* that match `win.system.providerName` + `eventID` directly, decoupling detection logic from decoder quirks.
- **Active response field mismatch** — Wazuh's default `firewall-drop` expects `srcip` but Suricata emits `src_ip`, causing silent automation failure. Built a universal iptables wrapper that extracts the IP from raw STDIN regardless of input format. Result: C2 user-agent detections now trigger instant firewall blocks.

→ Full lab journal with day-by-day progress: [`detection-lab/`](detection-lab/)

---

## 🤖 AI-Powered Components

**Automated alert triage with a local LLM.** Instead of forwarding every SIEM event to a human, this lab pipes security events (DNS queries, firewall blocks) through a locally-hosted LLM (Qwen 14B) that classifies each one — malicious, tracking, or benign — before an alert is ever raised. Known-safe and already-blocked traffic is filtered out, high-confidence threats are enriched with an attack-type classification (port scan, brute force, C2 beaconing), and only actionable alerts reach Discord, where a one-click SOAR pipeline can quarantine the source at the firewall. The result: an alert stream a single analyst can actually keep up with, with graceful degradation to rule-only alerting whenever the LLM is unavailable — AI as a triage force-multiplier, not a dependency.

### 1. LLM Threat Triage (DNS + Firewall)
Python integrations that feed security events to a locally-hosted LLM for classification before alerting:
- **DNS analysis** ([`integrations/custom-ai-dns-discord.py`](integrations/custom-ai-dns-discord.py)) — unknown domains are AI-classified (malicious / tracking / safe); blocked and known-safe domains are skipped to prevent alert fatigue
- **Firewall analysis** ([`integrations/custom-pfsense-ai-discord.py`](integrations/custom-pfsense-ai-discord.py)) — triggered on 20+ blocks/minute from a single IP; AI classifies attack type (port scan, brute force, etc.) with graceful fallback when the LLM is unavailable

### 2. Natural-Language Threat Hunting
[`services/threat_hunter.py`](services/threat_hunter.py) — query security logs in plain English via a FAISS vector store + REST API:

> *"Were there any SSH brute force attacks today?"*
> *"What IPs triggered the most alerts?"*

### 3. MCP / Chat API Server
[`services/mcp_server.py`](services/mcp_server.py) — REST API + web UI for SIEM interaction: agent status, alert summaries, conversational log queries.

### 4. AI File-Masquerade Detection (Magika)
[`integrations/file_masquerade_scan.py`](integrations/file_masquerade_scan.py) — uses Google's **[Magika](https://github.com/google/magika)** deep-learning content classifier to identify a file's *true* type from its bytes and flag files whose real content contradicts their extension — the classic dropper/webshell masquerade (a shell script saved as `report.csv`, an ELF disguised as `readme.txt`). Emits Wazuh-ready JSON events mapped to **MITRE ATT&CK [T1036.008](https://attack.mitre.org/techniques/T1036/008/)** (Masquerade File Type), consumed by [`rules/magika_masquerade_rules.xml`](rules/magika_masquerade_rules.xml) (levels 8→14, escalating for native executables in web-served dirs). Point it at an upload dir on a cron/inotify trigger:

```bash
file_masquerade_scan.py /var/www/uploads --json-out /var/log/masquerade.json
```

A self-test ([`integrations/selftest_masquerade.py`](integrations/selftest_masquerade.py)) verifies detection on synthetic samples and runs in CI.

---

## ⚡ Automated Response (SOAR)

Discord alerts include **one-click response buttons** wired to n8n workflows:

| Action | Flow |
|--------|------|
| 🔒 Quarantine | Discord button → n8n webhook → SSH to pfSense → block IP at firewall |
| 🔓 Unquarantine | Discord button → n8n webhook → release IP |
| 🔇 Ignore domain | Discord button → n8n webhook → append to Wazuh CDB safe list |

Protected-IP guardrails prevent the automation from ever quarantining critical infrastructure.

```
DNS Query → AdGuard
  ├── Blocked? → Skip (no alert)
  └── Not blocked?
        ├── Known safe / user-ignored? → Skip
        └── Unknown → AI Analysis
              ├── Safe/tracking? → Skip
              └── Malicious? → Discord Alert
                    ├── [Quarantine] → Block IP
                    └── [Ignore] → Add to safe list
```

---

## 🔇 Noise Reduction

A SIEM that alerts on everything alerts on nothing. Custom suppression ruleset:

| Event | Action |
|-------|--------|
| pfSense single blocks | Suppressed |
| AdGuard routine blocked queries | Suppressed |
| PAM session open/close | Suppressed |
| Sudo by trusted users | Suppressed |
| SSH from internal IPs | Suppressed |
| **SSH brute force (5+ failures)** | **Alert — level 10** |
| **pfSense attack pattern (20+ blocks/min)** | **Alert — level 8+** |

---

## 📁 Repository Structure

```
wazuh-ai-siem/
├── integrations/            # AI-powered Wazuh→Discord integrations (DNS, pfSense, SSH)
├── services/                # Threat Hunter (NL search) + MCP server + systemd units
├── rules/                   # Custom detection & noise-reduction rules (pfSense, AdGuard)
├── decoders/                # Custom log decoders (AdGuard)
├── scripts/                 # Setup, pfSense quarantine, integration tests
├── n8n-workflows/           # Quarantine / unquarantine / ignore automation (importable JSON)
├── config/                  # Example ossec.conf
├── docs/                    # Setup guide + troubleshooting
└── detection-lab/           # Detection engineering lab: AD attack sims, Sysmon rules,
    ├── README.md            #   day-by-day lab journal (GOAD, Kerberoasting, FIM, ...)
    ├── deployment.md        #   full infrastructure deployment guide
    ├── rules/windows/       #   custom Sysmon / Mimikatz detection rules
    └── active-response/     #   universal firewall-drop wrapper + manager config
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/trac3r00/wazuh-ai-siem.git
cd wazuh-ai-siem
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
```

**Prerequisites:** Wazuh 4.14+ on Ubuntu 24.04 (6+ cores, 16GB+ RAM) · pfSense with SSH access · AdGuard Home · LMStudio or Ollama · n8n · Discord webhook

Detailed instructions: [`docs/SETUP.md`](docs/SETUP.md) · [`docs/troubleshooting.md`](docs/troubleshooting.md)

### Configuration

Create `/etc/wazuh-ai-siem.env`:

```bash
LMSTUDIO_URL=http://YOUR_LLM_HOST:1234/v1/chat/completions
LMSTUDIO_MODEL=qwen/qwen3-14b
DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR_WEBHOOK
N8N_BASE_URL=https://n8n.yourserver.com/webhook
PFSENSE_HOST=YOUR_PFSENSE_IP
PFSENSE_SSH_PORT=22
PFSENSE_SSH_KEY=/etc/ssh/pfsense_automation
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=your_api_password
```

---

## 🧪 Testing

```bash
# Test the AI DNS integration
sudo python3 /var/ossec/integrations/custom-ai-dns-discord.py /tmp/test.alert

# Test natural-language threat hunting
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Were there any SSH attacks?", "hours": 24}'

# Test the MCP server
curl http://localhost:8081/alerts/summary

# Full integration test suite
./scripts/test-integrations.sh
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🙏 Acknowledgments

[Wazuh](https://wazuh.com/) · [GOAD](https://github.com/Orange-Cyberdefense/GOAD) · [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) · [LMStudio](https://lmstudio.ai/) · [n8n](https://n8n.io/) · [pfSense](https://www.pfsense.org/) · [AdGuard Home](https://adguard.com/en/adguard-home/overview.html) · [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)

---

*Built and operated by [@trac3r00](https://github.com/trac3r00) — every detection in this repo was validated against a real attack execution, not just theory.*
