# Wazuh AI SIEM

Local-LLM alert triage, threat hunting, detection rules, and response automation for a Wazuh deployment.

[![Security workflow](https://github.com/trac3r00/wazuh-ai-siem/actions/workflows/security.yml/badge.svg)](https://github.com/trac3r00/wazuh-ai-siem/actions/workflows/security.yml)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

This repository contains deployable extensions for an existing Wazuh manager. It adds custom pfSense and AdGuard detection content, Discord alert integrations, an LLM-backed archive search service, a REST and chat gateway, n8n response workflows, and an optional Magika-based file masquerade scanner.

The project is intended for a controlled lab or self-managed environment. The setup script installs repository components into system locations and restarts Wazuh; review all configuration values and rules before running it.

## Features

- pfSense rules for authentication failures, repeated firewall blocks, VPN events, configuration changes, and IDS/IPS alerts.
- AdGuard decoder and rules for DNS queries, filtered requests, suspicious TLDs, and high query volume.
- DNS, pfSense, and SSH integrations that send selected Wazuh alerts to Discord.
- Local-LLM classification for DNS and pfSense events through an OpenAI-compatible chat-completions endpoint.
- Natural-language search over Wazuh JSON archives using sentence-transformer embeddings and FAISS.
- REST endpoints and a browser UI for agents, alerts, summaries, and threat-hunter queries.
- Importable n8n workflows for quarantine, unquarantine, and ignored-domain actions.
- Content-based file masquerade detection with Magika and Wazuh rules mapped to ATT&CK T1036.008.
- Windows and active-response examples under `detection-lab/`.

## Architecture

```text
AdGuard logs ── Wazuh agent ─┐
                             │
pfSense syslog ──────────────┼──> Wazuh manager ──> Python integrations ──> Discord
                             │          │                       │
Endpoint events ─ Wazuh agent┘          │                       └──> n8n webhooks
                                        │                                  │
                                        │                                  └──> pfSense quarantine script
                                        │
                                        ├── JSON archives ──> Threat Hunter :8080 ──> local LLM
                                        │                         │
                                        └── Wazuh API :55000 <── REST/chat service :8081
```

The service named `wazuh-mcp` exposes a REST API and web UI. The checked-in implementation does not implement the Model Context Protocol transport.

## Requirements

The automated installer assumes:

- A running Wazuh manager with `/var/ossec` available.
- A Debian- or Ubuntu-based host with `apt`, `systemd`, and root access.
- Python 3 and the `python3.12-venv` package available from the configured package repositories.
- An OpenAI-compatible `/v1/chat/completions` endpoint for AI analysis.
- A Discord webhook for notifications.

pfSense SSH access, n8n, and AdGuard Home are required only for their corresponding integrations. The setup script does not install those external systems.

## Installation

Clone the repository and review the installer:

```bash
git clone https://github.com/trac3r00/wazuh-ai-siem.git
cd wazuh-ai-siem
```

Edit the configuration block near the top of `scripts/setup.sh`, then run:

```bash
sudo bash scripts/setup.sh
```

The script installs Python environments under `/opt`, copies Wazuh integrations, rules, and the AdGuard decoder under `/var/ossec`, installs two systemd services, enables JSON archive logging, and installs `/usr/local/bin/pfsense-quarantine.sh`.

Before running it, reconcile the overlapping rule IDs `111001` and `111002` in `rules/local_rules.xml` and `rules/local_adguard_rules.xml`. The installer copies both files unchanged, so they should not be enabled together until the local IDs and parent relationships have been reviewed.

Installation is not complete until the relevant `<integration>` and log-source blocks are added to `/var/ossec/etc/ossec.conf`. Use [`config/ossec.conf.example`](config/ossec.conf.example) as a reference and follow the [setup guide](docs/SETUP.md).

## Configuration

Configuration is stored directly in the checked-in scripts; there is no `.env` loader. Do not commit real credentials after editing these values.

| File | Effective settings |
| --- | --- |
| `scripts/setup.sh` | `DISCORD_WEBHOOK`, `N8N_BASE_URL`, `LMSTUDIO_URL`, `PFSENSE_HOST`, `PFSENSE_SSH_PORT`, `WAZUH_API_PASS` |
| `integrations/custom-ai-dns-discord.py` | `LMSTUDIO_URL`, `LMSTUDIO_MODEL`, `DISCORD_WEBHOOK`, `N8N_BASE_URL`, `IGNORED_DOMAINS_FILE` |
| `integrations/custom-pfsense-ai-discord.py` | `LMSTUDIO_URL`, `LMSTUDIO_MODEL`, `DISCORD_WEBHOOK`, `N8N_BASE_URL`, safe IP patterns, skipped ports |
| `integrations/custom-ssh-discord.py` | `DISCORD_WEBHOOK`, `N8N_BASE_URL` |
| `services/threat_hunter.py` | `LMSTUDIO_URL`, `LMSTUDIO_MODEL`, `ARCHIVES_PATH` |
| `services/mcp_server.py` | `WAZUH_API_URL`, `WAZUH_USER`, `WAZUH_PASS`, `THREAT_HUNTER_URL` |
| `scripts/pfsense-quarantine.sh` | `PFSENSE_HOST`, `PFSENSE_SSH_PORT`, `PFSENSE_USER`, `SSH_KEY`, `PROTECTED_IPS`, `LOG_FILE` |

The installer substitutes the Discord webhook, n8n base URL, LLM URL, pfSense host and port, and Wazuh API password. Change model names, API usernames, protected IP ranges, and other settings in the destination scripts after installation when the defaults do not match your environment.

The n8n workflow JSON files contain placeholder Discord URLs and require an n8n SSH credential to be selected after import.

## Usage

### Threat Hunter

Check service state and submit a natural-language query:

```bash
curl http://localhost:8080/

curl --request POST http://localhost:8080/query \
  --header 'Content-Type: application/json' \
  --data '{"question":"Show recent SSH authentication failures","hours":24,"max_results":10}'
```

Refresh the in-memory vector store or inspect its statistics:

```bash
curl --request POST 'http://localhost:8080/refresh?hours=24'
curl http://localhost:8080/stats
```

### REST and chat service

```bash
curl http://localhost:8081/agents
curl 'http://localhost:8081/alerts?limit=20&level=8'
curl http://localhost:8081/alerts/summary
```

Open `http://localhost:8081/ui` in a browser for the included chat interface. The service binds to all interfaces; restrict access at the host or network boundary before using it outside a trusted network.

### pfSense quarantine helper

After configuring the pfSense host, SSH key, protected addresses, and a pfSense table named `quarantine`:

```bash
sudo /usr/local/bin/pfsense-quarantine.sh block 192.0.2.50 "investigation"
sudo /usr/local/bin/pfsense-quarantine.sh list
sudo /usr/local/bin/pfsense-quarantine.sh unblock 192.0.2.50
```

Use only an address reserved for testing when validating block and unblock behavior.

### File masquerade scanner

The main setup script does not install this optional component.

```bash
python3 -m pip install magika
python3 integrations/file_masquerade_scan.py /path/to/scan \
  --json-out /var/log/masquerade.json \
  --fail-on-finding
```

To ingest its events, copy `rules/magika_masquerade_rules.xml` to the Wazuh rules directory and configure a JSON `<localfile>` for `/var/log/masquerade.json`, as shown in that rule file.

## Development and verification

The integration verification script expects a fully installed system with Wazuh, both systemd services, archive data, the pfSense SSH key, and the configured external services:

```bash
sudo bash scripts/test-integrations.sh
```

The Magika scanner has a self-contained synthetic test used by CI:

```bash
python3 -m pip install magika
python3 integrations/selftest_masquerade.py
```

The GitHub Actions `security` workflow runs this self-test on Python 3.12 and performs an advisory OSV dependency scan.

## Project structure

```text
config/             Example Wazuh configuration additions
decoders/           AdGuard decoder
detection-lab/      Windows rule and active-response lab artifacts
docs/               Installation and troubleshooting guides
integrations/       Wazuh alert integrations and Magika scanner
n8n-workflows/      Importable response workflow definitions
rules/              Wazuh detection and suppression rules
scripts/            Installer, verification, and quarantine scripts
services/           FastAPI services and systemd units
```

## Security considerations

- Replace every placeholder before deployment, but keep credentials out of version control.
- Review `rules/local_rules.xml` for environment-specific trusted users and networks before copying it to Wazuh.
- Reconcile duplicate local rule IDs before installation. The checked-in AdGuard integration example also targets rule `111001`, while the DNS integration skips events whose `IsFiltered` value is true.
- The APIs allow cross-origin requests and do not implement application-level authentication. Limit their network exposure.
- The quarantine script disables SSH host-key checking. Use it only in a controlled environment after reviewing the target and key settings.
- Treat LLM output as analyst context, not as a trusted authorization decision.

## Documentation

- [Setup guide](docs/SETUP.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Detection lab](detection-lab/README.md)

## License

Licensed under the [MIT License](LICENSE). Copyright © 2026 Trac3er00.
