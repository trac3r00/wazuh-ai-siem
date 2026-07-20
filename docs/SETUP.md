# Setup guide

This guide installs the components in this repository on an existing Wazuh manager. It does not install Wazuh, pfSense, AdGuard Home, n8n, Discord, or an LLM server.

## 1. Prepare the environment

The automated setup requires:

- A running Wazuh manager with `/var/ossec` and `wazuh-manager.service`.
- A Debian- or Ubuntu-based host with `apt`, `systemd`, and root access.
- Access to an OpenAI-compatible chat-completions endpoint.
- A Discord webhook URL.

Optional integrations additionally require:

- pfSense with SSH enabled and a table named `quarantine`.
- AdGuard Home with its query log collected by a Wazuh agent.
- n8n for the response workflows.

Back up the existing Wazuh configuration and custom rules before installation. The setup script copies files into `/var/ossec/etc/rules`, `/var/ossec/etc/decoders`, and `/var/ossec/integrations`, and it restarts the manager.

### Resolve checked-in rule conflicts

`rules/local_rules.xml` and `rules/local_adguard_rules.xml` both define rule IDs `111001` and `111002`. The installer copies both files unchanged. Before running it, select the intended definitions or assign unique local IDs and update all dependent `<if_sid>` and integration references. Validate the resulting rule set in a staging manager.

## 2. Clone and configure the repository

```bash
git clone https://github.com/trac3r00/wazuh-ai-siem.git
cd wazuh-ai-siem
```

Edit the configuration block near the top of `scripts/setup.sh`:

| Setting | Purpose |
| --- | --- |
| `DISCORD_WEBHOOK` | Destination for integration notifications |
| `N8N_BASE_URL` | Base URL ending in `/webhook`; workflow paths are appended by the integrations |
| `LMSTUDIO_URL` | Complete OpenAI-compatible `/v1/chat/completions` URL |
| `PFSENSE_HOST` | pfSense SSH host used by the quarantine helper |
| `PFSENSE_SSH_PORT` | pfSense SSH port |
| `WAZUH_API_PASS` | Password used by the REST/chat service to authenticate to the local Wazuh API |

The repository has no `.env` support. The installer substitutes these values into installed copies of the scripts. Do not commit configured credentials or webhook URLs.

The default model name is configured separately as `LMSTUDIO_MODEL` in:

- `integrations/custom-ai-dns-discord.py`
- `integrations/custom-pfsense-ai-discord.py`
- `services/threat_hunter.py`

If the OpenAI-compatible server exposes a different model identifier, update these values before installation or update the installed copies afterward.

## 3. Prepare pfSense automation

Skip this section when quarantine workflows are not required.

The quarantine helper uses the following settings in `scripts/pfsense-quarantine.sh`:

- `PFSENSE_HOST`
- `PFSENSE_SSH_PORT`
- `PFSENSE_USER`
- `SSH_KEY` (default: `/etc/ssh/pfsense_automation`)
- `PROTECTED_IPS`

Create the SSH key expected by the script:

```bash
sudo ssh-keygen -t ed25519 -f /etc/ssh/pfsense_automation -N ""
sudo cat /etc/ssh/pfsense_automation.pub
```

Add the public key to the configured pfSense account. In pfSense, create a table named `quarantine` and a firewall rule that blocks sources in that table. Review `PROTECTED_IPS` before deployment so management and infrastructure addresses cannot be blocked.

The script runs `pfctl -t quarantine` over SSH and disables strict host-key checking. Review that behavior before using it outside an isolated environment.

## 4. Run the installer

```bash
sudo bash scripts/setup.sh
```

The installer performs these repository-defined actions:

1. Installs Python virtual-environment and pip support with `apt`.
2. Copies the three Wazuh-to-Discord integrations and creates extensionless Wazuh wrappers.
3. Copies the pfSense, AdGuard, and local suppression rules plus the AdGuard decoder.
4. Creates `/var/ossec/etc/lists/ignored-domains.txt`.
5. Creates `/opt/threat-hunter-venv` and installs the Threat Hunter service on port `8080`.
6. Creates `/opt/wazuh-mcp/venv` and installs the REST/chat service on port `8081`.
7. Installs `/usr/local/bin/pfsense-quarantine.sh`.
8. Enables Wazuh JSON archives and starts the two systemd services.

The optional Magika scanner and `rules/magika_masquerade_rules.xml` are not installed by this script.

## 5. Configure Wazuh inputs and integrations

Merge only the required sections from [`config/ossec.conf.example`](../config/ossec.conf.example) into the existing `/var/ossec/etc/ossec.conf` inside its `<ossec_config>` element.

The example contains:

- A UDP `514` remote syslog listener for pfSense.
- `logall` and `logall_json`, required by the Threat Hunter's archive reader.
- DNS integration rule ID `111001`.
- pfSense integration rule IDs `112010` and `112011`.
- An SSH integration for the `sshd,authentication_failed` group at level `6` or higher.

The sample DNS integration targets rule `111001`. In `rules/local_adguard_rules.xml`, that rule represents a filtered query, while `custom-ai-dns-discord.py` exits without alerting when `IsFiltered` is true. After resolving the duplicate IDs, point the integration at a reviewed rule that supplies unfiltered DNS events if AI triage of unknown domains is required. Confirm the resulting alert JSON contains `QH`, `IP`, and `IsFiltered` before enabling Discord delivery.

Replace the example's allowed network with the actual pfSense source network. Validate the merged Wazuh configuration using the tooling supplied by the installed Wazuh version before restarting:

```bash
sudo systemctl restart wazuh-manager
```

### AdGuard collection

The checked-in decoder expects AdGuard query data containing `QH`, `QT`, `IP`, and `IsFiltered`. Configure the Wazuh agent on the AdGuard host to collect the actual AdGuard query log as JSON. The default AdGuard log location can vary, so use the path configured on that host rather than assuming one.

### pfSense collection

Configure pfSense remote logging to send the selected log categories to the Wazuh manager on UDP `514`. Restrict the Wazuh `<allowed-ips>` value to the required source network.

## 6. Configure n8n workflows

Import the three JSON files from `n8n-workflows/`:

| Workflow | Webhook path | Action |
| --- | --- | --- |
| `wazuh-quarantine-workflow.json` | `wazuh-quarantine` | Runs `pfsense-quarantine.sh block` over SSH |
| `wazuh-unquarantine-workflow.json` | `wazuh-unquarantine` | Runs `pfsense-quarantine.sh unblock` over SSH |
| `wazuh-ignore-workflow.json` | `wazuh-ignore` | Appends a domain to Wazuh's ignored-domain list |

For each imported workflow:

1. Select an n8n SSH credential that can execute the checked-in command on the Wazuh host.
2. Replace `YOUR_DISCORD_WEBHOOK_HERE` in the confirmation request.
3. Confirm that the production webhook URL matches `N8N_BASE_URL` plus the workflow path.
4. Review the command and query parameters before activation.

The workflow commands interpolate webhook query values into shell commands. Do not expose these webhooks to untrusted callers.

## 7. Verify the installation

Check the services and their root endpoints:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-threat-hunter
sudo systemctl status wazuh-mcp
curl http://localhost:8080/
curl http://localhost:8081/
```

Submit a minimal Threat Hunter query after Wazuh archives contain data:

```bash
curl --request POST http://localhost:8080/query \
  --header 'Content-Type: application/json' \
  --data '{"question":"Summarize recent high-level alerts","hours":24,"max_results":10}'
```

Run the repository's installed-system checks:

```bash
sudo bash scripts/test-integrations.sh
```

This script expects every core service, archive logging, integration file, pfSense helper, SSH key, and external AI endpoint to be configured. It is not a unit-test suite for an uninstalled checkout.

## 8. Install the optional Magika scanner

```bash
python3 -m pip install magika
python3 integrations/selftest_masquerade.py
python3 integrations/file_masquerade_scan.py /path/to/scan \
  --json-out /var/log/masquerade.json
```

Copy `rules/magika_masquerade_rules.xml` into the Wazuh rules directory and add a JSON `<localfile>` for `/var/log/masquerade.json`. The exact input block is documented in comments at the top of the rule file.

For failures after installation, see [Troubleshooting](troubleshooting.md).
