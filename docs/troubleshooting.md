# Troubleshooting

Use this guide after completing the [setup procedure](SETUP.md). Commands assume the repository's default installation paths.

## Installer stops early

`scripts/setup.sh` uses `set -e`, so the first failed command terminates the installation.

Check the last command printed by the installer. Common prerequisites are a working `apt` configuration, availability of `python3.12-venv`, a running `wazuh-manager.service`, and write access to `/var/ossec` and `/opt`.

After correcting the failure, run the installer again:

```bash
sudo bash scripts/setup.sh
```

Because the script copies files and performs substitutions in installed copies, recheck their configuration after a partial installation.

## Discord alerts are missing

Confirm that both the extensionless Wazuh wrappers and Python scripts were installed:

```bash
sudo ls -l /var/ossec/integrations/custom-ai-dns-discord*
sudo ls -l /var/ossec/integrations/custom-pfsense-ai-discord*
sudo ls -l /var/ossec/integrations/custom-ssh-discord*
```

Review the integration debug logs created by the setup script:

```bash
sudo tail -n 50 /tmp/ai-dns-debug.log
sudo tail -n 50 /tmp/pfsense-ai-debug.log
sudo tail -n 50 /tmp/ssh-discord-debug.log
```

Then verify:

- The installed scripts no longer contain `YOUR_DISCORD_WEBHOOK_HERE`.
- The relevant `<integration>` block from `config/ossec.conf.example` is present in `/var/ossec/etc/ossec.conf`.
- Wazuh is producing the expected rule ID or group.
- The alert file path passed by Wazuh contains both `/tmp/` and `.alert`; the three integrations deliberately ignore other argument shapes.

The DNS integration skips filtered queries, empty domains, entries in `/var/ossec/etc/lists/ignored-domains.txt`, and built-in safe patterns. With AI available, it sends only configured alert categories at `critical` or `high` threat level. The pfSense integration skips configured safe IP patterns and noisy destination ports.

The checked-in `config/ossec.conf.example` selects DNS rule `111001`, which is a filtered-query rule in `rules/local_adguard_rules.xml`; those events are intentionally skipped by the Python integration. If DNS AI alerts are required, resolve the duplicate AdGuard rule IDs first and configure a reviewed rule that emits unfiltered query data.

## LLM analysis is unavailable

`LMSTUDIO_URL` must be the complete OpenAI-compatible chat-completions URL, and `LMSTUDIO_MODEL` must match a model identifier accepted by that server.

Check the installed values in:

- `/var/ossec/integrations/custom-ai-dns-discord.py`
- `/var/ossec/integrations/custom-pfsense-ai-discord.py`
- `/var/ossec/integrations/threat_hunter.py`

Test the configured endpoint without printing credentials:

```bash
curl --request POST '<chat-completions-url>' \
  --header 'Content-Type: application/json' \
  --data '{"model":"<model-id>","messages":[{"role":"user","content":"health check"}],"max_tokens":10}'
```

The DNS and pfSense integrations send a fallback Discord alert when their LLM request fails. The Threat Hunter instead returns an error string in its `answer` field when the LLM cannot be reached.

## Threat Hunter does not start

Inspect the systemd unit and its logs:

```bash
sudo systemctl status wazuh-threat-hunter
sudo journalctl --unit wazuh-threat-hunter --lines 100
```

The unit runs:

```text
/opt/threat-hunter-venv/bin/python /var/ossec/integrations/threat_hunter.py
```

Confirm that both paths exist. The installer creates the virtual environment and installs LangChain, FAISS, sentence-transformers, FastAPI, Uvicorn, Requests, and HTTPX.

## Threat Hunter returns “Vector store not initialized”

The service builds its in-memory FAISS index from `/var/ossec/logs/archives/archives.json` and recursively discovered `*.json.gz` files. If no readable JSON events are found, `/query` returns HTTP 500.

```bash
sudo ls -l /var/ossec/logs/archives
sudo head -n 5 /var/ossec/logs/archives/archives.json
curl http://localhost:8080/stats
```

Ensure both `<logall>yes</logall>` and `<logall_json>yes</logall_json>` are active in `/var/ossec/etc/ossec.conf`, then restart Wazuh and refresh the index:

```bash
sudo systemctl restart wazuh-manager
curl --request POST 'http://localhost:8080/refresh?hours=24'
```

The current archive loader accepts an `hours` parameter but does not filter events by timestamp; it reads all accessible current and compressed JSON archive files. Large archives therefore increase startup and refresh cost.

## REST/chat service cannot authenticate to Wazuh

Inspect the service logs:

```bash
sudo systemctl status wazuh-mcp
sudo journalctl --unit wazuh-mcp --lines 100
```

Verify `WAZUH_API_URL`, `WAZUH_USER`, and `WAZUH_PASS` in `/opt/wazuh-mcp/server.py`. The setup script substitutes only `WAZUH_PASS`; change the URL or username manually when the local Wazuh API differs from the checked-in defaults.

After changing the installed file:

```bash
sudo systemctl restart wazuh-mcp
curl http://localhost:8081/agents
```

An HTTP 401 from the service indicates that its request to the Wazuh API authentication endpoint failed. The service intentionally disables TLS certificate verification for that local API connection; do not expose this pattern to untrusted networks.

## REST/chat service works but search fails

The `/search` and fallback `/chat` paths call the Threat Hunter at `THREAT_HUNTER_URL`, which defaults to `http://127.0.0.1:8080`.

```bash
curl http://localhost:8080/
curl --request POST http://localhost:8081/search \
  --header 'Content-Type: application/json' \
  --data '{"question":"Show authentication failures","hours":24,"max_results":10}'
```

If the services run on different hosts, update `THREAT_HUNTER_URL` in `/opt/wazuh-mcp/server.py` and restart `wazuh-mcp`.

## pfSense quarantine fails

Check the installed configuration and key path without displaying the private key:

```bash
sudo grep -E '^(PFSENSE_HOST|PFSENSE_SSH_PORT|PFSENSE_USER|SSH_KEY|PROTECTED_IPS)=' /usr/local/bin/pfsense-quarantine.sh
sudo test -f /etc/ssh/pfsense_automation
```

Confirm that pfSense has a table named `quarantine`, the configured account can run `pfctl`, and the firewall policy uses that table. Then test with a documentation-only address that is safe in your environment:

```bash
sudo /usr/local/bin/pfsense-quarantine.sh block 192.0.2.50 "test"
sudo /usr/local/bin/pfsense-quarantine.sh list
sudo /usr/local/bin/pfsense-quarantine.sh unblock 192.0.2.50
```

The script rejects missing addresses, strings that do not match its IPv4 pattern, and entries in `PROTECTED_IPS`. Operational messages are appended to `/var/log/pfsense-quarantine.log`.

## n8n workflow fails

Check the imported workflow against the checked-in definition:

- The webhook path is `wazuh-quarantine`, `wazuh-unquarantine`, or `wazuh-ignore`.
- The SSH node has a credential selected and can reach the Wazuh host.
- `/usr/local/bin/pfsense-quarantine.sh` exists for quarantine actions.
- `/var/ossec/etc/lists/ignored-domains.txt` is writable for ignore actions.
- `YOUR_DISCORD_WEBHOOK_HERE` has been replaced in the confirmation node.

Review the n8n execution record for the failing node. Do not include webhook URLs, SSH keys, or credentials in issue reports.

## Integration verification script exits before its summary

`scripts/test-integrations.sh` also uses `set -e`. A failed service or command can therefore terminate the script before its own pass/fail summary is printed. Run the checks above for the last section shown, correct that dependency, and rerun:

```bash
sudo bash scripts/test-integrations.sh
```

## Reporting an issue

Include the failing command, sanitized error text, installed component paths, and steps to reproduce. Remove webhook URLs, passwords, tokens, private addresses, hostnames, and log data that identifies users or systems.
