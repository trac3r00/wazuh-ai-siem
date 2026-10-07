# Cowrie honeypot to Wazuh

[Cowrie](https://github.com/cowrie/cowrie) is a medium-interaction SSH/Telnet
honeypot. It writes one JSON object per line to `var/log/cowrie/cowrie.json`.
Wazuh's built-in JSON decoder reads that file directly, so the integration is
just a `<localfile>` block plus `rules/cowrie_honeypot_rules.xml`.

## What gets alerted

| Rule   | Level | Cowrie event                                   | ATT&CK        |
|--------|-------|------------------------------------------------|---------------|
| 100980 | 3     | any `cowrie.*` event (base rule)               |               |
| 100981 | 5     | `cowrie.session.connect`                        | T1595         |
| 100982 | 6     | `cowrie.login.failed`                           | T1110         |
| 100983 | 10    | 8 failed logins from one `src_ip` in 120 s      | T1110.001     |
| 100984 | 12    | `cowrie.login.success` (attacker in decoy shell)| T1078         |
| 100985 | 10    | `cowrie.command.input`                          | T1059.004     |
| 100986 | 13    | command that fetches or stages a payload        | T1105         |
| 100987 | 13    | `cowrie.session.file_download` / `file_upload`  | T1105         |

Rule descriptions include the username and command but never the password the
attacker tried. The password is still stored in the raw event, so apply the
same retention policy as other attacker data.

## Deploy

These steps change a network-exposed host and the Wazuh manager. Do them in the
isolated lab first.

1. Run Cowrie on a dedicated VM or container in an isolated VLAN, as a
   non-root user, listening on 2222/2223. Forward port 22/23 to it only from
   the network you intend to expose. Do not run it on a host with real
   credentials or data.
2. Install the Wazuh agent on that host and add:

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/home/cowrie/cowrie/var/log/cowrie/cowrie.json</location>
   </localfile>
   ```

3. Copy `rules/cowrie_honeypot_rules.xml` to `/var/ossec/etc/rules/` on the
   manager, run `scripts/test-wazuh-rules.sh` locally, and then restart the
   manager.
4. Optional: point the existing pfSense quarantine active response at rule
   100984 or 100986. It is not enabled by default because a honeypot is meant
   to keep attackers talking.

## How it fits with Codex Security

Both sources land in the same Wazuh manager, so they can be read together:

- Codex Security (rules 100960-100967) shows which code paths in your own
  services are weak.
- The honeypot (rules 100980-100987) shows what attackers on the network are
  actually trying: credentials, commands, and payload URLs.

In the dashboard, filter `rule.groups: codex_security or rule.groups: honeypot`
to put "what is weak" next to "what is being tried". For example, a payload
staged through `wget` in the honeypot is worth checking against any Codex
finding about command injection or unsafe downloads in an exposed service.

## Test

`scripts/test-wazuh-rules.sh` starts a throwaway `wazuh/wazuh-manager`
container, loads both rule files, replays `tests/fixtures/cowrie-events.jsonl`
plus converter output from the Codex Security self-test bundle through
`wazuh-logtest`, and checks that each event hits its expected rule ID.

To check real honeypot output as well, set `COWRIE_LIVE_LOG` to a captured
`cowrie.json`. The expected rule for each line is derived from its `eventid`:

```sh
docker run -d --name cowrie-lab -p 127.0.0.1:22222:2222 \
  -e COWRIE_OUTPUT_JSONLOG_ENABLED=true -v cowrie-var:/cowrie/cowrie-git/var \
  cowrie/cowrie:latest
# ...generate some SSH traffic against 127.0.0.1:22222...
docker run --rm -v cowrie-var:/v alpine cat /v/log/cowrie/cowrie.json > cowrie.json
COWRIE_LIVE_LOG=$PWD/cowrie.json scripts/test-wazuh-rules.sh
```

The official Cowrie image only logs to stdout unless
`COWRIE_OUTPUT_JSONLOG_ENABLED=true` is set.
