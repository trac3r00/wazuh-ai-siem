# Changelog

## 2026-10-06

- Added Cowrie honeypot rules (100980-100987) for connections, failed and
  brute-force logins, accepted logins, commands, payload staging, and captured
  files. Descriptions never include attacker passwords.
- Added `scripts/test-wazuh-rules.sh`, which replays Cowrie fixtures and
  Codex Security converter output through `wazuh-logtest` in a throwaway
  manager container and checks every expected rule ID.
- Added `scripts/codex-security-scan-to-wazuh.sh` to run a scan and convert
  the result in one step.
- `scripts/test-wazuh-rules.sh` can also replay a real `cowrie.json` through
  `COWRIE_LIVE_LOG`, so rules are checked against live honeypot output and
  not only hand-written fixtures.

## 2026-10-03

- Added a local-only Codex Security adapter for completed canonical scan
  bundles. It verifies artifact hashes and emits minimized finding and
  coverage events as Wazuh JSONL.
- Added optional Wazuh rules and a localfile example, but kept live manager
  ingestion manual because retention and deployment are not approved.
- Kept honeypot deployment out of scope until the product, host, network
  exposure, and retention are selected.
