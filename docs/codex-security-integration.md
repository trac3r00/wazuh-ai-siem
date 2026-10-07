# Codex Security to Wazuh

This adapter converts a completed Codex Security scan bundle into minimized
Wazuh JSONL. It consumes the canonical `scan-manifest.json`, `findings.json`,
and `coverage.json` files, checks the manifest hashes for the two data files,
and refuses incomplete, mismatched, or tampered bundles.

The converter is local-only. It does not start `codex-security scan`, call a
model, upload artifacts, install Wazuh rules, or restart a service. A finding
event contains the finding title and summary, rule ID, severity, stable
fingerprint, CWE values, and one primary repository-relative location. It does
not copy source snippets, attack paths, remediation evidence, or the scan's
remote URL. A separate scan-coverage event records completeness and counts,
including deferred surfaces and explicit exclusions.

## Convert a completed scan

Run Codex Security separately after deciding the scan target, provider, and
cost boundary. Codex Security scan commands can send repository content to the
selected model provider and create persistent scan artifacts. No scan has been
run as part of this adapter change.

Given a completed scan directory containing the three canonical files:

```sh
uv run integrations/codex_security_to_wazuh.py /path/to/completed-scan
```

This writes JSONL to stdout. To append it to a local file:

```sh
uv run integrations/codex_security_to_wazuh.py \
  /path/to/completed-scan \
  --output /var/log/codex-security-events.jsonl
```

New output files are created with private permissions. Existing output files
must already be private, and symlink output paths are rejected. The converter
does not move or retain the original scan bundle.

## Optional Wazuh ingestion

Wazuh manager ingestion is not enabled by this repository change. After
approving the event data and retention policy:

1. Review `rules/codex_security_rules.xml` against the installed Wazuh version
   and existing custom rule IDs.
2. Copy the rule file to `/var/ossec/etc/rules/`.
3. Add the Codex Security `<localfile>` block from
   `config/ossec.conf.example` to the manager's `ossec.conf`.
4. Place the JSONL file at `/var/log/codex-security-events.jsonl` using the
   approved transfer method.
5. Validate the configuration and rules in the isolated Wazuh lab before
   restarting the manager.

The complete-scan rule is informational. A separate low-priority rule marks
`partial` or `unknown` coverage so an incomplete review is not mistaken for a
clean scan. Severity rules map Codex Security's canonical severity levels to
Wazuh alert levels; they do not take automated response actions.

To run a scan and convert it in one step:

```sh
scripts/codex-security-scan-to-wazuh.sh . ~/codex-security/wazuh-ai-siem \
  /var/log/codex-security-events.jsonl -- --path integrations --effort high
```

## Honeypot

Honeypot events come from Cowrie and use rules 100980-100987. See
[`honeypot-integration.md`](honeypot-integration.md) for deployment and for
how the two sources are read together in Wazuh.

## Test

The synthetic self-test creates a sealed canonical bundle, invokes the actual
converter CLI, checks emitted finding and coverage events, and verifies that a
modified artifact is rejected:

```sh
uv run integrations/selftest_codex_security.py
```

`scripts/test-wazuh-rules.sh` also replays the converter output through a real
`wazuh-logtest` and checks the rule IDs.
