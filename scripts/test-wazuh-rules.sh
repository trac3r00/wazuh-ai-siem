#!/usr/bin/env bash
# Replay sample events through wazuh-logtest in a throwaway manager container
# and check that each one hits the expected rule. Needs docker and uv.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
image=${WAZUH_IMAGE:-wazuh/wazuh-manager:4.9.2}
name=wazuh-ruletest-$$
work=$(mktemp -d)
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

wait_for_logtest() {
  for _ in $(seq 1 90); do
    if docker exec "$name" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "wazuh-logtest socket never appeared" >&2
  docker logs --tail 40 "$name" >&2
  return 1
}

docker run -d --platform linux/amd64 --name "$name" "$image" >/dev/null
wait_for_logtest

docker cp "$root/rules/cowrie_honeypot_rules.xml" "$name:/var/ossec/etc/rules/"
docker cp "$root/rules/codex_security_rules.xml" "$name:/var/ossec/etc/rules/"
docker exec "$name" chown wazuh:wazuh /var/ossec/etc/rules/cowrie_honeypot_rules.xml /var/ossec/etc/rules/codex_security_rules.xml
docker exec "$name" rm -f /var/ossec/queue/sockets/logtest
docker exec "$name" /var/ossec/bin/wazuh-control restart >/dev/null
wait_for_logtest

(cd "$root/integrations" && uv run --quiet --with 'pydantic>=2.12,<3' python - "$work/bundle" <<'PY'
import sys
from pathlib import Path
import selftest_codex_security
selftest_codex_security.write_bundle(Path(sys.argv[1]))
PY
)
uv run --quiet "$root/integrations/codex_security_to_wazuh.py" "$work/bundle" > "$work/codex.jsonl"

cat "$root/tests/fixtures/cowrie-events.jsonl" "$work/codex.jsonl" > "$work/events.jsonl"

expected=(
  100981
  100982 100982 100982 100982 100982 100982 100982 100983
  100984 100985 100986 100987
  100967 100962 100965
)

# Optional: also replay a real cowrie.json captured from a running honeypot.
# The expected rule for each line is derived from its eventid.
if [[ -n ${COWRIE_LIVE_LOG:-} ]]; then
  cat "$COWRIE_LIVE_LOG" >> "$work/events.jsonl"
  live_expected=$(python3 - "$COWRIE_LIVE_LOG" <<'PY'
import json
import re
import sys
from collections import Counter

staging = re.compile(r"wget |curl |tftp |ftpget |chmod \+x|base64 -d")
failures = Counter()
for line in open(sys.argv[1], encoding="utf-8"):
    if not line.strip():
        continue
    event = json.loads(line)
    kind = event["eventid"]
    if kind == "cowrie.session.connect":
        print(100981)
    elif kind == "cowrie.login.failed":
        failures[event["src_ip"]] += 1
        print(100983 if failures[event["src_ip"]] % 8 == 0 else 100982)
    elif kind == "cowrie.login.success":
        print(100984)
    elif kind == "cowrie.command.input":
        print(100986 if staging.search(event.get("input", "")) else 100985)
    elif kind in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        print(100987)
    else:
        print(100980)
PY
  )
  # shellcheck disable=SC2206 # one numeric rule ID per line
  expected+=($live_expected)
fi

docker exec -i "$name" /var/ossec/bin/wazuh-logtest < "$work/events.jsonl" > "$work/logtest.out" 2>&1

python3 - "$work/logtest.out" "${expected[@]}" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
expected = sys.argv[2:]
blocks = text.split("**Phase 1: Completed pre-decoding.")[1:]
actual = []
for block in blocks:
    match = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.\s+id: '(\d+)'", block)
    actual.append(match.group(1) if match else "none")

failed = len(actual) != len(expected)
for index, (want, got) in enumerate(zip(expected, actual), start=1):
    status = "ok" if want == got else "FAIL"
    failed |= want != got
    print(f"event {index:2d}: expected {want} got {got} {status}")
if len(actual) != len(expected):
    print(f"expected {len(expected)} results, logtest returned {len(actual)}")
if failed:
    print(text[-3000:], file=sys.stderr)
    sys.exit(1)
print(f"wazuh-logtest: all {len(expected)} events matched their rules")
PY
