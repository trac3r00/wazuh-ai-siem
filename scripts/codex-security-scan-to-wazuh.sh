#!/usr/bin/env bash
# Run a Codex Security scan on a repository, then convert the completed scan
# bundle into Wazuh JSONL with integrations/codex_security_to_wazuh.py.
#
# Usage:
#   scripts/codex-security-scan-to-wazuh.sh <repo> <artifact-dir> [jsonl-out] [-- extra scan args]
#
# Example:
#   scripts/codex-security-scan-to-wazuh.sh . ~/codex-security/wazuh-ai-siem \
#     /var/log/codex-security-events.jsonl -- --path integrations --effort high
#
# The scan sends repository content to the configured Codex Security provider.
# The artifact directory must be outside the repository. Without jsonl-out the
# events are written to stdout.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  sed -n '2,15p' "$0" >&2
  exit 64
fi

repo=$1
artifacts=$2
shift 2
out=""
if [[ $# -gt 0 && $1 != "--" ]]; then
  out=$1
  shift
fi
[[ ${1:-} == "--" ]] && shift

here=$(cd "$(dirname "$0")/.." && pwd)

codex-security scan "$repo" --headless --output-dir "$artifacts" "$@"

if [[ -n $out ]]; then
  uv run "$here/integrations/codex_security_to_wazuh.py" "$artifacts" --output "$out"
else
  uv run "$here/integrations/codex_security_to_wazuh.py" "$artifacts"
fi
