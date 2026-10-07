#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["pydantic>=2.12,<3"]
# ///

# ─── How to run ───
# 1. Install uv (if it is not already installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly:
#      uv run integrations/selftest_codex_security.py
# 3. Or run with Python that has Pydantic 2 installed:
#      python3 integrations/selftest_codex_security.py
# ──────────────────

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Final

from pydantic import TypeAdapter

HERE: Final = Path(__file__).resolve().parent
CONVERTER: Final = HERE / "codex_security_to_wazuh.py"
RULES: Final = HERE.parent / "rules" / "codex_security_rules.xml"
OSSEC_EXAMPLE: Final = HERE.parent / "config" / "ossec.conf.example"
SCAN_ID: Final = "scan_fixture_001"
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
EVENT_ADAPTER: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)


def write_bundle(scan_dir: Path) -> None:
    """Create a sealed Codex Security fixture without copying source evidence."""
    scan_dir.mkdir()
    findings: JsonObject = {
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": SCAN_ID,
        "findings": [
            {
                "findingId": "csf_fixture_high",
                "occurrenceId": "occ_fixture_high",
                "ruleId": "path-traversal.archive-extraction",
                "fingerprints": {
                    "algorithm": "codex-security/v1",
                    "primary": "codex-security/v1:sha256:abc123",
                },
                "title": "Unsafe archive extraction",
                "summary": "An attacker-controlled path reaches a filesystem write.",
                "severity": {"level": "high", "score": 8.1},
                "taxonomy": {"category": "path-traversal", "cwe": ["CWE-22"]},
                "locations": [
                    {
                        "path": "src/extract.py",
                        "startLine": 41,
                        "endLine": 44,
                        "role": "root_control",
                    }
                ],
                "codeEvidence": [{"snippet": "SECRET_SOURCE_SNIPPET"}],
            },
            {
                "findingId": "csf_fixture_info",
                "occurrenceId": "occ_fixture_info",
                "ruleId": "configuration.insecure-default",
                "fingerprints": {
                    "algorithm": "codex-security/v1",
                    "primary": "codex-security/v1:sha256:def456",
                },
                "title": "Review the default configuration",
                "summary": "A configuration surface needs review.",
                "severity": {"level": "informational"},
                "taxonomy": {"category": "configuration", "cwe": []},
                "locations": [{"path": "config/app.json", "startLine": 7}],
            },
        ],
    }
    coverage: JsonObject = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": SCAN_ID,
        "mode": "repository",
        "completeness": "partial",
        "inventoryStrategy": "repository",
        "includePaths": ["src/"],
        "excludePaths": ["vendor/"],
        "surfaces": [
            {
                "id": "surface_archive",
                "label": "Archive extraction",
                "disposition": "reported",
                "receiptRefs": [],
            },
            {
                "id": "surface_network",
                "label": "Network boundary",
                "disposition": "needs_follow_up",
                "receiptRefs": [],
            },
        ],
        "explicitExclusions": [{"pattern": "vendor/", "reason": "Third-party code"}],
        "deferred": [{"id": "deferred_network", "reason": "Runtime unavailable"}],
    }
    findings_bytes = json.dumps(findings, separators=(",", ":")).encode()
    coverage_bytes = json.dumps(coverage, separators=(",", ":")).encode()
    _ = (scan_dir / "findings.json").write_bytes(findings_bytes)
    _ = (scan_dir / "coverage.json").write_bytes(coverage_bytes)
    manifest: JsonObject = {
        "documentType": "codex-security.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": SCAN_ID,
            "producer": {"name": "codex-security-plugin", "version": "0.1.15"},
            "status": "completed",
            "startedAt": "2026-10-03T04:55:00Z",
            "completedAt": "2026-10-03T05:00:00Z",
            "sealedAt": "2026-10-03T05:00:01Z",
            "target": {
                "kind": "git_revision",
                "targetId": "target_fixture_001",
                "displayName": "fixture/wazuh-ai-siem",
                "revision": "deadbeef",
            },
            "scope": {"includePaths": ["src/"], "excludePaths": ["vendor/"]},
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
            "artifacts": [
                {
                    "path": "findings.json",
                    "sha256": hashlib.sha256(findings_bytes).hexdigest(),
                    "mediaType": "application/json",
                },
                {
                    "path": "coverage.json",
                    "sha256": hashlib.sha256(coverage_bytes).hexdigest(),
                    "mediaType": "application/json",
                },
            ],
        },
    }
    _ = (scan_dir / "scan-manifest.json").write_text(
        json.dumps(manifest, separators=(",", ":")),
        encoding="utf-8",
    )


def parse_event(line: str) -> JsonObject:
    """Parse one emitted JSON event for behavioral assertions."""
    event = EVENT_ADAPTER.validate_json(line)
    if isinstance(event, dict):
        return event
    raise AssertionError("converter output line is not a JSON object")


def main() -> int:
    """Exercise the converter's CLI with valid and tampered scan bundles."""
    rules = ElementTree.parse(RULES).getroot()
    rule_levels = {
        rule.attrib["id"]: rule.attrib["level"]
        for rule in rules.findall("rule")
    }
    assert rule_levels == {
        "100960": "3",
        "100961": "15",
        "100962": "12",
        "100963": "8",
        "100964": "5",
        "100965": "3",
        "100966": "3",
        "100967": "5",
    }, rule_levels

    config_text = OSSEC_EXAMPLE.read_text(encoding="utf-8")
    localfile_start = config_text.index("<localfile>")
    localfile_end = config_text.index("</localfile>", localfile_start) + len("</localfile>")
    localfile = ElementTree.fromstring(config_text[localfile_start:localfile_end])
    assert localfile.findtext("log_format") == "json"
    assert localfile.findtext("location") == "/var/log/codex-security-events.jsonl"

    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        scan_dir = root / "completed-scan"
        write_bundle(scan_dir)
        result = subprocess.run(
            [sys.executable, str(CONVERTER), str(scan_dir)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        events = [parse_event(line) for line in result.stdout.splitlines()]
        findings = [event for event in events if event["event"] == "code_security_finding"]
        coverage = next(event for event in events if event["event"] == "scan_coverage")
        assert len(findings) == 2, findings
        assert findings[0]["severity"] == "high", findings[0]
        assert findings[0]["source_path"] == "src/extract.py", findings[0]
        assert coverage["completeness"] == "partial", coverage
        assert coverage["deferred_count"] == 1, coverage
        assert "SECRET_SOURCE_SNIPPET" not in result.stdout, result.stdout

        output_path = root / "events.jsonl"
        for _ in range(2):
            appended = subprocess.run(
                [
                    sys.executable,
                    str(CONVERTER),
                    str(scan_dir),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            assert appended.returncode == 0, appended.stderr
            assert appended.stdout == "", appended.stdout
        assert len(output_path.read_text(encoding="utf-8").splitlines()) == 6
        assert os.stat(output_path).st_mode & 0o077 == 0

        symlink_target = root / "should-stay-empty.jsonl"
        _ = symlink_target.write_text("", encoding="utf-8")
        symlink_path = root / "events-link.jsonl"
        symlink_path.symlink_to(symlink_target)
        symlink_result = subprocess.run(
            [
                sys.executable,
                str(CONVERTER),
                str(scan_dir),
                "--output",
                str(symlink_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert symlink_result.returncode == 2, symlink_result
        assert symlink_target.read_text(encoding="utf-8") == ""

        tampered_dir = root / "tampered-scan"
        write_bundle(tampered_dir)
        with (tampered_dir / "findings.json").open("a", encoding="utf-8") as file:
            _ = file.write(" ")
        tampered = subprocess.run(
            [sys.executable, str(CONVERTER), str(tampered_dir)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert tampered.returncode == 2, tampered
        assert tampered.stdout == "", tampered.stdout

    print("Codex Security Wazuh adapter self-test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
