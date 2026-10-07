#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["pydantic>=2.12,<3"]
# ///

# ─── How to run ───
# 1. Install uv (if it is not already installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Convert a completed Codex Security scan to Wazuh JSONL:
#      uv run integrations/codex_security_to_wazuh.py /path/to/scan
# 3. Append events to a local JSONL file:
#      uv run integrations/codex_security_to_wazuh.py /path/to/scan \
#        --output /var/log/codex-security-events.jsonl
# ──────────────────

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from enum import StrEnum, unique
from pathlib import Path
from typing import Final, Literal, NotRequired, TypedDict, override

from pydantic import TypeAdapter

type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
JSON_VALUE_ADAPTER: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)

MAX_MANIFEST_BYTES: Final = 16 * 1024 * 1024
MAX_FINDINGS_BYTES: Final = 128 * 1024 * 1024
MAX_COVERAGE_BYTES: Final = 32 * 1024 * 1024
MAX_FINDINGS: Final = 100_000
MAX_LOCATIONS_PER_FINDING: Final = 100
MAX_TEXT_LENGTH: Final = 512
SCAN_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")


@unique
class Severity(StrEnum):
    """Severity values understood by the Codex Security Wazuh rules."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingEvent(TypedDict):
    """Minimized Wazuh event for one Codex Security finding."""

    integration: Literal["codex_security"]
    event: Literal["code_security_finding"]
    timestamp: str
    scan_id: str
    scan_mode: str
    target: str
    revision: NotRequired[str]
    finding_id: str
    occurrence_id: str
    fingerprint: str
    rule_id: str
    severity: Severity
    title: str
    summary: str
    source_path: str
    start_line: int
    end_line: NotRequired[int]
    location_count: int
    cwe: str


class CoverageEvent(TypedDict):
    """Wazuh event that records scan completeness without copying evidence."""

    integration: Literal["codex_security"]
    event: Literal["scan_coverage"]
    timestamp: str
    scan_id: str
    scan_mode: str
    inventory_strategy: str
    completeness: Literal["complete", "partial", "unknown"]
    target: str
    revision: NotRequired[str]
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    include_path_count: int
    exclude_path_count: int
    surface_count: int
    reported_surface_count: int
    no_issue_found_surface_count: int
    rejected_surface_count: int
    not_applicable_surface_count: int
    needs_follow_up_surface_count: int
    explicit_exclusion_count: int
    deferred_count: int


type WazuhEvent = FindingEvent | CoverageEvent
type SeverityCountKey = Literal[
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "informational_count",
]
type SurfaceCountKey = Literal[
    "reported_surface_count",
    "no_issue_found_surface_count",
    "rejected_surface_count",
    "not_applicable_surface_count",
    "needs_follow_up_surface_count",
]


class SeverityCounts(TypedDict):
    """Counts for the canonical Codex Security severity levels."""

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int


class SurfaceCounts(TypedDict):
    """Counts for canonical Codex Security coverage dispositions."""

    reported_surface_count: int
    no_issue_found_surface_count: int
    rejected_surface_count: int
    not_applicable_surface_count: int
    needs_follow_up_surface_count: int


@dataclass(frozen=True, slots=True)
class ScanBundle:
    """Validated immutable Codex Security canonical scan documents."""

    manifest: JsonObject
    findings: JsonObject
    coverage: JsonObject


@dataclass(frozen=True, slots=True)
class ScanBundleError(Exception):
    """A malformed, incomplete, or untrusted Codex Security scan bundle."""

    message: str

    @override
    def __str__(self) -> str:
        return self.message


SEVERITY_VALUES: Final[dict[str, Severity]] = {
    Severity.CRITICAL.value: Severity.CRITICAL,
    Severity.HIGH.value: Severity.HIGH,
    Severity.MEDIUM.value: Severity.MEDIUM,
    Severity.LOW.value: Severity.LOW,
    Severity.INFORMATIONAL.value: Severity.INFORMATIONAL,
}
SEVERITY_COUNT_KEYS: Final[dict[Severity, SeverityCountKey]] = {
    Severity.CRITICAL: "critical_count",
    Severity.HIGH: "high_count",
    Severity.MEDIUM: "medium_count",
    Severity.LOW: "low_count",
    Severity.INFORMATIONAL: "informational_count",
}
SURFACE_DISPOSITIONS: Final[dict[str, SurfaceCountKey]] = {
    "reported": "reported_surface_count",
    "no_issue_found": "no_issue_found_surface_count",
    "rejected": "rejected_surface_count",
    "not_applicable": "not_applicable_surface_count",
    "needs_follow_up": "needs_follow_up_surface_count",
}


class CliArguments(argparse.Namespace):
    """Arguments parsed from the command line."""

    scan_dir: Path | None = None
    output: str = "-"


def _mapping(value: JsonValue, label: str) -> JsonObject:
    if isinstance(value, dict):
        return value
    raise ScanBundleError(f"{label} must be a JSON object")


def _array(value: JsonValue, label: str) -> list[JsonValue]:
    if isinstance(value, list):
        return value
    raise ScanBundleError(f"{label} must be a JSON array")


def _required_string(
    mapping: JsonObject,
    key: str,
    label: str,
) -> str:
    value = mapping.get(key)
    if isinstance(value, str) and value.strip():
        return value
    raise ScanBundleError(f"{label}.{key} must be a non-empty string")


def _optional_string(mapping: JsonObject, key: str, label: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ScanBundleError(f"{label}.{key} must be a string")


def _string_array(value: JsonValue, label: str) -> list[str]:
    entries = _array(value, label)
    if any(not isinstance(entry, str) for entry in entries):
        raise ScanBundleError(f"{label} must contain only strings")
    return [entry for entry in entries if isinstance(entry, str)]


def _read_json(path: Path, max_bytes: int) -> tuple[JsonObject, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ScanBundleError(f"{path.name} must be a regular, non-symlink file")
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise ScanBundleError(f"{path.name} exceeds the {max_bytes}-byte limit")
        raw_bytes = path.read_bytes()
        parsed = JSON_VALUE_ADAPTER.validate_json(raw_bytes, strict=True)
    except (OSError, ValueError, RecursionError) as error:
        raise ScanBundleError(f"could not read valid JSON from {path.name}") from error
    return _mapping(parsed, path.name), raw_bytes


def _verify_artifact_hash(
    manifest: JsonObject,
    path_name: str,
    content: bytes,
) -> None:
    scan = _mapping(manifest.get("scan"), "scan-manifest.scan")
    artifacts = _array(scan.get("artifacts"), "scan-manifest.scan.artifacts")
    matches: list[JsonObject] = []
    for index, value in enumerate(artifacts):
        artifact = _mapping(value, f"scan-manifest.scan.artifacts[{index}]")
        if artifact.get("path") == path_name:
            matches.append(artifact)
    if len(matches) != 1:
        raise ScanBundleError(
            f"scan manifest must contain exactly one {path_name} hash"
        )
    expected = _required_string(matches[0], "sha256", f"artifact {path_name}")
    if not SHA256_PATTERN.fullmatch(expected):
        raise ScanBundleError(f"artifact {path_name} has an invalid SHA-256")
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        raise ScanBundleError(f"artifact hash mismatch for {path_name}")


def load_scan_bundle(scan_dir: Path) -> ScanBundle:
    """Load a completed, hash-verified Codex Security canonical bundle."""
    if scan_dir.is_symlink() or not scan_dir.is_dir():
        raise ScanBundleError("scan directory must be a real directory")
    manifest, _ = _read_json(scan_dir / "scan-manifest.json", MAX_MANIFEST_BYTES)
    findings, findings_bytes = _read_json(
        scan_dir / "findings.json",
        MAX_FINDINGS_BYTES,
    )
    coverage, coverage_bytes = _read_json(
        scan_dir / "coverage.json",
        MAX_COVERAGE_BYTES,
    )

    if manifest.get("documentType") != "codex-security.scan-manifest":
        raise ScanBundleError("scan manifest has an unsupported documentType")
    if manifest.get("schemaVersion") != "1.0":
        raise ScanBundleError("scan manifest has an unsupported schemaVersion")
    scan = _mapping(manifest.get("scan"), "scan-manifest.scan")
    if scan.get("status") != "completed":
        raise ScanBundleError("scan manifest status must be completed")
    scan_id = _required_string(scan, "id", "scan-manifest.scan")
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        raise ScanBundleError("scan id contains unsupported characters")
    _ = _required_string(scan, "startedAt", "scan-manifest.scan")
    _ = _required_string(scan, "completedAt", "scan-manifest.scan")
    _ = _required_string(scan, "sealedAt", "scan-manifest.scan")
    if scan.get("findingsRef") != "findings.json":
        raise ScanBundleError("scan manifest findingsRef must be findings.json")
    if scan.get("coverageRef") != "coverage.json":
        raise ScanBundleError("scan manifest coverageRef must be coverage.json")
    producer = _mapping(scan.get("producer"), "scan-manifest.scan.producer")
    _ = _required_string(producer, "name", "scan-manifest.scan.producer")
    _ = _required_string(producer, "version", "scan-manifest.scan.producer")
    target = _mapping(scan.get("target"), "scan-manifest.scan.target")
    target_kind = _required_string(target, "kind", "scan-manifest.scan.target")
    if target_kind not in {
        "git_revision",
        "git_worktree",
        "git_diff",
        "directory_snapshot",
    }:
        raise ScanBundleError(f"unsupported scan target kind: {target_kind}")
    _ = _required_string(target, "targetId", "scan-manifest.scan.target")
    _ = _required_string(target, "displayName", "scan-manifest.scan.target")
    _verify_artifact_hash(manifest, "findings.json", findings_bytes)
    _verify_artifact_hash(manifest, "coverage.json", coverage_bytes)

    if findings.get("documentType") != "codex-security.findings":
        raise ScanBundleError("findings document has an unsupported documentType")
    if findings.get("schemaVersion") != "1.0":
        raise ScanBundleError("findings document has an unsupported schemaVersion")
    if findings.get("scanId") != scan_id:
        raise ScanBundleError("findings scanId does not match the scan manifest")
    if coverage.get("documentType") != "codex-security.coverage":
        raise ScanBundleError("coverage document has an unsupported documentType")
    if coverage.get("schemaVersion") != "1.0":
        raise ScanBundleError("coverage document has an unsupported schemaVersion")
    if coverage.get("scanId") != scan_id:
        raise ScanBundleError("coverage scanId does not match the scan manifest")

    return ScanBundle(manifest=manifest, findings=findings, coverage=coverage)


def _clean_text(value: str, label: str) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        raise ScanBundleError(f"{label} must not be empty")
    return normalized[:MAX_TEXT_LENGTH]


def _safe_relative_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if normalized.startswith("/") or any(part == ".." for part in parts):
        return "<outside-repository>"
    if len(parts) > 0 and len(parts[0]) >= 2 and parts[0][1] == ":":
        return "<outside-repository>"
    return normalized.removeprefix("./") or "<unknown>"


def _severity_count_key(severity: Severity) -> SeverityCountKey:
    return SEVERITY_COUNT_KEYS[severity]


def _finding_event(
    finding_value: JsonValue,
    scan: JsonObject,
    completed_at: str,
    scan_id: str,
    scan_mode: str,
) -> tuple[FindingEvent, Severity]:
    finding = _mapping(finding_value, "finding")
    severity_data = _mapping(finding.get("severity"), "finding.severity")
    severity_name = _required_string(severity_data, "level", "finding.severity")
    severity = SEVERITY_VALUES.get(severity_name)
    if severity is None:
        raise ScanBundleError(f"unsupported finding severity: {severity_name}")

    locations = _array(finding.get("locations"), "finding.locations")
    if not locations or len(locations) > MAX_LOCATIONS_PER_FINDING:
        raise ScanBundleError(
            f"finding locations must contain 1 to {MAX_LOCATIONS_PER_FINDING} entries"
        )
    location_objects = [
        _mapping(value, f"finding.locations[{index}]")
        for index, value in enumerate(locations)
    ]
    primary_location = next(
        (
            location
            for location in location_objects
            if location.get("role") == "root_control"
        ),
        location_objects[0],
    )
    start_line_value = primary_location.get("startLine")
    if (
        not isinstance(start_line_value, int)
        or isinstance(start_line_value, bool)
        or start_line_value < 1
    ):
        raise ScanBundleError("finding primary location startLine must be positive")
    end_line_value = primary_location.get("endLine")
    if end_line_value is not None and (
        not isinstance(end_line_value, int)
        or isinstance(end_line_value, bool)
        or end_line_value < start_line_value
    ):
        raise ScanBundleError("finding primary location endLine is invalid")

    target = _mapping(scan.get("target"), "scan-manifest.scan.target")
    target_name = _optional_string(target, "displayName", "scan target") or "unknown"
    revision = _optional_string(target, "revision", "scan target")
    taxonomy = _mapping(finding.get("taxonomy"), "finding.taxonomy")
    cwe = _string_array(taxonomy.get("cwe"), "finding.taxonomy.cwe")
    event: FindingEvent = {
        "integration": "codex_security",
        "event": "code_security_finding",
        "timestamp": completed_at,
        "scan_id": scan_id,
        "scan_mode": scan_mode,
        "target": _clean_text(target_name, "scan target displayName"),
        "finding_id": _required_string(finding, "findingId", "finding"),
        "occurrence_id": _required_string(finding, "occurrenceId", "finding"),
        "fingerprint": _required_string(
            _mapping(finding.get("fingerprints"), "finding.fingerprints"),
            "primary",
            "finding.fingerprints",
        ),
        "rule_id": _clean_text(
            _required_string(finding, "ruleId", "finding"),
            "finding.ruleId",
        ),
        "severity": severity,
        "title": _clean_text(
            _required_string(finding, "title", "finding"),
            "finding.title",
        ),
        "summary": _clean_text(
            _required_string(finding, "summary", "finding"),
            "finding.summary",
        ),
        "source_path": _safe_relative_path(
            _required_string(primary_location, "path", "finding primary location")
        ),
        "start_line": start_line_value,
        "location_count": len(location_objects),
        "cwe": ",".join(_clean_text(code, "CWE") for code in cwe[:10]),
    }
    if revision is not None:
        event["revision"] = _clean_text(revision, "scan target revision")
    if end_line_value is not None:
        event["end_line"] = end_line_value
    return event, severity


def _coverage_event(
    bundle: ScanBundle,
    completed_at: str,
    scan_id: str,
    finding_count: int,
    severity_counts: SeverityCounts,
) -> CoverageEvent:
    scan = _mapping(bundle.manifest.get("scan"), "scan-manifest.scan")
    target = _mapping(scan.get("target"), "scan-manifest.scan.target")
    coverage = bundle.coverage
    completeness_value = _required_string(coverage, "completeness", "coverage")
    if completeness_value not in ("complete", "partial", "unknown"):
        raise ScanBundleError("coverage.completeness is unsupported")
    completeness: Literal["complete", "partial", "unknown"] = completeness_value

    surfaces = _array(coverage.get("surfaces"), "coverage.surfaces")
    disposition_counts: SurfaceCounts = {
        "reported_surface_count": 0,
        "no_issue_found_surface_count": 0,
        "rejected_surface_count": 0,
        "not_applicable_surface_count": 0,
        "needs_follow_up_surface_count": 0,
    }
    for index, surface_value in enumerate(surfaces):
        surface = _mapping(surface_value, f"coverage.surfaces[{index}]")
        disposition = _required_string(
            surface,
            "disposition",
            f"coverage.surfaces[{index}]",
        )
        if disposition not in SURFACE_DISPOSITIONS:
            raise ScanBundleError(f"unsupported surface disposition: {disposition}")
        count_key = SURFACE_DISPOSITIONS[disposition]
        disposition_counts[count_key] += 1

    mode = _required_string(coverage, "mode", "coverage")
    inventory = _required_string(coverage, "inventoryStrategy", "coverage")
    target_name = _optional_string(target, "displayName", "scan target") or "unknown"
    revision = _optional_string(target, "revision", "scan target")
    include_paths = _string_array(coverage.get("includePaths"), "coverage.includePaths")
    exclude_paths = _string_array(coverage.get("excludePaths"), "coverage.excludePaths")
    exclusions = _array(
        coverage.get("explicitExclusions"),
        "coverage.explicitExclusions",
    )
    deferred = _array(coverage.get("deferred"), "coverage.deferred")

    event: CoverageEvent = {
        "integration": "codex_security",
        "event": "scan_coverage",
        "timestamp": completed_at,
        "scan_id": scan_id,
        "scan_mode": _clean_text(mode, "coverage.mode"),
        "inventory_strategy": _clean_text(inventory, "coverage.inventoryStrategy"),
        "completeness": completeness,
        "target": _clean_text(target_name, "scan target displayName"),
        "finding_count": finding_count,
        **severity_counts,
        "include_path_count": len(include_paths),
        "exclude_path_count": len(exclude_paths),
        "surface_count": len(surfaces),
        **disposition_counts,
        "explicit_exclusion_count": len(exclusions),
        "deferred_count": len(deferred),
    }
    if revision is not None:
        event["revision"] = _clean_text(revision, "scan target revision")
    return event


def events_for_bundle(bundle: ScanBundle) -> list[WazuhEvent]:
    """Build minimized coverage and finding events from a verified scan bundle."""
    scan = _mapping(bundle.manifest.get("scan"), "scan-manifest.scan")
    scan_id = _required_string(scan, "id", "scan-manifest.scan")
    completed_at = _required_string(scan, "completedAt", "scan-manifest.scan")
    coverage = _mapping(bundle.coverage, "coverage")
    scan_mode = _required_string(coverage, "mode", "coverage")
    findings = _array(bundle.findings.get("findings"), "findings.findings")
    if len(findings) > MAX_FINDINGS:
        raise ScanBundleError(f"findings exceeds the {MAX_FINDINGS}-item limit")

    severity_counts: SeverityCounts = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "informational_count": 0,
    }
    finding_events: list[FindingEvent] = []
    for finding in findings:
        event, severity = _finding_event(
            finding,
            scan,
            completed_at,
            scan_id,
            scan_mode,
        )
        severity_counts[_severity_count_key(severity)] += 1
        finding_events.append(event)

    coverage_event = _coverage_event(
        bundle,
        completed_at,
        scan_id,
        len(finding_events),
        severity_counts,
    )
    return [coverage_event, *finding_events]


def _append_private_jsonl(path: Path, content: str) -> None:
    """Append events without following symlinks or exposing a new file by default."""
    if path.is_symlink():
        raise ScanBundleError("output must not be a symlink")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
            raise ScanBundleError("existing output file must be private (mode 0600)")
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            descriptor = -1
            _ = stream.write(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    """Convert a completed scan bundle to append-only Wazuh JSONL."""
    parser = argparse.ArgumentParser(
        description=(
            "Convert a hash-verified Codex Security completed scan to minimized "
            "Wazuh JSONL events."
        )
    )
    _ = parser.add_argument(
        "scan_dir",
        type=Path,
        help="Completed scan artifact directory.",
    )
    _ = parser.add_argument(
        "--output",
        default="-",
        help="Append events to FILE, or write to stdout when FILE is '-'.",
    )
    args = CliArguments()
    _ = parser.parse_args(argv, namespace=args)
    if args.scan_dir is None:
        parser.error("scan directory is required")

    try:
        bundle = load_scan_bundle(args.scan_dir)
        events = events_for_bundle(bundle)
        output = "".join(
            json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
            for event in events
        )
        if args.output == "-":
            _ = sys.stdout.write(output)
        else:
            _append_private_jsonl(Path(args.output), output)
    except (ScanBundleError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
