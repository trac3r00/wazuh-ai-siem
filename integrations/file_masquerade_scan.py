#!/usr/bin/env python3
"""
file_masquerade_scan.py — AI-powered file-type masquerade detector for Wazuh.

Uses Google's Magika (a ~1 MB deep-learning content classifier) to identify the
*true* type of every file by its bytes, then flags files whose real content does
not match what their extension claims. Attackers routinely disguise webshells,
ELF droppers, and scripts as .log/.txt/.csv/.jpg to slip past extension-based
controls — this catches that class of masquerade at the host level.

Typical uses
------------
  # Scan an upload / web-root directory, human-readable summary:
  ./file_masquerade_scan.py /var/www/uploads

  # Emit one Wazuh-ready JSON event per suspicious file to a log the agent tails
  # (localfile -> /var/ossec/logs/active-responses.log or a custom JSON logfile):
  ./file_masquerade_scan.py /var/www/uploads --json-out /var/log/masquerade.json

  # CI / cron gate — exit non-zero if any masquerade is found:
  ./file_masquerade_scan.py ./samples --fail-on-finding

Wazuh integration
-----------------
Point a <localfile> at the --json-out file with log_format "json". Each event
carries integration:"magika", src_path, claimed_type, detected_type,
content_group ("code"/"executable"/"archive"/...) and a severity so you can
write a rule like:

  <rule id="100950" level="12">
    <decoded_as>json</decoded_as>
    <field name="integration">magika</field>
    <field name="severity">high</field>
    <description>File masquerade: $(detected_type) disguised as .$(claimed_ext)</description>
    <mitre><id>T1036.008</id></mitre>   <!-- Masquerading: Masquerade File Type -->
  </rule>

Only runtime dependency: magika  (pip install magika)
Author: Trac3r00
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

try:
    from magika import Magika
except ImportError:
    sys.stderr.write(
        "error: magika is not installed. Run:  pip install magika\n"
    )
    sys.exit(2)


# --- Policy -----------------------------------------------------------------
# Content groups that should never legitimately hide behind a benign extension.
DANGEROUS_GROUPS = {"code", "executable"}

# Extensions that are "benign-looking" — data/text/media a defender would wave
# through. A dangerous content type behind one of these is the real red flag.
BENIGN_EXTS = {
    "log", "txt", "csv", "tsv", "json", "xml", "md", "ini", "cfg", "conf",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "html", "htm", "dat", "bak", "tmp",
}

# Map a detected magika label to a coarse content group + a masquerade severity.
# high  = code/executable disguised as data/media  (classic dropper/webshell)
# medium= type mismatch that is suspicious but lower-confidence
EXECUTABLE_LABELS = {"elf", "pebin", "machobin", "coff", "dex", "wasm"}
CODE_LABELS = {
    "python", "shell", "javascript", "php", "perl", "ruby", "powershell",
    "batch", "vba", "lua", "java", "c", "cpp", "csharp", "go", "asp",
}
ARCHIVE_LABELS = {"zip", "gzip", "rar", "sevenzip", "tar", "bzip2", "xz"}


def _content_group(label: str) -> str:
    if label in EXECUTABLE_LABELS:
        return "executable"
    if label in CODE_LABELS:
        return "code"
    if label in ARCHIVE_LABELS:
        return "archive"
    return "data"


def _iter_files(root: Path, follow_symlinks: bool = False):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and (follow_symlinks or not p.is_symlink()):
            yield p


def _severity(claimed_ext: str, group: str, score: float) -> str | None:
    """Return 'high'/'medium' if this is a masquerade worth alerting on, else None."""
    benign = claimed_ext in BENIGN_EXTS or claimed_ext == ""
    if group in DANGEROUS_GROUPS and benign:
        return "high" if score >= 0.80 else "medium"
    # Archive disguised as an image/text can be steganographic staging.
    if group == "archive" and claimed_ext in BENIGN_EXTS and claimed_ext not in {
        "zip", "gz", "7z", "rar", "tar", "xz", "bz2"
    }:
        return "medium" if score >= 0.80 else None
    return None


def scan(paths, follow_symlinks=False):
    m = Magika()
    findings = []
    scanned = 0
    for root in paths:
        root = Path(root).expanduser()
        if not root.exists():
            sys.stderr.write(f"warn: path not found: {root}\n")
            continue
        for f in _iter_files(root, follow_symlinks):
            scanned += 1
            try:
                res = m.identify_path(f)
            except Exception as e:  # unreadable / permission / race
                sys.stderr.write(f"warn: could not read {f}: {e}\n")
                continue
            label = res.output.label
            score = float(res.score)
            group = _content_group(label)
            claimed_ext = f.suffix.lower().lstrip(".")
            sev = _severity(claimed_ext, group, score)
            if sev is None:
                continue
            findings.append(
                {
                    "timestamp": _dt.datetime.now(_dt.timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                    "integration": "magika",
                    "event": "file_masquerade",
                    "severity": sev,
                    "src_path": str(f.resolve()),
                    "claimed_ext": claimed_ext,
                    "detected_type": label,
                    "detected_group": group,
                    "confidence": round(score, 3),
                    "mitre_technique": "T1036.008",
                    "size_bytes": f.stat().st_size,
                }
            )
    return findings, scanned


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Detect file-type masquerade (real content vs. extension) with Magika.",
    )
    ap.add_argument("paths", nargs="+", help="File(s) or directory(ies) to scan.")
    ap.add_argument(
        "--json-out",
        metavar="FILE",
        help="Append one JSON event per finding to FILE (Wazuh localfile source).",
    )
    ap.add_argument(
        "--follow-symlinks", action="store_true", help="Follow symlinked files."
    )
    ap.add_argument(
        "--fail-on-finding",
        action="store_true",
        help="Exit 1 if any masquerade is found (for CI / cron gating).",
    )
    ap.add_argument(
        "--quiet", action="store_true", help="Suppress the human summary on stdout."
    )
    args = ap.parse_args(argv)

    findings, scanned = scan(args.paths, follow_symlinks=args.follow_symlinks)

    if args.json_out:
        with open(args.json_out, "a", encoding="utf-8") as fh:
            for ev in findings:
                fh.write(json.dumps(ev) + "\n")

    if not args.quiet:
        if not findings:
            print(f"[magika] scanned {scanned} file(s) — no masquerade detected.")
        else:
            print(
                f"[magika] scanned {scanned} file(s) — "
                f"{len(findings)} MASQUERADE(S) DETECTED:\n"
            )
            for ev in findings:
                print(
                    f"  [{ev['severity'].upper():6s}] {ev['src_path']}\n"
                    f"           claims .{ev['claimed_ext'] or '(none)'} "
                    f"but is {ev['detected_type']} "
                    f"({ev['detected_group']}, conf={ev['confidence']}) "
                    f"— ATT&CK {ev['mitre_technique']}"
                )

    if args.fail_on_finding and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
