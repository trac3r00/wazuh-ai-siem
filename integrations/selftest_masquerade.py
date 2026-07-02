#!/usr/bin/env python3
"""Self-test for file_masquerade_scan.py.

Builds synthetic samples (a clean log + two masqueraded files), runs the
detector, and asserts the two masquerades are caught while the clean log is
not. Used by CI and runnable locally:  python integrations/selftest_masquerade.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "file_masquerade_scan.py")


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        samples = os.path.join(d, "samples")
        os.makedirs(samples)
        # Real log — must NOT be flagged.
        with open(os.path.join(samples, "access.log"), "w") as f:
            f.write('192.0.2.1 - - [02/Jul/2026:10:00:00] "GET / HTTP/1.1" 200 12\n')
        # Shell script disguised as .csv — MUST be flagged.
        with open(os.path.join(samples, "report.csv"), "w") as f:
            f.write("#!/bin/bash\necho staged\n")
        # Python reverse-shell stub disguised as .log — MUST be flagged.
        with open(os.path.join(samples, "system_update.log"), "w") as f:
            f.write("#!/usr/bin/env python3\nimport socket, subprocess, os\nsock = socket.socket()\n")

        out = os.path.join(d, "out.json")
        subprocess.run(
            [sys.executable, SCANNER, samples, "--json-out", out, "--quiet"],
            check=False,
        )

        events = []
        if os.path.exists(out):
            with open(out) as f:
                events = [json.loads(line) for line in f if line.strip()]

        by_name = {e["src_path"].split("/")[-1]: e for e in events}

        assert "report.csv" in by_name, "shell-as-.csv was not detected"
        assert by_name["report.csv"]["detected_type"] == "shell", by_name["report.csv"]
        assert "system_update.log" in by_name, "python-as-.log was not detected"
        assert by_name["system_update.log"]["detected_type"] == "python", by_name["system_update.log"]
        assert "access.log" not in by_name, "clean log was false-positived"

        print(f"magika self-test OK: {len(events)} masquerade(s) detected, clean log ignored")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
