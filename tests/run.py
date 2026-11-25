"""Run all offline fixture suites; no live server operations."""
from pathlib import Path
import subprocess
import sys

failed = []
for suite in sorted(Path(__file__).parent.glob("*.test.py")):
    print("Running " + suite.name, flush=True)
    result = subprocess.run([sys.executable, str(suite)])
    if result.returncode:
        failed.append(f"{suite.name} (exit {result.returncode})")

if failed:
    for failure in failed:
        print("Failed: " + failure, file=sys.stderr)
    sys.exit(1)
