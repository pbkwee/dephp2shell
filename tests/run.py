"""Run all offline fixture suites; no live server operations."""
from pathlib import Path
import subprocess
import sys

for suite in sorted(Path(__file__).parent.glob("*.test.py")):
    print("Running " + suite.name, flush=True)
    subprocess.run([sys.executable, str(suite)], check=True)
