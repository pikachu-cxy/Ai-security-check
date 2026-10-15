"""Bounded test-host prerequisite; never executes an application module."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

# Process startup/readiness allowance, not a target/security execution budget.
# One attempt only. The arithmetic template remains 30s, its worker 10s.
PROBE_TIMEOUT_SECONDS = 30
SUPPORTED_MAJOR = 24


def node_environment():
    env = dict(os.environ)
    # Match the fixed template worker's isolated environment; no global edits.
    env.pop('NODE_OPTIONS', None)
    env.pop('NODE_PATH', None)
    return env


def probe_node(*, expected_version=None, executable=None):
    node = executable or shutil.which('node')
    if not node:
        raise RuntimeError('NODE_HOST_REQUIRED: Node 24 must be installed for host tests')
    node = str(Path(node).resolve(strict=True))
    started = time.perf_counter()
    # A timeout, nonzero exit or unavailable executable must fail, never skip.
    result = subprocess.run([node, '--version'], shell=False, env=node_environment(),
        capture_output=True, text=True, check=True, timeout=PROBE_TIMEOUT_SECONDS)
    version = result.stdout.strip()
    match = re.fullmatch(r'v(\d+)\.\d+\.\d+', version)
    if not match or int(match[1]) != SUPPORTED_MAJOR:
        raise RuntimeError('NODE_HOST_UNSUPPORTED_VERSION: '+version)
    if expected_version is not None and version != 'v'+expected_version:
        raise RuntimeError(f'NODE_HOST_VERSION_MISMATCH: expected {expected_version}, observed {version}')
    return dict(status='NODE_HOST_READY', executable=node, version=version,
        executable_sha256=hashlib.sha256(Path(node).read_bytes()).hexdigest(),
        probe_wall_ms=round((time.perf_counter()-started)*1000,3),
        probe_timeout_seconds=PROBE_TIMEOUT_SECONDS, attempts=1,
        source='ACTUAL_VERSION_PROCESS_AND_EXECUTABLE_BYTES', target_executed=False)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--expected-version',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    # Refuse an old receipt: CI must bind success to this command's zero exit.
    if args.output.exists():
        raise ValueError('NODE_HOST_RECEIPT_ALREADY_EXISTS')
    report=probe_node(expected_version=args.expected_version)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__': main()
