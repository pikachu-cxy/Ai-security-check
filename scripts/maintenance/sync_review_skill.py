"""Sync generated repository Skill copies; never update installed user skills."""
from __future__ import annotations

import argparse
from pathlib import Path

from security_runtime.review_skill import GENERATED_FILES, generated_skill_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Report drift without writing files')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2] / 'src/security_runtime/skills/ai-security-review'
    drift = []
    for name in GENERATED_FILES:
        path = root / name
        expected = generated_skill_file(name)
        if not path.exists() or path.read_bytes() != expected:
            drift.append(name)
            if not args.check:
                path.write_bytes(expected)
    for name in drift:
        print(('Out of sync: ' if args.check else 'Updated: ') + name)
    return int(args.check and bool(drift))


if __name__ == '__main__':
    raise SystemExit(main())
