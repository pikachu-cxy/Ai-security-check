"""Regenerate or check the reviewed third-party notice document."""
from __future__ import annotations

import argparse
from pathlib import Path

from security_runtime.notices import render_third_party_notices


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[2] / "THIRD_PARTY_NOTICES.md"
    rendered = render_third_party_notices()
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != rendered:
            print("THIRD_PARTY_NOTICES.md is missing or out of date")
            return 1
        print("THIRD_PARTY_NOTICES.md matches reviewed metadata")
        return 0
    target.write_text(rendered, encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
