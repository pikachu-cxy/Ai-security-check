"""Generate a tap formula from checksums of real release artifacts."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from security_runtime._version import __version__


def artifact(data: dict, platform: str) -> tuple[str, str]:
    entry = data["artifacts"][platform]
    url, digest = entry["url"], entry["sha256"]
    if not url.startswith(f"https://github.com/pikachu-cxy/Ai-security-check/releases/download/v{__version__}/"):
        raise ValueError("Unexpected release asset URL")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid SHA256")
    return url, digest


def generate(manifest: Path, output: Path) -> None:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data["version"] != __version__:
        raise ValueError("Release version mismatch")
    arm_url, arm_sha = artifact(data, "macos-arm64")
    x64_url, x64_sha = artifact(data, "macos-x64")
    content = f'''class AiSecurityRuntime < Formula
  desc "Local security runtime for AI coding agents"
  homepage "https://github.com/pikachu-cxy/Ai-security-check"
  version "{__version__}"
  license :cannot_represent
  depends_on :macos

  on_macos do
    on_arm do
      url "{arm_url}"
      sha256 "{arm_sha}"
    end
    on_intel do
      url "{x64_url}"
      sha256 "{x64_sha}"
    end
  end

  def install
    libexec.install Dir["*"]
    bin.install_symlink libexec/"security-check"
  end

  test do
    assert_match "AI Security Runtime {__version__}", shell_output("#{{bin}}/security-check --version")
  end
end
'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("distribution/homebrew/Formula/ai-security-runtime.rb"))
    arguments = parser.parse_args()
    generate(arguments.manifest, arguments.output)
