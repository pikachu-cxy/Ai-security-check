"""Exercise an actual managed macOS payload in disposable user directories."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen


def run(command, env, cwd, timeout=180, accepted_codes=(0,)):
    result = subprocess.run(
        [str(part) for part in command], env=env, cwd=cwd,
        text=True, capture_output=True, timeout=timeout,
    )
    if result.returncode not in accepted_codes:
        # CI runs only with synthetic user paths and no project credentials.
        print(result.stdout[-12000:])
        print(result.stderr[-8000:], file=sys.stderr)
        raise RuntimeError(f"Acceptance command failed ({result.returncode}): {command[0]}")
    return result.stdout


def verify(archive: Path, platform: str, output: Path) -> None:
    if sys.platform != "darwin":
        raise RuntimeError("This acceptance must run on macOS")
    expected = archive.with_name(archive.name + ".sha256").read_text().split()[0]
    with archive.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == expected
    receipts = []
    with tempfile.TemporaryDirectory(prefix="macos-managed-acceptance-") as temporary:
        base = Path(temporary).resolve()
        payload = base / "payload"
        payload.mkdir()
        with tarfile.open(archive) as tar:
            if any(not (entry.isfile() or entry.isdir()) for entry in tar.getmembers()):
                raise ValueError("Unexpected archive entry")
            manifest = json.load(tar.extractfile("manifest.json"))
            (payload / "managed_install.py").write_bytes(tar.extractfile("managed_install.py").read())
        repository = Path(__file__).resolve().parents[1]
        entry = json.loads((repository / "src/security_runtime/python_downloads.json").read_text())[platform]
        python_archive = base / "python.tar.gz"
        with urlopen(entry["url"], timeout=120) as response, python_archive.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                target.write(chunk)
        with python_archive.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == entry["sha256"]
        # Exercise the unchanged public shell entry before the release exists.
        # Only its three exact download URLs are served from verified CI files;
        # all interpreter execution, hashing, extraction and setup are real.
        fixture_bin = base / "transport-fixture"
        fixture_bin.mkdir()
        release_base = "https://github.com/pikachu-cxy/Ai-security-check/releases/download/macos-trial-v0.3.9.2"
        routes = {
            entry["url"]: str(python_archive),
            f"{release_base}/{archive.name}": str(archive.resolve()),
            f"{release_base}/{archive.name}.sha256": str(archive.with_name(archive.name + ".sha256").resolve()),
        }
        real_curl = shutil.which("curl")
        assert real_curl
        curl = fixture_bin / "curl"
        curl.write_text(
            f"#!{sys.executable}\n"
            "import shutil, subprocess, sys\n"
            f"routes = {routes!r}\n"
            "args = sys.argv[1:]\n"
            "url = args[-1]\n"
            "if url in routes and '--output' in args:\n"
            "    shutil.copyfile(routes[url], args[args.index('--output') + 1])\n"
            "else:\n"
            f"    raise SystemExit(subprocess.call([{real_curl!r}, *args]))\n",
            encoding="utf-8",
        )
        curl.chmod(0o700)
        for host in ("cursor", "codex"):
            user = base / host
            user.mkdir()
            root = user / ".local/share/AI-Security-Runtime-macos-trial"
            env = {
                key: value for key, value in os.environ.items()
                if not key.startswith(("SECURITY_RUNTIME_", "PYTHON", "CODEX_"))
            }
            env.update(
                HOME=str(user), CODEX_HOME=str(user / ".codex"),
                SECURITY_RUNTIME_OFFLINE="1",
                SECURITY_RUNTIME_STATE_DIR=str(user / "state"),
                SECURITY_RUNTIME_DATA_DIR=str(user / "engines"),
                SECURITY_RUNTIME_SKILLS_DIR=str(user / ".agents/skills"),
                PATH=str(fixture_bin) + os.pathsep + os.environ["PATH"],
            )
            command = ["/bin/bash", repository / "distribution/macos/install.sh", host]
            run(command, env, user, timeout=300)
            launcher = root / "security-check"
            info = json.loads(run([launcher, "runtime-info", "--json"], env, user))
            identity = info["build_identity"]
            assert identity["status"] == "IDENTIFIED", identity
            assert identity["build_id"] == manifest["build_id"], identity
            assert identity["source_commit"] == manifest["source_commit"], identity
            assert info["version"] == manifest["version"]
            # The installer itself performs the MCP protocol self-test. A real
            # editor restart and desktop prompts remain separate manual checks.
            status_args = (["integration", "status", "cursor", "--scope", "global", "--json"]
                           if host == "cursor" else ["status", "--json"])
            first_status = json.loads(run([launcher, *status_args], env, user))
            run(command, env, user, timeout=300)
            second_status = json.loads(run([launcher, *status_args], env, user))
            assert first_status["overall"] == second_status["overall"] == "CONFIGURED"
            # Installation deliberately does not require ready engines offline.
            preparation = json.loads(run(
                [launcher, "preparation", "status", "--json"], env, user, accepted_codes=(0, 2),
            ))
            assert preparation["components_ready"] is False
            assert preparation["current_readiness"]["network_allowed"] is False
            receipts.append({
                "host": host, "local_install": "PASSED", "repeat_install": "PASSED",
                "build_id": identity["build_id"], "integration_status": second_status["overall"],
                "managed_python": entry["version"], "python_archive_sha256": entry["sha256"],
                "preparation_report_readable": isinstance(preparation, dict),
                "shell_bootstrap": "PASSED_WITH_LOCAL_RELEASE_TRANSPORT",
                "scanner_execution": "NOT_RUN", "desktop_connection": "PENDING_USER_TRIAL",
            })
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "platform": platform, "source_commit": manifest["source_commit"],
        "receipts": receipts, "gatekeeper_browser_first_launch": "PENDING_USER_TRIAL",
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--platform", choices=["macos-arm64", "macos-x64"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    verify(arguments.archive, arguments.platform, arguments.output)
