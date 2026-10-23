"""Public download staging keeps the verified metadata chain and receipts intact."""
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import make_release_metadata
from scripts.prepare_release_assets import PLATFORMS, prepare
from scripts.generate_winget_manifest import generate as winget
from scripts.update_homebrew_formula import generate as homebrew
from scripts.maintenance.validate_manager_metadata import validate
from security_runtime._version import __version__


@pytest.fixture
def release_root(tmp_path, monkeypatch):
    release = tmp_path / "dist/release"
    release.mkdir(parents=True)
    for platform, extension, _, _ in PLATFORMS:
        name = f"ai-security-runtime-v{__version__}-{platform}{extension}"
        archive = release / name
        archive.write_bytes(platform.encode())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (release / (name + ".sha256")).write_text(f"{digest}  {name}\n", encoding="utf-8")
        record = dict(version=__version__, source_commit="a" * 40, platform=platform,
                      archive_sha256=digest, smoke=True, managed_engines=True, plugin_discovery=True)
        (release / (name + ".verification.json")).write_text(json.dumps(record), encoding="utf-8")
        for suffix in ("hooks", "codex-integration", "osv-fallback", "fix-verify", "remediation", "confirmation-restart", "functional"):
            (release / (name + f".{suffix}.json")).write_text('{"fixture": true}', encoding="utf-8")
    monkeypatch.setattr(make_release_metadata, "__file__", str(tmp_path / "scripts/make_release_metadata.py"))
    monkeypatch.setattr(make_release_metadata.subprocess, "check_output", lambda *a, **kw: "a" * 40)
    make_release_metadata.main()
    manifest = release / "release-manifest.json"
    formula = tmp_path / "distribution/homebrew/Formula/ai-security-runtime.rb"
    managers = tmp_path / "distribution/winget"
    homebrew(manifest, formula)
    winget(manifest, managers)
    validate(manifest, managers, formula)
    for guide in ("INSTALL.zh-CN.md", "PILOT_INSTALL_AND_USE.zh-CN.md"):
        (release / guide).write_text("fixture guide", encoding="utf-8")
    return tmp_path


def test_public_assets_notes_and_lossless_evidence(release_root):
    release = release_root / "dist/release"
    originals = {p.name: p.read_bytes() for p in release.iterdir()}
    public, notes = prepare(release_root)
    expected = {"release-manifest.json", "SHA256SUMS.txt", f"ai-security-runtime-v{__version__}-release-evidence.zip"}
    text = notes.read_text(encoding="utf-8")
    assert text.startswith("## 下载安装包")
    for platform, extension, label, _ in PLATFORMS:
        name = f"ai-security-runtime-v{__version__}-{platform}{extension}"
        expected.update((name, name + ".sha256"))
        assert f"[下载 {label}]" in text
        assert json.loads(originals["release-manifest.json"])["artifacts"][platform]["url"] in text
        assert (public / name).read_bytes() == originals[name]
    assert {p.name for p in public.iterdir()} == expected
    assert len(expected) == 9
    assert (public / "release-manifest.json").read_bytes() == originals["release-manifest.json"]
    evidence_name = f"ai-security-runtime-v{__version__}-release-evidence.zip"
    with zipfile.ZipFile(public / evidence_name) as archive:
        for name, content in originals.items():
            if name not in expected:
                assert archive.read("release/" + name) == content
        assert len([n for n in archive.namelist() if n.endswith(".json")]) == 24
        assert len([n for n in archive.namelist() if n.endswith(".yaml")]) == 3
        assert any(n.endswith(".rb") for n in archive.namelist())
    for line in (public / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256((public / name).read_bytes()).hexdigest() == digest
    assert {p.name: p.read_bytes() for p in release.iterdir()} == originals
    with pytest.raises(ValueError, match="already exists"):
        prepare(release_root)


@pytest.mark.parametrize("damage", ["checksum", "archive", "verification", "aggregate", "version", "url", "guide", "manager"])
def test_staging_fails_closed(release_root, damage):
    release = release_root / "dist/release"
    name = f"ai-security-runtime-v{__version__}-windows-x64.zip"
    if damage == "checksum":
        (release / (name + ".sha256")).write_text("bad")
    elif damage == "archive":
        (release / name).write_bytes(b"tampered")
    elif damage == "verification":
        (release / (name + ".verification.json")).unlink()
    elif damage == "aggregate":
        (release / "SHA256SUMS.txt").write_text("bad")
    elif damage in ("version", "url"):
        path = release / "release-manifest.json"
        data = json.loads(path.read_text())
        if damage == "version":
            data["version"] = "0.0.0"
        else:
            data["artifacts"]["windows-x64"]["url"] = "https://example.com/wrong.zip"
        path.write_text(json.dumps(data))
    elif damage == "guide":
        (release / "INSTALL.zh-CN.md").unlink()
    else:
        next((release_root / "distribution/winget").glob("*.yaml")).unlink()
    with pytest.raises(ValueError):
        prepare(release_root)
    assert not (release_root / "dist/public-release").exists()


def test_stale_verification_still_blocks_metadata(release_root):
    release = release_root / "dist/release"
    path = next(release.glob("*.verification.json"))
    data = json.loads(path.read_text())
    data["source_commit"] = "b" * 40
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="stale native verification"):
        make_release_metadata.main()


def test_release_workflow_preserves_gates_and_uploads_only_staged_assets():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    jobs = workflow["jobs"]
    for job, needs in (("tests", "version"), ("compliance", "tests"), ("package", "compliance"), ("build", "package"), ("publish", "build")):
        assert jobs[job]["needs"] == needs
    runs = "\n".join(s.get("run", "") for s in jobs["publish"]["steps"])
    assert runs.index("make_release_metadata.py") < runs.index("validate_manager_metadata.py") < runs.index("prepare_release_assets.py") < runs.index("gh release upload")
    assert 'gh release upload "$RELEASE_TAG" dist/public-release/* --clobber' in runs
    assert runs.count("--notes-file dist/release-notes.md") == 2
    standalone = (root / ".github/workflows/standalone.yml").read_text()
    assert "--full --osv-fallback --fix-verify --hooks --remediation --codex-integration" in standalone
