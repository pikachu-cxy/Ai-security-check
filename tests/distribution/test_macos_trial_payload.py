import importlib.util
import json
from pathlib import Path
import tarfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("trial_payload", ROOT / "scripts/build/build_macos_trial_payload.py")
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def wheel(root, name="ai_security_runtime", version="0.3.9"):
    path = root / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name}-{version}.dist-info/METADATA",
                        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
        if name == "ai_security_runtime":
            archive.writestr("security_runtime/managed_release.json", json.dumps({
                "version": version, "build_id": "a" * 64, "source_commit": "b" * 40,
            }))
    return path


def test_offline_payload_locks_every_wheel_and_hashes_contents(tmp_path):
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    product = wheel(wheels)
    dependency = wheel(wheels, "example_dependency", "1.2.3")
    installer = tmp_path / "installer.py"
    installer.write_text("print('installer')\n")
    output = payload.package_payload(wheels, installer, tmp_path / "out", "macos-arm64")
    with tarfile.open(output) as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
        requirements = archive.extractfile("requirements.txt").read().decode()
        assert manifest["source_commit"] == "b" * 40
        assert manifest["platform"] == "macos-arm64"
        for path, digest in manifest["files"].items():
            assert payload.hashlib.sha256(archive.extractfile(path).read()).hexdigest() == digest
        assert f"ai-security-runtime==0.3.9 --hash=sha256:{payload.sha256(product)}" in requirements
        assert f"example-dependency==1.2.3 --hash=sha256:{payload.sha256(dependency)}" in requirements
    assert output.with_name(output.name + ".sha256").read_text().startswith(payload.sha256(output))
    with pytest.raises(ValueError, match="overwrite"):
        payload.package_payload(wheels, installer, tmp_path / "out", "macos-arm64")


def test_duplicate_or_missing_product_is_rejected(tmp_path):
    wheel(tmp_path, "some_dependency")
    installer = tmp_path / "installer.py"
    installer.write_text("")
    with pytest.raises(ValueError, match="managed release"):
        payload.package_payload(tmp_path, installer, tmp_path / "out", "macos-x64")
    wheel(tmp_path)
    wheel(tmp_path, version="0.3.10")
    with pytest.raises(ValueError, match="Duplicate"):
        payload.package_payload(tmp_path, installer, tmp_path / "out", "macos-x64")
