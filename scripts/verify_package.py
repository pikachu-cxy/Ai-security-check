"""Install the built wheel in a clean venv and exercise its release contract."""
from __future__ import annotations

import os
import subprocess
import tempfile
import venv
from pathlib import Path


def run(*command: str, cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True, timeout=300)


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    wheels = list((repository / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("Expected exactly one built wheel")
    with tempfile.TemporaryDirectory(prefix="ai-security-wheel-") as temporary:
        root = Path(temporary)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        cli = scripts / ("security-check.exe" if os.name == "nt" else "security-check")
        # Runtime tests install the declared scanner dependency. Package
        # integrity only needs the wheel and its lightweight YAML parser.
        run(str(python), "-m", "pip", "install", "--no-deps", str(wheels[0]), "PyYAML>=6,<7", cwd=root)
        run(str(cli), "--help", cwd=root)
        run(str(cli), "licenses", "--check-distribution", cwd=root)
        check = """
from pathlib import Path
import security_runtime
from security_runtime.rulepacks import RulePackManager
package = Path(security_runtime.__file__).resolve().parent
assert package.is_relative_to(Path(__import__('sys').prefix).resolve()), package
pack = RulePackManager().resolve()
assert pack.path.samefile(package / 'rules'), (pack.path, package)
assert pack.descriptor.rule_pack_id == 'ai-security-core'
for engine in ('semgrep', 'gitleaks', 'trivy'):
    assert (package / 'licenses' / engine / 'LICENSE').is_file()
    assert (package / 'licenses' / engine / 'NOTICE').is_file()
share = Path(__import__('sys').prefix) / 'share' / 'ai-security-runtime'
assert (share / 'THIRD_PARTY_NOTICES.md').is_file()
assert (share / 'SOURCE_OFFER.md').is_file()
print('Installed wheel integrity OK')
"""
        run(str(python), "-c", check, cwd=root)


if __name__ == "__main__":
    main()
