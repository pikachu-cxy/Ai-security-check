"""PyInstaller one-directory Runtime; scanner engines stay external."""

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, copy_metadata

root = Path(SPECPATH).resolve().parents[1]
package = root / "src" / "security_runtime"
datas = collect_data_files("security_runtime")
# Native rule identity includes its implementation bytes, including in PYZ builds.
datas += [(str(package / "dynamic_function.py"), "security_runtime")]
# Keep every flow helper readable for frozen implementation identity checks.
datas += [(str(source), "security_runtime") for source in
          (package / "dataflow.py", *sorted(package.glob("flow_*.py")))]
datas += [(str(root / name), "security_runtime") for name in ("LICENSE", "EULA.md", "LICENSING.md", "THIRD_PARTY_NOTICES.md", "SOURCE_OFFER.md")]
datas += copy_metadata("ai-security-runtime")
datas += copy_metadata("javalang") + copy_metadata("six")
datas += copy_metadata("packaging")
datas += copy_metadata("watchfiles")
hiddenimports = ["mcp.server.fastmcp", "mcp.server.fastmcp.server", "watchfiles._rust_notify"]

a = Analysis(
    [str(root / "distribution" / "build" / "entry.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["semgrep", "semgrep_core", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="security-check", console=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="security-check")
