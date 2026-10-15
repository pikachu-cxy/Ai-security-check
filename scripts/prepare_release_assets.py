"""Stage a small public asset set after native and package-manager validation."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

from security_runtime._version import __version__

REPOSITORY = "pikachu-cxy/Ai-security-check"
PLATFORMS = (
    ("windows-x64", ".zip", "Windows x64", "Windows 64 位电脑"),
    ("macos-arm64", ".tar.gz", "Mac Apple Silicon", "M1/M2/M3/M4 等 Apple 芯片"),
    ("macos-x64", ".tar.gz", "Mac Intel", "Intel 芯片 Mac"),
)


def prepare(root: Path) -> tuple[Path, Path]:
    release = root / "dist/release"
    public = root / "dist/public-release"
    # Never merge with an old staging directory: stale files must not be uploaded.
    if public.exists():
        raise ValueError("Public release staging directory already exists")
    manifest = json.loads((release / "release-manifest.json").read_text(encoding="utf-8"))
    if manifest["version"] != __version__:
        raise ValueError("Release version mismatch")
    base = f"https://github.com/{REPOSITORY}/releases/download/v{__version__}"
    names = []
    sums = []
    rows = []
    for platform, extension, label, choice in PLATFORMS:
        name = f"ai-security-runtime-v{__version__}-{platform}{extension}"
        entry = manifest["artifacts"][platform]
        digest = hashlib.sha256((release / name).read_bytes()).hexdigest()
        if entry != {"url": f"{base}/{name}", "sha256": digest}:
            raise ValueError(f"Archive metadata mismatch: {platform}")
        checksum = release / (name + ".sha256")
        line = f"{digest}  {name}"
        if checksum.read_text(encoding="utf-8").strip() != line:
            raise ValueError(f"Archive checksum mismatch: {platform}")
        if not (release / (name + ".verification.json")).is_file():
            raise ValueError(f"Missing native verification: {platform}")
        names.extend((name, checksum.name))
        sums.append(line)
        rows.append(f"| **[下载 {label}]({entry['url']})** | {choice} | [SHA256]({base}/{checksum.name}) |")
    if (release / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines() != sums:
        raise ValueError("Aggregate archive checksums mismatch")
    names.extend(("release-manifest.json", "SHA256SUMS.txt"))
    # Preserve all receipts and guides, including future specialty evidence.
    evidence = [(p, "release/" + p.name) for p in sorted(release.iterdir()) if p.name not in names]
    evidence.extend((p, p.relative_to(root).as_posix()) for p in sorted((root / "distribution/homebrew/Formula").glob("*.rb")))
    evidence.extend((p, p.relative_to(root).as_posix()) for p in sorted((root / "distribution/winget").glob("*.yaml")))
    if any(not p.is_file() or p.is_symlink() for p, _ in evidence):
        raise ValueError("Evidence must contain regular files only")
    if not any(name.endswith(".rb") for _, name in evidence) or sum(name.endswith(".yaml") for _, name in evidence) != 3:
        raise ValueError("Missing generated package-manager metadata")
    for guide in ("INSTALL.zh-CN.md", "PILOT_INSTALL_AND_USE.zh-CN.md"):
        if not (release / guide).is_file():
            raise ValueError(f"Missing installation guide: {guide}")
    public.mkdir()
    for name in names:
        shutil.copyfile(release / name, public / name)
    evidence_name = f"ai-security-runtime-v{__version__}-release-evidence.zip"
    with zipfile.ZipFile(public / evidence_name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, name in evidence:
            archive.write(path, name)
    evidence_digest = hashlib.sha256((public / evidence_name).read_bytes()).hexdigest()
    (public / "SHA256SUMS.txt").write_text("\n".join(sums + [f"{evidence_digest}  {evidence_name}"]) + "\n", encoding="utf-8")
    notes = root / "dist/release-notes.md"
    notes.write_text(
        "## 下载安装包\n\n"
        "按电脑类型点下面的下载入口，解压完整包使用；无需安装 Python。\n\n"
        "| 下载入口 | 怎么选 | 校验 |\n| --- | --- | --- |\n"
        + "\n".join(rows)
        + f"\n\nMac 在「关于本机」查看芯片；也可运行 `uname -m`：`arm64` 选 Apple Silicon，`x86_64` 选 Intel。\n\n"
        f"[安装与使用说明](https://github.com/{REPOSITORY}/blob/v{__version__}/README.md) · "
        f"[完整校验清单]({base}/SHA256SUMS.txt)\n\n"
        "GitHub 的 **Source code** 是源码压缩包，安装请选择上面的平台包。当前为 Developer Alpha 试用版。\n\n"
        "<details>\n<summary>维护者：验收证据与机器元数据</summary>\n\n"
        f"[验收证据 ZIP]({base}/{evidence_name}) 包含原生及专项验收 JSON、安装指南、Homebrew Formula 和 WinGet YAML；普通安装无需下载。\n\n"
        f"[release-manifest.json]({base}/release-manifest.json) 保留供工具读取。证据 ZIP 校验值在完整校验清单中。\n\n"
        "</details>\n", encoding="utf-8")
    return public, notes


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    public, notes = prepare(args.root)
    print(public)
    print(notes)
