#!/usr/bin/env python3
"""Install the opt-in macOS wheel delivery without changing project files.

This installer deliberately lives outside security_runtime. The existing host
installer remains the sole owner of MCP, Hooks, Skills and component preparation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import uuid
import venv

RELEASE_TAG = "macos-trial-v0.3.11"
SCHEMA = "macos-trial-payload-v1"
HEX = re.compile(r"[a-f0-9]{64}")
MAX_BYTES = 1024 * 1024 * 1024
MAX_FILES = 10000
ROOT_SCHEMA = "macos-trial-root-v1"


class InstallError(Exception):
    """A bounded diagnostic suitable for the user's installation log."""


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def no_links(path):
    path = Path(os.path.abspath(path))
    for item in [*reversed(path.parents), path]:
        if item.is_symlink():
            raise InstallError("安装路径含符号链接，已停止以保护已有文件。")
        if item.exists() and item != path and not item.is_dir():
            raise InstallError("安装路径的父目录不是目录。")
    return path


def relative_name(value):
    if not isinstance(value, str) or "\\" in value or any(ord(c) < 32 for c in value):
        raise InstallError("安装包包含无效路径。")
    name = PurePosixPath(value)
    if not value or name.is_absolute() or any(p in {"", ".", ".."} for p in value.split("/")):
        raise InstallError("安装包路径超出允许范围。")
    return name.as_posix()


def read_json(path):
    no_links(path)
    if not path.is_file() or path.stat().st_size > 4_000_000:
        raise InstallError("安装元数据缺失或过大。")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InstallError("安装元数据含重复字段。")
            result[key] = value
        return result
    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise InstallError("安装元数据格式错误。")
    return value


def atomic_json(path, value):
    no_links(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".receipt-", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write((json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n").encode())
    os.replace(temporary, path)


def safe_extract(archive, destination, expected_sha):
    """Validate the complete tar before creating any member on disk."""
    no_links(archive)
    no_links(destination)
    if not HEX.fullmatch(expected_sha) or digest(archive) != expected_sha:
        raise InstallError("下载包 SHA256 不一致，请重试安装。")
    if destination.exists():
        raise InstallError("解包目录已存在，拒绝覆盖。")
    with tarfile.open(archive, "r:gz") as bundle:
        names, folded, total = {}, set(), 0
        for entry in bundle:
            if len(names) >= MAX_FILES:
                raise InstallError("安装包文件数量超出限制。")
            name = relative_name(entry.name.rstrip("/") if entry.isdir() else entry.name)
            # Reject links, devices, FIFOs and sparse entries, even if they
            # would resolve inside the destination.
            if not (entry.isfile() or entry.isdir()) or entry.issparse():
                raise InstallError("安装包包含链接或特殊文件。")
            normalized = unicodedata.normalize("NFC", name).casefold()
            if name in names or normalized in folded:
                raise InstallError("安装包包含重复或大小写冲突路径。")
            names[name] = entry
            folded.add(normalized)
            total += entry.size
            if total > MAX_BYTES or entry.size < 0:
                raise InstallError("安装包解压大小超出限制。")
        if not names:
            raise InstallError("安装包为空。")
        for name in names:
            for parent in PurePosixPath(name).parents:
                if str(parent) in names and not names[str(parent)].isdir():
                    raise InstallError("安装包包含文件与目录冲突。")
        destination.mkdir(mode=0o700)
        for name, entry in names.items():
            target = destination.joinpath(*PurePosixPath(name).parts)
            if entry.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = bundle.extractfile(entry)
            if source is None:
                raise InstallError("安装包文件无法读取。")
            with source, target.open("xb") as output:
                remaining = entry.size
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise InstallError("安装包文件不完整。")
                    output.write(block)
                    remaining -= len(block)
            target.chmod(0o600)
    return destination


def verify_payload(payload, platform):
    manifest = read_json(payload / "manifest.json")
    if (manifest.get("schema") != SCHEMA or manifest.get("release_tag") != RELEASE_TAG
            or manifest.get("platform") != platform or manifest.get("version") != "0.3.11"
            or not HEX.fullmatch(str(manifest.get("build_id", "")))
            or not re.fullmatch(r"[a-f0-9]{40}", str(manifest.get("source_commit", "")))):
        raise InstallError("安装包版本、平台或构建身份不匹配。")
    files = manifest.get("files")
    if not isinstance(files, dict) or not {"requirements.txt", "managed_install.py"}.issubset(files):
        raise InstallError("安装包文件清单缺失。")
    actual = set()
    for path in payload.rglob("*"):
        no_links(path)
        if path.is_file() and path != payload / "manifest.json":
            actual.add(path.relative_to(payload).as_posix())
    if actual != set(files):
        raise InstallError("安装包文件清单与内容不一致。")
    for name, expected in files.items():
        relative_name(name)
        if not isinstance(expected, str) or not HEX.fullmatch(expected):
            raise InstallError("安装包文件校验值格式错误。")
        if digest(payload / name) != expected:
            raise InstallError("安装包内文件校验失败。")
        if name not in {"requirements.txt", "managed_install.py"} and not (
                name.startswith("wheelhouse/") and len(PurePosixPath(name).parts) == 2 and name.endswith(".whl")):
            raise InstallError("安装包包含未允许的文件。")
    if digest(Path(__file__)) != files["managed_install.py"]:
        raise InstallError("安装器与安装包版本不一致。")
    requirements = (payload / "requirements.txt").read_text(encoding="utf-8").splitlines()
    pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9_.+!-]+ --hash=sha256:[a-f0-9]{64}"
    if not requirements or any(not re.fullmatch(pattern, line) for line in requirements):
        raise InstallError("离线依赖必须全部固定版本和 SHA256。")
    return manifest


def run(command, *, cwd, timeout=300):
    environment = dict(os.environ, PYTHONNOUSERSITE="1", PIP_CONFIG_FILE=os.devnull,
                       PIP_NO_INPUT="1", PIP_DISABLE_PIP_VERSION_CHECK="1")
    # Never reuse a caller's project/global Runtime binding for installation.
    for key in ("PYTHONPATH", "PYTHONHOME", "SECURITY_RUNTIME_GLOBAL",
                "SECURITY_RUNTIME_WORKSPACE", "SECURITY_RUNTIME_INTEGRATION",
                "SECURITY_RUNTIME_HOST"):
        environment.pop(key, None)
    return subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=timeout, check=False)


def json_command(command, *, cwd, timeout=180):
    result = run(command, cwd=cwd, timeout=timeout)
    if len(result.stdout) > 2_000_000:
        raise InstallError("安装程序返回的状态过大。")
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise InstallError("安装程序未返回可验证的状态。") from None
    if not isinstance(value, dict):
        raise InstallError("安装程序状态格式错误。")
    return result.returncode, value


def verify_identity(python, manifest, root):
    code, info = json_command([str(python), "-I", "-m", "security_runtime.cli", "runtime-info", "--json"], cwd=root)
    identity = info.get("build_identity", {})
    if (code or identity.get("status") != "IDENTIFIED"
            or identity.get("delivery_kind") != "managed-wheel"
            or identity.get("integrity") != "PACKAGE_CONTENT_HASHES_VERIFIED"
            or any(identity.get(key) != manifest[key] for key in ("version", "build_id", "source_commit"))
            or info.get("version") != manifest["version"]):
        raise InstallError("已安装程序的构建身份校验失败，未切换现有入口。")
    return info


def validate_root(root):
    root = no_links(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir():
        raise InstallError("产品目录不是目录。")
    if os.name != "nt" and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o022):
        raise InstallError("产品目录必须由当前用户拥有，且其他用户不可写。")
    marker = root / ".macos-trial-owner.json"
    if marker.exists():
        if read_json(marker) != {"schema": ROOT_SCHEMA}:
            raise InstallError("产品目录归属不明，拒绝覆盖。")
    else:
        if (root / "security-check").exists() or (root / "active.json").exists() or (root / "versions").exists():
            raise InstallError("检测到没有归属记录的安装，拒绝覆盖。")
        atomic_json(marker, {"schema": ROOT_SCHEMA})
    launcher = no_links(root / "security-check")
    active = no_links(root / "active.json")
    pending_first_install = launcher.exists() and not active.exists() and launcher.read_bytes() == launcher_bytes(root)
    if launcher.exists() != active.exists() and not pending_first_install:
        raise InstallError("产品启动入口与归属记录不一致，已保留文件。")
    if launcher.exists() and active.exists():
        receipt = read_json(active)
        if receipt.get("schema") != ROOT_SCHEMA or receipt.get("launcher_sha256") != digest(launcher):
            raise InstallError("已有启动入口被修改，已保留，拒绝覆盖。")
    return root


def launcher_bytes(root):
    # The entry point is identical for every candidate in this channel.
    # Activation therefore needs one atomic active.json replacement, rather
    # than a two-file pointer update that can disagree after interruption.
    program = """import json, os, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
state_path = root / "active.json"
if any(p.is_symlink() for p in [root, *root.parents, state_path]) or state_path.stat().st_size > 16384:
    raise SystemExit("Runtime installation state is unsafe; retry the documented installer.")
state = json.loads(state_path.read_bytes())
build = state.get("build_id", "")
if state.get("schema") != "macos-trial-root-v1" or not isinstance(build, str) or not re.fullmatch("[a-f0-9]{64}", build):
    raise SystemExit("Runtime installation state is invalid; retry the documented installer.")
executable = root / "versions" / build / "venv" / "bin" / "python"
if any(p.is_symlink() for p in executable.parents):
    raise SystemExit("Runtime environment directory contains a link.")
os.execv(str(executable), [str(executable), "-I", "-m", "security_runtime.cli", *sys.argv[2:]])
"""
    return ("#!/bin/sh\n# AI Security Runtime macOS trial managed launcher\nexec "
            + shlex.quote(sys.executable) + " -I -c " + shlex.quote(program) + " "
            + shlex.quote(str(root)) + ' "$@"\n').encode()


def preflight_launcher(root):
    launcher = no_links(root / "security-check")
    data = launcher_bytes(root)
    if launcher.exists() and launcher.read_bytes() != data:
        raise InstallError("已有入口使用不同的运行环境；已保留，请联系支持确认升级路径。")
    return data


def activate(root, owner, host, manifest):
    validate_root(root)
    launcher = root / "security-check"
    data = preflight_launcher(root)
    existed = launcher.exists()
    if not existed:
        with tempfile.NamedTemporaryFile(dir=root, prefix=".launcher-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.chmod(0o700)
        os.replace(temporary, launcher)
    try:
        atomic_json(root / "active.json", {**owner, "host": host, "version": manifest["version"],
                    "launcher_sha256": hashlib.sha256(data).hexdigest()})
    except OSError:
        # Only a first-install launcher needs recovery. An existing launcher's
        # active pointer remains intact because atomic_json uses os.replace.
        if not existed and not launcher.is_symlink() and launcher.read_bytes() == data:
            launcher.unlink()
        raise


def install(payload, root, host, platform):
    manifest = verify_payload(payload, platform)
    root = validate_root(root)
    # The immutable entry point includes the bootstrap interpreter path.
    # Refuse an incompatible delivery before touching editor configuration.
    preflight_launcher(root)
    versions = no_links(root / "versions")
    versions.mkdir(mode=0o700, exist_ok=True)
    slot = no_links(versions / manifest["build_id"])
    owner = {"schema": ROOT_SCHEMA, "build_id": manifest["build_id"],
             "platform": platform, "source_commit": manifest["source_commit"]}
    marker = slot / "owner.json"
    if slot.exists():
        if read_json(marker) != owner:
            raise InstallError("候选版本目录归属不匹配，拒绝覆盖。")
    else:
        slot.mkdir(mode=0o700)
        atomic_json(marker, owner)
    environment = no_links(slot / "venv")
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = slot / "installed.json"
    if installed.exists():
        receipt = read_json(installed)
        if receipt != owner:
            raise InstallError("已有版本安装记录不匹配。")
    else:
        if environment.exists():
            # Interrupted attempts are evidence. Never recursively remove them.
            # A fresh attempt can be retried without erasing any old environment.
            failed = slot / ("venv-incomplete-" + uuid.uuid4().hex)
            environment.rename(failed)
        print("[安装] 正在建立产品专属环境并安装已校验的离线依赖。", flush=True)
        # PBS on macOS locates its shared library relative to the interpreter.
        # Preserve normal venv interpreter links; moving/copying the binary can
        # make @executable_path point at a directory without that library.
        venv.EnvBuilder(with_pip=True, symlinks=sys.platform == "darwin").create(environment)
        result = run([str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
                      "install", "--no-index", "--no-cache-dir", "--find-links", str(payload / "wheelhouse"),
                      "--require-hashes", "--only-binary=:all:", "-r", str(payload / "requirements.txt")],
                     cwd=slot, timeout=600)
        no_links(slot / "pip-install.log").write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise InstallError("离线依赖安装失败；日志保留在候选版本的 pip-install.log，重新运行安装命令可重试。")
        verify_identity(python, manifest, root)
        atomic_json(installed, owner)
    verify_identity(python, manifest, root)
    validate_root(root)
    preflight_launcher(root)
    print(f"[安装] 程序版本 {manifest['version']}，构建 {manifest['build_id'][:12]} 已校验。正在配置 {host.title()}。", flush=True)
    code, result = json_command([str(python), "-I", "-m", "security_runtime.cli", "install", host, "--json"],
                                cwd=root, timeout=240)
    atomic_json(slot / f"{host}-install-receipt.json", result)
    local = result.get("installation", {})
    # Exit 2 may mean usable local files but pending scanner downloads. The
    # existing installer receipt, not a friendly message, decides local success.
    if (code not in (0, 2) or local.get("contract") != "personal-install-v1"
            or local.get("status") != "INSTALLED" or local.get("local_files_ready") is not True):
        diagnostics = result.get("diagnostics", [])
        detail = ", ".join(str(x) for x in diagnostics[:8]) if isinstance(diagnostics, list) else ""
        raise InstallError("编辑器配置未完成；已有文件及候选程序已保留，请查看配置诊断：" + detail)
    activate(root, owner, host, manifest)
    launcher = root / "security-check"
    print(f"[完成] 产品 {manifest['version']} 和 {host.title()} 本地连接配置已安装。", flush=True)
    print(local.get("message", "请重启编辑器后验证连接。"), flush=True)
    readiness = result.get("scan_readiness", {})
    background = result.get("background_preparation", {})
    print("[组件] " + ("已准备完成。" if local.get("scan_ready") is True else
          f"尚未全部准备完成；准备任务状态：{background.get('status', 'UNKNOWN')}。"
          + str(readiness.get("message", ""))), flush=True)
    print(f"[下一步] 完全退出并重启 {host.title()}，回到文档页发送“检查安装状态”的请求；编辑器真实连接和项目路径需要重启后确认。", flush=True)
    print("[查询进度] " + shlex.quote(str(launcher)) + " preparation watch", flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="AI Security Runtime macOS trial installer")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=("macos-arm64", "macos-x64"))
    parser.add_argument("--host", required=True, choices=("cursor", "codex"))
    args = parser.parse_args(argv)
    try:
        if sys.platform != "darwin":
            raise InstallError("此入口只支持 macOS。")
        root = no_links(args.root)
        staging = no_links(args.archive.parent)
        payload = Path(tempfile.mkdtemp(prefix="payload-", dir=staging)) / "contents"
        safe_extract(args.archive, payload, args.sha256)
        install(payload, root, args.host, args.platform)
        return 0
    except (InstallError, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"[未完成] {error}", file=sys.stderr)
        print("候选文件和现有入口已保留。处理以上原因后重新运行同一安装命令；不要手动删除编辑器配置。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
