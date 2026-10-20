#!/bin/sh
# Opt-in macOS trial delivery. Never invokes sudo or changes quarantine policy.
set -eu
umask 077

case "${1-}" in
  --help|-h)
    printf '%s\n' '用法：sh install.sh cursor|codex' \
      '安装产品专属运行环境和编辑器连接；不会扫描项目或自动修复。' \
      '首次安装需要联网。安装后请完全退出并重启编辑器。'
    exit 0 ;;
  cursor|codex) host=$1 ;;
  *) printf '%s\n' '请指定编辑器：cursor 或 codex。' >&2; exit 2 ;;
esac
if [ "$#" -ne 1 ]; then
  printf '%s\n' '只接受一个编辑器参数；高级查询请使用安装后的 security-check。' >&2
  exit 2
fi
if [ "$(uname -s)" != Darwin ]; then
  printf '%s\n' '这个安装入口只支持 macOS。' >&2
  exit 2
fi
machine=$(uname -m)
# A terminal running under Rosetta still needs the native Apple Silicon build.
if [ "$machine" = x86_64 ] && [ "$(/usr/sbin/sysctl -in hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
  machine=arm64
fi
case "$machine" in
  arm64)
    platform=macos-arm64
    python_arch=aarch64
    python_sha=22625deaf5757e7c266cf1a096c9151a06b598b1e14632a2ec9993d58ec5fe84 ;;
  x86_64)
    platform=macos-x64
    python_arch=x86_64
    python_sha=a84ac7a36d465bc6eb68db84540fdb5da04333900e2c3cb34b5d454f2022048c ;;
  *) printf '%s\n' '此 Mac 的处理器架构暂不支持。' >&2; exit 2 ;;
esac

case "${HOME-}" in /*) ;; *) printf '%s\n' '无法确认用户主目录。' >&2; exit 1 ;; esac
root="$HOME/.local/share/AI-Security-Runtime-macos-trial"
# Fail closed for unexpected path aliases, including an existing managed root.
check_path() {
  check=$1
  while [ "$check" != / ] && [ -n "$check" ]; do
    if [ -L "$check" ]; then
      printf '%s\n' '安装路径含符号链接，已停止以保护已有文件。' >&2
      exit 1
    fi
    check=${check%/*}
  done
}
check_path "$root"
mkdir -p "$root"
if [ "$(stat -f %u "$root")" != "$(id -u)" ]; then
  printf '%s\n' '产品目录不属于当前用户，已停止。' >&2
  exit 1
fi
permissions=$(stat -f %Lp "$root")
case "$permissions" in *[2367][0-7]|*[0-7][2367])
  printf '%s\n' '产品目录允许其他用户写入，已停止；请联系支持检查目录权限。' >&2
  exit 1 ;;
esac
lock="$root/.install-lock"
if ! mkdir "$lock" 2>/dev/null; then
  printf '%s\n' "已有安装任务或上次安装意外中断。请确认其他安装已结束；若没有安装进程，只删除空目录 $lock 后重试。" >&2
  exit 1
fi
trap 'status=$?; rmdir "$lock" 2>/dev/null || true; if [ "$status" -ne 0 ]; then printf "%s\n" "[诊断] 本次下载和诊断文件保留在 ${stage:-$root}，可将报错和该路径反馈给支持。" >&2; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
stage=$(mktemp -d "$root/download-XXXXXXXX")
download() {
  curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 30 --retry 2 --output "$2" "$1"
}
verify_sha() {
  observed=$(shasum -a 256 "$1")
  observed=${observed%% *}
  if [ "$observed" != "$2" ]; then
    printf '%s\n' '下载内容 SHA256 不一致，已停止；重新运行同一安装命令可重试。' >&2
    exit 1
  fi
}
printf '%s\n' "[安装] 正在为 $host 准备 macOS 试用版；不会扫描项目或自动修复。"
python_root="$root/python-3.12.12-20260211-$platform"
check_path "$python_root"
if [ -e "$python_root" ]; then
  check_path "$python_root/.download-sha256"
  check_path "$python_root/.python-sha256"
  if [ ! -f "$python_root/.download-sha256" ] || [ ! -f "$python_root/.python-sha256" ] || [ "$(cat "$python_root/.download-sha256")" != "$python_sha" ]; then
    printf '%s\n' '已有 Python 目录没有匹配的归属记录，已保留并停止。' >&2
    exit 1
  fi
  verify_sha "$python_root/bin/python3" "$(cat "$python_root/.python-sha256")"
else
  printf '%s\n' '[安装] 正在下载产品专属 Python，您无需安装或配置系统 Python。'
  python_url="https://github.com/astral-sh/python-build-standalone/releases/download/20260211/cpython-3.12.12%2B20260211-$python_arch-apple-darwin-install_only_stripped.tar.gz"
  download "$python_url" "$stage/python.tar.gz"
  verify_sha "$stage/python.tar.gz" "$python_sha"
  # The upstream archive is immutable and verified against the literal digest
  # above before using the platform extractor. Extraction uses a fresh directory.
  mkdir "$stage/python-extract"
  tar -xzf "$stage/python.tar.gz" -C "$stage/python-extract"
  if [ ! -x "$stage/python-extract/python/bin/python3" ]; then
    printf '%s\n' 'Python 包缺少可运行解释器。' >&2
    exit 1
  fi
  printf '%s\n' "$python_sha" > "$stage/python-extract/python/.download-sha256"
  python_binary_sha=$(shasum -a 256 "$stage/python-extract/python/bin/python3")
  printf '%s\n' "${python_binary_sha%% *}" > "$stage/python-extract/python/.python-sha256"
  mv "$stage/python-extract/python" "$python_root"
fi
python="$python_root/bin/python3"
if ! "$python" -I -c 'import ssl, sys, venv; assert sys.version_info[:2] == (3, 12)' ; then
  printf '%s\n' 'Mac 未能启动产品专属 Python；请将上述错误反馈给文档页支持入口。当前安装尚未完成。' >&2
  exit 1
fi
base=https://github.com/pikachu-cxy/Ai-security-check/releases/download/macos-trial-v0.3.8.1
asset="ai-security-runtime-macos-trial-$platform.tar.gz"
printf '%s\n' '[安装] 正在下载并校验产品和离线依赖。'
download "$base/$asset" "$stage/$asset"
download "$base/$asset.sha256" "$stage/$asset.sha256"
# Only the uniquely named regular installer file is copied at bootstrap. All
# remaining archive members are validated/extracted by that verified installer.
payload_sha=$("$python" -I - "$stage/$asset" "$stage/$asset.sha256" "$stage/managed_install.py" "$asset" <<'PY'
import hashlib, pathlib, re, sys, tarfile
archive, checksum, target, name = map(pathlib.Path, sys.argv[1:])
text = checksum.read_text(encoding="ascii")
match = re.fullmatch(r"([a-f0-9]{64})(?:[ \t]+\*?" + re.escape(str(name)) + r")?\s*", text)
if not match:
    raise SystemExit("安装包 SHA256 文件格式或文件名不匹配。")
expected = match.group(1)
with archive.open("rb") as stream:
    observed = hashlib.file_digest(stream, "sha256").hexdigest()
if observed != expected:
    raise SystemExit("安装包 SHA256 不一致，已停止。")
with tarfile.open(archive, "r:gz") as bundle:
    matches = [item for item in bundle if item.name == "managed_install.py"]
    if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size < 1_000_000:
        raise SystemExit("安装包缺少唯一的普通安装脚本。")
    with bundle.extractfile(matches[0]) as stream, target.open("xb") as output:
        output.write(stream.read(1_000_000))
print(expected)
PY
)
"$python" -I "$stage/managed_install.py" --archive "$stage/$asset" --sha256 "$payload_sha" \
  --root "$root" --platform "$platform" --host "$host"
if ! "$python" -I - "$root" "$stage" <<'PY'
import pathlib, shutil, sys
root, stage = (pathlib.Path(p) for p in sys.argv[1:])
# Remove only this invocation's fresh staging directory, never versions, Python,
# host configuration, or a computed ancestor. Failed installations keep staging.
if (root.is_symlink() or stage.is_symlink() or stage.parent != root
        or not stage.name.startswith("download-") or stage.resolve().parent != root.resolve()):
    raise SystemExit("Temporary directory safety check failed.")
shutil.rmtree(stage)
PY
then
  printf '%s\n' "[提示] 安装已完成；本次临时下载目录仍保留在 $stage。"
fi
