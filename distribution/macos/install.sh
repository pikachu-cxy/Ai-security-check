#!/bin/sh
# Official macOS release delivery. Never invokes sudo or changes quarantine policy.
set -eu
umask 077

case "${1-}" in
  --help|-h)
    printf '%s\n' '用法：sh install.sh cursor|codex [本地安装包目录]' \
      '安装产品专属运行环境和编辑器连接；不会扫描项目或自动修复。' \
      '首次安装需要联网。安装后请完全退出并重启编辑器。'
    exit 0 ;;
  cursor|codex) host=$1 ;;
  *) printf '%s\n' '请指定编辑器：cursor 或 codex。' >&2; exit 2 ;;
esac
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  printf '%s\n' '用法：sh install.sh cursor|codex [本地安装包目录]' >&2
  exit 2
fi
payload_dir=
if [ "$#" -eq 2 ]; then
  payload_dir=$(CDPATH= cd -- "$2" && pwd -P) || exit 2
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
    ;;
  x86_64)
    platform=macos-x64
    ;;
  *) printf '%s\n' '此 Mac 的处理器架构暂不支持。' >&2; exit 2 ;;
esac

case "${HOME-}" in /*) ;; *) printf '%s\n' '无法确认用户主目录。' >&2; exit 1 ;; esac
root="$HOME/.local/share/AI-Security-Runtime-downloads"
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
  download_url=$1
  download_target=$2
  printf '%s\n' "[下载] ${download_target##*/}" >&2
  if curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 15 --max-time 600 \
    --output "$download_target.part" "$download_url"; then
    mv "$download_target.part" "$download_target"
    return 0
  else
    download_error=$?
  fi
  case "$download_error" in
    5|6|7|16|18|28|35|52|55|56|92)
      printf '%s\n' '[失败] 网络连接或传输异常，请检查能否访问 GitHub 及其下载服务，并检查代理/VPN 设置。网络恢复后重新运行安装命令。' >&2 ;;
    22)
      printf '%s\n' '[失败] 下载服务返回 HTTP 错误，请查看上方状态码；若为 404，请核对发行文件或将链接反馈给支持。' >&2 ;;
    60)
      printf '%s\n' '[失败] HTTPS 证书验证失败，请检查系统时间、证书和代理设置。' >&2 ;;
    *) printf '%s\n' '[失败] 下载未完成，请查看上方错误信息。' >&2 ;;
  esac
  printf '%s\n' "[诊断] ${download_target##*/}（curl $download_error）：$download_url" \
    '已停止安装，不自动重试；下载内容仍须通过校验。' >&2
  return "$download_error"
}
verify_sha() {
  observed=$(shasum -a 256 "$1")
  observed=${observed%% *}
  if [ "$observed" != "$2" ]; then
    printf '%s\n' '下载内容 SHA256 不一致，已停止；重新运行同一安装命令可重试。' >&2
    exit 1
  fi
}
version=0.3.12
base="https://github.com/pikachu-cxy/Ai-security-check/releases/download/v$version"
asset="ai-security-runtime-v$version-$platform.tar.gz"
printf '%s\n' "[安装] 正在为 $host 准备 $version macOS 正式版；不会扫描项目或自动修复。"
printf '%s\n' '[安装] 正在下载并校验产品和离线依赖。'
if [ -n "$payload_dir" ]; then
  cp "$payload_dir/$asset" "$stage/$asset"
  cp "$payload_dir/$asset.sha256" "$stage/$asset.sha256"
else
# Fetch the small checksum first; reuse archives only after matching it.
download "$base/$asset.sha256" "$stage/$asset.sha256"
expected_sha=$(awk 'NR == 1 {print $1}' "$stage/$asset.sha256")
reused=false
case "$expected_sha" in
  *[!a-f0-9]*|'') ;;
  *) if [ "${#expected_sha}" -eq 64 ]; then
    for previous in "$root"/download-*/"$asset"; do
      [ -f "$previous" ] || continue
      check_path "$previous"
      previous_sha=$(shasum -a 256 "$previous")
      if [ "${previous_sha%% *}" = "$expected_sha" ]; then
        cp "$previous" "$stage/$asset"
        printf '%s\n' '[恢复] 已复用校验匹配的产品包，无需重新下载。'
        reused=true
        break
      fi
    done
  fi ;;
esac
if [ "$reused" = false ]; then download "$base/$asset" "$stage/$asset"; fi
fi
# Verify before extraction or execution. Never bypass macOS security policy.
expected_sha=$(awk 'NR == 1 {print $1}' "$stage/$asset.sha256")
case "$expected_sha" in
  *[!a-f0-9]*|'') printf '%s\n' 'SHA256 文件格式无效，已停止。' >&2; exit 1 ;;
esac
if [ "${#expected_sha}" -ne 64 ] || [ "$(wc -l < "$stage/$asset.sha256" | tr -d ' ')" -gt 1 ]; then
  printf '%s\n' 'SHA256 文件格式无效，已停止。' >&2; exit 1
fi
verify_sha "$stage/$asset" "$expected_sha"
mkdir "$stage/extracted"
tar -tzf "$stage/$asset" > "$stage/members.txt"
if ! awk '
  /^security-check(\/|$)/ && $0 !~ /(^|\/)\.\.(\/|$)/ { next }
  { bad=1 }
  END { exit bad }
' "$stage/members.txt"; then
  printf '%s\n' '安装包路径异常，已停止。' >&2; exit 1
fi
tar -xzf "$stage/$asset" -C "$stage/extracted"
launcher="$stage/extracted/security-check/security-check"
if [ ! -x "$launcher" ] || [ -L "$launcher" ]; then
  printf '%s\n' '正式包缺少可执行程序，已停止。' >&2; exit 1
fi
printf '%s\n' '[安装] 已校验正式版完整包，正在接入编辑器。'
"$launcher" install "$host"
printf '%s\n' "[完成] 请重启 $host，并核对实际版本和构建。安装包保留在 $stage。"
