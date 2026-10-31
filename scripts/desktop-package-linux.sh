#!/usr/bin/env bash
# Portable Linux x64 package: the executable (UI embedded), its licenses, a
# short README and a manifest, in one tar.gz with a side-by-side checksum.
# Mirrors scripts/desktop-package-windows.ps1. Runtime state is created beside
# the executable under data/ on first launch; the package ships none.
#
#   scripts/desktop-package-linux.sh <executable> <output-directory> <inventory-directory> [version]
#
# The executable must be a release build (cargo build --release -p
# lovelyhawk-desktop --bin lovelyhawk); debug builds read automation-only
# variables and are refused. The inventory directory holds the output of
#   node scripts/desktop-third-party.mjs --target x86_64-unknown-linux-gnu --out <dir> --version <version>
# which needs the UI's node_modules, so it is usually made on the build host.
set -euo pipefail

usage='usage: desktop-package-linux.sh <executable> <output-directory> <inventory-directory> [version]'
executable=${1:?$usage}
output=${2:?$usage}
inventory=${3:?$usage}
version=${4:-0.0.3}
for file in SBOM.cdx.json THIRD_PARTY_LICENSES_RUST.txt; do
  [[ -f $inventory/$file ]] || { echo "missing $inventory/$file" >&2; exit 1; }
done
grep -q '(x86_64-unknown-linux-gnu)' "$inventory/THIRD_PARTY_LICENSES_RUST.txt" || { echo "the inventory was not made for x86_64-unknown-linux-gnu" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || { echo "invalid version '$version'" >&2; exit 1; }
config_version=$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$root/crates/lovelyhawk-desktop/tauri.conf.json")
[[ $config_version == "$version" ]] || { echo "version '$version' does not match tauri.conf.json '$config_version'" >&2; exit 1; }
[[ -f $executable ]] || { echo "missing executable '$executable'" >&2; exit 1; }
head -c 4 "$executable" | od -An -c | grep -q 'E   L   F' || { echo "'$executable' is not an ELF executable" >&2; exit 1; }
for marker in LOVELYHAWK_DEBUG_PORT LOVELYHAWK_TEST_DIALOG_ANSWERS LOVELYHAWK_TEST_CLIPBOARD_FILE LOVELYHAWK_ARCHIVE_ROOT LOVELYHAWK_DEV_SERVER; do
  if grep -aq "$marker" "$executable"; then echo "release executable still reads the debug-only variable '$marker'" >&2; exit 1; fi
done
notices="$root/ui/THIRD_PARTY_NOTICES.md"
for required in 'React 19.3.1' 'Tauri 2.12.5' '@tauri-apps/api 2.12.4' 'xterm.js 6.0.0' 'Inter 4.1' 'Cascadia Mono 2407.24'; do
  grep -qF "$required" "$notices" || { echo "third-party notices are missing '$required'" >&2; exit 1; }
done

mkdir -p "$output"
output=$(cd "$output" && pwd)
name="LovelyHawk-$version-linux-x64"
archive="$output/$name.tar.gz"
for existing in "$archive" "$archive.sha256"; do
  [[ ! -e $existing ]] || { echo "refusing to overwrite '$existing'" >&2; exit 1; }
done
stage=$(mktemp -d "$output/.desktop-stage-XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
package="$stage/$name"
mkdir "$package"
install -m 0755 "$executable" "$package/lovelyhawk"
install -m 0644 "$root/LICENSE" "$package/LICENSE"
install -m 0644 "$notices" "$package/THIRD_PARTY_NOTICES.md"
install -m 0644 "$inventory/SBOM.cdx.json" "$package/SBOM.cdx.json"
install -m 0644 "$inventory/THIRD_PARTY_LICENSES_RUST.txt" "$package/THIRD_PARTY_LICENSES_RUST.txt"
cat > "$package/README.txt" <<'README'
LovelyHawk 便携版（Linux x64）

直接运行 ./lovelyhawk，无需安装。
首次启动会在本程序旁边创建 data 文件夹，连接库、历史、案件与证据都保存在其中；
复制整个文件夹即可迁移。

运行需要系统提供 WebKitGTK 4.1 与 GTK 3（例如 Debian 12 / Ubuntu 22.04 的
libwebkit2gtk-4.1-0 与 libgtk-3-0）。同一个 data 文件夹同时只允许运行一份程序。
README

{
  printf '{\n  "schema": "lovelyhawk-portable-package/v1",\n  "product": "LovelyHawk",\n  "version": "%s",\n  "platform": "linux",\n  "arch": "x64",\n  "shell": "tauri-2.12.5",\n  "webview": "system WebKitGTK 4.1",\n  "files": [\n' "$version"
  first=1
  for file in LICENSE README.txt SBOM.cdx.json THIRD_PARTY_LICENSES_RUST.txt THIRD_PARTY_NOTICES.md lovelyhawk; do
    [[ $first == 1 ]] || printf ',\n'
    first=0
    printf '    { "path": "%s", "size": %s, "sha256": "%s" }' "$file" "$(stat -c %s "$package/$file")" "$(sha256sum "$package/$file" | cut -d' ' -f1)"
  done
  printf '\n  ]\n}\n'
} > "$package/PACKAGE_MANIFEST.json"

tar -C "$stage" --owner=0 --group=0 --numeric-owner -czf "$archive" "$name"
(cd "$output" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
echo "Portable package written to '$archive'."
