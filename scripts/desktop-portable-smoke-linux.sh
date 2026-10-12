#!/usr/bin/env bash
# Runs a portable Linux package the way an operator would, mirroring
# scripts/desktop-portable-smoke.ps1: checksum and exact file set, extraction
# into a fresh folder whose path has spaces and Chinese characters, launch
# with an empty home directory under a virtual display and window manager,
# wait until the page reports it rendered, close through the window manager,
# and require a clean exit with all state under data/ beside the executable.
# Anything written into the home directory is listed and fails the run.
#
#   scripts/desktop-portable-smoke-linux.sh <archive.tar.gz>
#
# Needs Xvfb, openbox, wmctrl and dbus-run-session.
set -euo pipefail

archive=$(readlink -f "${1:?usage: desktop-portable-smoke-linux.sh <archive.tar.gz>}")
startup_timeout=${STARTUP_TIMEOUT_SECONDS:-120}
shutdown_timeout=${SHUTDOWN_TIMEOUT_SECONDS:-30}
for tool in Xvfb openbox wmctrl dbus-run-session sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

(cd "$(dirname "$archive")" && sha256sum --quiet -c "$(basename "$archive").sha256")
work=$(mktemp -d "${TMPDIR:-/tmp}/LovelyHawk 便携 空格 测试-XXXXXX")
extract="$work/解压 目录"
home="$work/home"
mkdir -p "$extract" "$home"
tar -C "$extract" -xzf "$archive"
package=$(find "$extract" -mindepth 1 -maxdepth 1 -type d)
[[ $(printf '%s\n' "$package" | wc -l) == 1 ]] || { echo "the archive must hold one folder" >&2; exit 1; }
files=$(cd "$package" && find . -mindepth 1 | sort | tr '\n' ' ')
[[ $files == "./LICENSE ./PACKAGE_MANIFEST.json ./README.txt ./SBOM.cdx.json ./THIRD_PARTY_LICENSES_RUST.txt ./THIRD_PARTY_NOTICES.md ./lovelyhawk " ]] || { echo "unexpected package contents: $files" >&2; exit 1; }
for file in LICENSE README.txt SBOM.cdx.json THIRD_PARTY_LICENSES_RUST.txt THIRD_PARTY_NOTICES.md lovelyhawk; do
  expected=$(grep -o "\"path\": \"$file\", \"size\": [0-9]*, \"sha256\": \"[0-9a-f]*\"" "$package/PACKAGE_MANIFEST.json" | sed 's/.*"sha256": "\(.*\)"/\1/')
  actual=$(sha256sum "$package/$file" | cut -d' ' -f1)
  [[ -n $expected && $expected == "$actual" ]] || { echo "manifest hash mismatch for $file" >&2; exit 1; }
done

nonce=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
temporary=$(readlink -f "${TMPDIR:-/tmp}")
control="$temporary/lovelyhawk-smoke-$nonce"
mkdir "$control"
display=":$((90 + RANDOM % 9))"
Xvfb "$display" -screen 0 1600x1000x24 -nolisten tcp >/dev/null 2>&1 &
xvfb=$!
cleanup() {
  [[ -n ${wm:-} ]] && kill "$wm" 2>/dev/null || true
  kill "$xvfb" 2>/dev/null || true
  rm -rf -- "$control"
}
trap cleanup EXIT
sleep 1
DISPLAY=$display HOME=$home openbox >/dev/null 2>&1 &
wm=$!
sleep 1
# openbox itself may write its settings under the home directory; those are
# listed separately so they are not blamed on the application.
wm_files=$(cd "$home" && find . -mindepth 1 | sort)

started=$(date +%s)
env -i PATH="$PATH" DISPLAY="$display" HOME="$home" TMPDIR="$temporary" LANG=C.UTF-8 \
  LOVELYHAWK_SMOKE_READY_ROOT="$control" LOVELYHAWK_SMOKE_READY_NONCE="$nonce" \
  dbus-run-session -- "$package/lovelyhawk" > "$work/app.log" 2>&1 &
app=$!
until [[ -f $control/ready-$nonce.json ]]; do
  if ! kill -0 "$app" 2>/dev/null; then echo "the application exited before it rendered" >&2; tail -40 "$work/app.log" >&2; exit 1; fi
  if (( $(date +%s) - started > startup_timeout )); then echo "no readiness marker after ${startup_timeout}s" >&2; tail -40 "$work/app.log" >&2; kill "$app"; exit 1; fi
  sleep 1
done
ready_after=$(( $(date +%s) - started ))
grep -q '"status":"ready"' "$control/ready-$nonce.json"

window=$(DISPLAY=$display wmctrl -l | awk '/LovelyHawk/ {print $1; exit}')
[[ -n $window ]] || { echo "no LovelyHawk window is managed" >&2; DISPLAY=$display wmctrl -l >&2; kill "$app"; exit 1; }
DISPLAY=$display wmctrl -i -c "$window"
closed=$(date +%s)
while kill -0 "$app" 2>/dev/null; do
  if (( $(date +%s) - closed > shutdown_timeout )); then echo "the application did not exit within ${shutdown_timeout}s of closing its window" >&2; kill "$app"; exit 1; fi
  sleep 1
done
set +e
wait "$app"
exit_code=$?
set -e

[[ -d $package/data ]] || { echo "no data directory beside the executable" >&2; exit 1; }
outside=$(cd "$package" && find . -mindepth 1 -not -path './data' -not -path './data/*' | sort | tr '\n' ' ')
home_files=$(cd "$home" && find . -mindepth 1 | sort)
app_home_files=$(comm -13 <(printf '%s\n' "$wm_files") <(printf '%s\n' "$home_files") | sed '/^$/d')
data_entries=$(find "$package/data" -mindepth 1 | wc -l)

printf '{\n  "archive": "%s",\n  "exitCode": %s,\n  "readyAfterSeconds": %s,\n  "dataEntries": %s,\n  "homeWrites": %s,\n  "extractedPathHasSpacesAndCjk": true\n}\n' \
  "$(basename "$archive")" "$exit_code" "$ready_after" "$data_entries" "$(printf '%s\n' "$app_home_files" | sed '/^$/d' | wc -l)"
[[ $exit_code == 0 ]] || { echo "the application exited with $exit_code" >&2; tail -40 "$work/app.log" >&2; exit 1; }
[[ $outside == "./LICENSE ./PACKAGE_MANIFEST.json ./README.txt ./SBOM.cdx.json ./THIRD_PARTY_LICENSES_RUST.txt ./THIRD_PARTY_NOTICES.md ./lovelyhawk " ]] || { echo "files appeared outside data/: $outside" >&2; exit 1; }
if [[ -n $app_home_files ]]; then
  echo "the application wrote into the home directory:" >&2
  printf '%s\n' "$app_home_files" | head -40 >&2
  exit 1
fi
rm -rf -- "$work"
echo "Portable smoke passed."
