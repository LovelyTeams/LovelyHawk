#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: gpui-package-macos.sh \
  --binary PATH --output-dir DIR --notices PATH --sbom PATH --license PATH \
  [--version 1.0.0]

Creates LovelyRes-<version>-macos-universal.app.zip and its .sha256 file.
The input binary must already contain both arm64 and x86_64 slices.
EOF
}

binary=''
output_dir=''
notices=''
sbom=''
license_file=''
version='1.0.0'

while (($#)); do
  case "$1" in
    --binary) binary=${2:?missing value for --binary}; shift 2 ;;
    --output-dir) output_dir=${2:?missing value for --output-dir}; shift 2 ;;
    --notices) notices=${2:?missing value for --notices}; shift 2 ;;
    --sbom) sbom=${2:?missing value for --sbom}; shift 2 ;;
    --license) license_file=${2:?missing value for --license}; shift 2 ;;
    --version) version=${2:?missing value for --version}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$binary" && -n "$output_dir" && -n "$notices" && -n "$sbom" && -n "$license_file" ]] || {
  usage >&2
  exit 2
}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || {
  echo "Invalid version: $version" >&2
  exit 2
}

resolve_file() {
  local source_path=$1
  local source_dir
  source_dir=$(cd "$(dirname "$source_path")" && pwd -P)
  printf '%s/%s\n' "$source_dir" "$(basename "$source_path")"
}

binary=$(resolve_file "$binary")
notices=$(resolve_file "$notices")
sbom=$(resolve_file "$sbom")
license_file=$(resolve_file "$license_file")
mkdir -p -- "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)

architectures=$(lipo -archs "$binary")
[[ " $architectures " == *' arm64 '* && " $architectures " == *' x86_64 '* ]] || {
  echo "Universal binary must contain arm64 and x86_64; found: $architectures" >&2
  exit 1
}

stage=$(mktemp -d "${output_dir}/.gpui-stage.XXXXXX")
cleanup() {
  case "$stage" in
    "${output_dir}"/.gpui-stage.*) rm -rf -- "$stage" ;;
    *) echo "Refusing to remove unexpected staging path: $stage" >&2; return 1 ;;
  esac
}
trap cleanup EXIT

app="${stage}/LovelyRes.app"
macos_dir="${app}/Contents/MacOS"
resources_dir="${app}/Contents/Resources"
mkdir -p -- "$macos_dir" "$resources_dir"
install -m 0755 -- "$binary" "${macos_dir}/LovelyRes"
install -m 0644 -- "$license_file" "${resources_dir}/LICENSE"
install -m 0644 -- "$notices" "${resources_dir}/THIRD_PARTY_NOTICES.txt"
install -m 0644 -- "$sbom" "${resources_dir}/SBOM.cdx.json"

cat > "${app}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key><string>LovelyRes</string>
  <key>CFBundleExecutable</key><string>LovelyRes</string>
  <key>CFBundleIdentifier</key><string>com.lovelyres.gpui</string>
  <key>CFBundleName</key><string>LovelyRes</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${version}</string>
  <key>CFBundleVersion</key><string>${version}</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
plutil -lint "${app}/Contents/Info.plist"

archive="${output_dir}/LovelyRes-${version}-macos-universal.app.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
(
  cd "$output_dir"
  shasum -a 256 "LovelyRes-${version}-macos-universal.app.zip" \
    > "LovelyRes-${version}-macos-universal.app.zip.sha256"
)
printf 'Created %s\n' "$archive"
