#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: gpui-package-linux.sh \
  --binary PATH --output-dir DIR --notices PATH --sbom PATH --license PATH \
  [--version 1.0.0]

Creates LovelyRes-<version>-linux-x64.tar.zst and its .sha256 file.
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

binary=$(realpath "$binary")
notices=$(realpath "$notices")
sbom=$(realpath "$sbom")
license_file=$(realpath "$license_file")
mkdir -p -- "$output_dir"
output_dir=$(realpath "$output_dir")

package_name="LovelyRes-${version}-linux-x64"
stage=$(mktemp -d "${output_dir}/.gpui-stage.XXXXXX")
cleanup() {
  case "$stage" in
    "${output_dir}"/.gpui-stage.*) rm -rf -- "$stage" ;;
    *) echo "Refusing to remove unexpected staging path: $stage" >&2; return 1 ;;
  esac
}
trap cleanup EXIT

package_root="${stage}/${package_name}"
mkdir -p -- "${package_root}/data"
install -m 0755 -- "$binary" "${package_root}/LovelyRes"
install -m 0644 -- "$license_file" "${package_root}/LICENSE"
install -m 0644 -- "$notices" "${package_root}/THIRD_PARTY_NOTICES.txt"
install -m 0644 -- "$sbom" "${package_root}/SBOM.cdx.json"
printf '%s\n' \
  'LovelyRes portable runtime data belongs in this directory.' \
  'Keep it with the executable when moving or backing up the application.' \
  > "${package_root}/data/README.txt"

archive="${output_dir}/${package_name}.tar.zst"
tar --zstd -C "$stage" -cf "$archive" "$package_name"
(
  cd "$output_dir"
  sha256sum "${package_name}.tar.zst" > "${package_name}.tar.zst.sha256"
)
printf 'Created %s\n' "$archive"

