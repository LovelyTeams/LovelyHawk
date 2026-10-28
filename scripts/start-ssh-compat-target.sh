#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  echo "usage: $0 <image> <container-name> <host-port> <mode> <fixture-dir>" >&2
  exit 2
fi

image="$1"
name="$2"
host_port="$3"
mode="$4"
fixture_dir="$5"

docker_args=(-d --name "$name" -p "127.0.0.1:${host_port}:22")
if [[ "$mode" = 'high-latency' ]]; then docker_args+=(--cap-add NET_ADMIN); fi
if [[ -n "${LOVELYHAWK_DOCKER_NETWORK:-}" ]]; then
  docker_args+=(--network "$LOVELYHAWK_DOCKER_NETWORK" --network-alias "$name")
fi
docker run "${docker_args[@]}" "$image" sh -c 'while :; do sleep 3600; done' >/dev/null

docker exec -e LOVELYHAWK_SSHD_MODE="$mode" "$name" sh -lc '
  if command -v apk >/dev/null 2>&1; then
    if [ "$LOVELYHAWK_SSHD_MODE" = "dropbear" ]; then
      apk add --no-cache dropbear shadow sudo tcpdump coreutils findutils grep sed gawk iproute2 procps util-linux
    else
      apk add --no-cache openssh shadow sudo tcpdump coreutils findutils grep sed gawk iproute2 procps util-linux
    fi
    if [ "$LOVELYHAWK_SSHD_MODE" = "keyboard-interactive" ]; then apk add --no-cache openssh-server-pam; fi
  elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends openssh-server sudo tcpdump coreutils findutils grep sed gawk iproute2 procps util-linux ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y openssh-server sudo tcpdump coreutils findutils grep sed gawk iproute procps-ng util-linux shadow-utils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y openssh-server sudo tcpdump coreutils findutils grep sed gawk iproute procps-ng util-linux shadow-utils
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install openssh sudo tcpdump coreutils findutils grep sed gawk iproute2 procps util-linux shadow
  else
    echo "unsupported target package manager" >&2
    exit 1
  fi
'

docker exec "$name" mkdir -p /tmp/lovelyres-ssh-fixtures
if [[ -f "$fixture_dir/user_key.pub" ]]; then
  docker cp "$fixture_dir/user_key.pub" "$name:/tmp/lovelyres-ssh-fixtures/user_key.pub"
fi
if [[ -f "$fixture_dir/user_ca.pub" ]]; then
  docker cp "$fixture_dir/user_ca.pub" "$name:/tmp/lovelyres-ssh-fixtures/user_ca.pub"
fi
docker cp tests/ssh-compat/configure-target.sh "$name:/tmp/configure-lovelyres-target.sh"
docker cp tests/ssh-compat/configure-dropbear-target.sh "$name:/tmp/configure-lovelyres-dropbear-target.sh"
target_script=/tmp/configure-lovelyres-target.sh
if [[ "$mode" = 'dropbear' ]]; then target_script=/tmp/configure-lovelyres-dropbear-target.sh; fi
docker exec -d \
  -e LOVELYHAWK_SSHD_MODE="$mode" \
  -e LOVELYHAWK_SSHD_USER=incident \
  -e LOVELYHAWK_SSHD_PASSWORD=lovelyres-contract-password \
  "$name" sh -c "exec sh '$target_script' >/tmp/lovelyres-sshd.log 2>&1"

for _ in $(seq 1 45); do
  if ssh-keyscan -p "$host_port" -t ed25519 127.0.0.1 >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

docker logs "$name" >&2
docker exec "$name" sh -c 'cat /tmp/lovelyres-sshd.log 2>/dev/null || true' >&2
echo "SSH target did not become ready: $name" >&2
exit 1
