#!/usr/bin/env bash
# Disposable lab for every login method the connection editor offers.
#
#   login-methods-lab.sh up <fixture-dir> [address]   build keys, start targets
#   login-methods-lab.sh down                         remove what "up" created
#
# Run where `docker` works (on Windows: `wsl -u root -e bash <this> up ...`).
# <fixture-dir> receives throwaway keys and certificates; [address] is where
# the targets are published (default: this host's first address — WSL's own
# address, because the WSL localhost relay drops connections). Prints the
# environment for `cargo test -p lovelyhawk-core -- --ignored
# live_openssh_every_login_method live_openssh_keyboard_interactive_contract`.
#
# Targets (alpine, OpenSSH 9.x unless noted), all labelled
# lovelyhawk.test=login-methods; "down" removes only those and their network:
#   lh-login-main   password, Ed25519 (passphrase), ECDSA, RSA, agent keys,
#                   user certificates via TrustedUserCAKeys
#   lh-login-ki     keyboard-interactive through PAM
#   lh-login-jump   bastion; reaches lh-login-main by its published address
#   lh-login-legacy OpenSSH 8.6, which still accepts ssh-rsa-cert-v01
set -euo pipefail

LABEL=lovelyhawk.test=login-methods
NET=lh-login-net
HERE=$(cd "$(dirname "$0")" && pwd)
PASSWORD=lovelyres-contract-password
KEY_PASSPHRASE=lh-key-pass

down() {
  for id in $(docker ps -aq --filter "label=$LABEL"); do docker rm -f "$id" >/dev/null; done
  if [ "$(docker network inspect -f '{{index .Labels "lovelyhawk.test"}}' "$NET" 2>/dev/null)" = login-methods ]; then
    docker network rm "$NET" >/dev/null
  fi
}

keys() {
  local dir=$1
  mkdir -p "$dir" && cd "$dir"
  rm -f id_* cert_* agent_* ca ca.pub user_key.pub user_ca.pub
  ssh-keygen -q -t ed25519 -N "$KEY_PASSPHRASE" -C lh-ed25519 -f id_ed25519
  ssh-keygen -q -t ecdsa -b 256 -N '' -C lh-ecdsa -f id_ecdsa
  ssh-keygen -q -t rsa -b 3072 -N '' -C lh-rsa -f id_rsa
  ssh-keygen -q -t ed25519 -N '' -C lh-ca -f ca
  # Certificate keys are not authorised: logging in with one proves the CA path.
  ssh-keygen -q -t ed25519 -N '' -C lh-cert-ed25519 -f cert_ed25519
  ssh-keygen -q -t rsa -b 3072 -N '' -C lh-cert-rsa -f cert_rsa
  ssh-keygen -q -t ed25519 -N '' -C lh-agent-ed25519 -f agent_ed25519
  ssh-keygen -q -t rsa -b 3072 -N '' -C lh-agent-rsa -f agent_rsa
  ssh-keygen -q -s ca -I lh-cert-ed25519 -n incident -V -1h:+24h cert_ed25519.pub
  ssh-keygen -q -s ca -I lh-cert-rsa -n incident -V -1h:+24h cert_rsa.pub
  cat id_ed25519.pub id_ecdsa.pub id_rsa.pub agent_ed25519.pub agent_rsa.pub > user_key.pub
  cp ca.pub user_ca.pub
  cd - >/dev/null
}

start() { # name image host-port mode [extra packages]
  local name=$1 image=$2 port=$3 mode=$4 extra=${5:-}
  docker run -d --name "$name" --label "$LABEL" --network "$NET" --memory 256m --cpus 0.5 \
    -p "$ADDRESS:$port:22" "$image" sh -c 'while :; do sleep 3600; done' >/dev/null
  docker exec "$name" sh -c "apk add --no-cache -q openssh shadow $extra" >/dev/null
  docker exec "$name" mkdir -p /tmp/lovelyres-ssh-fixtures
  docker cp "$FIXTURES/user_key.pub" "$name:/tmp/lovelyres-ssh-fixtures/user_key.pub"
  docker cp "$FIXTURES/user_ca.pub" "$name:/tmp/lovelyres-ssh-fixtures/user_ca.pub"
  tr -d '\r' < "$HERE/configure-target.sh" | docker exec -i "$name" sh -c 'cat > /tmp/configure-target.sh'
  docker exec -d -e LOVELYHAWK_SSHD_MODE="$mode" -e LOVELYHAWK_SSHD_USER=incident \
    -e LOVELYHAWK_SSHD_PASSWORD="$PASSWORD" "$name" sh -c 'exec sh /tmp/configure-target.sh >/tmp/sshd.log 2>&1'
}

fingerprint() {
  local port=$1
  for _ in $(seq 1 30); do
    if ssh-keyscan -T 2 -p "$port" -t ed25519 "$ADDRESS" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  ssh-keyscan -T 2 -p "$port" -t ed25519 "$ADDRESS" 2>/dev/null | ssh-keygen -lf - | awk '{print $2}'
}

case "${1:-}" in
  up)
    FIXTURES=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
    ADDRESS=${3:-$(hostname -I | awk '{print $1}')}
    down
    keys "$FIXTURES"
    docker network create --label lovelyhawk.test=login-methods "$NET" >/dev/null
    start lh-login-main alpine:3.20 2261 certificate
    start lh-login-ki alpine:3.20 2262 keyboard-interactive openssh-server-pam
    start lh-login-jump alpine:3.20 2263 password
    start lh-login-legacy alpine:3.14 2264 certificate
    for pair in '2261:' '2263:_JUMP' '2264:_LEGACY'; do
      port=${pair%%:*} prefix=LOVELYHAWK_TEST_SSH${pair#*:}
      echo "export ${prefix}_HOST=$ADDRESS ${prefix}_PORT=$port ${prefix}_USERNAME=incident ${prefix}_PASSWORD=$PASSWORD ${prefix}_HOST_KEY='$(fingerprint "$port")'"
    done
    echo "export LOVELYHAWK_TEST_SSH_MFA_HOST=$ADDRESS LOVELYHAWK_TEST_SSH_MFA_PORT=2262 LOVELYHAWK_TEST_SSH_MFA_USERNAME=incident LOVELYHAWK_TEST_SSH_MFA_HOST_KEY='$(fingerprint 2262)' LOVELYHAWK_TEST_SSH_MFA_RESPONSES_JSON='[\"$PASSWORD\"]'"
    echo "export LOVELYHAWK_TEST_SSH_MATRIX_DIR=<absolute path of $FIXTURES as the test process sees it> LOVELYHAWK_TEST_SSH_MATRIX_KEY_PASSPHRASE=$KEY_PASSPHRASE"
    ;;
  down) down ;;
  *) echo "usage: $0 up <fixture-dir> [address] | down" >&2; exit 2 ;;
esac
