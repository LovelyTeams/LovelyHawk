#!/bin/sh
set -eu

mode="${LOVELYRES_SSHD_MODE:-password}"
user="${LOVELYRES_SSHD_USER:-incident}"
password="${LOVELYRES_SSHD_PASSWORD:-lovelyres-contract-password}"
fixture_dir="${LOVELYRES_SSHD_FIXTURE_DIR:-/tmp/lovelyres-ssh-fixtures}"
config=/tmp/lovelyres-sshd_config

mkdir -p /run/sshd /var/run/sshd "$fixture_dir"
ssh-keygen -A

if ! id "$user" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd -m -s /bin/sh "$user"
  else
    adduser -D -s /bin/sh "$user"
  fi
fi
printf '%s:%s\n' "$user" "$password" | chpasswd
mkdir -p "/home/$user/.ssh"
chmod 700 "/home/$user/.ssh"
if [ -s "$fixture_dir/user_key.pub" ]; then
  cp "$fixture_dir/user_key.pub" "/home/$user/.ssh/authorized_keys"
  chmod 600 "/home/$user/.ssh/authorized_keys"
fi
chown -R "$user" "/home/$user/.ssh"

{
  printf '%s\n' 'Port 22'
  printf '%s\n' 'ListenAddress 0.0.0.0'
  printf '%s\n' 'ListenAddress ::'
  printf '%s\n' 'UseDNS no'
  printf '%s\n' 'PermitRootLogin no'
  printf '%s\n' 'StrictModes no'
  printf '%s\n' 'AllowTcpForwarding yes'
  printf '%s\n' 'X11Forwarding no'
  printf '%s\n' 'PrintMotd no'
  printf '%s\n' 'PubkeyAuthentication yes'
  printf '%s\n' 'AuthorizedKeysFile .ssh/authorized_keys'
  if [ "$mode" = 'certificate' ]; then
    printf 'TrustedUserCAKeys %s\n' "$fixture_dir/user_ca.pub"
  fi
  if [ "$mode" = 'keyboard-interactive' ]; then
    printf '%s\n' 'PasswordAuthentication no'
    printf '%s\n' 'ChallengeResponseAuthentication yes'
    printf '%s\n' 'KbdInteractiveAuthentication yes'
    printf '%s\n' 'UsePAM yes'
  else
    printf '%s\n' 'PasswordAuthentication yes'
    printf '%s\n' 'UsePAM no'
  fi
  if [ "$mode" = 'no-pty' ]; then
    printf '%s\n' 'PermitTTY no'
  else
    printf '%s\n' 'PermitTTY yes'
  fi
  if [ "$mode" != 'no-sftp' ]; then
    if [ -x /usr/lib/ssh/sftp-server ]; then
      printf '%s\n' 'Subsystem sftp /usr/lib/ssh/sftp-server'
    elif [ -x /usr/libexec/openssh/sftp-server ]; then
      printf '%s\n' 'Subsystem sftp /usr/libexec/openssh/sftp-server'
    else
      printf '%s\n' 'Subsystem sftp internal-sftp'
    fi
  fi
  if [ "$mode" = 'restricted-account' ]; then
    printf 'Match User %s\n' "$user"
    printf '%s\n' '    ForceCommand /bin/false'
    printf '%s\n' '    PermitTTY no'
    printf '%s\n' '    AllowTcpForwarding no'
  fi
} > "$config"

exec /usr/sbin/sshd -D -e -f "$config"
