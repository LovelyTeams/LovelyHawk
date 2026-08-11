#!/bin/sh
set -eu

user="${LOVELYRES_SSHD_USER:-incident}"
password="${LOVELYRES_SSHD_PASSWORD:-lovelyres-contract-password}"
fixture_dir="${LOVELYRES_SSHD_FIXTURE_DIR:-/tmp/lovelyres-ssh-fixtures}"

if ! id "$user" >/dev/null 2>&1; then
  adduser -D -s /bin/sh "$user"
fi
printf '%s:%s\n' "$user" "$password" | chpasswd
mkdir -p "/home/$user/.ssh" /etc/dropbear
chmod 700 "/home/$user/.ssh"
if [ -s "$fixture_dir/user_key.pub" ]; then
  cp "$fixture_dir/user_key.pub" "/home/$user/.ssh/authorized_keys"
  chmod 600 "/home/$user/.ssh/authorized_keys"
fi
chown -R "$user" "/home/$user/.ssh"

if [ ! -s /etc/dropbear/dropbear_ed25519_host_key ]; then
  dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
fi

exec dropbear -F -E -p 22
