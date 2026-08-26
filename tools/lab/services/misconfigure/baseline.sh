#!/bin/sh
# A host whose six baseline files are all wrong, in the shapes that actually
# turn up on a compromised or never-hardened machine.
#
# Two of them are deliberately written as "active line, then the distribution's
# own commented default underneath". A reader that strips the comment marker
# before matching reports those as compliant while the host is wide open, so
# this file is the standing regression for that.
set -eu

mkdir -p /etc/ssh /etc/security /etc/audit /etc/sysctl.d

cat > /etc/ssh/sshd_config <<'EOF'
# Managed by nobody in particular.
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# root can log in with a password, and the packaged default sits underneath
# where a careless reader will pick it up instead.
PermitRootLogin yes
#PermitRootLogin prohibit-password

PasswordAuthentication yes
#PasswordAuthentication no

PermitEmptyPasswords yes
X11Forwarding yes
MaxAuthTries 10
ClientAliveInterval 0
ClientAliveCountMax 10
LoginGraceTime 600
IgnoreRhosts no
HostbasedAuthentication yes
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

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

cat > /etc/security/faillock.conf <<'EOF'
# Lockout is effectively switched off.
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

# A weak account so the account checks have something to find.
useradd -m -s /bin/bash operator 2>/dev/null || true
printf 'operator:123456\n' | chpasswd 2>/dev/null || true
chage -M 99999 -m 0 -W 0 operator 2>/dev/null || true

printf 'baseline host prepared\n'
