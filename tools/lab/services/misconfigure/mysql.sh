#!/bin/sh
# MySQL reachable from anywhere, reading local files, logging nothing, and
# with an account that has no password.
set -eu

mkdir -p /etc/mysql/conf.d /var/lib/mysql-files

CONF=/etc/my.cnf
[ -f /etc/mysql/my.cnf ] && CONF=/etc/mysql/my.cnf

cat > "$CONF" <<'EOF'
[mysqld]
user=mysql
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
port=3306

# Listening on every interface.
bind-address = 0.0.0.0
skip-networking = OFF

# LOAD DATA LOCAL INFILE is on and no directory bounds the file privileges,
# so SELECT ... INTO OUTFILE can write anywhere the server can.
local_infile = ON
secure_file_priv =

# Nothing is recorded: no general log, no slow query log, no audit.
general_log = 0
slow_query_log = 0
log_error = /var/log/mysql/error.log

# Transport is not encrypted and clients are not asked to be.
require_secure_transport = OFF
ssl = 0

# Old authentication and symlinks left enabled.
default_authentication_plugin = mysql_native_password
symbolic-links = 1

max_connections = 100000
max_allowed_packet = 1G

[client]
port=3306
EOF

# An account with no password at all, created on first start.
mkdir -p /docker-entrypoint-initdb.d
cat > /docker-entrypoint-initdb.d/00-lab.sql <<'EOF'
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS 'backup'@'%' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON *.* TO 'backup'@'%';
FLUSH PRIVILEGES;
EOF

printf 'mysql misconfigured\n'
