#!/bin/sh
# The same shape as the MySQL host, written where MariaDB actually reads it.
set -eu

mkdir -p /etc/mysql/mariadb.conf.d

cat > /etc/mysql/mariadb.conf.d/99-lab.cnf <<'EOF'
[mysqld]
# Listening on every interface.
bind-address = 0.0.0.0
skip-networking = 0

# Local file reads are on and unbounded.
local_infile = 1
secure_file_priv =

# Nothing is recorded.
general_log = 0
slow_query_log = 0
log_warnings = 0

# Transport is not encrypted.
ssl = 0
require_secure_transport = OFF

# Old plugin, symlinks on, and no ceiling on a packet.
symbolic-links = 1
max_connections = 100000
max_allowed_packet = 1G
EOF

mkdir -p /docker-entrypoint-initdb.d
cat > /docker-entrypoint-initdb.d/00-lab.sql <<'EOF'
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

printf 'mariadb misconfigured\n'
