#!/bin/sh
# PostgreSQL answering on every interface, trusting whoever connects, and
# keeping no record of who did.
#
# The data directory is created on first start, so the settings go into the
# initialisation hook rather than into a file that does not exist yet.
set -eu

mkdir -p /docker-entrypoint-initdb.d

cat > /docker-entrypoint-initdb.d/00-lab.sh <<'INIT'
#!/bin/sh
set -eu
CONF="$PGDATA/postgresql.conf"
HBA="$PGDATA/pg_hba.conf"

cat >> "$CONF" <<'EOF'

# --- lab: everything below is deliberately wrong -----------------------------

# Reachable from anywhere.
listen_addresses = '*'
port = 5432

# Nothing is written down: no connection log, no statement log, no slow query
# threshold, and the log goes to a collector that is switched off.
logging_collector = off
log_connections = off
log_disconnections = off
log_statement = 'none'
log_min_duration_statement = -1
log_line_prefix = ''

# Transport is not encrypted and the client is not asked to encrypt.
ssl = off

# Passwords are stored with the obsolete algorithm.
password_encryption = md5

# A crash can lose committed transactions.
fsync = off
synchronous_commit = off
full_page_writes = off
EOF

# Every connection is trusted, including from outside the host.
cat > "$HBA" <<'EOF'
# TYPE  DATABASE  USER  ADDRESS       METHOD
local   all       all                 trust
host    all       all   127.0.0.1/32  trust
host    all       all   ::1/128       trust
host    all       all   0.0.0.0/0     trust
host    all       all   ::/0          trust
EOF

# An account whose password is its name.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<'SQL'
CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app';
CREATE ROLE backup LOGIN SUPERUSER PASSWORD '123456';
SQL
INIT

chmod +x /docker-entrypoint-initdb.d/00-lab.sh
printf 'postgres misconfigured\n'
