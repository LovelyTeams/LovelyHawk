#!/bin/sh
# openGauss with the same faults as the PostgreSQL host, written where
# openGauss keeps them.
#
# The data directory belongs to the omm account and is built on first start,
# so the edits are staged and applied by the entrypoint hook rather than now.
set -eu

mkdir -p /opt/lab

cat > /opt/lab/misconfigure-late.sh <<'LATE'
#!/bin/sh
# Applied once the cluster exists.
set -eu
DATA=${PGDATA:-/var/lib/opengauss/data}
[ -d "$DATA" ] || DATA=$(find /var/lib -maxdepth 4 -name postgresql.conf 2>/dev/null | head -n 1 | xargs -r dirname)
[ -n "${DATA:-}" ] && [ -d "$DATA" ] || exit 0

cat >> "$DATA/postgresql.conf" <<'EOF'

# --- lab: everything below is deliberately wrong -----------------------------
listen_addresses = '*'
password_encryption_type = 0
ssl = off
log_connections = off
log_disconnections = off
log_statement = 'none'
log_min_duration_statement = -1
audit_enabled = off
failed_login_attempts = 0
password_lock_time = 0
password_effect_time = 0
EOF

cat > "$DATA/pg_hba.conf" <<'EOF'
# TYPE  DATABASE  USER  ADDRESS       METHOD
local   all       all                 trust
host    all       all   0.0.0.0/0     trust
host    all       all   ::/0          trust
EOF
LATE

chmod +x /opt/lab/misconfigure-late.sh
printf 'opengauss staged\n'
