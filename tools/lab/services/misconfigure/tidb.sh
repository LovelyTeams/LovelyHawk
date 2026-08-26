#!/bin/sh
# TiDB with the security section emptied out: no cluster TLS, no audit, and
# the status endpoint answering to anyone who asks.
set -eu

mkdir -p /etc/tidb

cat > /etc/tidb/tidb.toml <<'EOF'
host = "0.0.0.0"
port = 4000
store = "unistore"
path = "/tmp/tidb"

# The status endpoint carries metrics and configuration and is not restricted.
status-host = "0.0.0.0"
status-port = 10080
enable-telemetry = false

[security]
# No transport encryption between client and server, and none inside the
# cluster either.
ssl-ca = ""
ssl-cert = ""
ssl-key = ""
cluster-ssl-ca = ""
cluster-ssl-cert = ""
cluster-ssl-key = ""
# Any account may read arbitrary local files through the server.
skip-grant-table = true

[log]
level = "error"
# Nothing about who connected is written down.
[log.file]
filename = "/var/log/tidb.log"
max-days = 1

[performance]
max-procs = 0

[experimental]
allow-expression-index = true
EOF

printf 'tidb misconfigured\n'
