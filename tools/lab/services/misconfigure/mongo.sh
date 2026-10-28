#!/bin/sh
# MongoDB with authorization switched off and the wire protocol open to the
# network, which is the shape behind most of the "database ransomed" stories.
set -eu

mkdir -p /etc/mongo /data/db

cat > /etc/mongod.conf <<'EOF'
storage:
  dbPath: /data/db

systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  logAppend: true
  # Nothing above a warning is kept.
  verbosity: 0
  quiet: true

net:
  port: 27017
  # Reachable from anywhere.
  bindIp: 0.0.0.0
  # No transport encryption.
  tls:
    mode: disabled

security:
  # Anyone who can reach the port is an administrator.
  authorization: disabled
  javascriptEnabled: true

# No auditing is configured at all.
EOF

mkdir -p /var/log/mongodb
printf 'mongodb misconfigured\n'
