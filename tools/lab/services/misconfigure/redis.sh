#!/bin/sh
# Redis with no password, bound to every interface, protected mode off and
# the commands that turn it into a shell left under their own names.
#
# This is the single most-exploited service configuration on the internet, and
# it is what an unattended `apt install redis` plus one careless edit gives you.
set -eu

mkdir -p /etc/redis /var/lib/redis

cat > /etc/redis/redis.conf <<'EOF'
# Reachable from anywhere, with the safety net that would otherwise refuse
# such connections switched off.
bind 0.0.0.0
protected-mode no
port 6379

# No authentication at all.
# requirepass is not set on purpose.

daemonize no
supervised no
pidfile /var/run/redis_6379.pid
loglevel notice
logfile ""
databases 16

# CONFIG SET can point the dump file anywhere, and the commands that make that
# useful are still called what an attacker expects.
dir /var/lib/redis
dbfilename dump.rdb

save 900 1
save 300 10
save 60 10000

appendonly no

# No limit, so a client can fill memory until the host swaps.
maxmemory 0

# Anyone connected can read the whole key space.
notify-keyspace-events ""
EOF

chmod 0644 /etc/redis/redis.conf
printf 'redis misconfigured\n'
