#!/bin/sh
# Starts everything, and keeps sshd alive whatever the rest of it does.
#
# `set -e` is deliberately absent: a database that refuses to start is one of
# the states this host is for, and it still has to be loggable-into so the
# operator can see why. PID 1 is a plain sleep, so no single service can take
# the host down with it.
set +e

log() { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$1" >> /var/log/lab-arena.log; }
: > /var/log/lab-arena.log

/usr/sbin/sshd -D -e >>/var/log/lab-arena.log 2>&1 &
SSHD_PID=$!
log "sshd started"

# Every service is started detached and allowed to fail. Its own log stays
# where the product puts it, so LovelyHawk reads a real one.
# These live under /run, which a container starts empty. Without them MariaDB
# aborts on "Bind on unix socket: No such file or directory" seconds after it
# says it started, which reads as a database that is up until something asks
# it a question.
mkdir -p /run/redis /run/mysqld /run/postgresql /var/log/redis /var/log/nginx /var/log/mysql
chown -R redis:redis /run/redis /var/log/redis /var/lib/redis 2>/dev/null
chown -R mysql:mysql /run/mysqld /var/log/mysql 2>/dev/null
chown -R postgres:postgres /run/postgresql 2>/dev/null

nginx -g 'daemon off;' >>/var/log/lab-arena.log 2>&1 &
log "nginx started"

(
  # MariaDB writes its data directory on first start.
  [ -d /var/lib/mysql/mysql ] || mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
  chown -R mysql:mysql /var/lib/mysql /var/log/mysql 2>/dev/null
  exec mariadbd --user=mysql
) >>/var/log/lab-arena.log 2>&1 &
log "mariadb started"

redis-server /etc/redis/redis.conf >>/var/log/lab-arena.log 2>&1 &
log "redis started"

(
  PG_BIN=$(ls -1d /usr/lib/postgresql/*/bin 2>/dev/null | head -n 1)
  PG_CONF=$(ls -1d /etc/postgresql/*/main 2>/dev/null | head -n 1)
  PG_DATA=$(ls -1d /var/lib/postgresql/*/main 2>/dev/null | head -n 1)
  [ -n "$PG_BIN" ] && [ -n "$PG_CONF" ] && [ -n "$PG_DATA" ] || exit 0
  chown -R postgres:postgres "$PG_DATA" 2>/dev/null
  exec su postgres -c "$PG_BIN/postgres -D $PG_DATA -c config_file=$PG_CONF/postgresql.conf"
) >>/var/log/lab-arena.log 2>&1 &
log "postgres started"

cron >>/var/log/lab-arena.log 2>&1 &

# Only sshd is watched. Losing a database is a state worth investigating;
# losing sshd means the host cannot be investigated at all.
(
  while true; do
    sleep 5
    kill -0 "$SSHD_PID" 2>/dev/null && continue
    /usr/sbin/sshd -D -e >>/var/log/lab-arena.log 2>&1 &
    SSHD_PID=$!
  done
) >/dev/null 2>&1 &

exec sleep infinity
