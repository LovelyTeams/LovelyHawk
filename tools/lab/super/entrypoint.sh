#!/bin/sh
# Starts everything on the super arena and keeps sshd alive whatever else does.
# As with the ordinary arena, `set -e` is deliberately absent: a service that
# refuses to start is one of the states this host is for, and the host still
# has to be loggable-into so the operator can see why. PID 1 is a plain sleep,
# so no one service can take the host down with it.
set +e

log() { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$1" >> /var/log/lab-super.log; }
: > /var/log/lab-super.log

/usr/sbin/sshd -D -e >>/var/log/lab-super.log 2>&1 &
SSHD_PID=$!
log "sshd started"

# Runtime dirs a container starts without; without them the databases abort
# shortly after reporting themselves up.
mkdir -p /run/redis /run/mysqld /run/postgresql /var/log/redis /var/log/nginx \
         /var/log/mysql /run/apache2 /var/run/vsftpd/empty
chown -R redis:redis /run/redis /var/log/redis /var/lib/redis 2>/dev/null
chown -R mysql:mysql /run/mysqld /var/log/mysql 2>/dev/null
chown -R postgres:postgres /run/postgresql 2>/dev/null

nginx -g 'daemon off;' >>/var/log/lab-super.log 2>&1 &
log "nginx started"

# Apache on :8080 (nginx owns :80).
if [ -x /usr/sbin/apache2ctl ] || [ -x /usr/sbin/apache2 ]; then
  . /etc/apache2/envvars 2>/dev/null
  /usr/sbin/apache2 -D FOREGROUND >>/var/log/lab-super.log 2>&1 &
  log "apache started"
fi

# FTP, wide open.
if [ -x /usr/sbin/vsftpd ]; then
  /usr/sbin/vsftpd /etc/vsftpd.conf >>/var/log/lab-super.log 2>&1 &
  log "vsftpd started"
fi

(
  [ -d /var/lib/mysql/mysql ] || mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
  chown -R mysql:mysql /var/lib/mysql /var/log/mysql 2>/dev/null
  exec mariadbd --user=mysql
) >>/var/log/lab-super.log 2>&1 &
log "mariadb started"

redis-server /etc/redis/redis.conf >>/var/log/lab-super.log 2>&1 &
log "redis started"

(
  PG_BIN=$(ls -1d /usr/lib/postgresql/*/bin 2>/dev/null | head -n 1)
  PG_CONF=$(ls -1d /etc/postgresql/*/main 2>/dev/null | head -n 1)
  PG_DATA=$(ls -1d /var/lib/postgresql/*/main 2>/dev/null | head -n 1)
  [ -n "$PG_BIN" ] && [ -n "$PG_CONF" ] && [ -n "$PG_DATA" ] || exit 0
  chown -R postgres:postgres "$PG_DATA" 2>/dev/null
  exec su postgres -c "$PG_BIN/postgres -D $PG_DATA -c config_file=$PG_CONF/postgresql.conf"
) >>/var/log/lab-super.log 2>&1 &
log "postgres started"

cron >>/var/log/lab-super.log 2>&1 &

# --- Two things that should make an operator look twice -------------------
# A process running from /tmp under a kernel-thread name: argv[0] says
# "[kworker/1:0]" but it lives in /tmp and is a copy of sleep. It does nothing
# but sit there; the point is that it should not be where it is or named what
# it is. `exec -a` is a bash builtin (dash, this script's shell, has no -a).
cp /bin/sleep /tmp/.dbus 2>/dev/null \
  && bash -c 'cd /tmp && exec -a "[kworker/1:0]" /tmp/.dbus infinity' >/dev/null 2>&1 &
log "masquerading idle process started"

# A listener on an odd port that answers with a banner and nothing else (no
# shell): an unexpected open port for the network and open-ports views.
if command -v socat >/dev/null 2>&1; then
  socat TCP-LISTEN:8081,fork,reuseaddr SYSTEM:'echo super-lab; cat >/dev/null' \
    >>/var/log/lab-super.log 2>&1 &
  log "banner listener on :8081 started"
fi

# An at job queued for boot, a scheduler an operator rarely checks.
command -v atd >/dev/null 2>&1 && atd >>/var/log/lab-super.log 2>&1 &
printf '/usr/local/lib/pyshared/.helper >/dev/null 2>&1\n' | at now + 1 minute >/dev/null 2>&1

# Only sshd is watched: losing a service is worth investigating, losing sshd
# means the host cannot be investigated at all.
(
  while true; do
    sleep 5
    kill -0 "$SSHD_PID" 2>/dev/null && continue
    /usr/sbin/sshd -D -e >>/var/log/lab-super.log 2>&1 &
    SSHD_PID=$!
  done
) >/dev/null 2>&1 &

exec sleep infinity
