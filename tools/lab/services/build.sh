#!/bin/sh
# Builds and starts the配置基线 lab: one SSH-reachable host per service, each
# running the real product with a deliberately bad configuration.
#
# Safe to re-run. A host that fails to build does not stop the rest, and the
# summary at the end says which ones are up.
set +e

HERE=$(cd "$(dirname "$0")" && pwd)
PASSWORD='LabRoot#2026'

# name | base image | installer | misconfigure script | ssh port | service command
HOSTS='
nginx|lab-base/nginx:1.27|apt|nginx|2231|nginx -g "daemon off;"
httpd|lab-base/httpd:2.4|apt|httpd|2232|httpd-foreground
tomcat|lab-base/tomcat:10.1|apt|tomcat|2233|/usr/local/tomcat/bin/catalina.sh run
mysql|lab-base/mysql:8.0|microdnf|mysql|2234|/entrypoint.sh mysqld
mariadb|lab-base/mariadb:11|apt|mariadb|2235|/usr/local/bin/docker-entrypoint.sh mariadbd
postgres|lab-base/postgres:16|apt|postgres|2236|/usr/local/bin/docker-entrypoint.sh postgres
redis|lab-base/redis:7|apt|redis|2237|redis-server /etc/redis/redis.conf
mongo|lab-base/mongo:7|apt|mongo|2238|mongod --config /etc/mongod.conf
opengauss|lab-base/opengauss:5.0.0|apt|opengauss|2239|/entrypoint.sh gaussdb
tidb|lab-base/tidb:v7.5.0|dnf|tidb|2240|/tidb-server --config /etc/tidb/tidb.toml
baseline-deb|debian:12|apt|baseline|2241|
baseline-el|almalinux:9|dnf|baseline|2242|
'

built=''
failed=''

for row in $(printf '%s' "$HOSTS" | tr ' ' '\001'); do
  row=$(printf '%s' "$row" | tr '\001' ' ')
  name=$(printf '%s' "$row" | cut -d'|' -f1)
  base=$(printf '%s' "$row" | cut -d'|' -f2)
  installer=$(printf '%s' "$row" | cut -d'|' -f3)
  script=$(printf '%s' "$row" | cut -d'|' -f4)
  port=$(printf '%s' "$row" | cut -d'|' -f5)
  command=$(printf '%s' "$row" | cut -d'|' -f6)
  [ -n "$name" ] || continue

  echo "=== $name  ($base, ssh $port)"
  if ! docker image inspect "$base" >/dev/null 2>&1; then
    echo "    base image missing; run pull.sh first"
    failed="$failed $name"
    continue
  fi

  if ! docker build -q \
      --build-arg "BASE=$base" \
      --build-arg "INSTALLER=$installer" \
      --build-arg "SERVICE=$script" \
      -t "lovelyres-svc:$name" \
      "$HERE" >/dev/null 2>/tmp/build-$name.log; then
    echo "    BUILD FAILED — $(tail -n 3 /tmp/build-$name.log | tr '\n' ' ')"
    failed="$failed $name"
    continue
  fi

  docker rm -f "svc-$name" >/dev/null 2>&1
  if docker run -d --name "svc-$name" \
      -p "$port:22" \
      -e "LAB_SERVICE_COMMAND=$command" \
      "lovelyres-svc:$name" >/dev/null 2>/tmp/run-$name.log; then
    echo "    started"
    built="$built $name"
  else
    echo "    RUN FAILED — $(tail -n 2 /tmp/run-$name.log | tr '\n' ' ')"
    failed="$failed $name"
  fi
done

echo
echo "=== up ==="
docker ps --filter name=svc- --format '{{.Names}}  {{.Ports}}  {{.Status}}'
echo
echo "built:$built"
[ -n "$failed" ] && echo "failed:$failed"
echo "root password: $PASSWORD"
exit 0
