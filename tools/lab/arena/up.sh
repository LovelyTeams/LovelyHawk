#!/bin/sh
# Builds the arena host if it is not built, and starts it.
#
# Safe to re-run: the image is cached, the container is recreated, and the
# restart policy brings it back by itself if the virtual machine goes down.
set +e

HERE=$(cd "$(dirname "$0")" && pwd)
PORT=2250

if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect lovelyres-lab:arena >/dev/null 2>&1; then
  echo "构建综合靶机镜像（第一次要装 nginx / mariadb / postgresql / redis，需要几分钟）…"
  if ! docker build -t lovelyres-lab:arena "$HERE" >/tmp/build-arena.log 2>&1; then
    echo "构建失败："
    grep -iv "deprecated\|buildx\|docs.docker.com" /tmp/build-arena.log | tail -n 8
    exit 1
  fi
fi

docker rm -f lab-arena >/dev/null 2>&1
docker run -d --name lab-arena \
  --restart unless-stopped \
  -p "$PORT:22" \
  lovelyres-lab:arena >/dev/null 2>&1 || {
    echo "启动失败。"
    exit 1
  }

# Long enough that a service which starts and then aborts has already done so.
# A database reports itself up for a second or two before it discovers it has
# nowhere to put its socket, and checking too early calls that a success.
sleep 20

echo
docker ps --filter name=lab-arena --format '{{.Names}}  {{.Status}}  {{.Ports}}'
echo
echo "服务："
docker exec lab-arena sh -c '
  for entry in "sshd:22" "nginx:80" "mariadbd:3306" "redis-server:6379" "postgres:5432"; do
    name=${entry%%:*}; port=${entry##*:}
    if pgrep -x "$name" >/dev/null 2>&1 || pgrep -f "$name" >/dev/null 2>&1; then
      printf "  %-14s 在跑（:%s）\n" "$name" "$port"
    else
      printf "  %-14s 没起来（:%s）\n" "$name" "$port"
    fi
  done' 2>/dev/null

echo
echo "地址 $(hostname -I | awk '{print $1}'):$PORT   root / LabRoot#2026"
exit 0
