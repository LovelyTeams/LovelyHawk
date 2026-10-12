#!/bin/sh
# Builds the super arena if it is not built, and starts it.
#
# Safe to re-run: the image is cached, the container is recreated, and the
# restart policy brings it back if the virtual machine goes down. Build context
# is the parent tools/lab directory, because the image reuses arena's
# misconfigure.sh.
#
#   wsl -d Ubuntu -u root -e sh /mnt/d/LovelyRes/tools/lab/super/up.sh
#   REBUILD=1 ...   to rebuild the image
set +e

HERE=$(cd "$(dirname "$0")" && pwd)
LAB="$HERE/.."
PORT=2251

if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect lovelyres-lab:super >/dev/null 2>&1; then
  echo "构建超级靶机镜像（第一次要装 nginx / apache / mariadb / postgresql / redis / vsftpd，需要几分钟）…"
  if ! docker build -f "$HERE/Dockerfile" -t lovelyres-lab:super "$LAB" >/tmp/build-super.log 2>&1; then
    echo "构建失败："
    grep -iv "deprecated\|buildx\|docs.docker.com" /tmp/build-super.log | tail -n 15
    exit 1
  fi
fi

docker rm -f lab-super >/dev/null 2>&1
docker run -d --name lab-super \
  --restart unless-stopped \
  -p "$PORT:22" \
  lovelyres-lab:super >/dev/null 2>&1 || {
    echo "启动失败。"
    exit 1
  }

# Long enough that a service which starts and then aborts has already done so.
sleep 20

echo
docker ps --filter name=lab-super --format '{{.Names}}  {{.Status}}  {{.Ports}}'
echo
echo "服务："
docker exec lab-super sh -c '
  for entry in "sshd:22" "nginx:80" "apache2:8080" "vsftpd:21" "mariadbd:3306" "redis-server:6379" "postgres:5432"; do
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
