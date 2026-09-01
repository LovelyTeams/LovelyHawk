#!/bin/sh
# Fills the inner daemon with the things a container security audit exists to
# find, plus enough ordinary clutter that finding them is not trivial.
#
# Every item here matches one branch of `build_security_audit` in
# crates/lovelyres-core/src/docker.rs. If a check has nothing to fire on, the
# lab proves the check runs but never proves it can say "yes".
set +e

IMAGE=docker.m.daocloud.io/library/alpine:3.20
# A second base, on purpose. Everything else here is busybox, which has no
# bash — so a lab built only from Alpine can never show that the terminal
# picks bash where one exists, only that it falls back when none does. Half a
# branch tested reads exactly like a whole one until the day it does not.
FAT_IMAGE=docker.m.daocloud.io/library/debian:12-slim
BUSY='sleep infinity'

echo "拉基础镜像…"
docker pull "$IMAGE" >/dev/null 2>&1 || { echo "  拉不到 $IMAGE，靶机会是空的"; exit 0; }
docker tag "$IMAGE" alpine:3.20 >/dev/null 2>&1
# An untagged-latest image, which the audit calls out on its own.
docker tag "$IMAGE" incident-tools:latest >/dev/null 2>&1
if docker pull "$FAT_IMAGE" >/dev/null 2>&1; then
  docker tag "$FAT_IMAGE" debian:12-slim >/dev/null 2>&1
else
  echo "  拉不到 $FAT_IMAGE，带 bash 的那台会缺席"
fi

run() {
  name=$1
  shift
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" "$@" alpine:3.20 sh -c "$BUSY" >/dev/null 2>&1 \
    && echo "  + $name" \
    || echo "  ! $name 起不来"
}

echo "种植容器…"

# --- 正常的几个，做背景噪声
run web-frontend --label app=web -p 127.0.0.1:8081:80
run api-backend --label app=api
run cache-node --label app=cache

# 唯一一台带 bash 的：容器终端要证明它会挑 bash，而不是一律退到 sh。
docker rm -f app-shell >/dev/null 2>&1
docker run -d --name app-shell --label app=shell debian:12-slim \
  sh -c "$BUSY" >/dev/null 2>&1 \
  && echo "  + app-shell（有 bash）" \
  || echo "  ! app-shell 起不来"

# --- 每个一条审计发现
# 全特权：容器逃逸最直接的一条路
run legacy-agent --privileged
# 宿主 PID 命名空间：能看到并 kill 宿主上的进程
run monitor-sidecar --pid=host
# 宿主 IPC
run shm-worker --ipc=host
# 危险 capabilities
run net-tuner --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE
# 挂了 docker.sock：等于把整个 daemon 交出去
run ci-runner -v /var/run/docker.sock:/var/run/docker.sock
# 读写挂载宿主 /etc
run config-sync -v /etc:/host-etc
# 宿主网络
run edge-proxy --net=host
# 端口发布到所有网卡
run open-admin -p 0.0.0.0:9090:9090
# latest 标签
docker rm -f drifted-tool >/dev/null 2>&1
docker run -d --name drifted-tool incident-tools:latest sh -c "$BUSY" >/dev/null 2>&1 \
  && echo "  + drifted-tool" || echo "  ! drifted-tool 起不来"

# --- 两个停掉的容器，给动作那条路各一种结局
# 启动后能一直跑：动作的正常路径，验证应该通过。
run stopped-worker
docker stop stopped-worker >/dev/null 2>&1
# 启动后立刻退出：验证应该判定"没到目标状态"并回滚。这条路光靠单测证明不了，
# 因为单测里主机说什么都是编的。
docker rm -f stopped-batch >/dev/null 2>&1
docker run -d --name stopped-batch alpine:3.20 sh -c 'echo done' >/dev/null 2>&1 \
  && echo "  + stopped-batch（启动后立刻退出，故意的）"
sleep 1
docker stop stopped-batch >/dev/null 2>&1

echo "种植网络与卷…"
docker network create incident-net >/dev/null 2>&1 && echo "  + incident-net"
docker network create --internal quarantine-net >/dev/null 2>&1 && echo "  + quarantine-net"
docker volume create evidence-data >/dev/null 2>&1 && echo "  + evidence-data"
docker volume create app-state >/dev/null 2>&1 && echo "  + app-state"

echo "启动 Compose 项目…"
if docker compose -p incident -f /srv/incident/compose.yml up -d >/dev/null 2>&1; then
  echo "  + incident（Compose）"
else
  echo "  ! Compose 项目起不来"
fi

echo "容器数：$(docker ps -a -q | wc -l)"
