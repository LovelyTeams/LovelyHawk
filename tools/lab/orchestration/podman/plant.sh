#!/bin/sh
# A handful of containers under Podman, including two the security audit has
# to complain about. Fewer than the Docker host on purpose: what this lab is
# for is proving the tool finds and uses Podman at all, not re-proving every
# audit branch on a second runtime.
set +e

IMAGE=docker.m.daocloud.io/library/alpine:3.20

echo "拉基础镜像…"
podman pull "$IMAGE" >/dev/null 2>&1 || { echo "  拉不到 $IMAGE，靶机会是空的"; exit 0; }
podman tag "$IMAGE" alpine:3.20 >/dev/null 2>&1

run() {
  name=$1
  shift
  podman rm -f "$name" >/dev/null 2>&1
  podman run -d --name "$name" "$@" alpine:3.20 sh -c 'sleep infinity' >/dev/null 2>&1 \
    && echo "  + $name" \
    || echo "  ! $name 起不来"
}

echo "种植容器…"
run app-frontend --label app=web
run app-worker --label app=worker
# One of each so the audit has something to say on this runtime too.
run legacy-agent --privileged
run edge-proxy --net=host

echo "种植网络与卷…"
podman network create incident-net >/dev/null 2>&1 && echo "  + incident-net"
podman volume create evidence-data >/dev/null 2>&1 && echo "  + evidence-data"

echo "容器数：$(podman ps -a -q | wc -l)"
echo "确认这台机器上没有 docker：$(command -v docker || echo '没有，正是要的样子')"
