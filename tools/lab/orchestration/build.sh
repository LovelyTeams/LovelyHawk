#!/bin/sh
# Builds and starts the container-orchestration lab: one host running its own
# Docker daemon, and one host holding kubectl against a real k3s cluster.
#
# Safe to re-run. Neither host stops the other from coming up, and the summary
# says which one is where.
set +e

HERE=$(cd "$(dirname "$0")" && pwd)
K3S_IMAGE=docker.m.daocloud.io/rancher/k3s:v1.31.4-k3s1
PASSWORD='LabRoot#2026'
DOCKER_PORT=2244
KUBERNETES_PORT=2245
PODMAN_PORT=2246
ARENA_PORT=2247

echo "=== k3s 集群 (lab-k3s)"
if ! docker image inspect "$K3S_IMAGE" >/dev/null 2>&1; then
  echo "    拉镜像…"
  docker pull "$K3S_IMAGE" >/dev/null 2>&1 || { echo "    拉不到 $K3S_IMAGE"; }
fi
docker rm -f lab-k3s >/dev/null 2>&1
docker volume create lab-k3s-config >/dev/null 2>&1
# The kubeconfig has to leave the cluster container for the client host to use
# it, so /etc/rancher/k3s is a named volume both containers mount.
#
# --tls-san=k3s because the client reaches the API server by that name: the
# certificate k3s generates covers its own container id and localhost, and
# without the extra name every kubectl call fails verification.
if docker run -d --name lab-k3s --privileged \
    --tmpfs /run --tmpfs /var/run \
    -v lab-k3s-config:/etc/rancher/k3s \
    -v "$HERE/k3s/registries.yaml:/etc/rancher/k3s/registries.yaml:ro" \
    -e K3S_KUBECONFIG_MODE=0644 \
    "$K3S_IMAGE" server --disable=traefik --disable=metrics-server \
    --tls-san=k3s >/dev/null 2>/tmp/k3s-run.log; then
  echo "    started"
else
  echo "    RUN FAILED — $(tail -n 2 /tmp/k3s-run.log | tr '\n' ' ')"
fi

echo "=== Docker 靶机 (svc-docker, ssh $DOCKER_PORT)"
if docker build -q -t lovelyres-svc:docker "$HERE/docker" >/dev/null 2>/tmp/build-docker.log; then
  docker rm -f svc-docker >/dev/null 2>&1
  docker volume create lab-docker-lib >/dev/null 2>&1
  # --privileged is what lets this host run a daemon of its own instead of
  # borrowing the lab machine's.
  #
  # /var/lib/docker must be a volume, not the container's own filesystem: that
  # filesystem is already overlayfs, overlay-on-overlay is refused by the
  # kernel, and the symptom is every `docker run` failing at mount time while
  # pulls and networks and volumes all still work.
  if docker run -d --name svc-docker --privileged \
      -p "$DOCKER_PORT:22" \
      -v lab-docker-lib:/var/lib/docker \
      lovelyres-svc:docker >/dev/null 2>/tmp/run-docker.log; then
    echo "    started（内层 daemon 与容器还要一两分钟）"
  else
    echo "    RUN FAILED — $(tail -n 2 /tmp/run-docker.log | tr '\n' ' ')"
  fi
else
  echo "    BUILD FAILED — $(tail -n 3 /tmp/build-docker.log | tr '\n' ' ')"
fi

echo "=== Podman 靶机 (svc-podman, ssh $PODMAN_PORT)"
if docker build -q -t lovelyres-svc:podman "$HERE/podman" >/dev/null 2>/tmp/build-podman.log; then
  docker rm -f svc-podman >/dev/null 2>&1
  docker volume create lab-podman-lib >/dev/null 2>&1
  # Same overlay-on-overlay problem the Docker host has, for the same reason:
  # Podman's own storage cannot live on the container's overlayfs.
  if docker run -d --name svc-podman --privileged \
      -p "$PODMAN_PORT:22" \
      -v lab-podman-lib:/var/lib/containers \
      lovelyres-svc:podman >/dev/null 2>/tmp/run-podman.log; then
    echo "    started（容器还要一两分钟）"
  else
    echo "    RUN FAILED — $(tail -n 2 /tmp/run-podman.log | tr '\n' ' ')"
  fi
else
  echo "    BUILD FAILED — $(tail -n 3 /tmp/build-podman.log | tr '\n' ' ')"
fi

echo "=== Kubernetes 靶机 (svc-kubernetes, ssh $KUBERNETES_PORT)"
if docker build -q --build-arg "K3S_IMAGE=$K3S_IMAGE" \
    -t lovelyres-svc:kubernetes "$HERE/kubernetes" >/dev/null 2>/tmp/build-kubernetes.log; then
  docker rm -f svc-kubernetes >/dev/null 2>&1
  if docker run -d --name svc-kubernetes \
      -p "$KUBERNETES_PORT:22" \
      --link lab-k3s:k3s \
      -v lab-k3s-config:/mnt/k3s:ro \
      -e LAB_CLUSTER_HOST=k3s \
      lovelyres-svc:kubernetes >/dev/null 2>/tmp/run-kubernetes.log; then
    echo "    started（集群与工作负载还要一两分钟）"
  else
    echo "    RUN FAILED — $(tail -n 2 /tmp/run-kubernetes.log | tr '\n' ' ')"
  fi
else
  echo "    BUILD FAILED — $(tail -n 3 /tmp/build-kubernetes.log | tr '\n' ' ')"
fi

echo "=== 综合靶机 (svc-arena, ssh $ARENA_PORT) —— 一台机器上同时有 Docker 和 Kubernetes"
if docker build -q --build-arg "K3S_IMAGE=$K3S_IMAGE" \
    -t lovelyres-svc:arena "$HERE/arena" >/dev/null 2>/tmp/build-arena.log; then
  docker rm -f svc-arena >/dev/null 2>&1
  docker volume create lab-arena-docker >/dev/null 2>&1
  docker volume create lab-arena-rancher >/dev/null 2>&1
  # Both runtimes keep their state on real volumes for the same reason: their
  # snapshotters cannot stack overlayfs on the container's own overlayfs, and
  # k3s fails with "overlayfs snapshotter cannot be enabled" while Docker fails
  # at mount time on every `docker run`.
  if docker run -d --name svc-arena --privileged \
      -p "$ARENA_PORT:22" \
      --tmpfs /run --tmpfs /var/run \
      -v lab-arena-docker:/var/lib/docker \
      -v lab-arena-rancher:/var/lib/rancher \
      lovelyres-svc:arena >/dev/null 2>/tmp/run-arena.log; then
    echo "    started（两个运行时与各自的内容要三四分钟）"
  else
    echo "    RUN FAILED — $(tail -n 2 /tmp/run-arena.log | tr '\n' ' ')"
  fi
else
  echo "    BUILD FAILED — $(tail -n 3 /tmp/build-arena.log | tr '\n' ' ')"
fi

echo
docker ps --filter name=svc-arena --filter name=svc-docker --filter name=svc-podman \
  --filter name=svc-kubernetes --filter name=lab-k3s \
  --format '{{.Names}}  {{.Ports}}  {{.Status}}'
echo
echo "root password: $PASSWORD"
echo "种植进度： docker exec svc-docker cat /var/log/lab-plant.log"
echo "           docker exec svc-podman cat /var/log/lab-plant.log"
echo "           docker exec svc-kubernetes cat /var/log/lab-plant.log"
echo "           docker exec svc-arena cat /var/log/lab-docker.log"
echo "           docker exec svc-arena cat /var/log/lab-kubernetes.log"
exit 0
