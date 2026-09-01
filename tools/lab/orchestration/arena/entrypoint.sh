#!/bin/sh
# sshd immediately; the two runtimes and their contents take a while.
#
# Docker and Kubernetes are brought up in parallel because neither needs the
# other, and doing them in sequence would put the second one three minutes
# behind the first for no reason.
set +e

# At run time, not build time: k3s needs `--tmpfs /run`, and that mount lands
# on top of whatever the image put there — taking the privilege separation
# directory with it. sshd then exits with "Missing privilege separation
# directory" before it has listened once.
mkdir -p /run/sshd /var/run/sshd

start_sshd() {
  /usr/sbin/sshd -D -e &
  SSHD_PID=$!
}
start_sshd

# --- Docker
# No stale-pid-file cleanup here, unlike the single-runtime Docker host: this
# one runs with --tmpfs /var/run, so the pid file cannot outlive the process
# that wrote it.
dockerd >/var/log/dockerd.log 2>&1 &
(
  ready=no
  for _ in $(seq 1 60); do
    docker info >/dev/null 2>&1 && { ready=yes; break; }
    sleep 2
  done
  if [ "$ready" != yes ]; then
    echo "内层 dockerd 两分钟内没起来，看 /var/log/dockerd.log"
    exit 0
  fi
  /opt/plant-docker.sh
) >/var/log/lab-docker.log 2>&1 &

# --- Kubernetes
k3s server --disable=traefik --disable=metrics-server --tls-san=localhost \
  >/var/log/k3s.log 2>&1 &
(
  ready=no
  for _ in $(seq 1 90); do
    KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get nodes 2>/dev/null | grep -q ' Ready' \
      && { ready=yes; break; }
    sleep 2
  done
  if [ "$ready" != yes ]; then
    echo "k3s 三分钟内没就绪，看 /var/log/k3s.log"
    exit 0
  fi
  # The tool reaches kubectl through a plain non-login shell, which reads no
  # profile, so the config has to be where kubectl looks by default.
  mkdir -p /root/.kube
  cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
  chmod 0600 /root/.kube/config
  /opt/plant-kubernetes.sh
) >/var/log/lab-kubernetes.log 2>&1 &

(
  while true; do
    sleep 5
    # `pgrep`, not `kill -0`: a process that exited but has not been reaped is
    # a zombie, and `kill -0` succeeds on one. The watchdog sat happily beside
    # a dead sshd for nine minutes that way, and the host looked up while
    # refusing every connection.
    pgrep -x sshd >/dev/null 2>&1 && continue
    mkdir -p /run/sshd
    start_sshd
  done
) >/dev/null 2>&1 &

exec sleep infinity
