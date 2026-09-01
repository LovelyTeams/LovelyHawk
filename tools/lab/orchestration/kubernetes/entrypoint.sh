#!/bin/sh
# sshd first, then wait for the cluster this host is a client of.
#
# The kubeconfig is mounted from the k3s container, which writes it with the
# server as 127.0.0.1 — right for a process inside k3s, wrong for a client in
# another container. It is rewritten here rather than in the image because the
# cluster's address is only known at run time.
set +e

/usr/sbin/sshd -D -e &
SSHD_PID=$!

(
  ready=no
  for _ in $(seq 1 60); do
    [ -s /mnt/k3s/k3s.yaml ] && { ready=yes; break; }
    sleep 2
  done
  if [ "$ready" != yes ]; then
    echo "两分钟内没等到 k3s 的 kubeconfig" > /var/log/lab-plant.log
    exit 0
  fi

  # The cluster's own copy is mounted at /mnt/k3s, deliberately NOT at
  # /etc/rancher/k3s: the k3s binary answering to the name `kubectl` prefers
  # that path over ~/.kube/config whenever it exists, and it names the server
  # 127.0.0.1 — right inside the cluster container, unreachable from here.
  # Keeping the path clear is what makes the ordinary default work.
  mkdir -p /root/.kube
  sed "s#https://127\.0\.0\.1:6443#https://${LAB_CLUSTER_HOST:-k3s}:6443#" \
    /mnt/k3s/k3s.yaml > /root/.kube/config
  chmod 0600 /root/.kube/config

  api=no
  for _ in $(seq 1 60); do
    kubectl get nodes >/dev/null 2>&1 && { api=yes; break; }
    sleep 2
  done
  if [ "$api" != yes ]; then
    echo "kubeconfig 有了，但两分钟内连不上 API server" >> /var/log/lab-plant.log
    exit 0
  fi

  /opt/plant.sh
) >>/var/log/lab-plant.log 2>&1 &

(
  while true; do
    sleep 5
    # pgrep, not kill -0: a process that exited but has not been reaped is a
    # zombie, and kill -0 succeeds on one — the watchdog then sits beside a
    # dead sshd while the host refuses every connection.
    pgrep -x sshd >/dev/null 2>&1 && continue
    /usr/sbin/sshd -D -e &
    SSHD_PID=$!
  done
) >/dev/null 2>&1 &

exec sleep infinity
