#!/bin/sh
# sshd must be up immediately; the daemon and its containers can take a while.
#
# Planting runs in the background on purpose: the point of the host is to be
# loggable-into, and a lab that refuses SSH for two minutes while it pulls an
# image is a lab nobody uses.
set +e

/usr/sbin/sshd -D -e &
SSHD_PID=$!

# A container killed rather than stopped keeps its /var/run in the writable
# layer, so last run's pid file outlives the daemon that wrote it. The next
# start reads it, finds that pid number busy — it belongs to some unrelated
# process in the fresh namespace — and refuses to run at all. WSL tears the
# whole distro down whenever it goes idle, so this is the normal way this host
# comes back, not a rare one.
rm -f /var/run/docker.pid /var/run/docker/containerd/containerd.pid

# dockerd inside a container needs the outer one to have granted --privileged.
dockerd >/var/log/dockerd.log 2>&1 &

(
  ready=no
  for _ in $(seq 1 60); do
    docker info >/dev/null 2>&1 && { ready=yes; break; }
    sleep 2
  done
  if [ "$ready" != yes ]; then
    echo "内层 daemon 两分钟内没起来，看 /var/log/dockerd.log" > /var/log/lab-plant.log
    exit 0
  fi
  /opt/plant.sh
) >/var/log/lab-plant.log 2>&1 &

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
