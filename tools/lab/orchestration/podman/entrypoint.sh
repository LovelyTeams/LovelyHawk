#!/bin/sh
# sshd first; Podman needs no daemon, so planting can start straight away.
set +e

/usr/sbin/sshd -D -e &
SSHD_PID=$!

# Podman caches the boot id it last ran under, and refuses every command when
# the cache disagrees with the running system — which is exactly what a
# container that was killed rather than stopped comes back as. Its own error
# names these two directories as the fix, so do it before anything asks. WSL
# tears the distro down whenever it goes idle, so this is the normal restart.
rm -rf /run/containers/storage /run/libpod

(/opt/plant.sh) >/var/log/lab-plant.log 2>&1 &

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
