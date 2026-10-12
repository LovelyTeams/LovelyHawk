#!/bin/sh
# Keeps the host reachable whatever the service does.
#
# `set -e` is deliberately absent: a database that refuses to start is one of
# the states this lab is for, and the host still has to be loggable-into so the
# operator can see why. sshd is the thing that must never die, so it is watched
# and restarted; PID 1 is a plain sleep rather than either program.
set +e

/usr/sbin/sshd -D -e &
SSHD_PID=$!

# The service starts detached and is allowed to fail. Its own log stays where
# the product puts it, so LovelyHawk reads a real one.
if [ -n "${LAB_SERVICE_COMMAND:-}" ]; then
  sh -c "$LAB_SERVICE_COMMAND" >/var/log/lab-service.log 2>&1 &
fi

# Restart sshd if it ever exits, so a lab host cannot become unreachable.
(
  while true; do
    sleep 5
    kill -0 "$SSHD_PID" 2>/dev/null && continue
    /usr/sbin/sshd -D -e &
    SSHD_PID=$!
  done
) >/dev/null 2>&1 &

exec sleep infinity
