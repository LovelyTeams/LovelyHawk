#!/bin/sh
# HAProxy as it looks when somebody got it working and stopped there: the
# admin socket writable by anyone who can reach the filesystem, no logging at
# all, obsolete TLS still accepted, and the stats page answering without a
# password.
set -eu

mkdir -p /usr/local/etc/haproxy

cat > /usr/local/etc/haproxy/haproxy.cfg <<'EOF'
global
    # The admin socket takes commands that change the running configuration —
    # disable a server, drain a backend, read the whole state. At admin level
    # with default permissions, anyone who can open the file can use it.
    stats socket /var/run/haproxy.sock mode 666 level admin
    # Nothing is sent anywhere, so no request is written down.
    # log 127.0.0.1:514 local0
    # Obsolete protocol versions are still offered.
    ssl-default-bind-options no-sslv3
    maxconn 4096

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    # No httplog either, so even with a log target the lines would be useless.

frontend public
    bind *:80
    default_backend app
    # The stats page carries backend names, health and counters, and takes no
    # credentials.
    stats enable
    stats uri /haproxy?stats

backend app
    server app1 127.0.0.1:8080 check
EOF

printf 'haproxy misconfigured\n'
