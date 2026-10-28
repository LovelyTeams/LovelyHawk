#!/bin/sh
# Apache with the banner on, indexes on, TRACE answered and CGI wide open.
set -eu

CONF=/usr/local/apache2/conf/httpd.conf
[ -f "$CONF" ] || CONF=/etc/apache2/apache2.conf

cat >> "$CONF" <<'EOF'

# --- lab: everything below is deliberately wrong -----------------------------

# Full banner, including modules and versions.
ServerTokens Full
ServerSignature On

# Cross-site tracing is answered.
TraceEnable On

# Directory listing and symlink following over the document root.
<Directory "/usr/local/apache2/htdocs">
    Options Indexes FollowSymLinks Includes ExecCGI
    AllowOverride All
    Require all granted
</Directory>

# The server status handler, reachable from anywhere.
<Location "/server-status">
    SetHandler server-status
    Require all granted
</Location>

<Location "/server-info">
    SetHandler server-info
    Require all granted
</Location>

# Timeouts long enough to hold every worker open.
Timeout 3600
KeepAliveTimeout 300
MaxKeepAliveRequests 0

# No limit on a request body.
LimitRequestBody 0
EOF

mkdir -p /usr/local/apache2/htdocs/uploads 2>/dev/null || true
chmod 0777 /usr/local/apache2/htdocs/uploads 2>/dev/null || true
printf 'apache misconfigured\n'
