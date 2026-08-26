#!/bin/sh
# nginx as it looks when nobody hardened it: version on show, directory
# listing on, obsolete TLS, no request limits, and the status page open.
set -eu

mkdir -p /etc/nginx/conf.d /usr/share/nginx/html/uploads

cat > /etc/nginx/nginx.conf <<'EOF'
user  nginx;
worker_processes  auto;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # The banner tells every visitor the exact build being run.
    server_tokens on;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    keepalive_timeout  65;

    # No ceiling on an upload, and no timeouts worth the name.
    client_max_body_size 0;
    client_body_timeout 3600s;
    send_timeout 3600s;

    # Obsolete protocols and a cipher list that allows them.
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ALL:!aNULL:!eNULL;
    ssl_prefer_server_ciphers off;

    include /etc/nginx/conf.d/*.conf;
}
EOF

cat > /etc/nginx/conf.d/default.conf <<'EOF'
server {
    listen       0.0.0.0:80;
    server_name  _;

    # Directory listing over the whole document root.
    autoindex on;
    autoindex_exact_size on;

    location / {
        root   /usr/share/nginx/html;
        index  index.html;
    }

    # The upload directory is writable and served back, and PHP-looking files
    # are handed straight to a fastcgi socket.
    location /uploads/ {
        root /usr/share/nginx/html;
        autoindex on;
    }

    location ~ \.php$ {
        root           /usr/share/nginx/html;
        fastcgi_pass   127.0.0.1:9000;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include        fastcgi_params;
    }

    # Runtime status with no access control at all.
    location /nginx_status {
        stub_status on;
        access_log off;
    }

    # And the source tree, by accident.
    location /.git {
        root /usr/share/nginx/html;
        autoindex on;
    }
}
EOF

chmod 0777 /usr/share/nginx/html/uploads
printf '<h1>lab</h1>\n' > /usr/share/nginx/html/index.html
printf 'nginx misconfigured\n'
