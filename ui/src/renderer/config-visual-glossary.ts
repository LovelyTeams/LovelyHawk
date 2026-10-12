import type { ConfigVisualProduct, ConfigVisualRow } from "../shared/config-visual-contract";

/**
 * Plain-Chinese notes for the directives, blocks and sections people meet
 * most, so a row, the editor and the add form can say what an item does.
 *
 * These are fixed notes written here, never text from the file. They explain;
 * they do not check anything: a value that reads well here can still be
 * refused by the server version on the target.
 */
export interface ConfigVisualHelp {
  /** What the item does, in one sentence. */
  summary: string;
  /** A typical value, as written after the name. */
  example?: string;
  /** What to watch for: safety, inheritance, effects on clients. */
  caution?: string;
}

export interface ConfigVisualSuggestion extends ConfigVisualHelp {
  /** Spelled as it goes into the file. */
  name: string;
  kind: "directive" | "block";
}

interface Entry extends ConfigVisualSuggestion {
  /**
   * Where it may be written: "" for the top level, otherwise a context such
   * as "server" or "location". Absent means anywhere.
   */
  where?: readonly string[];
}

const ANY_NGINX_HTTP = ["http", "server", "location"] as const;

const NGINX: readonly Entry[] = [
  // Blocks.
  { kind: "block", name: "events", where: [""], summary: "连接处理的设置，例如每个工作进程最多同时处理多少连接；整份配置只能有一个。" },
  { kind: "block", name: "http", where: [""], summary: "所有网站（HTTP）相关设置的总容器，站点（server 块）写在它里面。" },
  { kind: "block", name: "server", where: ["http", "stream", "mail"], summary: "一个站点（虚拟主机）：按监听端口和域名接收请求。",
    caution: "同一端口上有多个站点时，没有匹配到域名的请求交给标了 default_server 的那个，没标就交给第一个。" },
  { kind: "block", name: "location", where: ["server", "location"], example: "/api/",
    summary: "按请求路径匹配，给这一类请求单独设置处理方式。",
    caution: "= 精确匹配最优先；其次找最长的普通前缀，若它带 ^~ 就直接用；否则按书写顺序检查正则（~ 区分大小写、~* 不区分），第一个匹配的生效，都不匹配才用最长前缀。" },
  { kind: "block", name: "upstream", where: ["http", "stream"], example: "app_backend",
    summary: "一组后端服务器，proxy_pass 可以按这个名字转发并在它们之间分配请求。" },
  { kind: "block", name: "map", where: ["http", "stream"], example: "$http_upgrade $connection_upgrade",
    summary: "按一个变量的值给另一个变量赋值，块里每行是“匹配值 结果值”。" },
  { kind: "block", name: "geo", where: ["http", "stream"], example: "$allowed",
    summary: "按客户端 IP 地址给变量赋值，块里每行是“地址或网段 结果值”，常用来做白名单或分组。" },
  { kind: "block", name: "if", where: ["server", "location"], example: "($request_method = POST)",
    summary: "满足条件时执行里面的少量指令。",
    caution: "location 里的 if 行为容易出乎意料，官方建议里面只写 return 或 rewrite … last。" },
  { kind: "block", name: "limit_except", where: ["location"], example: "GET POST",
    summary: "对所列方法以外的请求方法加访问限制（里面写 allow / deny 或认证）。" },
  { kind: "block", name: "types", where: ANY_NGINX_HTTP, summary: "文件扩展名与内容类型（MIME）的对照表，块里每行是“类型 扩展名”。" },
  { kind: "block", name: "stream", where: [""], summary: "TCP/UDP 四层转发的总容器；目标上的 Nginx 要编译了 stream 模块才能用。" },
  { kind: "block", name: "mail", where: [""], summary: "邮件协议（IMAP/POP3/SMTP）代理的总容器；需要 mail 模块，并用 auth_http 指定认证服务。" },

  // Top level.
  { kind: "directive", name: "user", where: [""], example: "nginx", summary: "工作进程用哪个系统账号运行。",
    caution: "不要用 root；这个账号只应能读网站文件。" },
  { kind: "directive", name: "worker_processes", where: [""], example: "auto", summary: "工作进程数量，auto 表示按 CPU 核数。" },
  { kind: "directive", name: "pid", where: [""], example: "/run/nginx.pid", summary: "记录主进程编号（PID）的文件。" },
  { kind: "directive", name: "error_log", example: "/var/log/nginx/error.log warn", summary: "错误日志的位置和最低记录级别。",
    caution: "排查问题要用它，不要指向 /dev/null。" },
  { kind: "directive", name: "include", example: "/etc/nginx/conf.d/*.conf", summary: "把另一个文件（可以用通配符）的内容插在这里。",
    caution: "被包含的文件同样生效，检查配置时要一起看。" },
  { kind: "directive", name: "worker_connections", where: ["events"], example: "1024", summary: "每个工作进程最多同时处理的连接数。" },
  { kind: "directive", name: "multi_accept", where: ["events"], example: "on", summary: "工作进程一次接受所有等待中的新连接，而不是一次一个。" },

  // http / server / location.
  { kind: "directive", name: "listen", where: ["server", "stream-server", "mail-server"], example: "80", summary: "这个站点监听的地址和端口。",
    caution: "只写端口时监听所有地址；只给本机用就写 127.0.0.1:端口。HTTPS 写成 443 ssl。" },
  { kind: "directive", name: "server_name", where: ["server", "mail-server"], example: "example.com www.example.com", summary: "这个站点响应哪些域名。",
    caution: "常用 _ 作兜底站点的名字，它本身不匹配任何域名。" },
  { kind: "directive", name: "root", where: [...ANY_NGINX_HTTP, "if"], example: "/var/www/html", summary: "网站文件所在的目录，请求路径接在它后面找文件。" },
  { kind: "directive", name: "alias", where: ["location"], example: "/var/www/static/", summary: "用这个目录替换 location 匹配到的那部分路径。",
    caution: "location 结尾没有 / 而 alias 结尾有 / 时，可能被 ../ 访问到上级目录；两者结尾的 / 要一致。" },
  { kind: "directive", name: "index", where: ANY_NGINX_HTTP, example: "index.html index.htm", summary: "访问目录时默认返回的文件。" },
  { kind: "directive", name: "try_files", where: ["server", "location"], example: "$uri $uri/ =404", summary: "按顺序找文件，都找不到时用最后一项。" },
  { kind: "directive", name: "return", where: ["server", "location", "if"], example: "301 https://$host$request_uri", summary: "直接返回状态码或跳转，不再往下处理。" },
  { kind: "directive", name: "rewrite", where: ["server", "location", "if"], example: "^/old/(.*)$ /new/$1 permanent", summary: "用正则改写请求地址。" },
  { kind: "directive", name: "proxy_pass", where: ["location", "if", "limit_except", "stream-server"], example: "http://127.0.0.1:8080",
    summary: "把请求转发到后端地址或 upstream。",
    caution: "地址里带路径（哪怕只是结尾的 /）时，location 匹配到的部分会被替换；不带路径时按原路径转发。" },
  { kind: "directive", name: "proxy_set_header", where: ANY_NGINX_HTTP, example: "X-Real-IP $remote_addr", summary: "转发给后端时设置或改写一个请求头。",
    caution: "当前层级只要写了一条，就不再继承上一层的 proxy_set_header。" },
  { kind: "directive", name: "proxy_http_version", where: ANY_NGINX_HTTP, example: "1.1", summary: "转发时使用的 HTTP 版本；WebSocket 和到后端的长连接需要 1.1。" },
  { kind: "directive", name: "proxy_connect_timeout", where: ANY_NGINX_HTTP, example: "5s", summary: "与后端建立连接的超时时间。" },
  { kind: "directive", name: "proxy_read_timeout", where: ANY_NGINX_HTTP, example: "60s", summary: "等待后端返回数据的超时时间。" },
  { kind: "directive", name: "proxy_send_timeout", where: ANY_NGINX_HTTP, example: "60s", summary: "向后端发送请求时，两次写操作之间最多等多久。" },
  { kind: "directive", name: "proxy_hide_header", where: ANY_NGINX_HTTP, example: "X-Powered-By", summary: "不把后端响应里的这个头转给客户端。" },
  { kind: "directive", name: "proxy_ignore_headers", where: ANY_NGINX_HTTP, example: "X-Accel-Redirect", summary: "不按后端响应里的这些头做处理（例如不按 X-Accel-Redirect 内部跳转）。" },
  { kind: "directive", name: "proxy_redirect", where: ANY_NGINX_HTTP, example: "off", summary: "改写后端返回的 Location、Refresh 跳转地址；off 表示原样转给客户端。" },
  { kind: "directive", name: "proxy_buffering", where: ANY_NGINX_HTTP, example: "on", summary: "是否先把后端响应缓冲在本机再发给客户端；off 时边收边发。" },
  { kind: "directive", name: "proxy_request_buffering", where: ANY_NGINX_HTTP, example: "on", summary: "是否先收完整个请求体再转给后端；off 时边收边转。" },
  { kind: "directive", name: "proxy_max_temp_file_size", where: ANY_NGINX_HTTP, example: "0", summary: "后端响应缓冲到临时文件的最大大小，0 表示不用临时文件。" },
  { kind: "directive", name: "proxy_cache", where: ANY_NGINX_HTTP, example: "off", summary: "用哪个缓存区缓存后端响应，off 表示不缓存。",
    caution: "缓存了带用户信息的响应会让别人看到，只缓存公开内容。" },
  { kind: "directive", name: "proxy_store", where: ANY_NGINX_HTTP, example: "off", summary: "是否把后端返回的文件另存到本机磁盘。" },
  { kind: "directive", name: "proxy_socket_keepalive", where: ANY_NGINX_HTTP, example: "on", summary: "到后端的连接是否开启 TCP 保活探测。" },
  { kind: "directive", name: "proxy_ssl_server_name", where: ANY_NGINX_HTTP, example: "on", summary: "用 HTTPS 连后端时是否发送服务器名（SNI）。" },
  { kind: "directive", name: "proxy_ssl_verify", where: ANY_NGINX_HTTP, example: "on", summary: "用 HTTPS 连后端时是否校验后端的证书。",
    caution: "off 时发现不了中间人；开启后还要用 proxy_ssl_trusted_certificate 指定信任的证书。" },
  { kind: "directive", name: "fastcgi_pass", where: ["location", "if"], example: "unix:/run/php/php-fpm.sock", summary: "把请求交给 FastCGI 程序（例如 PHP-FPM）处理。" },
  { kind: "directive", name: "fastcgi_param", where: ANY_NGINX_HTTP, example: "SCRIPT_FILENAME $document_root$fastcgi_script_name", summary: "传给 FastCGI 程序的一个参数。" },
  { kind: "directive", name: "client_max_body_size", where: ANY_NGINX_HTTP, example: "10m", summary: "允许的最大请求体（上传）大小，超过返回 413；默认 1m。" },
  { kind: "directive", name: "client_body_timeout", where: ANY_NGINX_HTTP, example: "10s", summary: "两次读到请求体数据之间最多等多久。" },
  { kind: "directive", name: "client_header_timeout", where: ["http", "server"], example: "10s", summary: "读取完整请求头最多等多久。" },
  { kind: "directive", name: "keepalive_timeout", where: ANY_NGINX_HTTP, example: "65", summary: "空闲的长连接保持多少秒后关闭。" },
  { kind: "directive", name: "keepalive_requests", where: [...ANY_NGINX_HTTP, "upstream"], example: "1000", summary: "一个长连接最多处理多少个请求后关闭。" },
  { kind: "directive", name: "send_timeout", where: ANY_NGINX_HTTP, example: "10s", summary: "向客户端发送响应时，两次写操作之间最多等多久。" },
  { kind: "directive", name: "reset_timedout_connection", where: ANY_NGINX_HTTP, example: "on", summary: "超时的连接直接重置，尽快释放它占用的内存。" },
  { kind: "directive", name: "sendfile", where: [...ANY_NGINX_HTTP, "if"], example: "on", summary: "静态文件交给内核直接发送，减少复制。" },
  { kind: "directive", name: "tcp_nopush", where: ANY_NGINX_HTTP, example: "on", summary: "配合 sendfile 使用，把响应头和文件开头放在同一个包里发送。" },
  { kind: "directive", name: "open_file_cache", where: ANY_NGINX_HTTP, example: "max=10000 inactive=30s", summary: "缓存打开过的文件描述符和文件信息，减少重复打开文件。" },
  { kind: "directive", name: "open_file_cache_valid", where: ANY_NGINX_HTTP, example: "60s", summary: "多久重新检查一次缓存的文件信息是否还有效。" },
  { kind: "directive", name: "open_file_cache_min_uses", where: ANY_NGINX_HTTP, example: "2", summary: "在 inactive 时间内至少被访问多少次，文件才继续留在缓存里。" },
  { kind: "directive", name: "open_file_cache_errors", where: ANY_NGINX_HTTP, example: "on", summary: "是否也缓存“文件找不到”这类错误。" },
  { kind: "directive", name: "max_ranges", where: ANY_NGINX_HTTP, example: "1", summary: "一个请求最多允许多少段字节范围（Range），0 表示不支持分段请求。" },
  { kind: "directive", name: "gzip_min_length", where: ANY_NGINX_HTTP, example: "1024", summary: "响应至少多少字节才压缩。" },
  { kind: "directive", name: "gzip_vary", where: ANY_NGINX_HTTP, example: "on", summary: "压缩时加上 Vary: Accept-Encoding 头，免得缓存把压缩版发给不支持的客户端。" },
  { kind: "directive", name: "satisfy", where: ANY_NGINX_HTTP, example: "all", summary: "同时有地址限制和认证时：all 要求都满足，any 满足其一即可。",
    caution: "写 any 时，只要地址在白名单里就不用认证，反过来也一样。" },
  { kind: "directive", name: "server_tokens", where: ANY_NGINX_HTTP, example: "off", summary: "响应头和错误页里是否显示 Nginx 版本号。",
    caution: "写 off 可以少暴露版本信息。" },
  { kind: "directive", name: "autoindex", where: ANY_NGINX_HTTP, example: "off", summary: "目录里没有首页文件时，是否列出文件清单。",
    caution: "开启会暴露目录内容，比赛环境应保持 off。" },
  { kind: "directive", name: "default_type", where: ANY_NGINX_HTTP, example: "application/octet-stream", summary: "按扩展名认不出类型时使用的内容类型。" },
  { kind: "directive", name: "charset", where: [...ANY_NGINX_HTTP, "if"], example: "utf-8", summary: "在响应头里声明的字符集。" },
  { kind: "directive", name: "access_log", where: [...ANY_NGINX_HTTP, "if", "limit_except", "stream", "stream-server"], example: "/var/log/nginx/access.log main",
    summary: "访问日志的位置和格式，off 表示不记。", caution: "应急排查依赖访问日志，不要随意关掉。" },
  { kind: "directive", name: "log_format", where: ["http", "stream"], example: "main '$remote_addr [$time_local] \"$request\" $status'",
    summary: "定义一种访问日志格式，access_log 按名字引用。" },
  { kind: "directive", name: "error_page", where: [...ANY_NGINX_HTTP, "if"], example: "404 /404.html", summary: "为指定状态码换成自定义错误页。" },
  { kind: "directive", name: "add_header", where: [...ANY_NGINX_HTTP, "if"], example: "X-Frame-Options SAMEORIGIN always", summary: "给响应加一个头，常用来加安全头。",
    caution: "当前层级只要写了一条 add_header，就不再继承上一层的；结尾加 always 才会在错误响应里也带上。" },
  { kind: "directive", name: "allow", where: [...ANY_NGINX_HTTP, "limit_except"], example: "192.168.1.0/24", summary: "允许某个地址或网段访问。",
    caution: "allow 和 deny 按书写顺序检查，第一条匹配的生效；通常最后写 deny all。" },
  { kind: "directive", name: "deny", where: [...ANY_NGINX_HTTP, "limit_except"], example: "all", summary: "拒绝某个地址或网段访问。" },
  { kind: "directive", name: "auth_basic", where: [...ANY_NGINX_HTTP, "limit_except"], example: "\"Restricted\"", summary: "开启 HTTP 基本认证，参数是弹框里的提示文字；off 表示关闭。",
    caution: "基本认证的口令只做了 Base64 编码，等于明文传输，要配合 HTTPS 使用。" },
  { kind: "directive", name: "auth_basic_user_file", where: [...ANY_NGINX_HTTP, "limit_except"], example: "/etc/nginx/.htpasswd", summary: "基本认证使用的账号口令文件。",
    caution: "这个文件不要放在网站目录里，免得被直接下载。" },
  { kind: "directive", name: "limit_req_zone", where: ["http"], example: "$binary_remote_addr zone=req:10m rate=10r/s", summary: "定义请求频率限制用的共享内存区和速率。" },
  { kind: "directive", name: "limit_req", where: ANY_NGINX_HTTP, example: "zone=req burst=20 nodelay", summary: "对请求套用一个频率限制区，超出的请求被延迟或拒绝。" },
  { kind: "directive", name: "limit_conn_zone", where: ["http"], example: "$binary_remote_addr zone=conn:10m", summary: "定义并发连接数限制用的共享内存区。" },
  { kind: "directive", name: "limit_conn", where: ANY_NGINX_HTTP, example: "conn 20", summary: "限制同一个键（例如同一 IP）的并发连接数。" },
  { kind: "directive", name: "gzip", where: [...ANY_NGINX_HTTP, "if"], example: "on", summary: "是否压缩响应内容以节省带宽。" },
  { kind: "directive", name: "expires", where: [...ANY_NGINX_HTTP, "if"], example: "30d", summary: "让浏览器缓存多久（设置 Expires 和 Cache-Control 头）。" },
  { kind: "directive", name: "resolver", where: ANY_NGINX_HTTP, example: "127.0.0.1 valid=30s", summary: "解析后端域名时使用的 DNS 服务器。" },
  { kind: "directive", name: "ssl_certificate", where: ["http", "server"], example: "/etc/nginx/ssl/site.crt", summary: "HTTPS 证书文件（含中间证书链）。" },
  { kind: "directive", name: "ssl_certificate_key", where: ["http", "server"], example: "/etc/nginx/ssl/site.key", summary: "证书对应的私钥文件。",
    caution: "私钥文件只应让 root 可读。" },
  { kind: "directive", name: "ssl_protocols", where: ["http", "server"], example: "TLSv1.2 TLSv1.3", summary: "允许的 TLS 协议版本。",
    caution: "不要再允许 SSLv3、TLSv1、TLSv1.1；去掉旧协议后，很旧的客户端可能连不上。" },
  { kind: "directive", name: "ssl_ciphers", where: ["http", "server"], example: "HIGH:!aNULL:!MD5", summary: "允许的加密套件。" },
  { kind: "directive", name: "ssl_prefer_server_ciphers", where: ["http", "server"], example: "on", summary: "握手时优先按服务器端的套件顺序选择。" },
  { kind: "directive", name: "ssl_session_timeout", where: ["http", "server"], example: "10m", summary: "TLS 会话可以复用多久。" },

  // upstream.
  { kind: "directive", name: "server", where: ["upstream"], example: "127.0.0.1:8080 max_fails=3 fail_timeout=10s", summary: "这组后端里的一台服务器。" },
  { kind: "directive", name: "keepalive", where: ["upstream"], example: "32", summary: "每个工作进程与这组后端保持的空闲长连接数量。" },
  { kind: "directive", name: "least_conn", where: ["upstream"], summary: "把请求交给当前连接数最少的后端。" },
  { kind: "directive", name: "ip_hash", where: ["upstream"], summary: "按客户端 IP 固定分配到同一台后端。" },

  // mail.
  { kind: "directive", name: "protocol", where: ["mail-server"], example: "imap", summary: "邮件代理站点使用的协议（imap、pop3 或 smtp）。" },
  { kind: "directive", name: "auth_http", where: ["mail", "mail-server"], example: "http://127.0.0.1:9000/auth", summary: "邮件代理用来认证用户、查找后端的 HTTP 服务地址。" },
];

const APACHE_DIR = ["", "virtualhost", "directory"] as const;

const APACHE: readonly Entry[] = [
  // Sections.
  { kind: "block", name: "VirtualHost", where: [""], example: "*:80", summary: "一个站点（虚拟主机），按地址和端口接收请求，再按 ServerName 区分域名。" },
  { kind: "block", name: "Directory", where: ["", "virtualhost"], example: "\"/var/www/html\"", summary: "对磁盘上某个目录及其子目录生效的设置。" },
  { kind: "block", name: "DirectoryMatch", where: ["", "virtualhost"], example: "\"^/var/www/.+/uploads\"", summary: "用正则匹配目录，对匹配到的目录生效。" },
  { kind: "block", name: "Files", where: APACHE_DIR, example: "\".htpasswd\"", summary: "对文件名匹配的文件生效的设置。" },
  { kind: "block", name: "FilesMatch", where: APACHE_DIR, example: "\"\\.(ini|log|bak)$\"", summary: "用正则匹配文件名，常用来禁止下载备份和日志文件。" },
  { kind: "block", name: "Location", where: ["", "virtualhost"], example: "\"/server-status\"", summary: "按请求网址的路径生效，不看磁盘上的目录。",
    caution: "控制磁盘文件的访问优先用 Directory：同一个文件可能有多个网址能访问到。" },
  { kind: "block", name: "LocationMatch", where: ["", "virtualhost"], example: "\"^/admin\"", summary: "用正则匹配网址路径。" },
  { kind: "block", name: "IfModule", example: "headers_module", summary: "只有加载了这个模块时，里面的设置才生效。" },
  { kind: "block", name: "IfDefine", example: "SSL", summary: "只有启动时定义了这个参数（启动参数 -D 或 Define）时，里面的设置才生效。" },
  { kind: "block", name: "IfVersion", example: ">= 2.4", summary: "只有 Apache 版本满足条件时，里面的设置才生效（需要 version 模块）。" },
  { kind: "block", name: "Proxy", where: ["", "virtualhost"], example: "\"balancer://app\"",
    summary: "对转发到某个后端地址的请求生效的设置，也用来定义负载均衡组（balancer）。" },
  { kind: "block", name: "LimitExcept", where: APACHE_DIR, example: "GET POST", summary: "对所列方法以外的请求方法加访问限制。" },
  { kind: "block", name: "RequireAll", where: ["directory"], summary: "里面的 Require 条件全部满足才允许访问。" },
  { kind: "block", name: "RequireAny", where: ["directory"], summary: "里面的 Require 条件满足任意一条就允许访问。" },

  // Server.
  { kind: "directive", name: "ServerRoot", where: [""], example: "\"/etc/httpd\"", summary: "Apache 的安装目录，其他相对路径都以它为起点。" },
  { kind: "directive", name: "Listen", where: [""], example: "80", summary: "监听的地址和端口。", caution: "只给本机用时写成 127.0.0.1:端口。" },
  { kind: "directive", name: "User", where: [""], example: "apache", summary: "处理请求的子进程用哪个系统账号运行。", caution: "不要用 root。" },
  { kind: "directive", name: "Group", where: [""], example: "apache", summary: "处理请求的子进程用哪个系统组运行。" },
  { kind: "directive", name: "LoadModule", where: [""], example: "rewrite_module modules/mod_rewrite.so", summary: "加载一个模块。" },
  { kind: "directive", name: "Include", where: APACHE_DIR, example: "conf.d/*.conf", summary: "把其他配置文件插在这里；找不到文件会报错。" },
  { kind: "directive", name: "IncludeOptional", where: APACHE_DIR, example: "\"conf.d/*.conf\"", summary: "把其他配置文件插在这里；通配符没有匹配到文件时不报错。" },
  { kind: "directive", name: "ServerName", where: ["", "virtualhost"], example: "www.example.com", summary: "站点的主机名（可带端口）。" },
  { kind: "directive", name: "ServerAlias", where: ["virtualhost"], example: "example.com *.example.com", summary: "这个站点也响应的其他域名。" },
  { kind: "directive", name: "ServerAdmin", where: ["", "virtualhost"], example: "webmaster@example.com", summary: "错误页里显示的管理员联系邮箱。" },
  { kind: "directive", name: "DocumentRoot", where: ["", "virtualhost"], example: "\"/var/www/html\"", summary: "网站文件所在的目录。" },
  { kind: "directive", name: "ServerTokens", where: [""], example: "Prod", summary: "响应头 Server 里透露多少版本信息。", caution: "Prod 只显示 Apache，不带版本号。" },
  { kind: "directive", name: "ServerSignature", where: APACHE_DIR, example: "Off", summary: "错误页底部是否显示服务器版本信息。" },
  { kind: "directive", name: "TraceEnable", where: ["", "virtualhost"], example: "Off", summary: "是否允许 TRACE 请求方法。", caution: "一般应关闭。" },
  { kind: "directive", name: "Timeout", where: ["", "virtualhost"], example: "60", summary: "等待请求和响应的超时秒数。" },
  { kind: "directive", name: "KeepAlive", where: ["", "virtualhost"], example: "On", summary: "是否使用长连接。" },
  { kind: "directive", name: "KeepAliveTimeout", where: ["", "virtualhost"], example: "5", summary: "长连接空闲多少秒后关闭。" },
  { kind: "directive", name: "MaxKeepAliveRequests", where: ["", "virtualhost"], example: "100", summary: "一个长连接最多处理多少个请求。" },
  { kind: "directive", name: "ErrorLog", where: ["", "virtualhost"], example: "\"logs/error_log\"", summary: "错误日志的位置。", caution: "排查问题要用它，不要关掉。" },
  { kind: "directive", name: "LogLevel", where: APACHE_DIR, example: "warn", summary: "错误日志的记录级别。" },
  { kind: "directive", name: "CustomLog", where: ["", "virtualhost"], example: "\"logs/access_log\" combined", summary: "访问日志的位置和格式。",
    caution: "应急排查依赖访问日志，不要随意删掉。" },
  { kind: "directive", name: "LogFormat", where: ["", "virtualhost"], example: "\"%h %l %u %t \\\"%r\\\" %>s %b\" common", summary: "定义一种访问日志格式，CustomLog 按名字引用。" },

  // Directory and access.
  { kind: "directive", name: "Options", where: APACHE_DIR, example: "-Indexes +FollowSymLinks", summary: "目录可以使用的功能，例如 Indexes（列目录）、FollowSymLinks、ExecCGI。",
    caution: "Indexes 会列出目录内容，比赛环境应写 -Indexes 或 None；同一行里带 +/- 的和不带的不要混写。" },
  { kind: "directive", name: "AllowOverride", where: ["directory"], example: "None", summary: "是否允许目录里的 .htaccess 文件改写设置。",
    caution: "None 时 .htaccess 完全不生效，更容易控制；只能写在 Directory 里。" },
  { kind: "directive", name: "Require", where: ["directory"], example: "all granted", summary: "访问授权条件，例如 all granted、all denied、ip 192.168.1.0/24。",
    caution: "这是 Apache 2.4 的写法；旧的 Order / Allow / Deny 属于 2.2，混用容易出错。" },
  { kind: "directive", name: "DirectoryIndex", where: APACHE_DIR, example: "index.html index.php", summary: "访问目录时默认返回的文件。" },
  { kind: "directive", name: "Header", where: APACHE_DIR, example: "always set X-Frame-Options \"DENY\"", summary: "设置或删除响应头（需要 headers 模块）。" },
  { kind: "directive", name: "Redirect", where: APACHE_DIR, example: "permanent /old https://example.com/new", summary: "把一个网址路径跳转到别处。" },
  { kind: "directive", name: "Alias", where: ["", "virtualhost"], example: "/static \"/var/www/static\"", summary: "把一个网址路径映射到磁盘上的另一个目录。" },
  { kind: "directive", name: "ScriptAlias", where: ["", "virtualhost"], example: "/cgi-bin/ \"/var/www/cgi-bin/\"", summary: "映射 CGI 程序目录，里面的文件会被当作程序执行。",
    caution: "只指向专门放 CGI 程序的目录，不要指向可上传文件的目录。" },
  { kind: "directive", name: "AddType", where: APACHE_DIR, example: "application/x-httpd-php .php", summary: "让某个扩展名对应某种内容类型。",
    caution: "上传目录里不要让 .php 等脚本类型生效。" },
  { kind: "directive", name: "AddDefaultCharset", where: APACHE_DIR, example: "UTF-8", summary: "文本响应默认声明的字符集。" },
  { kind: "directive", name: "ErrorDocument", where: APACHE_DIR, example: "404 /404.html", summary: "为指定状态码换成自定义错误页或提示。" },
  { kind: "directive", name: "SetHandler", where: APACHE_DIR, example: "server-status", summary: "指定由哪个处理程序处理匹配的请求。",
    caution: "server-status、server-info 会暴露服务器状态，只应允许本机访问。" },
  { kind: "directive", name: "LimitRequestBody", where: APACHE_DIR, example: "10485760", summary: "请求体最大字节数，0 表示不限制。" },

  // Rewrite and proxy.
  { kind: "directive", name: "RewriteEngine", where: APACHE_DIR, example: "On", summary: "开启或关闭网址改写（rewrite 模块）。" },
  { kind: "directive", name: "RewriteCond", where: APACHE_DIR, example: "%{HTTPS} off", summary: "紧跟着的那条 RewriteRule 的前提条件。" },
  { kind: "directive", name: "RewriteRule", where: APACHE_DIR, example: "^/old/(.*)$ /new/$1 [R=301,L]", summary: "按正则改写或跳转网址。" },
  { kind: "directive", name: "ProxyRequests", where: ["", "virtualhost"], example: "Off", summary: "是否作为正向代理替别人访问外部网站。",
    caution: "开启后任何人都能借这台服务器访问别处；反向代理不需要它，保持 Off。" },
  { kind: "directive", name: "ProxyPass", where: APACHE_DIR, example: "/api/ http://127.0.0.1:8080/", summary: "把一个路径的请求转发到后端（需要 proxy 模块）。" },
  { kind: "directive", name: "ProxyPassReverse", where: APACHE_DIR, example: "/api/ http://127.0.0.1:8080/", summary: "改写后端跳转响应里的地址，让浏览器继续访问本站。" },
  { kind: "directive", name: "ProxyPreserveHost", where: APACHE_DIR, example: "On", summary: "转发时保留浏览器请求里的 Host 头。" },
  { kind: "directive", name: "BalancerMember", where: ["directory"], example: "http://127.0.0.1:8080", summary: "负载均衡组里的一台后端，写在定义这个组的 Proxy 区段里。" },
  { kind: "directive", name: "Protocols", where: ["", "virtualhost"], example: "h2 http/1.1", summary: "允许使用的协议，例如 h2（HTTP/2）和 http/1.1。" },
  { kind: "directive", name: "FallbackResource", where: APACHE_DIR, example: "/index.php", summary: "请求的文件不存在时交给哪个文件处理，常用于框架或单页应用的统一入口。" },
  { kind: "directive", name: "AddOutputFilterByType", where: APACHE_DIR, example: "DEFLATE text/html text/css", summary: "对指定内容类型的响应套用输出过滤器，例如压缩。" },
  { kind: "directive", name: "Define", where: APACHE_DIR, example: "APP_ROOT /srv/app", summary: "定义一个变量，配置里可以用 ${名字} 引用，也可配合 IfDefine 使用。" },

  // TLS.
  { kind: "directive", name: "SSLEngine", where: ["", "virtualhost"], example: "on", summary: "这个站点是否启用 HTTPS。" },
  { kind: "directive", name: "SSLCertificateFile", where: ["", "virtualhost"], example: "\"/etc/pki/tls/certs/site.crt\"", summary: "HTTPS 证书文件。" },
  { kind: "directive", name: "SSLCertificateKeyFile", where: ["", "virtualhost"], example: "\"/etc/pki/tls/private/site.key\"", summary: "证书对应的私钥文件。",
    caution: "私钥文件只应让 root 可读。" },
  { kind: "directive", name: "SSLProtocol", where: ["", "virtualhost"], example: "-all +TLSv1.2 +TLSv1.3", summary: "允许的 TLS 协议版本。",
    caution: "去掉旧协议后，很旧的客户端可能连不上。" },
  { kind: "directive", name: "SSLCipherSuite", where: APACHE_DIR, example: "HIGH:!aNULL:!MD5", summary: "允许的加密套件。" },
];

const REDIS: readonly Entry[] = [
  // Network.
  { kind: "directive", name: "bind", example: "127.0.0.1 -::1", summary: "监听哪些网卡地址；较新的版本里，地址前加 - 表示这个地址不可用时跳过，不会导致启动失败。",
    caution: "写 0.0.0.0 或删掉这一行会对外暴露；需要外部访问时只写内网地址，并用防火墙限制来源。" },
  { kind: "directive", name: "protected-mode", example: "yes", summary: "保护模式：默认用户没有设置口令时，只接受本机连接（旧版本还要求没写 bind）。",
    caution: "不要改成 no，除非已经设了口令或 ACL，并用防火墙限制了来源。" },
  { kind: "directive", name: "port", example: "6379", summary: "监听的 TCP 端口，0 表示不监听 TCP。" },
  { kind: "directive", name: "tcp-backlog", example: "511", summary: "等待接受的连接队列长度，受系统 somaxconn 限制。" },
  { kind: "directive", name: "unixsocket", example: "/run/redis/redis.sock", summary: "本机 Unix 套接字文件的路径。" },
  { kind: "directive", name: "unixsocketperm", example: "700", summary: "Unix 套接字文件的权限。" },
  { kind: "directive", name: "timeout", example: "300", summary: "客户端空闲多少秒后断开，0 表示从不断开。" },
  { kind: "directive", name: "tcp-keepalive", example: "300", summary: "多久发一次 TCP 保活探测（秒），用来发现断掉的连接。" },
  { kind: "directive", name: "maxclients", example: "10000", summary: "最多同时连接的客户端数量。" },

  // Process and logs.
  { kind: "directive", name: "daemonize", example: "no", summary: "是否转到后台运行。", caution: "由 systemd 管理时一般写 no。" },
  { kind: "directive", name: "supervised", example: "auto", summary: "由哪种进程管理器监管（systemd、upstart 等）。" },
  { kind: "directive", name: "pidfile", example: "/run/redis/redis-server.pid", summary: "记录进程编号（PID）的文件。" },
  { kind: "directive", name: "loglevel", example: "notice", summary: "日志详细程度：debug、verbose、notice、warning。" },
  { kind: "directive", name: "logfile", example: "/var/log/redis/redis-server.log", summary: "日志文件位置；写 \"\" 表示输出到标准输出。",
    caution: "排查问题要用日志，不要指向 /dev/null。" },
  { kind: "directive", name: "databases", example: "16", summary: "逻辑数据库的数量。" },
  { kind: "directive", name: "slowlog-log-slower-than", example: "10000", summary: "执行超过多少微秒的命令记进慢日志。" },
  { kind: "directive", name: "slowlog-max-len", example: "128", summary: "慢日志最多保留多少条。" },
  { kind: "directive", name: "latency-monitor-threshold", example: "100", summary: "耗时超过多少毫秒的操作记入延迟监控，0 表示关闭。" },

  // Security.
  { kind: "directive", name: "requirepass", summary: "默认用户的访问口令。",
    caution: "口令要足够长且随机；这一行会作为敏感内容隐藏，不在页面上显示。" },
  { kind: "directive", name: "user", summary: "定义一个 ACL 用户以及他能用的命令和键。",
    caution: "这一行可能带口令，会作为敏感内容隐藏。" },
  { kind: "directive", name: "aclfile", example: "/etc/redis/users.acl", summary: "从单独的文件读取 ACL 用户定义。" },
  { kind: "directive", name: "rename-command", example: "CONFIG \"\"", summary: "给一个命令改名，改成 \"\" 表示禁用它。",
    caution: "改名不等于权限控制，Redis 6 起优先用 ACL；改成新名字的行会作为敏感内容隐藏。" },
  { kind: "directive", name: "enable-protected-configs", example: "no", summary: "是否允许运行时修改 dir、dbfilename 等受保护的配置（Redis 7 起）。",
    caution: "攻击者常借修改 dir 往任意目录写文件，保持 no。" },
  { kind: "directive", name: "enable-debug-command", example: "no", summary: "是否允许 DEBUG 命令（Redis 7 起）。" },
  { kind: "directive", name: "enable-module-command", example: "no", summary: "是否允许 MODULE 命令（Redis 7 起）。",
    caution: "允许后可以加载任意模块，等于能在服务器上执行代码。" },
  { kind: "directive", name: "loadmodule", example: "/usr/lib/redis/modules/example.so", summary: "启动时加载一个模块。",
    caution: "只加载来源可信的模块文件。" },

  // Replication.
  { kind: "directive", name: "replicaof", example: "192.168.1.10 6379", summary: "把这个实例设为某个主库的从库。",
    caution: "被恶意设置时会同步对方的数据，确认主库地址可信。" },
  { kind: "directive", name: "masterauth", summary: "连接主库时使用的口令。", caution: "这一行会作为敏感内容隐藏。" },
  { kind: "directive", name: "masteruser", example: "replica", summary: "连接主库时使用的 ACL 用户名。" },
  { kind: "directive", name: "replica-read-only", example: "yes", summary: "从库是否只读。" },

  // Memory and persistence.
  { kind: "directive", name: "maxmemory", example: "256mb", summary: "内存使用上限。" },
  { kind: "directive", name: "maxmemory-policy", example: "allkeys-lru", summary: "达到内存上限后怎样淘汰数据。",
    caution: "noeviction 表示不淘汰，达到上限后写入会被拒绝。" },
  { kind: "directive", name: "dir", example: "/var/lib/redis", summary: "工作目录，快照和追加日志都写在这里。",
    caution: "目录只应让 Redis 自己的账号可写；不要用 root 运行 Redis。" },
  { kind: "directive", name: "dbfilename", example: "dump.rdb", summary: "快照（RDB）文件名。" },
  { kind: "directive", name: "save", example: "900 1", summary: "多少秒内至少有多少次写入就生成一次快照；写 \"\" 表示关闭快照。",
    caution: "Redis 7 起一行可以写多组；更早的版本每行只能写一组，多写的会被忽略。" },
  { kind: "directive", name: "stop-writes-on-bgsave-error", example: "yes", summary: "快照失败时是否拒绝写入，以免数据悄悄丢失。" },
  { kind: "directive", name: "rdbcompression", example: "yes", summary: "快照文件是否压缩。" },
  { kind: "directive", name: "rdbchecksum", example: "yes", summary: "快照文件末尾是否写校验和，读取时用来发现损坏。" },
  { kind: "directive", name: "appendonly", example: "yes", summary: "是否开启追加日志（AOF）持久化。" },
  { kind: "directive", name: "appendfilename", example: "\"appendonly.aof\"", summary: "追加日志的文件名。" },
  { kind: "directive", name: "appenddirname", example: "\"appendonlydir\"", summary: "追加日志文件所在的子目录（Redis 7 起）。" },
  { kind: "directive", name: "appendfsync", example: "everysec", summary: "追加日志多久写一次盘：always、everysec 或 no。",
    caution: "always 最安全但最慢；no 交给系统决定，断电可能丢更多数据。" },

  // TLS.
  { kind: "directive", name: "tls-port", example: "6380", summary: "TLS 加密连接的监听端口。" },
  { kind: "directive", name: "tls-cert-file", example: "/etc/redis/tls/redis.crt", summary: "TLS 证书文件。" },
  { kind: "directive", name: "tls-key-file", example: "/etc/redis/tls/redis.key", summary: "TLS 私钥文件。", caution: "私钥文件只应让 Redis 的账号可读。" },
  { kind: "directive", name: "tls-ca-cert-file", example: "/etc/redis/tls/ca.crt", summary: "用来验证对方证书的 CA 证书。" },
  { kind: "directive", name: "tls-auth-clients", example: "yes", summary: "是否要求客户端出示证书。" },

  { kind: "directive", name: "include", example: "/etc/redis/local.conf", summary: "把另一个配置文件的内容插在这里。",
    caution: "大多数选项写了多次时以最后一次为准，所以 include 写在前面还是后面会影响结果。" },
];

const HAPROXY_PROXIES = ["defaults", "frontend", "backend", "listen"] as const;
const HAPROXY_FRONTS = ["frontend", "listen"] as const;
const HAPROXY_BACKS = ["backend", "listen"] as const;

const HAPROXY: readonly Entry[] = [
  // Sections.
  { kind: "block", name: "global", where: [""], summary: "全局设置：进程、日志、安全和性能参数，整份配置通常只有一个。" },
  { kind: "block", name: "defaults", where: [""], summary: "默认设置：后面的 frontend、backend、listen 没写的项都取这里的值。",
    caution: "可以写多个 defaults，每个只影响写在它后面的区段。" },
  { kind: "block", name: "frontend", where: [""], example: "http_in", summary: "对外入口：在哪些地址和端口接收连接，以及把请求交给哪个后端。" },
  { kind: "block", name: "backend", where: [""], example: "app", summary: "一组后端服务器，以及健康检查和分配请求的方式。" },
  { kind: "block", name: "listen", where: [""], example: "stats", summary: "入口和后端合在一起的写法，常用于 TCP 转发或统计页面。" },
  { kind: "block", name: "userlist", where: [""], example: "admins", summary: "一组用户和他们的口令，供 HTTP 认证使用。",
    caution: "口令建议写成加密后的形式，不要用 insecure-password 明文；含口令的行会作为敏感内容隐藏。" },
  { kind: "block", name: "peers", where: [""], example: "lb_peers", summary: "多台 HAProxy 之间同步粘性会话、限速计数等表数据。" },
  { kind: "block", name: "resolvers", where: [""], example: "dns", summary: "解析后端域名时使用的 DNS 服务器设置。" },
  { kind: "block", name: "cache", where: [""], example: "small", summary: "响应缓存的大小和保存时间。" },
  { kind: "block", name: "http-errors", where: [""], example: "site_errors", summary: "一组自定义错误页面，可在各区段里按名字引用。" },
  { kind: "block", name: "ring", where: [""], example: "logbuf", summary: "日志等消息在内存里的环形缓冲区（2.2 起）。" },
  { kind: "block", name: "log-forward", where: [""], example: "syslog", summary: "接收 syslog 日志再转发出去（2.3 起）。" },
  { kind: "block", name: "fcgi-app", where: [""], example: "php", summary: "FastCGI 应用（例如 PHP-FPM）的设置（2.1 起）。" },
  { kind: "block", name: "crt-store", where: [""], example: "certs", summary: "集中定义证书和私钥文件的位置（3.0 起）。" },
  { kind: "block", name: "mailers", where: [""], example: "ops", summary: "健康检查状态变化时发邮件提醒用的邮件服务器；新版本已不建议使用。" },
  { kind: "block", name: "program", where: [""], example: "agent", summary: "让 HAProxy 主进程启动并看管的外部程序；新版本已弃用。" },

  // global.
  { kind: "directive", name: "log", where: ["global", ...HAPROXY_PROXIES], example: "/dev/log local0", summary: "日志发往哪里，以及使用的日志设施。",
    caution: "排查问题要用日志；代理区段里写 log global 表示沿用全局设置。" },
  { kind: "directive", name: "user", where: ["global"], example: "haproxy", summary: "进程用哪个系统账号运行。", caution: "不要用 root。" },
  { kind: "directive", name: "group", where: ["global"], example: "haproxy", summary: "进程用哪个系统组运行。" },
  { kind: "directive", name: "chroot", where: ["global"], example: "/var/lib/haproxy", summary: "启动后把进程限制在这个目录里，减小被攻破后的影响。" },
  { kind: "directive", name: "pidfile", where: ["global"], example: "/run/haproxy.pid", summary: "记录进程编号（PID）的文件。" },
  { kind: "directive", name: "daemon", where: ["global"], summary: "转到后台运行。", caution: "由 systemd 管理时一般不需要。" },
  { kind: "directive", name: "nbthread", where: ["global"], example: "4", summary: "使用多少个线程处理连接。" },
  { kind: "directive", name: "maxconn", where: ["global", "defaults", ...HAPROXY_FRONTS], example: "4096", summary: "最多同时处理多少个连接。" },
  { kind: "directive", name: "stats", example: "enable", summary: "统计页面或管理接口的设置，例如 stats socket、stats uri、stats enable。",
    caution: "统计页面和管理接口只应开放给管理员；stats auth 这一行会作为敏感内容隐藏。" },
  { kind: "directive", name: "ssl-default-bind-options", where: ["global"], example: "ssl-min-ver TLSv1.2 no-tls-tickets",
    summary: "所有 TLS 监听默认使用的选项，例如最低协议版本。", caution: "提高最低版本后，很旧的客户端可能连不上。" },
  { kind: "directive", name: "ssl-default-bind-ciphers", where: ["global"], example: "ECDHE+AESGCM:ECDHE+CHACHA20", summary: "TLS 1.2 及更早版本默认允许的加密套件。" },
  { kind: "directive", name: "ssl-default-bind-ciphersuites", where: ["global"], example: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", summary: "TLS 1.3 默认允许的加密套件。" },
  { kind: "directive", name: "tune.ssl.default-dh-param", where: ["global"], example: "2048", summary: "DHE 密钥交换使用的参数长度。" },

  // Proxies.
  { kind: "directive", name: "mode", where: HAPROXY_PROXIES, example: "http", summary: "按 HTTP 还是 TCP 处理连接：http 能看懂请求内容，tcp 只做转发。" },
  { kind: "directive", name: "option", where: HAPROXY_PROXIES, example: "httplog", summary: "开启一个选项，例如 httplog（详细日志）、forwardfor（带上客户端地址）、redispatch。",
    caution: "不同选项作用完全不同；前面加 no 表示关闭，例如 no option httplog。" },
  { kind: "directive", name: "timeout", where: [...HAPROXY_PROXIES, "resolvers"], example: "connect 5s", summary: "某个阶段的超时，例如 connect、client、server、http-request。",
    caution: "没写超时会让慢速连接长期占用资源，HAProxy 启动时也会给出警告。" },
  { kind: "directive", name: "retries", where: ["defaults", ...HAPROXY_BACKS], example: "3", summary: "连接后端失败后重试几次。" },
  { kind: "directive", name: "bind", where: [...HAPROXY_FRONTS, "peers", "log-forward"], example: ":80", summary: "这个入口监听的地址和端口；HTTPS 时在后面带上证书。",
    caution: "只写端口时监听所有地址；只给本机用就写 127.0.0.1:端口。" },
  { kind: "directive", name: "default_backend", where: ["defaults", ...HAPROXY_FRONTS], example: "app", summary: "没有命中其他规则时，请求交给哪个后端。" },
  { kind: "directive", name: "use_backend", where: HAPROXY_FRONTS, example: "api if { path_beg /api }", summary: "满足条件时把请求交给指定的后端。" },
  { kind: "directive", name: "balance", where: ["defaults", ...HAPROXY_BACKS], example: "roundrobin", summary: "在后端服务器之间分配请求的方式，例如 roundrobin、leastconn、source。" },
  { kind: "directive", name: "server", where: [...HAPROXY_BACKS, "peers"], example: "app1 127.0.0.1:8080 check", summary: "一台后端服务器：名字、地址和端口，以及健康检查等参数。",
    caution: "不写 check 就不做健康检查，出了故障的服务器仍会收到请求。" },
  { kind: "directive", name: "default-server", where: ["defaults", ...HAPROXY_BACKS], example: "inter 3s fall 3 rise 2", summary: "这个后端里每台 server 默认带上的参数。" },
  { kind: "directive", name: "acl", where: [...HAPROXY_FRONTS, "backend"], example: "is_admin path_beg /admin", summary: "给一个判断条件起名字，供后面的规则引用。" },
  { kind: "directive", name: "http-request", where: [...HAPROXY_FRONTS, "backend"], example: "deny if { path_beg /.git }", summary: "对请求做处理，例如拒绝、改写请求头、限速。",
    caution: "规则按书写顺序执行，deny 之类的规则命中后，后面的不再执行。" },
  { kind: "directive", name: "http-response", where: [...HAPROXY_FRONTS, "backend"], example: "set-header X-Frame-Options DENY", summary: "对响应做处理，例如加安全头、删掉透露版本的头。" },
  { kind: "directive", name: "tcp-request", where: [...HAPROXY_FRONTS, "backend"], example: "connection reject if { src 203.0.113.0/24 }", summary: "在连接或内容层面做处理，例如按来源拒绝连接。" },
  { kind: "directive", name: "http-check", where: ["defaults", ...HAPROXY_BACKS], example: "expect status 200", summary: "HTTP 健康检查发送什么、期望得到什么（2.2 起的写法）。" },
  { kind: "directive", name: "stick-table", where: [...HAPROXY_FRONTS, "backend"], example: "type ip size 100k expire 30s store http_req_rate(10s)",
    summary: "按客户端记录数据（例如请求速率）的表，用来限速或会话保持。" },
  { kind: "directive", name: "capture", where: HAPROXY_FRONTS, example: "request header Host len 64", summary: "把请求或响应里的某个头记进日志。" },
  { kind: "directive", name: "errorfile", where: [...HAPROXY_PROXIES, "http-errors"], example: "503 /etc/haproxy/errors/503.http", summary: "为某个状态码换成自定义错误页文件。" },
  { kind: "directive", name: "compression", where: HAPROXY_PROXIES, example: "algo gzip", summary: "压缩响应使用的算法和内容类型。" },
  { kind: "directive", name: "cookie", where: ["defaults", ...HAPROXY_BACKS], example: "SERVERID insert indirect nocache", summary: "用 Cookie 记住客户端该去哪台服务器（会话保持）。" },
  { kind: "directive", name: "redirect", where: [...HAPROXY_FRONTS, "backend"], example: "scheme https code 301 if !{ ssl_fc }", summary: "把请求跳转到别处，例如 HTTP 跳到 HTTPS。" },
  { kind: "directive", name: "monitor-uri", where: ["defaults", ...HAPROXY_FRONTS], example: "/haproxy-health", summary: "专给监控用的地址，访问它直接得到 200，不转给后端。" },

  // Other sections.
  { kind: "directive", name: "user", where: ["userlist"], summary: "定义一个用户和他的口令。", caution: "含口令的行会作为敏感内容隐藏。" },
  { kind: "directive", name: "group", where: ["userlist"], example: "admins users alice,bob", summary: "定义一个用户组和组里的用户。" },
  { kind: "directive", name: "peer", where: ["peers"], example: "lb1 10.0.0.1:10000", summary: "一台参与同步的 HAProxy：名字、地址和端口。" },
  { kind: "directive", name: "nameserver", where: ["resolvers"], example: "dns1 10.0.0.53:53", summary: "用来解析域名的一台 DNS 服务器。" },
  { kind: "directive", name: "total-max-size", where: ["cache"], example: "64", summary: "缓存最多占用多少内存（MB）。" },
  { kind: "directive", name: "max-age", where: ["cache"], example: "60", summary: "缓存的内容最多保存多少秒。" },
];

// MySQL and MariaDB option files. Places are option groups as the servers
// read them: every server group ([mysqld], [server], [mariadb], [galera],
// versioned ones such as [mysqld-8.0]) is "mysqld"; [client] and its MariaDB
// relatives are "client". A name is looked up with - and _ treated alike, as
// the servers read option names.
const OPTION_CLIENTS = ["client", "mysql", "mysqldump"] as const;

const OPTION_FILE_COMMON: readonly Entry[] = [
  // Groups.
  { kind: "block", name: "mysqld", where: [""], summary: "数据库服务进程读取的选项组，服务端设置大多写在这里。" },
  { kind: "block", name: "client", where: [""], summary: "所有客户端程序（命令行客户端、备份工具等）都会读取的选项组。",
    caution: "不要在这里写登录口令：含口令的行会作为敏感内容隐藏，整份文件也不能再预览和复制。" },
  { kind: "block", name: "mysql", where: [""], summary: "命令行客户端读取的选项组。" },
  { kind: "block", name: "mysqldump", where: [""], summary: "备份工具 mysqldump 读取的选项组。" },
  { kind: "block", name: "mysqld_safe", where: [""], summary: "启动脚本 mysqld_safe 读取的选项组，例如错误日志放在哪里。" },

  // Who runs it and where its files are.
  { kind: "directive", name: "user", where: ["mysqld"], example: "mysql", summary: "服务进程以哪个系统账号运行。",
    caution: "不要用 root。" },
  { kind: "directive", name: "datadir", where: ["mysqld"], example: "/var/lib/mysql", summary: "数据文件所在的目录。",
    caution: "换目录要先停服务、迁移数据，并确认新目录归运行账号所有。" },
  { kind: "directive", name: "socket", where: ["mysqld", ...OPTION_CLIENTS], example: "/var/run/mysqld/mysqld.sock",
    summary: "本机连接用的套接字文件；服务端和客户端要写成同一个路径。" },
  { kind: "directive", name: "pid-file", where: ["mysqld", "mysqld_safe"], example: "/var/run/mysqld/mysqld.pid", summary: "记录进程编号（PID）的文件。" },
  { kind: "directive", name: "log_error", where: ["mysqld", "mysqld_safe"], example: "/var/log/mysql/error.log",
    summary: "错误日志文件，启动失败和运行中的异常都记在这里。", caution: "排查问题要用，不要指向不存在或运行账号写不进去的目录。" },
  { kind: "directive", name: "default_storage_engine", where: ["mysqld"], example: "InnoDB", summary: "新建表默认使用的存储引擎。" },

  // Network exposure.
  { kind: "directive", name: "port", where: ["mysqld"], example: "3306", summary: "服务监听的 TCP 端口。" },
  { kind: "directive", name: "bind-address", where: ["mysqld"], example: "127.0.0.1", summary: "监听哪个网卡地址；127.0.0.1 表示只允许本机连接。",
    caution: "改成 0.0.0.0 或公网地址会把数据库暴露到网络上，要同时用防火墙限制来源。" },
  { kind: "directive", name: "skip-networking", where: ["mysqld"], summary: "关闭 TCP 监听，只能通过本机套接字连接。",
    caution: "远程客户端和主从复制都会因此连不上。" },
  { kind: "directive", name: "skip-name-resolve", where: ["mysqld"], summary: "不对客户端地址做反向域名解析，连接更快；授权里只能写 IP，不能写主机名。" },
  { kind: "directive", name: "max_connections", where: ["mysqld"], example: "500", summary: "同时允许的最大客户端连接数。",
    caution: "每个连接都要占内存，设得过大可能在高峰时耗尽内存。" },
  { kind: "directive", name: "max_connect_errors", where: ["mysqld"], example: "100", summary: "同一来源连续连接出错多少次后被拒绝连接。" },
  { kind: "directive", name: "connect_timeout", where: ["mysqld"], example: "10", summary: "建立连接时等客户端完成握手的最长秒数。" },
  { kind: "directive", name: "wait_timeout", where: ["mysqld"], example: "28800", summary: "空闲的非交互连接多少秒后断开。" },
  { kind: "directive", name: "interactive_timeout", where: ["mysqld"], example: "28800", summary: "空闲的交互式连接（例如命令行客户端）多少秒后断开。" },
  { kind: "directive", name: "require_secure_transport", where: ["mysqld"], example: "ON", summary: "只接受加密（TLS）连接或本机套接字连接。",
    caution: "打开前先配好服务器证书，并确认所有客户端都能用加密连接。" },
  { kind: "directive", name: "ssl_ca", where: ["mysqld"], example: "/etc/mysql/certs/ca.pem", summary: "签发服务器和客户端证书的 CA 证书文件。" },
  { kind: "directive", name: "ssl_cert", where: ["mysqld"], example: "/etc/mysql/certs/server-cert.pem", summary: "服务器证书文件。" },
  { kind: "directive", name: "tls_version", where: ["mysqld"], example: "TLSv1.2,TLSv1.3", summary: "允许的 TLS 协议版本；旧的 TLSv1、TLSv1.1 应去掉。" },

  // File access from SQL.
  { kind: "directive", name: "local_infile", where: ["mysqld"], example: "0", summary: "是否允许 LOAD DATA LOCAL 读取客户端本地的文件。",
    caution: "建议设为 0，避免被利用来读取客户端上的文件。" },
  { kind: "directive", name: "secure_file_priv", where: ["mysqld"], example: "/var/lib/mysql-files",
    summary: "LOAD DATA 和 SELECT … INTO OUTFILE 只能读写这个目录里的文件。", caution: "留空表示不限制，不要留空；目录必须已存在，否则服务起不来。" },
  { kind: "directive", name: "skip-grant-tables", where: ["mysqld"], summary: "跳过权限检查，任何人都能不经验证直接登录。",
    caution: "只在找回管理员账号时临时使用，用完立刻删掉这一行并重启服务。" },
  { kind: "directive", name: "read_only", where: ["mysqld"], example: "ON", summary: "只读：没有管理权限的账号不能写入，常用于从库。" },

  // Logs an investigation needs.
  { kind: "directive", name: "general_log", where: ["mysqld"], example: "0", summary: "通用查询日志开关：记录收到的每一条语句。",
    caution: "会记录全部语句、量很大，只在排查时临时打开。" },
  { kind: "directive", name: "general_log_file", where: ["mysqld"], example: "/var/log/mysql/general.log", summary: "通用查询日志写到哪个文件。" },
  { kind: "directive", name: "slow_query_log", where: ["mysqld"], example: "1", summary: "慢查询日志开关。" },
  { kind: "directive", name: "slow_query_log_file", where: ["mysqld"], example: "/var/log/mysql/slow.log", summary: "慢查询日志写到哪个文件。" },
  { kind: "directive", name: "long_query_time", where: ["mysqld"], example: "2", summary: "执行超过多少秒的语句记入慢查询日志。" },
  { kind: "directive", name: "log_output", where: ["mysqld"], example: "FILE", summary: "通用查询日志和慢查询日志写到文件（FILE）还是写进表（TABLE）。" },

  // Binary log and replication.
  { kind: "directive", name: "server_id", where: ["mysqld"], example: "1", summary: "复制环境里每台服务器的唯一编号。" },
  { kind: "directive", name: "log_bin", where: ["mysqld"], example: "mysql-bin", summary: "开启二进制日志并指定文件名前缀，主从复制和按时间点恢复都要用。",
    caution: "MySQL 8.0 起默认就开启；MariaDB 默认关闭。" },
  { kind: "directive", name: "skip-log-bin", where: ["mysqld"], summary: "关闭二进制日志。", caution: "关闭后不能做主从复制，也不能按时间点恢复。" },
  { kind: "directive", name: "binlog_format", where: ["mysqld"], example: "ROW", summary: "二进制日志的记录方式，ROW 逐行记录变化，最适合复制。" },
  { kind: "directive", name: "binlog_expire_logs_seconds", where: ["mysqld"], example: "604800",
    summary: "二进制日志保留多少秒后自动清理（MySQL 8.0、MariaDB 10.6 起）。" },
  { kind: "directive", name: "expire_logs_days", where: ["mysqld"], example: "7", summary: "二进制日志保留天数（旧写法）。",
    caution: "MySQL 8.0 起已弃用，请改用 binlog_expire_logs_seconds。" },
  { kind: "directive", name: "sync_binlog", where: ["mysqld"], example: "1", summary: "二进制日志多久同步到磁盘一次；1 表示每次提交都同步，最安全。" },

  // Storage and memory.
  { kind: "directive", name: "innodb_buffer_pool_size", where: ["mysqld"], example: "1G", summary: "InnoDB 缓存数据和索引用的内存，对性能影响最大。",
    caution: "专用数据库服务器常设为物理内存的一半到四分之三，要给系统和连接留出内存。" },
  { kind: "directive", name: "innodb_file_per_table", where: ["mysqld"], example: "1", summary: "每张 InnoDB 表单独一个数据文件，删表后空间能还给磁盘。" },
  { kind: "directive", name: "innodb_doublewrite", where: ["mysqld"], example: "ON", summary: "双写缓冲：防止页面写到一半时宕机造成数据页损坏。",
    caution: "关闭能快一些，但断电时可能损坏数据，一般不要关。" },
  { kind: "directive", name: "innodb_lock_wait_timeout", where: ["mysqld"], example: "50", summary: "事务等待行锁多少秒后放弃并报错。" },
  { kind: "directive", name: "innodb_print_all_deadlocks", where: ["mysqld"], example: "ON", summary: "把每次死锁的详情写进错误日志，排查并发问题时有用。" },
  { kind: "directive", name: "innodb_flush_log_at_trx_commit", where: ["mysqld"], example: "1",
    summary: "事务提交时日志怎样写盘：1 每次提交都落盘，最安全；0 和 2 更快，但宕机可能丢掉最近约一秒的事务。" },
  { kind: "directive", name: "table_open_cache", where: ["mysqld"], example: "4000", summary: "能同时保持打开的表的数量。" },
  { kind: "directive", name: "tmp_table_size", where: ["mysqld"], example: "64M", summary: "内存临时表的大小上限，超出就转到磁盘。",
    caution: "实际上限取它和 max_heap_table_size 中较小的一个。" },
  { kind: "directive", name: "max_heap_table_size", where: ["mysqld"], example: "64M", summary: "内存表（MEMORY 引擎）的大小上限，也限制内存临时表。" },
  { kind: "directive", name: "performance_schema", where: ["mysqld"], example: "ON", summary: "性能监控库开关，排查慢查询和锁等待时有用。" },

  // Text and time.
  { kind: "directive", name: "character-set-server", where: ["mysqld"], example: "utf8mb4", summary: "服务端默认字符集。",
    caution: "建议用 utf8mb4；改动只影响之后新建的库和表。" },
  { kind: "directive", name: "collation-server", where: ["mysqld"], example: "utf8mb4_unicode_ci", summary: "服务端默认排序规则，要和字符集对应。" },
  { kind: "directive", name: "default-time-zone", where: ["mysqld"], example: "+08:00", summary: "服务端默认时区。" },
  { kind: "directive", name: "sql_mode", where: ["mysqld"], example: "STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION",
    summary: "SQL 模式：严格模式下写入不合法的数据会报错，而不是悄悄截断。" },
  { kind: "directive", name: "lower_case_table_names", where: ["mysqld"], example: "1", summary: "表名是否区分大小写。",
    caution: "MySQL 8.0 起只能在初始化数据目录时设定，之后再改服务会起不来。" },
  { kind: "directive", name: "max_allowed_packet", where: ["mysqld", ...OPTION_CLIENTS], example: "64M", summary: "单条语句或单行数据的最大大小。" },

  // Clients.
  { kind: "directive", name: "user", where: OPTION_CLIENTS, example: "ops", summary: "客户端默认用哪个数据库账号登录。" },
  { kind: "directive", name: "host", where: OPTION_CLIENTS, example: "127.0.0.1", summary: "客户端默认连接哪台服务器。" },
  { kind: "directive", name: "port", where: OPTION_CLIENTS, example: "3306", summary: "客户端默认连接的端口。" },
  { kind: "directive", name: "default-character-set", where: OPTION_CLIENTS, example: "utf8mb4", summary: "客户端连接使用的字符集。" },
  { kind: "directive", name: "safe-updates", where: ["mysql"], summary: "拒绝不带 WHERE 或 LIMIT 的 UPDATE、DELETE，防止误改整张表。" },
  { kind: "directive", name: "single-transaction", where: ["mysqldump"], summary: "导出 InnoDB 表时使用一致性快照，不锁表。" },
  { kind: "directive", name: "quick", where: ["mysqldump"], summary: "逐行读取，导出大表时省内存。" },
  { kind: "directive", name: "routines", where: ["mysqldump"], summary: "同时导出存储过程和函数。" },
];

const MYSQL_OPTIONS: readonly Entry[] = [
  ...OPTION_FILE_COMMON,
  { kind: "directive", name: "default_authentication_plugin", where: ["mysqld"], summary: "新账号默认使用的认证方式。",
    caution: "MySQL 8.0.27 起弃用、8.4 已移除，请改用 authentication_policy。" },
  { kind: "directive", name: "authentication_policy", where: ["mysqld"], example: "*", summary: "新账号可以使用哪些认证方式（MySQL 8.0.27 起）。" },
  { kind: "directive", name: "mysqlx", where: ["mysqld"], example: "OFF", summary: "X 协议插件开关（默认监听 33060 端口）；不用 MySQL Shell 文档存储时可以关闭，少开一个端口。" },
  { kind: "directive", name: "log_error_verbosity", where: ["mysqld"], example: "2", summary: "错误日志记多详细：1 只记错误，2 再加警告，3 再加提示信息。" },
  { kind: "directive", name: "ssl-mode", where: OPTION_CLIENTS, example: "REQUIRED", summary: "客户端是否必须使用加密连接；REQUIRED 表示必须加密。" },
];

const MARIADB_OPTIONS: readonly Entry[] = [
  ...OPTION_FILE_COMMON,
  { kind: "block", name: "server", where: [""], summary: "MariaDB 服务端读取的选项组，作用与 [mysqld] 相同。" },
  { kind: "block", name: "mariadb", where: [""], summary: "只有 MariaDB 服务端读取的选项组，适合放 MariaDB 特有的选项。" },
  { kind: "block", name: "galera", where: [""], summary: "带 Galera 集群功能的 MariaDB 服务端读取的选项组，用来放集群设置。" },
  { kind: "block", name: "client-server", where: [""], summary: "MariaDB 客户端和服务端都会读取的选项组。" },
  { kind: "block", name: "client-mariadb", where: [""], summary: "MariaDB 客户端程序读取的选项组。" },
  { kind: "directive", name: "wsrep_on", where: ["mysqld"], example: "ON", summary: "开启 Galera 集群复制。" },
  { kind: "directive", name: "wsrep_provider", where: ["mysqld"], example: "/usr/lib/galera/libgalera_smm.so", summary: "Galera 复制库文件的位置。" },
  { kind: "directive", name: "wsrep_cluster_name", where: ["mysqld"], example: "db_cluster", summary: "集群名称，所有节点必须一致。" },
  { kind: "directive", name: "wsrep_cluster_address", where: ["mysqld"], example: "gcomm://10.0.0.11,10.0.0.12", summary: "集群里各节点的地址。" },
  { kind: "directive", name: "innodb_autoinc_lock_mode", where: ["mysqld"], example: "2", summary: "自增值的加锁方式；Galera 集群要求设为 2。" },
  // MariaDB 10.11 renamed the slow log options; the old names still work.
  { kind: "directive", name: "log_slow_query", where: ["mysqld"], example: "1", summary: "慢查询日志开关（MariaDB 10.11 起的名字，旧名 slow_query_log）。" },
  { kind: "directive", name: "log_slow_query_file", where: ["mysqld"], example: "/var/log/mysql/slow.log", summary: "慢查询日志写到哪个文件（旧名 slow_query_log_file）。" },
  { kind: "directive", name: "log_slow_query_time", where: ["mysqld"], example: "2", summary: "执行超过多少秒的语句记入慢查询日志（旧名 long_query_time）。" },
];

const CATALOG: Record<ConfigVisualProduct, readonly Entry[]> = {
  nginx: NGINX, apache: APACHE, redis: REDIS, haproxy: HAPROXY, mysql: MYSQL_OPTIONS, mariadb: MARIADB_OPTIONS,
};

function isOptionFile(product: ConfigVisualProduct): boolean {
  return product === "mysql" || product === "mariadb";
}

/** An option-file name as the servers read it: case aside, - and _ alike. */
function optionName(name: string): string {
  return name.toLowerCase().replace(/-/gu, "_");
}

/**
 * Nginx and HAProxy names are exact; Apache and Redis read names without
 * regard to case; option files also read - and _ alike.
 */
function sameName(product: ConfigVisualProduct, a: string, b: string): boolean {
  if (isOptionFile(product)) return optionName(a) === optionName(b);
  return product === "nginx" || product === "haproxy" ? a === b : a.toLowerCase() === b.toLowerCase();
}

/** The place an option group stands for; see OPTION_FILE_COMMON. */
function optionGroupPlace(group: string): string {
  const name = optionName(group);
  if (/^(mysqld|server|mariadb|mariadbd|galera)(_[0-9][0-9.]*)?$/u.test(name)) return "mysqld";
  if (name === "client" || name === "client_server" || name === "client_mariadb") return "client";
  if (name === "mysql" || name === "mariadb_client") return "mysql";
  if (name === "mysqldump" || name === "mariadb_dump") return "mysqldump";
  if (name === "mysqld_safe" || name === "mariadbd_safe" || name === "safe_mysqld") return "mysqld_safe";
  return name;
}

/** The notes for option-file include lines, which are not options. */
function includeHelp(name: string): ConfigVisualHelp | null {
  switch (name.replace(/\s+/gu, "").toLowerCase()) {
    case "!include": return { summary: "再读取另一个选项文件，路径要写全。", example: "/etc/mysql/extra.cnf" };
    case "!includedir": return { summary: "读取这个目录里所有 .cnf 文件（Windows 上还有 .ini 文件）。", example: "/etc/mysql/conf.d/" };
    default: return null;
  }
}

/**
 * The place a new item goes, as the catalog names places: "" for the top
 * level, else the nearest enclosing block that decides what is allowed.
 * Apache's <IfModule> and similar wrappers pass through to what is around them.
 */
export function configVisualPlace(rows: readonly ConfigVisualRow[], parent: ConfigVisualRow | null,
  product: ConfigVisualProduct): string {
  return placeOf(new Map(rows.map((row) => [row.id, row])), parent, product);
}

function placeOf(byId: ReadonlyMap<string, ConfigVisualRow>, parent: ConfigVisualRow | null,
  product: ConfigVisualProduct): string {
  for (let current = parent; current !== null; current = current.parentId === null ? null : byId.get(current.parentId) ?? null) {
    const name = (current.name ?? "").toLowerCase();
    if (product === "nginx") {
      if (name !== "server") return name;
      // A server in stream or mail takes other directives than one in http.
      for (let outer = current.parentId === null ? undefined : byId.get(current.parentId); outer !== undefined;
        outer = outer.parentId === null ? undefined : byId.get(outer.parentId)) {
        if (outer.name === "stream") return "stream-server";
        if (outer.name === "mail") return "mail-server";
      }
      return "server";
    }
    // HAProxy sections do not nest: the section keyword is the place.
    if (product === "haproxy") return name;
    // Option groups do not nest either; several names read the same.
    if (isOptionFile(product)) return optionGroupPlace(current.name ?? "");
    if (product === "apache") {
      if (name === "virtualhost") return "virtualhost";
      if (/^(directory|directorymatch|location|locationmatch|files|filesmatch|proxy|proxymatch|limit|limitexcept|require(all|any|none))$/u.test(name)) {
        return "directory";
      }
      continue;
    }
    return "";
  }
  return "";
}

/** The note for an item by its kind and name, wherever it is written. */
export function configVisualHelp(product: ConfigVisualProduct, kind: "directive" | "block", name: string,
  place?: string): ConfigVisualHelp | null {
  const wanted = name.trim();
  if (wanted === "") return null;
  if (isOptionFile(product) && kind === "directive" && wanted.startsWith("!")) return includeHelp(wanted);
  const matches = CATALOG[product].filter((entry) => entry.kind === kind && sameName(product, entry.name, wanted));
  const fitting = place === undefined ? matches : matches.filter((entry) => entry.where === undefined || entry.where.includes(place));
  const entry = fitting[0] ?? matches[0];
  return entry === undefined ? null : helpOf(entry);
}

function helpOf(entry: Entry): ConfigVisualHelp {
  return {
    summary: entry.summary,
    ...(entry.example === undefined ? {} : { example: entry.example }),
    ...(entry.caution === undefined ? {} : { caution: entry.caution }),
  };
}

/**
 * The note a tree row shows, if any. Inside an Nginx map or types block each
 * line is a pair of values, not a directive, and is described as one.
 */
export function configVisualRowHelp(row: ConfigVisualRow, rows: readonly ConfigVisualRow[],
  product: ConfigVisualProduct): ConfigVisualHelp | null {
  return rowHelp(row, new Map(rows.map((candidate) => [candidate.id, candidate])), product);
}

/** Every row's note at once, for a whole tree. */
export function configVisualRowHelps(rows: readonly ConfigVisualRow[],
  product: ConfigVisualProduct): Map<string, ConfigVisualHelp> {
  const byId = new Map(rows.map((row) => [row.id, row]));
  const helps = new Map<string, ConfigVisualHelp>();
  for (const row of rows) {
    const help = rowHelp(row, byId, product);
    if (help !== null) helps.set(row.id, help);
  }
  return helps;
}

function rowHelp(row: ConfigVisualRow, byId: ReadonlyMap<string, ConfigVisualRow>,
  product: ConfigVisualProduct): ConfigVisualHelp | null {
  if ((row.kind !== "directive" && row.kind !== "block") || row.name === null) return null;
  const parent = row.parentId === null ? null : byId.get(row.parentId) ?? null;
  if (product === "nginx" && parent !== null && row.kind === "directive") {
    if (parent.name === "map") return { summary: "一条对应关系：左边是要匹配的值（default 表示都不匹配时），右边是赋给变量的结果。" };
    if (parent.name === "types") return { summary: "一条类型对照：左边是内容类型，右边是使用它的扩展名。" };
    if (parent.name === "geo") return { summary: "一条地址对应：左边是地址或网段（default 表示其他地址），右边是赋给变量的结果。" };
  }
  return configVisualHelp(product, row.kind, row.name, placeOf(byId, parent, product));
}

/** Common items for the add form: those that fit where the item goes. */
export function configVisualSuggestions(product: ConfigVisualProduct, kind: "directive" | "block",
  place: string): ConfigVisualSuggestion[] {
  const fitting = CATALOG[product]
    .filter((entry) => entry.kind === kind && (entry.where === undefined || entry.where.includes(place)))
    .map((entry) => ({ name: entry.name, kind: entry.kind, ...helpOf(entry) }));
  // An include line may stand at the top of an option file or inside a group.
  if (!isOptionFile(product) || kind !== "directive") return fitting;
  const includes = ["!include", "!includedir"].map((name) => ({ name, kind: "directive" as const, ...includeHelp(name)! }));
  return [...fitting, ...includes];
}

/** What to say about an item the catalog has no note for. */
export function configVisualUnknownHelp(product: ConfigVisualProduct): string {
  const label = { nginx: "Nginx", apache: "Apache httpd", redis: "Redis", haproxy: "HAProxy", mysql: "MySQL", mariadb: "MariaDB" }[product];
  return `这一项不在内置说明里。请对照目标上 ${label} 版本的官方文档确认它的含义和写法；拼错的名称会在部署前的检查中报错。`;
}

/** Every note for a product, for checks over the whole catalog. */
export function configVisualCatalog(product: ConfigVisualProduct): readonly ConfigVisualSuggestion[] {
  return CATALOG[product].map((entry) => ({ name: entry.name, kind: entry.kind, ...helpOf(entry) }));
}

export interface ConfigVisualFileItem {
  name: string;
  kind: "directive" | "block";
  help: ConfigVisualHelp | null;
}

const MAX_FILE_ITEMS = 200;
const HAPROXY_SECTION_WORDS: ReadonlySet<string> = new Set(
  HAPROXY.filter((entry) => entry.kind === "block").map((entry) => entry.name));

/**
 * The directives and blocks a generated file uses, each once in the order
 * they first appear, with the note for each. Lines inside an Nginx map,
 * types or geo block are pairs of values and are not listed. A plain line
 * scan for explaining a draft, not a parser: it decides nothing.
 */
export function configVisualFileItems(product: ConfigVisualProduct, text: string): ConfigVisualFileItem[] {
  const items: ConfigVisualFileItem[] = [];
  const seen = new Set<string>();
  const nginxStack: string[] = [];
  for (const raw of text.split(/\r?\n/u)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    let found: { name: string; kind: "directive" | "block" } | null = null;
    if (product === "nginx") {
      const name = /^([A-Za-z_][A-Za-z0-9_]*)(?=[\s;{]|$)/u.exec(line)?.[1];
      const open = line.indexOf("{");
      const end = line.indexOf(";");
      const isBlock = open >= 0 && (end < 0 || open < end);
      const insideValues = nginxStack.some((block) => block === "map" || block === "types" || block === "geo");
      if (name !== undefined && !insideValues) found = { name, kind: isBlock ? "block" : "directive" };
      // Track nesting so lines inside map/types/geo are not taken for directives.
      for (const character of line) {
        if (character === "{") nginxStack.push(name ?? "");
        if (character === "}") nginxStack.pop();
      }
    } else if (product === "haproxy") {
      const word = /^([A-Za-z][A-Za-z0-9_.:-]*)(?=[\s#]|$)/u.exec(line)?.[1];
      if (word !== undefined) {
        found = { name: word, kind: HAPROXY_SECTION_WORDS.has(word) ? "block" : "directive" };
      }
    } else if (isOptionFile(product)) {
      // [group], name=value or a bare flag; ; and # start comments; include
      // lines say where other files come from and are not listed.
      if (line.startsWith(";") || line.startsWith("!")) continue;
      const group = /^\[([A-Za-z][A-Za-z0-9_.-]*)\]/u.exec(line)?.[1];
      const option = /^([A-Za-z][A-Za-z0-9_.-]*)\s*(?:=|$)/u.exec(line)?.[1];
      if (group !== undefined) found = { name: group, kind: "block" };
      else if (option !== undefined) found = { name: option, kind: "directive" };
    } else if (product === "apache") {
      const section = /^<([A-Za-z][A-Za-z0-9]*)/u.exec(line)?.[1];
      const directive = /^([A-Za-z][A-Za-z0-9]*)(?=\s|$)/u.exec(line)?.[1];
      if (section !== undefined) found = { name: section, kind: "block" };
      else if (directive !== undefined) found = { name: directive, kind: "directive" };
    } else {
      const key = /^([A-Za-z][A-Za-z0-9-]*)(?=\s|$)/u.exec(line)?.[1];
      if (key !== undefined) found = { name: key, kind: "directive" };
    }
    if (found === null) continue;
    const key = `${found.kind}:${product === "nginx" || product === "haproxy" ? found.name
      : isOptionFile(product) ? optionName(found.name) : found.name.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ ...found, help: configVisualHelp(product, found.kind, found.name) });
    if (items.length >= MAX_FILE_ITEMS) break;
  }
  return items;
}
