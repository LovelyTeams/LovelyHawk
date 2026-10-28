//! Deterministic generation of bounded Nginx site configuration snippets.
//!
//! User-provided values cross typed validation boundaries before rendering.
//! The generated document contains only a closed set of directives and can be
//! saved locally only through a non-overwriting, native-dialog path contract.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

use url::{Host, Url};

use crate::{
    CoreError, CoreResult,
    middleware_document::{
        MiddlewareDocument, MiddlewareDocumentNodeKind, MiddlewareDocumentSyntax,
    },
    sftp::RemotePath,
};

pub const MAX_GENERATED_NGINX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_UPSTREAM_BYTES: usize = 2_048;
const MAX_FORBIDDEN_PATH_BYTES: usize = 512;
const SUGGESTED_FILE_NAME: &str = "nginx-site.conf";
const STATIC_ASSET_LOCATION_PATH: &str = "/assets";
const WEBSOCKET_LOCATION_PATH: &str = "/ws";
const HEALTH_CHECK_LOCATION_PATH: &str = "/healthz";
const SPA_FALLBACK_PATH: &str = "/index.html";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NginxSiteKind {
    Static,
    ReverseProxy,
}

impl NginxSiteKind {
    pub const ALL: [Self; 2] = [Self::Static, Self::ReverseProxy];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Static => "静态站点",
            Self::ReverseProxy => "反向代理",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NginxSiteFeature {
    ForbiddenPath403,
    SecurityHeaders,
    DisableDirectoryListing,
    RestrictRequestMethods,
    HideVersion,
    RestrictSourceIp,
    GzipCompression,
    StaticAssetCaching,
    WebSocketProxy,
    HealthCheck,
    DenyHiddenFiles,
    DenySensitiveFiles,
    ClientBodyLimit,
    KeepaliveTuning,
    Utf8Charset,
    IndexFiles,
    StaticTryFiles,
    Sendfile,
    OpenFileCache,
    ProxyTimeouts,
    DisableProxyBuffering,
    DisableProxyRequestBuffering,
    RequestIdHeaders,
    SpaFallback,
    ClientIoTimeouts,
    LimitRangeRequests,
    ResetTimedOutConnection,
    ProxySocketKeepalive,
    DisableProxyTempFiles,
    ProxyRedirectOff,
    HttpsUpstreamSni,
}

impl NginxSiteFeature {
    pub const ALL: [Self; 31] = [
        Self::ForbiddenPath403,
        Self::SecurityHeaders,
        Self::DisableDirectoryListing,
        Self::RestrictRequestMethods,
        Self::HideVersion,
        Self::RestrictSourceIp,
        Self::GzipCompression,
        Self::StaticAssetCaching,
        Self::WebSocketProxy,
        Self::HealthCheck,
        Self::DenyHiddenFiles,
        Self::DenySensitiveFiles,
        Self::ClientBodyLimit,
        Self::KeepaliveTuning,
        Self::Utf8Charset,
        Self::IndexFiles,
        Self::StaticTryFiles,
        Self::Sendfile,
        Self::OpenFileCache,
        Self::ProxyTimeouts,
        Self::DisableProxyBuffering,
        Self::DisableProxyRequestBuffering,
        Self::RequestIdHeaders,
        Self::SpaFallback,
        Self::ClientIoTimeouts,
        Self::LimitRangeRequests,
        Self::ResetTimedOutConnection,
        Self::ProxySocketKeepalive,
        Self::DisableProxyTempFiles,
        Self::ProxyRedirectOff,
        Self::HttpsUpstreamSni,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 => "forbidden-path-403",
            Self::SecurityHeaders => "security-headers",
            Self::DisableDirectoryListing => "disable-directory-listing",
            Self::RestrictRequestMethods => "restrict-request-methods",
            Self::HideVersion => "hide-version",
            Self::RestrictSourceIp => "restrict-source-ip",
            Self::GzipCompression => "gzip-compression",
            Self::StaticAssetCaching => "static-asset-caching",
            Self::WebSocketProxy => "websocket-proxy",
            Self::HealthCheck => "health-check",
            Self::DenyHiddenFiles => "deny-hidden-files",
            Self::DenySensitiveFiles => "deny-sensitive-files",
            Self::ClientBodyLimit => "client-body-limit",
            Self::KeepaliveTuning => "keepalive-tuning",
            Self::Utf8Charset => "utf8-charset",
            Self::IndexFiles => "index-files",
            Self::StaticTryFiles => "static-try-files",
            Self::Sendfile => "sendfile",
            Self::OpenFileCache => "open-file-cache",
            Self::ProxyTimeouts => "proxy-timeouts",
            Self::DisableProxyBuffering => "disable-proxy-buffering",
            Self::DisableProxyRequestBuffering => "disable-proxy-request-buffering",
            Self::RequestIdHeaders => "request-id-headers",
            Self::SpaFallback => "spa-fallback",
            Self::ClientIoTimeouts => "client-io-timeouts",
            Self::LimitRangeRequests => "limit-range-requests",
            Self::ResetTimedOutConnection => "reset-timed-out-connection",
            Self::ProxySocketKeepalive => "proxy-socket-keepalive",
            Self::DisableProxyTempFiles => "disable-proxy-temp-files",
            Self::ProxyRedirectOff => "proxy-redirect-off",
            Self::HttpsUpstreamSni => "https-upstream-sni",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 => "禁止指定路径（HTTP 403）",
            Self::SecurityHeaders => "添加固定安全响应头",
            Self::DisableDirectoryListing => "关闭目录浏览",
            Self::RestrictRequestMethods => "限制请求方法",
            Self::HideVersion => "隐藏版本信息",
            Self::RestrictSourceIp => "限制直接 TCP 来源 IP",
            Self::GzipCompression => "启用 Gzip 压缩",
            Self::StaticAssetCaching => "配置静态资源缓存",
            Self::WebSocketProxy => "反向代理 WebSocket",
            Self::HealthCheck => "添加健康检查端点",
            Self::DenyHiddenFiles => "拒绝隐藏文件",
            Self::DenySensitiveFiles => "拒绝敏感与备份文件",
            Self::ClientBodyLimit => "限制请求体大小",
            Self::KeepaliveTuning => "配置 Keepalive",
            Self::Utf8Charset => "声明 UTF-8 字符集",
            Self::IndexFiles => "配置默认首页",
            Self::StaticTryFiles => "启用静态文件查找",
            Self::Sendfile => "启用 Sendfile",
            Self::OpenFileCache => "启用文件句柄缓存",
            Self::ProxyTimeouts => "配置代理超时",
            Self::DisableProxyBuffering => "关闭代理响应缓冲",
            Self::DisableProxyRequestBuffering => "关闭代理请求缓冲",
            Self::RequestIdHeaders => "传递请求 ID",
            Self::SpaFallback => "启用 SPA 路由回退",
            Self::ClientIoTimeouts => "限制客户端 I/O 超时",
            Self::LimitRangeRequests => "限制静态站点多段 Range 请求",
            Self::ResetTimedOutConnection => "重置超时连接",
            Self::ProxySocketKeepalive => "启用上游 TCP 存活探测",
            Self::DisableProxyTempFiles => "禁止代理响应缓存或写入磁盘",
            Self::ProxyRedirectOff => "关闭上游重定向改写",
            Self::HttpsUpstreamSni => "仅发送 HTTPS 上游 SNI（不校验证书）",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 => "拒绝访问指定路径及其可选子路径，返回 HTTP 403。",
            Self::SecurityHeaders => {
                "定义固定浏览器响应头；反向代理会先隐藏上游同名头。server 级 add_header 会替代从 http 级继承的完整 add_header 列表。"
            }
            Self::DisableDirectoryListing => "显式关闭目录索引，避免目录内容被列出。",
            Self::RestrictRequestMethods => "所有生成的请求入口仅允许 GET 和 HEAD。",
            Self::HideVersion => "关闭 Nginx 响应和错误页中的版本号披露。",
            Self::RestrictSourceIp => {
                "所有生成入口只允许一个直接连接 Nginx 的 TCP peer IP/CIDR；不读取 X-Forwarded-For。"
            }
            Self::GzipCompression => {
                "为符合 Nginx 条件的文本响应启用 Gzip；携带 Via 的代理请求默认不压缩，TLS 动态响应需评估 BREACH 风险。"
            }
            Self::StaticAssetCaching => "为固定的 /assets/ 请求入口设置七天缓存时间。",
            Self::WebSocketProxy => "为固定的 /ws/ 请求入口加入 WebSocket 升级头。",
            Self::HealthCheck => "在固定的 /healthz 入口返回 HTTP 200，供存活探测使用。",
            Self::DenyHiddenFiles => "拒绝隐藏文件和目录，同时保留标准的 .well-known 入口。",
            Self::DenySensitiveFiles => "拒绝常见配置、日志、备份和临时文件后缀。",
            Self::ClientBodyLimit => "将客户端请求体上限固定为 10 MiB。",
            Self::KeepaliveTuning => "设置固定的连接空闲时间和单连接请求数上限。",
            Self::Utf8Charset => "为可添加字符集的文本响应声明 UTF-8。",
            Self::IndexFiles => "按固定顺序查找 index.html 和 index.htm。",
            Self::StaticTryFiles => "仅提供真实存在的静态路径，否则返回 HTTP 404。",
            Self::Sendfile => "使用 Sendfile 与 TCP_NOPUSH 发送静态文件。",
            Self::OpenFileCache => "缓存常用静态文件句柄和查找错误，减少文件系统开销。",
            Self::ProxyTimeouts => "为连接、发送和读取上游响应设置有界超时。",
            Self::DisableProxyBuffering => "将上游响应直接流式传递给客户端。",
            Self::DisableProxyRequestBuffering => "将客户端请求体直接流式传递给上游。",
            Self::RequestIdHeaders => "将 Nginx 请求 ID 传给上游并返回给客户端。",
            Self::SpaFallback => {
                "静态主入口找不到文件时回退到 /index.html，静态资源入口仍返回 404。"
            }
            Self::ClientIoTimeouts => "将客户端请求头、请求体和响应写入等待时间固定为 30 秒。",
            Self::LimitRangeRequests => {
                "仅用于静态站点：每个请求最多处理一个字节范围；超出时忽略 Range 并返回完整响应。"
            }
            Self::ResetTimedOutConnection => "使用 TCP RST 释放已超时连接占用的套接字资源。",
            Self::ProxySocketKeepalive => "为连接上游的套接字启用 TCP SO_KEEPALIVE 存活探测。",
            Self::DisableProxyTempFiles => {
                "显式关闭继承的代理 cache/store，并禁止普通代理响应缓冲到磁盘临时文件。"
            }
            Self::ProxyRedirectOff => "不再改写上游响应中的 Location 与 Refresh 头。",
            Self::HttpsUpstreamSni => {
                "只在连接 HTTPS 上游时发送 SNI；不会启用 proxy_ssl_verify，也不验证上游服务器身份。"
            }
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 | Self::RequestIdHeaders => "站点/Location",
            Self::SecurityHeaders
            | Self::DisableDirectoryListing
            | Self::HideVersion
            | Self::GzipCompression
            | Self::ClientBodyLimit
            | Self::KeepaliveTuning
            | Self::Utf8Charset
            | Self::IndexFiles
            | Self::Sendfile
            | Self::OpenFileCache
            | Self::ProxyTimeouts
            | Self::DisableProxyBuffering
            | Self::DisableProxyRequestBuffering
            | Self::ClientIoTimeouts
            | Self::LimitRangeRequests
            | Self::ResetTimedOutConnection
            | Self::ProxySocketKeepalive
            | Self::DisableProxyTempFiles
            | Self::ProxyRedirectOff
            | Self::HttpsUpstreamSni => "站点",
            Self::RestrictRequestMethods
            | Self::RestrictSourceIp
            | Self::StaticAssetCaching
            | Self::WebSocketProxy
            | Self::HealthCheck
            | Self::DenyHiddenFiles
            | Self::DenySensitiveFiles
            | Self::StaticTryFiles
            | Self::SpaFallback => "Location",
        }
    }

    pub const fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::SecurityHeaders
                | Self::DisableDirectoryListing
                | Self::HideVersion
                | Self::IndexFiles
                | Self::StaticTryFiles
        )
    }

    pub const fn supports_kind(self, kind: NginxSiteKind) -> bool {
        match self {
            Self::IndexFiles
            | Self::StaticTryFiles
            | Self::Sendfile
            | Self::OpenFileCache
            | Self::SpaFallback
            | Self::LimitRangeRequests => {
                matches!(kind, NginxSiteKind::Static)
            }
            Self::WebSocketProxy
            | Self::ProxyTimeouts
            | Self::DisableProxyBuffering
            | Self::DisableProxyRequestBuffering
            | Self::RequestIdHeaders
            | Self::ProxySocketKeepalive
            | Self::DisableProxyTempFiles
            | Self::ProxyRedirectOff
            | Self::HttpsUpstreamSni => matches!(kind, NginxSiteKind::ReverseProxy),
            Self::ForbiddenPath403
            | Self::SecurityHeaders
            | Self::DisableDirectoryListing
            | Self::RestrictRequestMethods
            | Self::HideVersion
            | Self::RestrictSourceIp
            | Self::GzipCompression
            | Self::StaticAssetCaching
            | Self::HealthCheck
            | Self::DenyHiddenFiles
            | Self::DenySensitiveFiles
            | Self::ClientBodyLimit
            | Self::KeepaliveTuning
            | Self::Utf8Charset
            | Self::ClientIoTimeouts
            | Self::ResetTimedOutConnection => true,
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::ForbiddenPath403 => &["403", "禁止路径", "拒绝访问", "return 403"],
            Self::SecurityHeaders => &["安全响应头", "security headers", "nosniff", "SAMEORIGIN"],
            Self::DisableDirectoryListing => &["关闭目录浏览", "autoindex off", "目录索引"],
            Self::RestrictRequestMethods => &["限制请求方法", "GET HEAD", "limit_except"],
            Self::HideVersion => &["隐藏版本", "server_tokens off", "版本信息"],
            Self::RestrictSourceIp => &[
                "直接来源 IP",
                "TCP peer",
                "CIDR",
                "allow deny",
                "不读取 X-Forwarded-For",
            ],
            Self::GzipCompression => &["gzip", "压缩", "Via", "BREACH", "传输压缩"],
            Self::StaticAssetCaching => &["静态缓存", "assets", "expires 7d"],
            Self::WebSocketProxy => &["WebSocket", "Upgrade", "连接升级", "ws"],
            Self::HealthCheck => &["健康检查", "healthz", "存活探测", "HTTP 200"],
            Self::DenyHiddenFiles => &["隐藏文件", "dotfiles", ".git", ".well-known"],
            Self::DenySensitiveFiles => &["敏感文件", "备份文件", "日志", "sql", "bak"],
            Self::ClientBodyLimit => &["请求体", "上传大小", "client_max_body_size", "10m"],
            Self::KeepaliveTuning => &["keepalive", "长连接", "连接复用"],
            Self::Utf8Charset => &["UTF-8", "charset", "字符集", "编码"],
            Self::IndexFiles => &["index", "默认首页", "index.html", "index.htm"],
            Self::StaticTryFiles => &["try_files", "静态文件", "404", "路径查找"],
            Self::Sendfile => &["sendfile", "tcp_nopush", "零拷贝", "静态性能"],
            Self::OpenFileCache => &["open_file_cache", "文件句柄", "静态缓存"],
            Self::ProxyTimeouts => &["代理超时", "proxy_read_timeout", "上游超时"],
            Self::DisableProxyBuffering => &["proxy_buffering off", "响应流式", "SSE"],
            Self::DisableProxyRequestBuffering => {
                &["proxy_request_buffering off", "请求流式", "上传流式"]
            }
            Self::RequestIdHeaders => &["请求 ID", "X-Request-ID", "$request_id", "链路追踪"],
            Self::SpaFallback => &["SPA", "单页应用", "index.html", "前端路由", "try_files"],
            Self::ClientIoTimeouts => &[
                "客户端超时",
                "client_header_timeout",
                "client_body_timeout",
                "send_timeout",
            ],
            Self::LimitRangeRequests => &["静态 Range", "字节范围", "max_ranges", "分段下载"],
            Self::ResetTimedOutConnection => &[
                "超时连接",
                "TCP RST",
                "reset_timedout_connection",
                "释放套接字",
            ],
            Self::ProxySocketKeepalive => &[
                "上游 TCP",
                "SO_KEEPALIVE",
                "proxy_socket_keepalive",
                "存活探测",
            ],
            Self::DisableProxyTempFiles => &[
                "代理临时文件",
                "proxy_max_temp_file_size 0",
                "proxy_cache off",
                "proxy_store off",
                "禁止落盘",
                "磁盘缓冲",
            ],
            Self::ProxyRedirectOff => &["proxy_redirect off", "Location", "Refresh", "重定向改写"],
            Self::HttpsUpstreamSni => &[
                "HTTPS 上游",
                "SNI",
                "proxy_ssl_server_name",
                "不校验证书",
                "不验证身份",
                "TLS server name",
            ],
        }
    }
}

/// One exact DNS name accepted by the first generator version.
///
/// Wildcards, regex server names, IP literals, variables and multiple names
/// are deliberately excluded so input cannot cross an Nginx token boundary.
/// This value participates in virtual-server selection only. If this server is
/// the default for its listen socket, an unmatched or missing Host can still be
/// routed here, so `server_name` must never be treated as a Host allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxServerNames(String);

impl NginxServerNames {
    pub const fn meaning() -> &'static str {
        "server_name 只参与 Nginx 虚拟主机选择；默认 server 仍可接收未匹配或缺失的 Host，因此它不是 Host 访问白名单。"
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        if value != value.trim() {
            return Err(CoreError::validation(
                "Nginx server name",
                "must not contain leading or trailing whitespace",
            ));
        }
        if value.parse::<IpAddr>().is_ok() {
            return Err(CoreError::validation(
                "Nginx server name",
                "the first generator version requires one exact DNS name, not an IP literal",
            ));
        }
        Ok(Self(normalize_dns_name("Nginx server name", value)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let normalized = normalize_dns_name("Nginx server name", &self.0)?;
        if normalized != self.0 {
            return Err(CoreError::validation(
                "Nginx server name",
                "stored server name is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NginxListenPort(u16);

impl NginxListenPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty() || value.len() > 5 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CoreError::validation(
                "Nginx listen port",
                "must contain only decimal digits in 1..=65535",
            ));
        }
        let port = value
            .parse::<u16>()
            .map_err(|_| CoreError::validation("Nginx listen port", "must be in 1..=65535"))?;
        if port == 0 {
            return Err(CoreError::validation(
                "Nginx listen port",
                "must be in 1..=65535",
            ));
        }
        Ok(Self(port))
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    fn validate(self) -> CoreResult<()> {
        if self.0 == 0 {
            return Err(CoreError::validation(
                "Nginx listen port",
                "must be in 1..=65535",
            ));
        }
        Ok(())
    }
}

/// One canonical URI path used by the closed HTTP 403 goal.
///
/// The value is deliberately narrower than the full Nginx URI grammar so it
/// can never introduce a token, variable, regex, query, or comment boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxForbiddenPath(String);

impl NginxForbiddenPath {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.len() < 2
            || value.len() > MAX_FORBIDDEN_PATH_BYTES
            || value != value.trim()
            || !value.is_ascii()
            || !value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
        {
            return Err(CoreError::validation(
                "Nginx forbidden path",
                "must be a bounded canonical ASCII path such as /admin, without a trailing slash",
            ));
        }
        if value.split('/').skip(1).any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                })
        }) {
            return Err(CoreError::validation(
                "Nginx forbidden path",
                "each path segment may contain only ASCII letters, digits, hyphen, underscore, dot, or tilde",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let parsed = Self::parse(&self.0)?;
        if parsed != *self {
            return Err(CoreError::validation(
                "Nginx forbidden path",
                "stored path is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NginxForbiddenPathScope {
    Exact,
    PathAndDescendants,
}

impl NginxForbiddenPathScope {
    pub const ALL: [Self; 2] = [Self::Exact, Self::PathAndDescendants];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "仅此路径",
            Self::PathAndDescendants => "此路径及子路径",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxForbiddenPathRule {
    path: NginxForbiddenPath,
    scope: NginxForbiddenPathScope,
}

impl NginxForbiddenPathRule {
    pub fn new(path: NginxForbiddenPath, scope: NginxForbiddenPathScope) -> CoreResult<Self> {
        path.validate()?;
        Ok(Self { path, scope })
    }

    pub fn path(&self) -> &NginxForbiddenPath {
        &self.path
    }

    pub const fn scope(&self) -> NginxForbiddenPathScope {
        self.scope
    }

    fn validate(&self) -> CoreResult<()> {
        self.path.validate()
    }
}

/// One canonical IP address or CIDR accepted by the closed source restriction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxAllowedSource(String);

impl NginxAllowedSource {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value != value.trim()
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "Nginx allowed source",
                "must be one bounded IP address or CIDR without whitespace or control characters",
            ));
        }

        let canonical = if let Some((address, prefix)) = value.split_once('/') {
            if address.is_empty()
                || prefix.is_empty()
                || prefix.contains('/')
                || !prefix.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(CoreError::validation(
                    "Nginx allowed source",
                    "CIDR must contain one IP address and one decimal prefix length",
                ));
            }
            let address = address.parse::<IpAddr>().map_err(|_| {
                CoreError::validation("Nginx allowed source", "CIDR address is invalid")
            })?;
            let prefix = prefix.parse::<u8>().map_err(|_| {
                CoreError::validation("Nginx allowed source", "CIDR prefix length is invalid")
            })?;
            let network = canonical_cidr_network(address, prefix)?;
            format!("{network}/{prefix}")
        } else {
            value
                .parse::<IpAddr>()
                .map_err(|_| {
                    CoreError::validation(
                        "Nginx allowed source",
                        "must be one valid IP address or CIDR",
                    )
                })?
                .to_string()
        };
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let parsed = Self::parse(&self.0)?;
        if parsed != *self {
            return Err(CoreError::validation(
                "Nginx allowed source",
                "stored source is not canonical",
            ));
        }
        Ok(())
    }
}

fn canonical_cidr_network(address: IpAddr, prefix: u8) -> CoreResult<IpAddr> {
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            Ok(IpAddr::V4((u32::from(address) & mask).into()))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            Ok(IpAddr::V6((u128::from(address) & mask).into()))
        }
        IpAddr::V4(_) | IpAddr::V6(_) => Err(CoreError::validation(
            "Nginx allowed source",
            "CIDR prefix exceeds the address family width",
        )),
    }
}

/// An absolute POSIX document root that is also safe as one Nginx argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxStaticRoot(RemotePath);

impl NginxStaticRoot {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value != value.trim() {
            return Err(CoreError::validation(
                "Nginx static root",
                "must not contain leading or trailing whitespace",
            ));
        }
        let path = RemotePath::new(value.to_owned())?;
        validate_static_root(&path)?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn as_remote_path(&self) -> &RemotePath {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        validate_static_root(&self.0)
    }
}

/// A normalized HTTP(S) origin suitable for a fixed `proxy_pass` directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxUpstream(String);

impl NginxUpstream {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value.len() > MAX_UPSTREAM_BYTES
            || value != value.trim()
            || !value.is_ascii()
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "Nginx upstream",
                "must be a bounded ASCII HTTP(S) origin without whitespace, controls, or backslashes",
            ));
        }
        let parsed = Url::parse(value)
            .map_err(|error| CoreError::validation("Nginx upstream", error.to_string()))?;
        let scheme = match parsed.scheme() {
            "http" => "http",
            "https" => "https",
            _ => {
                return Err(CoreError::validation(
                    "Nginx upstream",
                    "only http and https origins are supported",
                ));
            }
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(CoreError::validation(
                "Nginx upstream",
                "embedded credentials are forbidden",
            ));
        }
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(CoreError::validation(
                "Nginx upstream",
                "must be an origin only, without a path, query, or fragment",
            ));
        }
        let host = parsed
            .host()
            .ok_or_else(|| CoreError::validation("Nginx upstream", "host is required"))?;
        let host = match host {
            Host::Domain(domain) => normalize_dns_name("Nginx upstream host", domain)?,
            Host::Ipv4(address) => {
                if address.is_unspecified() {
                    return Err(CoreError::validation(
                        "Nginx upstream host",
                        "an unspecified IP address cannot be used as a proxy destination",
                    ));
                }
                address.to_string()
            }
            Host::Ipv6(address) => {
                if address.is_unspecified() {
                    return Err(CoreError::validation(
                        "Nginx upstream host",
                        "an unspecified IP address cannot be used as a proxy destination",
                    ));
                }
                format!("[{address}]")
            }
        };
        let port = parsed.port();
        if port == Some(0) {
            return Err(CoreError::validation(
                "Nginx upstream port",
                "must be in 1..=65535",
            ));
        }
        let origin = port.map_or_else(
            || format!("{scheme}://{host}"),
            |port| format!("{scheme}://{host}:{port}"),
        );
        if origin.len() > MAX_UPSTREAM_BYTES {
            return Err(CoreError::validation(
                "Nginx upstream",
                "normalized origin exceeds the bounded limit",
            ));
        }
        Ok(Self(origin))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn supports_https_sni(&self) -> bool {
        let Ok(parsed) = Url::parse(&self.0) else {
            return false;
        };
        parsed.scheme() == "https" && matches!(parsed.host(), Some(Host::Domain(_)))
    }

    fn validate(&self) -> CoreResult<()> {
        let normalized = Self::parse(&self.0)?;
        if normalized != *self {
            return Err(CoreError::validation(
                "Nginx upstream",
                "stored upstream is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NginxSiteTarget {
    Static(NginxStaticRoot),
    ReverseProxy(NginxUpstream),
}

impl NginxSiteTarget {
    pub const fn kind(&self) -> NginxSiteKind {
        match self {
            Self::Static(_) => NginxSiteKind::Static,
            Self::ReverseProxy(_) => NginxSiteKind::ReverseProxy,
        }
    }

    fn validate(&self) -> CoreResult<()> {
        match self {
            Self::Static(root) => root.validate(),
            Self::ReverseProxy(upstream) => upstream.validate(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxSiteConfig {
    names: NginxServerNames,
    port: NginxListenPort,
    target: NginxSiteTarget,
    features: BTreeSet<NginxSiteFeature>,
    forbidden_path_rule: Option<NginxForbiddenPathRule>,
    allowed_source_rule: Option<NginxAllowedSource>,
}

impl NginxSiteConfig {
    pub fn new(
        names: NginxServerNames,
        port: NginxListenPort,
        target: NginxSiteTarget,
        security_headers: bool,
    ) -> CoreResult<Self> {
        names.validate()?;
        port.validate()?;
        target.validate()?;
        let mut features = BTreeSet::new();
        if target.kind() == NginxSiteKind::Static {
            features.insert(NginxSiteFeature::IndexFiles);
            features.insert(NginxSiteFeature::StaticTryFiles);
        }
        if security_headers {
            features.insert(NginxSiteFeature::SecurityHeaders);
            features.insert(NginxSiteFeature::HideVersion);
        }
        Ok(Self {
            names,
            port,
            target,
            features,
            forbidden_path_rule: None,
            allowed_source_rule: None,
        })
    }

    pub fn with_forbidden_path_rule(mut self, rule: NginxForbiddenPathRule) -> CoreResult<Self> {
        rule.validate()?;
        self.forbidden_path_rule = Some(rule);
        self.features.insert(NginxSiteFeature::ForbiddenPath403);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_allowed_source_rule(mut self, source: NginxAllowedSource) -> CoreResult<Self> {
        source.validate()?;
        self.allowed_source_rule = Some(source);
        self.features.insert(NginxSiteFeature::RestrictSourceIp);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_feature(mut self, feature: NginxSiteFeature, enabled: bool) -> CoreResult<Self> {
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub const fn kind(&self) -> NginxSiteKind {
        self.target.kind()
    }

    pub fn names(&self) -> &NginxServerNames {
        &self.names
    }

    pub const fn port(&self) -> NginxListenPort {
        self.port
    }

    pub fn target(&self) -> &NginxSiteTarget {
        &self.target
    }

    pub fn security_headers(&self) -> bool {
        self.feature_enabled(NginxSiteFeature::SecurityHeaders)
    }

    pub fn feature_enabled(&self, feature: NginxSiteFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn forbidden_path_rule(&self) -> Option<&NginxForbiddenPathRule> {
        self.forbidden_path_rule.as_ref()
    }

    pub fn allowed_source_rule(&self) -> Option<&NginxAllowedSource> {
        self.allowed_source_rule.as_ref()
    }

    pub fn generate(&self) -> CoreResult<GeneratedNginxConfig> {
        self.names.validate()?;
        self.port.validate()?;
        self.target.validate()?;
        if let Some(rule) = &self.forbidden_path_rule {
            rule.validate()?;
        }
        if let Some(source) = &self.allowed_source_rule {
            source.validate()?;
        }
        self.validate_features()?;

        let mut contents = String::with_capacity(2_048);
        contents.push_str("server {\n    listen ");
        contents.push_str(&self.port.get().to_string());
        contents.push_str(";\n    # ");
        contents.push_str(NginxServerNames::meaning());
        contents.push_str("\n    server_name ");
        contents.push_str(self.names.as_str());
        contents.push(';');

        if let NginxSiteTarget::Static(root) = &self.target {
            contents.push_str("\n\n    root \"");
            contents.push_str(root.as_str());
            contents.push_str("\";");
            if self.feature_enabled(NginxSiteFeature::IndexFiles) {
                contents.push_str("\n    index index.html index.htm;");
            }
        }

        if self.feature_enabled(NginxSiteFeature::HideVersion) {
            contents.push_str("\n\n    server_tokens off;");
        }

        let security_headers = self.feature_enabled(NginxSiteFeature::SecurityHeaders);
        let request_id_headers = self.feature_enabled(NginxSiteFeature::RequestIdHeaders);
        if security_headers || request_id_headers {
            contents.push_str(
                "\n\n    # 本 server 定义 add_header 后，不再继承 http 级 add_header 列表；请在此审阅完整响应头策略。",
            );
        }

        if security_headers {
            if self.kind() == NginxSiteKind::ReverseProxy {
                contents.push_str(
                    "\n    proxy_hide_header X-Content-Type-Options;\n    proxy_hide_header X-Frame-Options;\n    proxy_hide_header Referrer-Policy;",
                );
            }
            contents.push_str(
                "\n    add_header X-Content-Type-Options \"nosniff\" always;\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            );
        }

        if request_id_headers {
            contents.push_str(
                "\n\n    proxy_hide_header X-Request-ID;\n    add_header X-Request-ID $request_id always;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::DisableDirectoryListing) {
            contents.push_str("\n\n    autoindex off;");
        }

        if self.feature_enabled(NginxSiteFeature::ClientBodyLimit) {
            contents.push_str("\n\n    client_max_body_size 10m;");
        }

        if self.feature_enabled(NginxSiteFeature::ClientIoTimeouts) {
            contents.push_str(
                "\n\n    client_header_timeout 30s;\n    client_body_timeout 30s;\n    send_timeout 30s;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::LimitRangeRequests) {
            contents.push_str("\n\n    max_ranges 1;");
        }

        if self.feature_enabled(NginxSiteFeature::ResetTimedOutConnection) {
            contents.push_str("\n\n    reset_timedout_connection on;");
        }

        if self.feature_enabled(NginxSiteFeature::KeepaliveTuning) {
            contents.push_str("\n\n    keepalive_timeout 65s;\n    keepalive_requests 1000;");
        }

        if self.feature_enabled(NginxSiteFeature::Utf8Charset) {
            contents.push_str("\n\n    charset utf-8;");
        }

        if self.feature_enabled(NginxSiteFeature::Sendfile) {
            contents.push_str("\n\n    sendfile on;\n    tcp_nopush on;");
        }

        if self.feature_enabled(NginxSiteFeature::OpenFileCache) {
            contents.push_str(
                "\n\n    open_file_cache max=1000 inactive=20s;\n    open_file_cache_valid 30s;\n    open_file_cache_min_uses 2;\n    open_file_cache_errors on;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::ProxyTimeouts) {
            contents.push_str(
                "\n\n    proxy_connect_timeout 5s;\n    proxy_send_timeout 60s;\n    proxy_read_timeout 60s;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::ProxySocketKeepalive) {
            contents.push_str("\n\n    proxy_socket_keepalive on;");
        }

        if self.feature_enabled(NginxSiteFeature::DisableProxyTempFiles) {
            contents.push_str(
                "\n\n    proxy_cache off;\n    proxy_store off;\n    proxy_max_temp_file_size 0;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::ProxyRedirectOff) {
            contents.push_str("\n\n    proxy_redirect off;");
        }

        if self.feature_enabled(NginxSiteFeature::HttpsUpstreamSni) {
            contents.push_str(
                "\n\n    # 仅发送 SNI；未启用 proxy_ssl_verify，不能验证 HTTPS 上游服务器身份。\n    proxy_ssl_server_name on;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::DisableProxyBuffering) {
            contents.push_str(
                "\n\n    proxy_buffering off;\n    proxy_ignore_headers X-Accel-Buffering;",
            );
        }

        if self.feature_enabled(NginxSiteFeature::DisableProxyRequestBuffering) {
            contents.push_str("\n\n    proxy_request_buffering off;");
        }

        if self.feature_enabled(NginxSiteFeature::GzipCompression) {
            contents.push_str(
                "\n\n    # gzip_proxied 保持 off：携带 Via 的请求不会压缩；TLS 动态响应需评估 BREACH 风险。\n    gzip on;\n    gzip_vary on;\n    gzip_min_length 1024;\n    gzip_types text/plain text/css application/json application/javascript application/xml image/svg+xml;",
            );
        }

        let restrict_methods = self.feature_enabled(NginxSiteFeature::RestrictRequestMethods);
        let allowed_source = self
            .feature_enabled(NginxSiteFeature::RestrictSourceIp)
            .then_some(self.allowed_source_rule.as_ref())
            .flatten();
        let static_try_files = self.feature_enabled(NginxSiteFeature::StaticTryFiles);
        let spa_fallback = self.feature_enabled(NginxSiteFeature::SpaFallback);
        if restrict_methods || allowed_source.is_some() {
            contents.push_str(
                "\n\n    # 显式覆盖可能从 http 级继承的 satisfy any，访问限制必须全部满足。\n    satisfy all;",
            );
        }
        if self.kind() == NginxSiteKind::ReverseProxy {
            contents.push_str(
                "\n\n    # DirectClient baseline：每个代理入口都会覆盖客户端提供的转发身份，不建立可信代理链。",
            );
        }

        if self.feature_enabled(NginxSiteFeature::DenyHiddenFiles) {
            contents.push_str("\n\n    location ~ (^|/)\\.(?!well-known(?:/|$)) {\n");
            push_location_guards(&mut contents, restrict_methods, allowed_source);
            contents.push_str("        return 404;\n    }");
        }

        if self.feature_enabled(NginxSiteFeature::DenySensitiveFiles) {
            contents.push_str(
                "\n\n    location ~* \\.(?:bak|conf|dist|env|ini|log|old|orig|save|sql|swp|tmp)$ {\n",
            );
            push_location_guards(&mut contents, restrict_methods, allowed_source);
            contents.push_str("        return 404;\n    }");
        }

        if self.feature_enabled(NginxSiteFeature::HealthCheck) {
            contents.push_str("\n\n    location = /healthz {\n");
            push_location_guards(&mut contents, restrict_methods, allowed_source);
            contents.push_str("        access_log off;\n        empty_gif;\n    }");
        }

        if self.feature_enabled(NginxSiteFeature::ForbiddenPath403) {
            let rule = self
                .forbidden_path_rule
                .as_ref()
                .expect("feature completeness was validated");
            contents.push_str("\n\n    location = ");
            contents.push_str(rule.path().as_str());
            contents.push_str(" {\n");
            push_location_guards(&mut contents, restrict_methods, allowed_source);
            contents.push_str("        return 403;\n    }");
            if rule.scope() == NginxForbiddenPathScope::PathAndDescendants {
                contents.push_str("\n\n    location ^~ ");
                contents.push_str(rule.path().as_str());
                contents.push_str("/ {\n");
                push_location_guards(&mut contents, restrict_methods, allowed_source);
                contents.push_str("        return 403;\n    }");
            }
        }

        if self.feature_enabled(NginxSiteFeature::StaticAssetCaching) || spa_fallback {
            contents.push_str("\n\n    location /assets/ {\n");
            push_location_guards(&mut contents, restrict_methods, allowed_source);
            push_target_directives(
                &mut contents,
                &self.target,
                false,
                static_try_files || spa_fallback,
                false,
                request_id_headers,
            );
            if self.feature_enabled(NginxSiteFeature::StaticAssetCaching) {
                contents.push_str("        expires 7d;\n");
            }
            contents.push_str("    }");
        }

        if self.feature_enabled(NginxSiteFeature::WebSocketProxy) {
            contents.push_str("\n\n    location /ws/ {\n");
            push_location_guards(&mut contents, restrict_methods, allowed_source);
            push_target_directives(
                &mut contents,
                &self.target,
                true,
                static_try_files,
                false,
                request_id_headers,
            );
            contents.push_str("    }");
        }

        contents.push_str("\n\n    location / {\n");
        push_location_guards(&mut contents, restrict_methods, allowed_source);
        push_target_directives(
            &mut contents,
            &self.target,
            false,
            static_try_files,
            spa_fallback,
            request_id_headers,
        );
        contents.push_str("    }\n}\n");

        validate_generated_document(&contents)?;
        Ok(GeneratedNginxConfig { contents })
    }

    fn validate_features(&self) -> CoreResult<()> {
        self.validate_feature_compatibility()?;
        if self.feature_enabled(NginxSiteFeature::ForbiddenPath403)
            && self.forbidden_path_rule.is_none()
        {
            return Err(CoreError::validation(
                "Nginx forbidden path feature",
                "requires one validated forbidden path rule",
            ));
        }
        if self.feature_enabled(NginxSiteFeature::RestrictSourceIp)
            && self.allowed_source_rule.is_none()
        {
            return Err(CoreError::validation(
                "Nginx source restriction feature",
                "requires one validated IP address or CIDR",
            ));
        }
        Ok(())
    }

    fn validate_feature_compatibility(&self) -> CoreResult<()> {
        if let Some(feature) = self
            .features
            .iter()
            .find(|feature| !feature.supports_kind(self.kind()))
        {
            return Err(CoreError::validation(
                "Nginx site feature",
                format!(
                    "{} is not available for the {} baseline",
                    feature.title(),
                    self.kind().label()
                ),
            ));
        }
        if self.feature_enabled(NginxSiteFeature::StaticTryFiles)
            && self.feature_enabled(NginxSiteFeature::SpaFallback)
        {
            return Err(CoreError::validation(
                "Nginx static routing features",
                format!(
                    "{} and {} are mutually exclusive main-location fallbacks",
                    NginxSiteFeature::StaticTryFiles.title(),
                    NginxSiteFeature::SpaFallback.title()
                ),
            ));
        }
        if self.feature_enabled(NginxSiteFeature::HttpsUpstreamSni)
            && !matches!(
                &self.target,
                NginxSiteTarget::ReverseProxy(upstream) if upstream.supports_https_sni()
            )
        {
            return Err(CoreError::validation(
                "Nginx HTTPS upstream SNI feature",
                "requires an https:// upstream with a DNS host name",
            ));
        }
        if !self.feature_enabled(NginxSiteFeature::ForbiddenPath403) {
            return Ok(());
        }
        let Some(rule) = self.forbidden_path_rule.as_ref() else {
            return Ok(());
        };
        if self.feature_enabled(NginxSiteFeature::HealthCheck)
            && rule.path().as_str() == HEALTH_CHECK_LOCATION_PATH
        {
            return Err(CoreError::validation(
                "Nginx feature locations",
                format!(
                    "forbidden path {HEALTH_CHECK_LOCATION_PATH} conflicts with the fixed {} location",
                    NginxSiteFeature::HealthCheck.title()
                ),
            ));
        }
        if self.feature_enabled(NginxSiteFeature::SpaFallback)
            && rule.path().as_str() == SPA_FALLBACK_PATH
        {
            return Err(CoreError::validation(
                "Nginx feature locations",
                format!(
                    "forbidden path {SPA_FALLBACK_PATH} conflicts with the fixed {} target",
                    NginxSiteFeature::SpaFallback.title()
                ),
            ));
        }
        if rule.scope() != NginxForbiddenPathScope::PathAndDescendants {
            return Ok(());
        }
        for (feature, path) in [
            (
                NginxSiteFeature::StaticAssetCaching,
                STATIC_ASSET_LOCATION_PATH,
            ),
            (NginxSiteFeature::SpaFallback, STATIC_ASSET_LOCATION_PATH),
            (NginxSiteFeature::WebSocketProxy, WEBSOCKET_LOCATION_PATH),
        ] {
            if self.feature_enabled(feature) && rule.path().as_str() == path {
                return Err(CoreError::validation(
                    "Nginx feature locations",
                    format!(
                        "forbidden descendants for {path}/ conflict with the fixed {} location",
                        feature.title()
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn push_location_guards(
    contents: &mut String,
    restrict_methods: bool,
    allowed_source: Option<&NginxAllowedSource>,
) {
    if restrict_methods {
        contents.push_str("        limit_except GET HEAD {\n            deny all;\n        }\n");
    }
    if let Some(source) = allowed_source {
        contents.push_str("        allow ");
        contents.push_str(source.as_str());
        contents.push_str(";\n        deny all;\n");
    }
}

fn push_target_directives(
    contents: &mut String,
    target: &NginxSiteTarget,
    websocket: bool,
    static_try_files: bool,
    spa_fallback: bool,
    request_id_headers: bool,
) {
    match target {
        NginxSiteTarget::Static(_) => {
            debug_assert!(
                !websocket,
                "static baselines reject WebSocket before rendering"
            );
            if spa_fallback {
                contents.push_str("        try_files $uri $uri/ /index.html;\n");
            } else if static_try_files {
                contents.push_str("        try_files $uri $uri/ =404;\n");
            }
        }
        NginxSiteTarget::ReverseProxy(upstream) => {
            contents.push_str("        proxy_pass ");
            contents.push_str(upstream.as_str());
            contents.push_str(
                ";\n        proxy_http_version 1.1;\n        proxy_set_header Host $proxy_host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_set_header Forwarded \"\";\n",
            );
            if websocket {
                contents.push_str(
                    "        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n",
                );
            }
            if request_id_headers {
                contents.push_str("        proxy_set_header X-Request-ID $request_id;\n");
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedNginxConfig {
    contents: String,
}

impl GeneratedNginxConfig {
    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub const fn suggested_file_name(&self) -> &'static str {
        SUGGESTED_FILE_NAME
    }

    /// Write to a new `.conf` selected by a native save dialog.
    ///
    /// Existing files are never replaced. A partially written file is removed
    /// after the handle is closed if flushing or syncing fails.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_export_destination(destination)?;
        validate_generated_document(&self.contents)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io("create generated Nginx configuration", destination, source)
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io("write generated Nginx configuration", destination, source)
            })?;
            file.flush().map_err(|source| {
                CoreError::io("flush generated Nginx configuration", destination, source)
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io("sync generated Nginx configuration", destination, source)
            })
        })();
        drop(file);

        if let Err(error) = write_result {
            if let Err(cleanup_error) = fs::remove_file(destination) {
                tracing::error!(
                    error = %cleanup_error,
                    "failed to remove partial generated Nginx configuration"
                );
            }
            return Err(error);
        }
        Ok(destination.to_path_buf())
    }
}

fn normalize_dns_name(subject: &'static str, value: &str) -> CoreResult<String> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(CoreError::validation(
            subject,
            "must be a non-empty ASCII DNS name of at most 253 bytes",
        ));
    }
    if value.ends_with('.') {
        return Err(CoreError::validation(
            subject,
            "must not use a trailing root-label dot",
        ));
    }
    for label in value.split('.') {
        let bytes = label.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
        if !valid {
            return Err(CoreError::validation(
                subject,
                "each DNS label must be 1..=63 ASCII letters, digits, or inner hyphens",
            ));
        }
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_static_root(path: &RemotePath) -> CoreResult<()> {
    let value = path.as_str();
    if value == "/" {
        return Err(CoreError::validation(
            "Nginx static root",
            "refuses to expose the remote filesystem root",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(CoreError::validation(
            "Nginx static root",
            "must contain only ASCII letters, digits, slash, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

fn validate_generated_document(contents: &str) -> CoreResult<()> {
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_NGINX_CONFIG_BYTES
        || contents.contains('\0')
        || contents.contains('\r')
        || !contents.ends_with('\n')
    {
        return Err(CoreError::validation(
            "generated Nginx configuration",
            format!(
                "must be non-empty LF-only UTF-8 with a terminal newline and at most {MAX_GENERATED_NGINX_CONFIG_BYTES} bytes"
            ),
        ));
    }
    let document = MiddlewareDocument::parse(
        MiddlewareDocumentSyntax::Nginx,
        contents.as_bytes().to_vec(),
    )
    .map_err(|error| CoreError::validation("generated Nginx configuration", error.to_string()))?;
    if document
        .nodes()
        .iter()
        .any(|node| node.kind == MiddlewareDocumentNodeKind::Opaque)
    {
        return Err(CoreError::validation(
            "generated Nginx configuration",
            "closed template did not produce a structurally complete Nginx document",
        ));
    }
    Ok(())
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated Nginx configuration destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated Nginx configuration destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
    {
        return Err(CoreError::validation(
            "generated Nginx configuration destination",
            "must use the .conf extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated Nginx configuration destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated Nginx configuration destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-nginx-config-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn static_config(security_headers: bool) -> NginxSiteConfig {
        NginxSiteConfig::new(
            NginxServerNames::parse("Example.COM").unwrap(),
            NginxListenPort::parse("8080").unwrap(),
            NginxSiteTarget::Static(NginxStaticRoot::parse("/srv/www/example").unwrap()),
            security_headers,
        )
        .unwrap()
    }

    fn reverse_proxy_config(security_headers: bool) -> NginxSiteConfig {
        NginxSiteConfig::new(
            NginxServerNames::parse("api.example.com").unwrap(),
            NginxListenPort::parse("80").unwrap(),
            NginxSiteTarget::ReverseProxy(NginxUpstream::parse("http://127.0.0.1:3000").unwrap()),
            security_headers,
        )
        .unwrap()
    }

    fn https_reverse_proxy_config(security_headers: bool) -> NginxSiteConfig {
        NginxSiteConfig::new(
            NginxServerNames::parse("api.example.com").unwrap(),
            NginxListenPort::parse("443").unwrap(),
            NginxSiteTarget::ReverseProxy(
                NginxUpstream::parse("https://upstream.example:8443").unwrap(),
            ),
            security_headers,
        )
        .unwrap()
    }

    #[test]
    fn feature_metadata_is_complete_unique_and_has_exact_defaults() {
        assert_eq!(
            NginxSiteFeature::ALL,
            [
                NginxSiteFeature::ForbiddenPath403,
                NginxSiteFeature::SecurityHeaders,
                NginxSiteFeature::DisableDirectoryListing,
                NginxSiteFeature::RestrictRequestMethods,
                NginxSiteFeature::HideVersion,
                NginxSiteFeature::RestrictSourceIp,
                NginxSiteFeature::GzipCompression,
                NginxSiteFeature::StaticAssetCaching,
                NginxSiteFeature::WebSocketProxy,
                NginxSiteFeature::HealthCheck,
                NginxSiteFeature::DenyHiddenFiles,
                NginxSiteFeature::DenySensitiveFiles,
                NginxSiteFeature::ClientBodyLimit,
                NginxSiteFeature::KeepaliveTuning,
                NginxSiteFeature::Utf8Charset,
                NginxSiteFeature::IndexFiles,
                NginxSiteFeature::StaticTryFiles,
                NginxSiteFeature::Sendfile,
                NginxSiteFeature::OpenFileCache,
                NginxSiteFeature::ProxyTimeouts,
                NginxSiteFeature::DisableProxyBuffering,
                NginxSiteFeature::DisableProxyRequestBuffering,
                NginxSiteFeature::RequestIdHeaders,
                NginxSiteFeature::SpaFallback,
                NginxSiteFeature::ClientIoTimeouts,
                NginxSiteFeature::LimitRangeRequests,
                NginxSiteFeature::ResetTimedOutConnection,
                NginxSiteFeature::ProxySocketKeepalive,
                NginxSiteFeature::DisableProxyTempFiles,
                NginxSiteFeature::ProxyRedirectOff,
                NginxSiteFeature::HttpsUpstreamSni,
            ]
        );
        assert_eq!(NginxSiteFeature::ALL.len(), 31);
        let keys = NginxSiteFeature::ALL
            .into_iter()
            .map(NginxSiteFeature::key)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(keys.len(), NginxSiteFeature::ALL.len());
        assert!(NginxSiteFeature::ALL.into_iter().all(|feature| {
            !feature.key().is_empty()
                && !feature.title().is_empty()
                && !feature.summary().is_empty()
                && !feature.scope().is_empty()
                && !feature.aliases().is_empty()
        }));
        assert_eq!(
            NginxSiteFeature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                NginxSiteFeature::SecurityHeaders,
                NginxSiteFeature::DisableDirectoryListing,
                NginxSiteFeature::HideVersion,
                NginxSiteFeature::IndexFiles,
                NginxSiteFeature::StaticTryFiles,
            ])
        );
    }

    #[test]
    fn feature_support_matrix_is_explicit_for_every_site_kind() {
        let static_only = BTreeSet::from([
            NginxSiteFeature::IndexFiles,
            NginxSiteFeature::StaticTryFiles,
            NginxSiteFeature::Sendfile,
            NginxSiteFeature::OpenFileCache,
            NginxSiteFeature::SpaFallback,
            NginxSiteFeature::LimitRangeRequests,
        ]);
        let proxy_only = BTreeSet::from([
            NginxSiteFeature::WebSocketProxy,
            NginxSiteFeature::ProxyTimeouts,
            NginxSiteFeature::DisableProxyBuffering,
            NginxSiteFeature::DisableProxyRequestBuffering,
            NginxSiteFeature::RequestIdHeaders,
            NginxSiteFeature::ProxySocketKeepalive,
            NginxSiteFeature::DisableProxyTempFiles,
            NginxSiteFeature::ProxyRedirectOff,
            NginxSiteFeature::HttpsUpstreamSni,
        ]);

        for feature in NginxSiteFeature::ALL {
            assert_eq!(
                feature.supports_kind(NginxSiteKind::Static),
                !proxy_only.contains(&feature),
                "{feature:?}"
            );
            assert_eq!(
                feature.supports_kind(NginxSiteKind::ReverseProxy),
                !static_only.contains(&feature),
                "{feature:?}"
            );
        }
    }

    #[test]
    fn security_sensitive_metadata_states_the_closed_semantics() {
        assert!(NginxServerNames::meaning().contains("不是 Host 访问白名单"));
        assert!(
            NginxSiteFeature::SecurityHeaders
                .summary()
                .contains("替代从 http 级继承")
        );
        assert!(
            NginxSiteFeature::RestrictSourceIp
                .summary()
                .contains("TCP peer")
        );
        assert!(
            NginxSiteFeature::RestrictSourceIp
                .summary()
                .contains("不读取 X-Forwarded-For")
        );
        assert!(
            NginxSiteFeature::LimitRangeRequests
                .summary()
                .starts_with("仅用于静态站点")
        );
        assert!(
            NginxSiteFeature::DisableProxyTempFiles
                .summary()
                .contains("cache/store")
        );
        assert!(
            NginxSiteFeature::HttpsUpstreamSni
                .title()
                .contains("不校验证书")
        );
        assert!(
            NginxSiteFeature::HttpsUpstreamSni
                .summary()
                .contains("不验证上游服务器身份")
        );
        assert!(!NginxSiteFeature::GzipCompression.default_enabled());
        assert!(
            NginxSiteFeature::GzipCompression
                .summary()
                .contains("BREACH")
        );
    }

    #[test]
    fn access_guards_override_inherited_satisfy_any() {
        let baseline = reverse_proxy_config(false).generate().unwrap();
        assert!(!baseline.contents().contains("    satisfy all;"));

        let methods = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::RestrictRequestMethods, true)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(methods.contents().matches("    satisfy all;").count(), 1);
        assert!(methods.contents().contains("limit_except GET HEAD"));
        assert!(
            methods
                .contents()
                .contains("覆盖可能从 http 级继承的 satisfy any")
        );

        let source = reverse_proxy_config(false)
            .with_allowed_source_rule(NginxAllowedSource::parse("192.0.2.10").unwrap())
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(source.contents().matches("    satisfy all;").count(), 1);
        assert!(source.contents().contains("allow 192.0.2.10;"));
        assert!(source.contents().contains("deny all;"));
    }

    #[test]
    fn proxy_headers_replace_untrusted_identity_and_fixed_response_headers() {
        let generated = reverse_proxy_config(true).generate().unwrap();
        let contents = generated.contents();
        for directive in [
            "proxy_set_header Host $proxy_host;",
            "proxy_set_header X-Forwarded-For $remote_addr;",
            "proxy_set_header Forwarded \"\";",
            "proxy_hide_header X-Content-Type-Options;",
            "proxy_hide_header X-Frame-Options;",
            "proxy_hide_header Referrer-Policy;",
        ] {
            assert!(contents.contains(directive), "{directive:?}");
        }
        assert!(!contents.contains("proxy_set_header Host $host;"));
        assert!(!contents.contains("$proxy_add_x_forwarded_for"));
        assert!(contents.contains("不再继承 http 级 add_header 列表"));
        assert!(contents.contains("DirectClient baseline"));

        let static_headers = static_config(false)
            .with_feature(NginxSiteFeature::SecurityHeaders, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            static_headers
                .contents()
                .contains("add_header X-Frame-Options")
        );
        assert!(!static_headers.contents().contains("proxy_hide_header"));

        let request_id_only = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::RequestIdHeaders, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            request_id_only
                .contents()
                .contains("proxy_hide_header X-Request-ID;")
        );
        assert!(
            request_id_only
                .contents()
                .contains("不再继承 http 级 add_header 列表")
        );
    }

    #[test]
    fn range_temp_file_sni_and_gzip_features_fail_closed() {
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::LimitRangeRequests, true)
                .is_err()
        );
        let ranges = static_config(false)
            .with_feature(NginxSiteFeature::LimitRangeRequests, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(ranges.contents().contains("max_ranges 1;"));

        let no_disk = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::DisableProxyTempFiles, true)
            .unwrap()
            .generate()
            .unwrap();
        for directive in [
            "proxy_cache off;",
            "proxy_store off;",
            "proxy_max_temp_file_size 0;",
        ] {
            assert!(no_disk.contents().contains(directive), "{directive:?}");
        }

        let sni = https_reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::HttpsUpstreamSni, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(sni.contents().contains("proxy_ssl_server_name on;"));
        assert!(sni.contents().contains("未启用 proxy_ssl_verify"));
        assert!(!sni.contents().contains("proxy_ssl_verify on;"));

        let gzip = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::GzipCompression, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(gzip.contents().contains("gzip on;"));
        assert!(gzip.contents().contains("gzip_proxied 保持 off"));
        assert!(!gzip.contents().contains("gzip_proxied any"));
    }

    #[test]
    fn compatibility_constructor_maps_only_the_legacy_security_pair() {
        let enabled = reverse_proxy_config(true);
        assert!(enabled.security_headers());
        assert!(enabled.feature_enabled(NginxSiteFeature::SecurityHeaders));
        assert!(enabled.feature_enabled(NginxSiteFeature::HideVersion));
        for feature in NginxSiteFeature::ALL {
            if !matches!(
                feature,
                NginxSiteFeature::SecurityHeaders | NginxSiteFeature::HideVersion
            ) {
                assert!(!enabled.feature_enabled(feature), "{feature:?}");
            }
        }

        let disabled = reverse_proxy_config(false);
        assert!(!disabled.security_headers());
        assert!(
            NginxSiteFeature::ALL
                .into_iter()
                .all(|feature| !disabled.feature_enabled(feature))
        );

        let static_baseline = static_config(false);
        assert!(static_baseline.feature_enabled(NginxSiteFeature::IndexFiles));
        assert!(static_baseline.feature_enabled(NginxSiteFeature::StaticTryFiles));
    }

    #[test]
    fn static_template_is_exact_and_deterministic() {
        let config = static_config(false);
        let first = config.generate().unwrap();
        let second = config.generate().unwrap();
        assert_eq!(config.kind(), NginxSiteKind::Static);
        assert_eq!(first, second);
        assert_eq!(first.suggested_file_name(), "nginx-site.conf");
        assert_eq!(
            first.contents(),
            "server {\n    listen 8080;\n    # server_name 只参与 Nginx 虚拟主机选择；默认 server 仍可接收未匹配或缺失的 Host，因此它不是 Host 访问白名单。\n    server_name example.com;\n\n    root \"/srv/www/example\";\n    index index.html index.htm;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n"
        );
        assert!(first.contents().len() <= MAX_GENERATED_NGINX_CONFIG_BYTES);
    }

    #[test]
    fn reverse_proxy_template_has_only_fixed_security_directives() {
        let generated = reverse_proxy_config(true).generate().unwrap();
        assert_eq!(
            generated.contents(),
            "server {\n    listen 80;\n    # server_name 只参与 Nginx 虚拟主机选择；默认 server 仍可接收未匹配或缺失的 Host，因此它不是 Host 访问白名单。\n    server_name api.example.com;\n\n    server_tokens off;\n\n    # 本 server 定义 add_header 后，不再继承 http 级 add_header 列表；请在此审阅完整响应头策略。\n    proxy_hide_header X-Content-Type-Options;\n    proxy_hide_header X-Frame-Options;\n    proxy_hide_header Referrer-Policy;\n    add_header X-Content-Type-Options \"nosniff\" always;\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n    # DirectClient baseline：每个代理入口都会覆盖客户端提供的转发身份，不建立可信代理链。\n\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n        proxy_http_version 1.1;\n        proxy_set_header Host $proxy_host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_set_header Forwarded \"\";\n    }\n}\n"
        );
        assert_eq!(
            reverse_proxy_config(false).kind(),
            NginxSiteKind::ReverseProxy
        );
    }

    #[test]
    fn additive_features_are_order_independent_and_keep_the_baseline() {
        let first = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::SecurityHeaders, true)
            .unwrap()
            .with_feature(NginxSiteFeature::GzipCompression, true)
            .unwrap()
            .generate()
            .unwrap();
        let second = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::GzipCompression, true)
            .unwrap()
            .with_feature(NginxSiteFeature::SecurityHeaders, true)
            .unwrap()
            .generate()
            .unwrap();

        assert_eq!(first, second);
        assert!(first.contents().contains("listen 80;"));
        assert!(first.contents().contains("server_name api.example.com;"));
        assert!(
            first
                .contents()
                .contains("proxy_pass http://127.0.0.1:3000;")
        );
        assert!(
            first
                .contents()
                .contains("add_header X-Content-Type-Options")
        );
        assert!(first.contents().contains("gzip on;"));
    }

    #[test]
    fn disabling_one_feature_preserves_the_other_feature_and_baseline() {
        let generated = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::SecurityHeaders, true)
            .unwrap()
            .with_feature(NginxSiteFeature::GzipCompression, true)
            .unwrap()
            .with_feature(NginxSiteFeature::GzipCompression, false)
            .unwrap()
            .generate()
            .unwrap();

        assert!(
            generated
                .contents()
                .contains("add_header X-Content-Type-Options")
        );
        assert!(!generated.contents().contains("gzip on;"));
        assert!(
            generated
                .contents()
                .contains("proxy_pass http://127.0.0.1:3000;")
        );
    }

    #[test]
    fn nginx_feature_removal_updates_typed_model_and_generated_preview() {
        let enabled = reverse_proxy_config(false)
            .with_feature(NginxSiteFeature::SecurityHeaders, true)
            .unwrap();
        let before = enabled.generate().unwrap();
        assert!(enabled.feature_enabled(NginxSiteFeature::SecurityHeaders));
        assert!(
            before
                .contents()
                .contains("add_header X-Content-Type-Options")
        );
        assert!(
            before
                .contents()
                .contains("proxy_hide_header X-Content-Type-Options;")
        );

        let removed = enabled
            .with_feature(NginxSiteFeature::SecurityHeaders, false)
            .unwrap();
        let after = removed.generate().unwrap();
        assert!(!removed.feature_enabled(NginxSiteFeature::SecurityHeaders));
        assert!(
            !after
                .contents()
                .contains("add_header X-Content-Type-Options")
        );
        assert!(
            !after
                .contents()
                .contains("proxy_hide_header X-Content-Type-Options;")
        );
        assert!(after.contents().contains("listen 80;"));
        assert!(
            after
                .contents()
                .contains("proxy_pass http://127.0.0.1:3000;")
        );
    }

    #[test]
    fn forbidden_path_goal_is_segment_safe_and_deterministic() {
        let rule = NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse("/admin").unwrap(),
            NginxForbiddenPathScope::PathAndDescendants,
        )
        .unwrap();
        let config = reverse_proxy_config(false)
            .with_forbidden_path_rule(rule)
            .unwrap();
        let generated = config.generate().unwrap();
        let exact = "    location = /admin {\n        return 403;\n    }";
        let descendants = "    location ^~ /admin/ {\n        return 403;\n    }";
        let fallback = "    location / {\n        proxy_pass";

        assert_eq!(
            config.forbidden_path_rule().unwrap().scope(),
            NginxForbiddenPathScope::PathAndDescendants
        );
        assert!(generated.contents().contains(exact));
        assert!(generated.contents().contains(descendants));
        assert!(!generated.contents().contains("location /admin {"));
        assert!(!generated.contents().contains("/administrator"));
        assert!(generated.contents().find(exact) < generated.contents().find(descendants));
        assert!(generated.contents().find(descendants) < generated.contents().find(fallback));
        validate_generated_document(generated.contents()).unwrap();

        let exact_only = reverse_proxy_config(false)
            .with_forbidden_path_rule(
                NginxForbiddenPathRule::new(
                    NginxForbiddenPath::parse("/admin").unwrap(),
                    NginxForbiddenPathScope::Exact,
                )
                .unwrap(),
            )
            .unwrap()
            .generate()
            .unwrap();
        assert!(exact_only.contents().contains(exact));
        assert!(!exact_only.contents().contains("location ^~ /admin/"));
    }

    #[test]
    fn forbidden_path_goal_rejects_root_ambiguity_and_token_injection() {
        assert_eq!(
            NginxForbiddenPath::parse("/admin/tools").unwrap().as_str(),
            "/admin/tools"
        );
        let maximum = format!("/{}", "a".repeat(MAX_FORBIDDEN_PATH_BYTES - 1));
        assert_eq!(
            NginxForbiddenPath::parse(&maximum).unwrap().as_str(),
            maximum
        );
        let oversized = format!("/{}", "a".repeat(MAX_FORBIDDEN_PATH_BYTES));
        assert!(NginxForbiddenPath::parse(&oversized).is_err());
        for invalid in [
            "",
            "/",
            "admin",
            " /admin",
            "/admin ",
            "/admin/",
            "//admin",
            "/admin//users",
            "/admin/./users",
            "/admin/../public",
            "/admin%2Fusers",
            "/admin?debug=1",
            "/admin#comment",
            "/admin;return",
            "/admin{",
            "/$admin",
            "/管理",
        ] {
            assert!(NginxForbiddenPath::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn allowed_source_normalizes_ip_and_cidr_and_rejects_injection() {
        assert_eq!(
            NginxAllowedSource::parse("192.0.2.10").unwrap().as_str(),
            "192.0.2.10"
        );
        assert_eq!(
            NginxAllowedSource::parse("192.0.2.129/24")
                .unwrap()
                .as_str(),
            "192.0.2.0/24"
        );
        assert_eq!(
            NginxAllowedSource::parse("2001:0db8:0:0::1")
                .unwrap()
                .as_str(),
            "2001:db8::1"
        );
        assert_eq!(
            NginxAllowedSource::parse("2001:db8:abcd::1234/48")
                .unwrap()
                .as_str(),
            "2001:db8:abcd::/48"
        );
        assert_eq!(
            NginxAllowedSource::parse("203.0.113.9/0").unwrap().as_str(),
            "0.0.0.0/0"
        );
        assert_eq!(
            NginxAllowedSource::parse("2001:db8::1/0").unwrap().as_str(),
            "::/0"
        );

        for invalid in [
            "",
            " 192.0.2.1",
            "192.0.2.1 ",
            "192.0.2.1; deny all",
            "192.0.2.1#comment",
            "192.0.2.1/",
            "/24",
            "192.0.2.1/24/1",
            "192.0.2.1/-1",
            "192.0.2.1/+24",
            "192.0.2.1/33",
            "2001:db8::1/129",
            "$remote_addr",
            "all",
            "unix:",
            "例子",
        ] {
            assert!(NginxAllowedSource::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn every_reverse_proxy_feature_composes_and_guards_every_request_location() {
        let mut config = https_reverse_proxy_config(false);
        for feature in NginxSiteFeature::ALL
            .into_iter()
            .filter(|feature| feature.supports_kind(NginxSiteKind::ReverseProxy))
        {
            config = config.with_feature(feature, true).unwrap();
        }
        config = config
            .with_forbidden_path_rule(
                NginxForbiddenPathRule::new(
                    NginxForbiddenPath::parse("/admin").unwrap(),
                    NginxForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .unwrap()
            .with_allowed_source_rule(NginxAllowedSource::parse("10.20.30.41/24").unwrap())
            .unwrap();

        let generated = config.generate().unwrap();
        let contents = generated.contents();
        for unique in [
            "    server_tokens off;",
            "    add_header X-Content-Type-Options \"nosniff\" always;",
            "    add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "    proxy_hide_header X-Content-Type-Options;",
            "    proxy_hide_header X-Frame-Options;",
            "    proxy_hide_header Referrer-Policy;",
            "    autoindex off;",
            "    gzip on;",
            "    gzip_vary on;",
            "    gzip_min_length 1024;",
            "    add_header X-Request-ID $request_id always;",
            "    client_max_body_size 10m;",
            "    client_header_timeout 30s;",
            "    client_body_timeout 30s;",
            "    send_timeout 30s;",
            "    reset_timedout_connection on;",
            "    keepalive_timeout 65s;",
            "    keepalive_requests 1000;",
            "    charset utf-8;",
            "    proxy_connect_timeout 5s;",
            "    proxy_send_timeout 60s;",
            "    proxy_read_timeout 60s;",
            "    proxy_socket_keepalive on;",
            "    proxy_cache off;",
            "    proxy_store off;",
            "    proxy_max_temp_file_size 0;",
            "    proxy_redirect off;",
            "    proxy_ssl_server_name on;",
            "    proxy_buffering off;",
            "    proxy_ignore_headers X-Accel-Buffering;",
            "    proxy_request_buffering off;",
            "    proxy_hide_header X-Request-ID;",
            "    satisfy all;",
            "        expires 7d;",
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection \"upgrade\";",
        ] {
            assert_eq!(contents.matches(unique).count(), 1, "{unique:?}");
        }
        assert_eq!(contents.matches("    location / {").count(), 1);
        assert_eq!(contents.matches("    location /assets/ {").count(), 1);
        assert_eq!(contents.matches("    location /ws/ {").count(), 1);
        assert_eq!(contents.matches("    location = /healthz {").count(), 1);
        assert_eq!(
            contents
                .matches("    location ~ (^|/)\\.(?!well-known(?:/|$)) {")
                .count(),
            1
        );
        assert_eq!(
            contents
                .matches(
                    "    location ~* \\.(?:bak|conf|dist|env|ini|log|old|orig|save|sql|swp|tmp)$ {"
                )
                .count(),
            1
        );
        let location_count = contents.matches("    location ").count();
        assert_eq!(location_count, 8);
        assert_eq!(
            contents.matches("        limit_except GET HEAD {").count(),
            location_count
        );
        assert_eq!(
            contents.matches("        allow 10.20.30.0/24;").count(),
            location_count
        );
        assert_eq!(
            contents
                .matches("        proxy_set_header X-Request-ID $request_id;")
                .count(),
            3
        );
        for directive in [
            "        proxy_set_header Host $proxy_host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $remote_addr;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_set_header Forwarded \"\";",
        ] {
            assert_eq!(contents.matches(directive).count(), 3, "{directive:?}");
        }
        assert!(!contents.contains("proxy_set_header Host $host;"));
        assert!(!contents.contains("$proxy_add_x_forwarded_for"));
        assert!(!contents.contains("max_ranges"));
        assert!(contents.contains("不再继承 http 级 add_header 列表"));
        assert!(contents.contains("未启用 proxy_ssl_verify"));
        assert!(contents.contains("DirectClient baseline"));
        assert!(contents.contains("proxy_pass https://upstream.example:8443;"));
        assert!(contents.len() <= MAX_GENERATED_NGINX_CONFIG_BYTES);
        validate_generated_document(contents).unwrap();
    }

    #[test]
    fn every_static_feature_composes_and_static_baseline_features_can_be_disabled() {
        let mut config = static_config(false);
        for feature in NginxSiteFeature::ALL.into_iter().filter(|feature| {
            feature.supports_kind(NginxSiteKind::Static)
                && *feature != NginxSiteFeature::SpaFallback
        }) {
            config = config.with_feature(feature, true).unwrap();
        }
        let generated = config
            .with_forbidden_path_rule(
                NginxForbiddenPathRule::new(
                    NginxForbiddenPath::parse("/admin").unwrap(),
                    NginxForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .unwrap()
            .with_allowed_source_rule(NginxAllowedSource::parse("192.0.2.10").unwrap())
            .unwrap()
            .generate()
            .unwrap();
        let contents = generated.contents();
        for unique in [
            "    index index.html index.htm;",
            "    sendfile on;",
            "    tcp_nopush on;",
            "    open_file_cache max=1000 inactive=20s;",
            "    open_file_cache_valid 30s;",
            "    open_file_cache_min_uses 2;",
            "    open_file_cache_errors on;",
            "    client_header_timeout 30s;",
            "    client_body_timeout 30s;",
            "    send_timeout 30s;",
            "    max_ranges 1;",
            "    reset_timedout_connection on;",
        ] {
            assert_eq!(contents.matches(unique).count(), 1, "{unique:?}");
        }
        assert_eq!(
            contents
                .matches("        try_files $uri $uri/ =404;")
                .count(),
            2
        );
        assert!(!contents.contains("proxy_pass "));
        validate_generated_document(contents).unwrap();

        let minimal = static_config(false)
            .with_feature(NginxSiteFeature::IndexFiles, false)
            .unwrap()
            .with_feature(NginxSiteFeature::StaticTryFiles, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!minimal.contents().contains("    index "));
        assert!(!minimal.contents().contains("        try_files "));
        assert!(
            minimal
                .contents()
                .contains("    root \"/srv/www/example\";")
        );
        validate_generated_document(minimal.contents()).unwrap();
    }

    #[test]
    fn spa_fallback_replaces_only_the_main_static_location_fallback() {
        let spa_only = static_config(false)
            .with_feature(NginxSiteFeature::StaticTryFiles, false)
            .unwrap()
            .with_feature(NginxSiteFeature::SpaFallback, true)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(
            spa_only
                .contents()
                .matches("    location /assets/ {")
                .count(),
            1
        );
        assert!(
            spa_only
                .contents()
                .contains("try_files $uri $uri/ /index.html;")
        );
        assert!(spa_only.contents().contains("try_files $uri $uri/ =404;"));
        assert!(!spa_only.contents().contains("expires 7d;"));

        let generated = static_config(false)
            .with_feature(NginxSiteFeature::StaticTryFiles, false)
            .unwrap()
            .with_feature(NginxSiteFeature::SpaFallback, true)
            .unwrap()
            .with_feature(NginxSiteFeature::StaticAssetCaching, true)
            .unwrap()
            .generate()
            .unwrap();
        let contents = generated.contents();

        assert_eq!(
            contents
                .matches("        try_files $uri $uri/ /index.html;")
                .count(),
            1
        );
        assert_eq!(
            contents
                .matches("        try_files $uri $uri/ =404;")
                .count(),
            1
        );
        assert_eq!(contents.matches("    location /assets/ {").count(), 1);
        assert_eq!(contents.matches("        expires 7d;").count(), 1);
        let assets = contents
            .split_once("    location /assets/ {")
            .unwrap()
            .1
            .split_once("    }")
            .unwrap()
            .0;
        assert!(assets.contains("try_files $uri $uri/ =404;"));
        assert!(!assets.contains("/index.html"));
        let main = contents.split_once("    location / {").unwrap().1;
        assert!(main.contains("try_files $uri $uri/ /index.html;"));
        validate_generated_document(contents).unwrap();
    }

    #[test]
    fn incompatible_features_and_fixed_location_conflicts_fail_closed() {
        assert!(
            static_config(false)
                .with_feature(NginxSiteFeature::SpaFallback, true)
                .is_err()
        );
        assert!(
            static_config(false)
                .with_feature(NginxSiteFeature::StaticTryFiles, false)
                .unwrap()
                .with_feature(NginxSiteFeature::SpaFallback, true)
                .unwrap()
                .with_feature(NginxSiteFeature::StaticTryFiles, true)
                .is_err()
        );
        assert!(
            static_config(false)
                .with_feature(NginxSiteFeature::WebSocketProxy, true)
                .is_err()
        );
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::Sendfile, true)
                .is_err()
        );
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::HttpsUpstreamSni, true)
                .is_err()
        );
        assert!(
            NginxSiteConfig::new(
                NginxServerNames::parse("api.example.com").unwrap(),
                NginxListenPort::parse("443").unwrap(),
                NginxSiteTarget::ReverseProxy(
                    NginxUpstream::parse("https://127.0.0.1:8443").unwrap(),
                ),
                false,
            )
            .unwrap()
            .with_feature(NginxSiteFeature::HttpsUpstreamSni, true)
            .is_err()
        );
        assert!(
            https_reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::HttpsUpstreamSni, true)
                .unwrap()
                .generate()
                .unwrap()
                .contents()
                .contains("proxy_ssl_server_name on;")
        );

        let assets_rule = NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse(STATIC_ASSET_LOCATION_PATH).unwrap(),
            NginxForbiddenPathScope::PathAndDescendants,
        )
        .unwrap();
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::StaticAssetCaching, true)
                .unwrap()
                .with_forbidden_path_rule(assets_rule)
                .is_err()
        );

        let websocket_rule = NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse(WEBSOCKET_LOCATION_PATH).unwrap(),
            NginxForbiddenPathScope::PathAndDescendants,
        )
        .unwrap();
        assert!(
            reverse_proxy_config(false)
                .with_forbidden_path_rule(websocket_rule)
                .unwrap()
                .with_feature(NginxSiteFeature::WebSocketProxy, true)
                .is_err()
        );

        let exact_assets = NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse(STATIC_ASSET_LOCATION_PATH).unwrap(),
            NginxForbiddenPathScope::Exact,
        )
        .unwrap();
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::StaticAssetCaching, true)
                .unwrap()
                .with_forbidden_path_rule(exact_assets)
                .unwrap()
                .generate()
                .is_ok()
        );

        for scope in [
            NginxForbiddenPathScope::Exact,
            NginxForbiddenPathScope::PathAndDescendants,
        ] {
            let health_rule = NginxForbiddenPathRule::new(
                NginxForbiddenPath::parse(HEALTH_CHECK_LOCATION_PATH).unwrap(),
                scope,
            )
            .unwrap();
            assert!(
                reverse_proxy_config(false)
                    .with_feature(NginxSiteFeature::HealthCheck, true)
                    .unwrap()
                    .with_forbidden_path_rule(health_rule)
                    .is_err()
            );

            let index_rule = NginxForbiddenPathRule::new(
                NginxForbiddenPath::parse(SPA_FALLBACK_PATH).unwrap(),
                scope,
            )
            .unwrap();
            assert!(
                static_config(false)
                    .with_feature(NginxSiteFeature::StaticTryFiles, false)
                    .unwrap()
                    .with_feature(NginxSiteFeature::SpaFallback, true)
                    .unwrap()
                    .with_forbidden_path_rule(index_rule)
                    .is_err()
            );
        }

        let spa_assets_rule = NginxForbiddenPathRule::new(
            NginxForbiddenPath::parse(STATIC_ASSET_LOCATION_PATH).unwrap(),
            NginxForbiddenPathScope::PathAndDescendants,
        )
        .unwrap();
        assert!(
            static_config(false)
                .with_feature(NginxSiteFeature::StaticTryFiles, false)
                .unwrap()
                .with_feature(NginxSiteFeature::SpaFallback, true)
                .unwrap()
                .with_forbidden_path_rule(spa_assets_rule)
                .is_err()
        );
    }

    #[test]
    fn parameterized_features_fail_closed_until_their_typed_rule_exists() {
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::ForbiddenPath403, true)
                .unwrap()
                .generate()
                .is_err()
        );
        assert!(
            reverse_proxy_config(false)
                .with_feature(NginxSiteFeature::RestrictSourceIp, true)
                .unwrap()
                .generate()
                .is_err()
        );
    }

    #[test]
    fn exact_dns_name_is_normalized_and_hostile_forms_are_rejected() {
        assert_eq!(
            NginxServerNames::parse("WWW.Example.COM").unwrap().as_str(),
            "www.example.com"
        );
        for invalid in [
            "",
            " example.com",
            "example.com ",
            "example.com.",
            ".example.com",
            "example..com",
            "-example.com",
            "example-.com",
            "127.0.0.1",
            "*.example.com",
            "_",
            "$hostname",
            "~^example",
            "example.com; include /etc/shadow",
            "example.com#comment",
            "例子.测试",
        ] {
            assert!(NginxServerNames::parse(invalid).is_err(), "{invalid:?}");
        }
        assert!(NginxServerNames::parse(&format!("{}.test", "a".repeat(64))).is_err());
        let oversized = vec!["a".repeat(63); 4].join(".");
        assert!(oversized.len() > 253);
        assert!(NginxServerNames::parse(&oversized).is_err());
    }

    #[test]
    fn listen_port_accepts_only_nonzero_u16_decimal() {
        assert_eq!(NginxListenPort::parse("1").unwrap().get(), 1);
        assert_eq!(NginxListenPort::parse("080").unwrap().get(), 80);
        assert_eq!(NginxListenPort::parse("65535").unwrap().get(), 65_535);
        for invalid in ["", "0", "65536", " 80", "80 ", "+80", "-1", "8x"] {
            assert!(NginxListenPort::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn static_root_has_both_posix_and_nginx_token_boundaries() {
        assert_eq!(
            NginxStaticRoot::parse("/var/www/site-1_html")
                .unwrap()
                .as_str(),
            "/var/www/site-1_html"
        );
        for invalid in [
            "",
            "/",
            "var/www",
            "/var/www/",
            "/var//www",
            "/var/www/../etc",
            "/var/www/./site",
            "/var\\www",
            "/var/www/site name",
            "/var/www/$root",
            "/var/www/site;include",
            "/var/www/site#comment",
            "/var/www/\"site\"",
            "/var/www/{site}",
            "/var/www/站点",
        ] {
            assert!(NginxStaticRoot::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn upstream_is_an_origin_only_and_is_canonicalized() {
        assert!(
            NginxUpstream::parse("https://Backend.Example:8443")
                .unwrap()
                .supports_https_sni()
        );
        assert!(
            !NginxUpstream::parse("http://backend.example:8080")
                .unwrap()
                .supports_https_sni()
        );
        assert!(
            !NginxUpstream::parse("https://127.0.0.1:8443")
                .unwrap()
                .supports_https_sni()
        );
        assert_eq!(
            NginxUpstream::parse("HTTP://Backend.Example:8080/")
                .unwrap()
                .as_str(),
            "http://backend.example:8080"
        );
        assert_eq!(
            NginxUpstream::parse("http://127.0.0.1:3000")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            NginxUpstream::parse("http://[::1]:8080").unwrap().as_str(),
            "http://[::1]:8080"
        );
        for invalid in [
            "",
            "backend.example:8080",
            "ftp://backend.example",
            "http://user@backend.example",
            "http://user:secret@backend.example",
            "http://backend.example/api",
            "http://backend.example/?debug=1",
            "http://backend.example/#fragment",
            "http://backend.example:0",
            "http://0.0.0.0:8080",
            "http://[::]:8080",
            "http://backend.example;include",
            " http://backend.example",
            "http:\\backend.example",
            "http://例子.测试",
        ] {
            assert!(NginxUpstream::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn generated_output_is_a_complete_bounded_nginx_document() {
        for config in [static_config(true), reverse_proxy_config(false)] {
            let generated = config.generate().unwrap();
            assert!(!generated.contents().contains('\r'));
            assert!(generated.contents().ends_with('\n'));
            validate_generated_document(generated.contents()).unwrap();
        }
    }

    #[test]
    fn write_new_saves_exact_bytes_and_never_overwrites() {
        let root = TestRoot::new();
        let generated = static_config(true).generate().unwrap();
        let destination = root.0.join("site.conf");
        assert_eq!(generated.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );

        fs::write(&destination, b"existing sentinel").unwrap();
        assert!(generated.write_new(&destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"existing sentinel");
    }

    #[test]
    fn write_new_rejects_untrusted_destination_shapes() {
        let root = TestRoot::new();
        let generated = reverse_proxy_config(false).generate().unwrap();
        assert!(generated.write_new(Path::new("relative.conf")).is_err());
        assert!(generated.write_new(&root.0.join("site.txt")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("site.conf"))
                .is_err()
        );
    }
}
