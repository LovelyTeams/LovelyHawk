//! Deterministic generation of bounded Apache HTTP Server 2.4 site snippets.
//!
//! User-provided values cross typed validation boundaries before rendering.
//! Generated files are top-level server-configuration includes, never
//! `.htaccess` files. They remain local drafts until the exact target runtime,
//! module inventory, complete include graph, `httpd -t`, and request behavior
//! have been independently verified.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Component, Path, PathBuf},
};

use url::{Host, Url};

use crate::{CoreError, CoreResult, apache_visual::ApacheVisualDocument, sftp::RemotePath};

pub const MAX_GENERATED_APACHE_CONFIG_BYTES: usize = 32 * 1024;
const MAX_UPSTREAM_BYTES: usize = 2_048;
const MAX_FORBIDDEN_PATH_BYTES: usize = 512;
const SUGGESTED_FILE_NAME: &str = "apache-site.conf";
const STATIC_ASSET_PATH: &str = "/assets";
const SPA_FALLBACK_PATH: &str = "/index.html";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheSiteKind {
    Static,
    ReverseProxy,
}

impl ApacheSiteKind {
    pub const ALL: [Self; 2] = [Self::Static, Self::ReverseProxy];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Static => "静态站点",
            Self::ReverseProxy => "反向代理",
        }
    }

    /// Modules required by the immutable target skeleton before optional
    /// features are composed. Deployments must still validate the exact module
    /// inventory with the target's own `httpd` binary.
    pub const fn baseline_required_modules(self) -> &'static [&'static str] {
        match self {
            Self::Static => &["authz_core_module"],
            Self::ReverseProxy => &["proxy_module", "proxy_http_module"],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApacheSiteFeature {
    ForbiddenPath403,
    SecurityHeaders,
    DisableDirectoryListing,
    DisableHtaccessOverrides,
    RestrictRequestMethods,
    ReduceVersionDisclosure,
    DisableTrace,
    RestrictSourceIp,
    GzipCompression,
    StaticAssetCaching,
    DenyHiddenPaths,
    DenySensitiveFiles,
    ClientBodyLimit,
    KeepaliveTuning,
    Utf8Charset,
    IndexFiles,
    Sendfile,
    ProxyTimeouts,
    PreserveOriginalHost,
    SpaFallback,
    RequestReadTimeouts,
    LimitRangeRequests,
}

impl ApacheSiteFeature {
    pub const ALL: [Self; 22] = [
        Self::ForbiddenPath403,
        Self::SecurityHeaders,
        Self::DisableDirectoryListing,
        Self::DisableHtaccessOverrides,
        Self::RestrictRequestMethods,
        Self::ReduceVersionDisclosure,
        Self::DisableTrace,
        Self::RestrictSourceIp,
        Self::GzipCompression,
        Self::StaticAssetCaching,
        Self::DenyHiddenPaths,
        Self::DenySensitiveFiles,
        Self::ClientBodyLimit,
        Self::KeepaliveTuning,
        Self::Utf8Charset,
        Self::IndexFiles,
        Self::Sendfile,
        Self::ProxyTimeouts,
        Self::PreserveOriginalHost,
        Self::SpaFallback,
        Self::RequestReadTimeouts,
        Self::LimitRangeRequests,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 => "forbidden-path-403",
            Self::SecurityHeaders => "security-headers",
            Self::DisableDirectoryListing => "disable-directory-listing",
            Self::DisableHtaccessOverrides => "disable-htaccess-overrides",
            Self::RestrictRequestMethods => "restrict-request-methods",
            Self::ReduceVersionDisclosure => "reduce-version-disclosure",
            Self::DisableTrace => "disable-trace",
            Self::RestrictSourceIp => "restrict-source-ip",
            Self::GzipCompression => "gzip-compression",
            Self::StaticAssetCaching => "static-asset-caching",
            Self::DenyHiddenPaths => "deny-hidden-paths",
            Self::DenySensitiveFiles => "deny-sensitive-files",
            Self::ClientBodyLimit => "client-body-limit",
            Self::KeepaliveTuning => "keepalive-tuning",
            Self::Utf8Charset => "utf8-charset",
            Self::IndexFiles => "index-files",
            Self::Sendfile => "sendfile",
            Self::ProxyTimeouts => "proxy-timeouts",
            Self::PreserveOriginalHost => "preserve-original-host",
            Self::SpaFallback => "spa-fallback",
            Self::RequestReadTimeouts => "request-read-timeouts",
            Self::LimitRangeRequests => "limit-range-requests",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 => "禁止指定路径（HTTP 403）",
            Self::SecurityHeaders => "添加安全响应头",
            Self::DisableDirectoryListing => "关闭目录浏览",
            Self::DisableHtaccessOverrides => "禁用 .htaccess 覆盖",
            Self::RestrictRequestMethods => "限制请求方法",
            Self::ReduceVersionDisclosure => "减少版本信息暴露",
            Self::DisableTrace => "禁用 TRACE 方法",
            Self::RestrictSourceIp => "限制访问来源 IP",
            Self::GzipCompression => "启用 Gzip 压缩",
            Self::StaticAssetCaching => "配置静态资源缓存",
            Self::DenyHiddenPaths => "拒绝隐藏路径",
            Self::DenySensitiveFiles => "拒绝敏感与备份文件",
            Self::ClientBodyLimit => "限制请求体大小",
            Self::KeepaliveTuning => "配置 KeepAlive",
            Self::Utf8Charset => "声明 UTF-8 字符集",
            Self::IndexFiles => "配置默认首页",
            Self::Sendfile => "启用 Sendfile",
            Self::ProxyTimeouts => "配置代理超时",
            Self::PreserveOriginalHost => "向上游保留原始 Host",
            Self::SpaFallback => "启用 SPA 路由回退",
            Self::RequestReadTimeouts => "限制请求读取时间",
            Self::LimitRangeRequests => "限制多段 Range 请求",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ForbiddenPath403 => "拒绝访问指定规范 URI 路径及其可选子路径。",
            Self::SecurityHeaders => "覆盖三项固定浏览器安全响应头；应用仍需独立验证兼容性。",
            Self::DisableDirectoryListing => "从站点目录选项中移除 Indexes，避免目录内容被列出。",
            Self::DisableHtaccessOverrides => {
                "站点目录不读取分布式 .htaccess 覆盖，配置集中在服务器文件。"
            }
            Self::RestrictRequestMethods => "站点仅允许 GET 和 HEAD；必须同时保持 TRACE 已禁用。",
            Self::ReduceVersionDisclosure => {
                "仅保留 Apache 产品标识并关闭服务器生成页面的签名，不是独立安全控制。"
            }
            Self::DisableTrace => "让 Apache core 与代理对 TRACE 返回 HTTP 405。",
            Self::RestrictSourceIp => "整个生成站点只允许一个规范 IP 地址或 CIDR 来源。",
            Self::GzipCompression => {
                "为固定文本 MIME 类型启用 DEFLATE；TLS 敏感响应仍需评估压缩侧信道风险。"
            }
            Self::StaticAssetCaching => "为固定的 /assets/ 文件目录生成七天 Expires 缓存策略。",
            Self::DenyHiddenPaths => "拒绝 URI 中的隐藏路径段，同时保留标准 .well-known 入口。",
            Self::DenySensitiveFiles => "拒绝常见配置、日志、备份和临时文件后缀。",
            Self::ClientBodyLimit => "将客户端请求体上限固定为 10 MiB。",
            Self::KeepaliveTuning => "显式启用持久连接并设置固定请求数与空闲时间。",
            Self::Utf8Charset => {
                "为站点文本响应添加 UTF-8 默认字符集；仅适用于内容确为 UTF-8 的站点。"
            }
            Self::IndexFiles => "按固定顺序查找 index.html 和 index.htm。",
            Self::Sendfile => "允许内核 Sendfile 发送静态文件；网络文件系统和异常平台需谨慎启用。",
            Self::ProxyTimeouts => "把反向代理连接超时固定为 5 秒、I/O 超时固定为 60 秒。",
            Self::PreserveOriginalHost => {
                "把客户端 Host 原样传给上游；仅在上游明确依赖该主机名时启用。"
            }
            Self::SpaFallback => "静态文件不存在时回退到 /index.html，/assets/ 仍保持 404。",
            Self::RequestReadTimeouts => "为请求头和请求体设置最短速率及有界读取时间。",
            Self::LimitRangeRequests => "静态响应最多处理一个字节范围，超出时返回完整资源。",
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::ReduceVersionDisclosure => "全局/虚拟主机",
            Self::ForbiddenPath403
            | Self::RestrictRequestMethods
            | Self::RestrictSourceIp
            | Self::DenyHiddenPaths => "Location",
            Self::DisableDirectoryListing
            | Self::DisableHtaccessOverrides
            | Self::StaticAssetCaching
            | Self::DenySensitiveFiles
            | Self::Utf8Charset
            | Self::IndexFiles
            | Self::Sendfile
            | Self::SpaFallback
            | Self::LimitRangeRequests => "Directory",
            Self::SecurityHeaders
            | Self::DisableTrace
            | Self::GzipCompression
            | Self::ClientBodyLimit
            | Self::KeepaliveTuning
            | Self::RequestReadTimeouts => "虚拟主机",
            Self::ProxyTimeouts | Self::PreserveOriginalHost => "反向代理",
        }
    }

    pub const fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::SecurityHeaders
                | Self::DisableDirectoryListing
                | Self::DisableHtaccessOverrides
                | Self::ReduceVersionDisclosure
                | Self::DisableTrace
                | Self::IndexFiles
        )
    }

    pub const fn supports_kind(self, kind: ApacheSiteKind) -> bool {
        match self {
            Self::DisableDirectoryListing
            | Self::DisableHtaccessOverrides
            | Self::StaticAssetCaching
            | Self::DenySensitiveFiles
            | Self::Utf8Charset
            | Self::IndexFiles
            | Self::Sendfile
            | Self::SpaFallback
            | Self::LimitRangeRequests => matches!(kind, ApacheSiteKind::Static),
            Self::ProxyTimeouts | Self::PreserveOriginalHost => {
                matches!(kind, ApacheSiteKind::ReverseProxy)
            }
            Self::ForbiddenPath403
            | Self::SecurityHeaders
            | Self::RestrictRequestMethods
            | Self::ReduceVersionDisclosure
            | Self::DisableTrace
            | Self::RestrictSourceIp
            | Self::GzipCompression
            | Self::DenyHiddenPaths
            | Self::ClientBodyLimit
            | Self::KeepaliveTuning
            | Self::RequestReadTimeouts => true,
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::ForbiddenPath403 => &["403", "禁止路径", "Require all denied", "LocationMatch"],
            Self::SecurityHeaders => &["安全响应头", "mod_headers", "nosniff", "X-Frame-Options"],
            Self::DisableDirectoryListing => &["目录浏览", "Options -Indexes", "autoindex"],
            Self::DisableHtaccessOverrides => &["htaccess", "AllowOverride None", "覆盖配置"],
            Self::RestrictRequestMethods => &["请求方法", "GET HEAD", "Require method", "405"],
            Self::ReduceVersionDisclosure => {
                &["隐藏版本", "ServerTokens Prod", "ServerSignature Off"]
            }
            Self::DisableTrace => &["TRACE", "TraceEnable Off", "关闭 trace", "405"],
            Self::RestrictSourceIp => &["来源 IP", "CIDR", "Require ip", "访问来源"],
            Self::GzipCompression => &["gzip", "DEFLATE", "mod_deflate", "压缩"],
            Self::StaticAssetCaching => &["静态缓存", "assets", "ExpiresActive", "七天缓存"],
            Self::DenyHiddenPaths => &["隐藏路径", "dotfiles", ".git", ".well-known"],
            Self::DenySensitiveFiles => &["敏感文件", "备份文件", "FilesMatch", "bak"],
            Self::ClientBodyLimit => &["请求体", "上传大小", "LimitRequestBody", "10 MiB"],
            Self::KeepaliveTuning => &["KeepAlive", "长连接", "MaxKeepAliveRequests"],
            Self::Utf8Charset => &["UTF-8", "AddDefaultCharset", "字符集"],
            Self::IndexFiles => &["DirectoryIndex", "默认首页", "index.html"],
            Self::Sendfile => &["EnableSendfile", "零拷贝", "静态性能"],
            Self::ProxyTimeouts => &["代理超时", "connectiontimeout", "ProxyPass timeout"],
            Self::PreserveOriginalHost => &["ProxyPreserveHost", "原始 Host", "上游主机名"],
            Self::SpaFallback => &["SPA", "FallbackResource", "单页应用", "前端路由"],
            Self::RequestReadTimeouts => &["RequestReadTimeout", "Slowloris", "读取超时"],
            Self::LimitRangeRequests => &["Range", "MaxRanges", "分段下载", "字节范围"],
        }
    }

    pub const fn required_modules(self) -> &'static [&'static str] {
        match self {
            Self::ForbiddenPath403 | Self::DenyHiddenPaths | Self::DenySensitiveFiles => {
                &["authz_core_module"]
            }
            Self::SecurityHeaders => &["headers_module"],
            Self::RestrictRequestMethods => &["authz_core_module"],
            Self::RestrictSourceIp => &["authz_core_module", "authz_host_module"],
            Self::GzipCompression => &["filter_module", "deflate_module"],
            Self::StaticAssetCaching => &["expires_module"],
            Self::IndexFiles | Self::SpaFallback => &["dir_module"],
            Self::ProxyTimeouts | Self::PreserveOriginalHost => {
                &["proxy_module", "proxy_http_module"]
            }
            Self::RequestReadTimeouts => &["reqtimeout_module"],
            Self::DisableDirectoryListing
            | Self::DisableHtaccessOverrides
            | Self::ReduceVersionDisclosure
            | Self::DisableTrace
            | Self::ClientBodyLimit
            | Self::KeepaliveTuning
            | Self::Utf8Charset
            | Self::Sendfile
            | Self::LimitRangeRequests => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApacheServerName(String);

impl ApacheServerName {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value != value.trim() {
            return Err(CoreError::validation(
                "Apache server name",
                "must not contain leading or trailing whitespace",
            ));
        }
        if value.parse::<IpAddr>().is_ok() {
            return Err(CoreError::validation(
                "Apache server name",
                "the first generator version requires one exact DNS name, not an IP literal",
            ));
        }
        Ok(Self(normalize_dns_name("Apache server name", value)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let normalized = normalize_dns_name("Apache server name", &self.0)?;
        if normalized != self.0 {
            return Err(CoreError::validation(
                "Apache server name",
                "stored server name is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApacheListenPort(u16);

impl ApacheListenPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty() || value.len() > 5 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CoreError::validation(
                "Apache virtual-host port",
                "must contain only decimal digits in 1..=65535",
            ));
        }
        let port = value.parse::<u16>().map_err(|_| {
            CoreError::validation("Apache virtual-host port", "must be in 1..=65535")
        })?;
        if port == 0 {
            return Err(CoreError::validation(
                "Apache virtual-host port",
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
                "Apache virtual-host port",
                "must be in 1..=65535",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApacheForbiddenPath(String);

impl ApacheForbiddenPath {
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
                "Apache forbidden path",
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
                "Apache forbidden path",
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
                "Apache forbidden path",
                "stored path is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApacheForbiddenPathScope {
    Exact,
    PathAndDescendants,
}

impl ApacheForbiddenPathScope {
    pub const ALL: [Self; 2] = [Self::Exact, Self::PathAndDescendants];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "仅此路径",
            Self::PathAndDescendants => "此路径及子路径",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApacheForbiddenPathRule {
    path: ApacheForbiddenPath,
    scope: ApacheForbiddenPathScope,
}

impl ApacheForbiddenPathRule {
    pub fn new(path: ApacheForbiddenPath, scope: ApacheForbiddenPathScope) -> CoreResult<Self> {
        path.validate()?;
        Ok(Self { path, scope })
    }

    pub fn path(&self) -> &ApacheForbiddenPath {
        &self.path
    }

    pub const fn scope(&self) -> ApacheForbiddenPathScope {
        self.scope
    }

    fn validate(&self) -> CoreResult<()> {
        self.path.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApacheAllowedSource(String);

impl ApacheAllowedSource {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value != value.trim()
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "Apache allowed source",
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
                    "Apache allowed source",
                    "CIDR must contain one IP address and one decimal prefix length",
                ));
            }
            let address = address.parse::<IpAddr>().map_err(|_| {
                CoreError::validation("Apache allowed source", "CIDR address is invalid")
            })?;
            let prefix = prefix.parse::<u8>().map_err(|_| {
                CoreError::validation("Apache allowed source", "CIDR prefix length is invalid")
            })?;
            let network = canonical_cidr_network(address, prefix)?;
            format!("{network}/{prefix}")
        } else {
            value
                .parse::<IpAddr>()
                .map_err(|_| {
                    CoreError::validation(
                        "Apache allowed source",
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
                "Apache allowed source",
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
            "Apache allowed source",
            "CIDR prefix exceeds the address family width",
        )),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApacheStaticRoot(RemotePath);

impl ApacheStaticRoot {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value != value.trim() {
            return Err(CoreError::validation(
                "Apache static root",
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApacheUpstream(String);

impl ApacheUpstream {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value.len() > MAX_UPSTREAM_BYTES
            || value != value.trim()
            || !value.is_ascii()
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "Apache upstream",
                "must be a bounded ASCII HTTP origin without whitespace, controls, or backslashes",
            ));
        }
        let parsed = Url::parse(value)
            .map_err(|error| CoreError::validation("Apache upstream", error.to_string()))?;
        if parsed.scheme() != "http" {
            return Err(CoreError::validation(
                "Apache upstream",
                "the first generator version supports only http:// origins; HTTPS requires an explicit trusted CA contract",
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(CoreError::validation(
                "Apache upstream",
                "embedded credentials are forbidden",
            ));
        }
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(CoreError::validation(
                "Apache upstream",
                "must be an origin only, without a path, query, or fragment",
            ));
        }
        let host = parsed
            .host()
            .ok_or_else(|| CoreError::validation("Apache upstream", "host is required"))?;
        let host = match host {
            Host::Domain(domain) => normalize_dns_name("Apache upstream host", domain)?,
            Host::Ipv4(address) => {
                if address.is_unspecified() {
                    return Err(CoreError::validation(
                        "Apache upstream host",
                        "an unspecified IP address cannot be used as a proxy destination",
                    ));
                }
                address.to_string()
            }
            Host::Ipv6(address) => {
                if address.is_unspecified() {
                    return Err(CoreError::validation(
                        "Apache upstream host",
                        "an unspecified IP address cannot be used as a proxy destination",
                    ));
                }
                format!("[{address}]")
            }
        };
        let port = parsed.port();
        if port == Some(0) {
            return Err(CoreError::validation(
                "Apache upstream port",
                "must be in 1..=65535",
            ));
        }
        let origin = port.map_or_else(
            || format!("http://{host}"),
            |port| format!("http://{host}:{port}"),
        );
        if origin.len() > MAX_UPSTREAM_BYTES {
            return Err(CoreError::validation(
                "Apache upstream",
                "normalized origin exceeds the bounded limit",
            ));
        }
        Ok(Self(origin))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let normalized = Self::parse(&self.0)?;
        if normalized != *self {
            return Err(CoreError::validation(
                "Apache upstream",
                "stored upstream is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApacheSiteTarget {
    Static(ApacheStaticRoot),
    ReverseProxy(ApacheUpstream),
}

impl ApacheSiteTarget {
    pub const fn kind(&self) -> ApacheSiteKind {
        match self {
            Self::Static(_) => ApacheSiteKind::Static,
            Self::ReverseProxy(_) => ApacheSiteKind::ReverseProxy,
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
pub struct ApacheSiteConfig {
    name: ApacheServerName,
    port: ApacheListenPort,
    target: ApacheSiteTarget,
    features: BTreeSet<ApacheSiteFeature>,
    forbidden_path_rule: Option<ApacheForbiddenPathRule>,
    allowed_source_rule: Option<ApacheAllowedSource>,
}

impl ApacheSiteConfig {
    pub fn new(
        name: ApacheServerName,
        port: ApacheListenPort,
        target: ApacheSiteTarget,
        security_headers: bool,
    ) -> CoreResult<Self> {
        name.validate()?;
        port.validate()?;
        target.validate()?;

        let kind = target.kind();
        let mut features = ApacheSiteFeature::ALL
            .into_iter()
            .filter(|feature| feature.default_enabled() && feature.supports_kind(kind))
            .collect::<BTreeSet<_>>();
        if !security_headers {
            features.remove(&ApacheSiteFeature::SecurityHeaders);
        }

        let config = Self {
            name,
            port,
            target,
            features,
            forbidden_path_rule: None,
            allowed_source_rule: None,
        };
        config.validate_feature_compatibility()?;
        Ok(config)
    }

    pub fn with_forbidden_path_rule(mut self, rule: ApacheForbiddenPathRule) -> CoreResult<Self> {
        rule.validate()?;
        self.forbidden_path_rule = Some(rule);
        self.features.insert(ApacheSiteFeature::ForbiddenPath403);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_allowed_source_rule(mut self, source: ApacheAllowedSource) -> CoreResult<Self> {
        source.validate()?;
        self.allowed_source_rule = Some(source);
        self.features.insert(ApacheSiteFeature::RestrictSourceIp);
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub fn with_feature(mut self, feature: ApacheSiteFeature, enabled: bool) -> CoreResult<Self> {
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate_feature_compatibility()?;
        Ok(self)
    }

    pub const fn kind(&self) -> ApacheSiteKind {
        self.target.kind()
    }

    pub fn name(&self) -> &ApacheServerName {
        &self.name
    }

    pub const fn port(&self) -> ApacheListenPort {
        self.port
    }

    pub fn target(&self) -> &ApacheSiteTarget {
        &self.target
    }

    pub fn security_headers(&self) -> bool {
        self.feature_enabled(ApacheSiteFeature::SecurityHeaders)
    }

    pub fn feature_enabled(&self, feature: ApacheSiteFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn forbidden_path_rule(&self) -> Option<&ApacheForbiddenPathRule> {
        self.forbidden_path_rule.as_ref()
    }

    pub fn allowed_source_rule(&self) -> Option<&ApacheAllowedSource> {
        self.allowed_source_rule.as_ref()
    }

    pub fn generate(&self) -> CoreResult<GeneratedApacheConfig> {
        self.name.validate()?;
        self.port.validate()?;
        self.target.validate()?;
        if let Some(rule) = &self.forbidden_path_rule {
            rule.validate()?;
        }
        if let Some(source) = &self.allowed_source_rule {
            source.validate()?;
        }
        self.validate_features()?;

        let mut contents = String::with_capacity(4_096);
        if self.feature_enabled(ApacheSiteFeature::ReduceVersionDisclosure) {
            contents.push_str("ServerTokens Prod\nServerSignature Off\n\n");
        }

        contents.push_str("<VirtualHost *:");
        contents.push_str(&self.port.get().to_string());
        contents.push_str(">\n    ServerName ");
        contents.push_str(self.name.as_str());

        if self.feature_enabled(ApacheSiteFeature::DisableTrace) {
            contents.push_str("\n\n    TraceEnable Off");
        }

        if self.feature_enabled(ApacheSiteFeature::SecurityHeaders) {
            contents.push_str(
                "\n\n    Header onsuccess unset X-Content-Type-Options\n    Header always set X-Content-Type-Options \"nosniff\"\n    Header onsuccess unset X-Frame-Options\n    Header always set X-Frame-Options \"SAMEORIGIN\"\n    Header onsuccess unset Referrer-Policy\n    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            );
        }

        if self.feature_enabled(ApacheSiteFeature::GzipCompression) {
            contents.push_str(
                "\n\n    AddOutputFilterByType DEFLATE text/plain text/html text/css application/json application/javascript application/xml image/svg+xml",
            );
        }

        if self.feature_enabled(ApacheSiteFeature::ClientBodyLimit) {
            contents.push_str("\n\n    LimitRequestBody 10485760");
        }

        if self.feature_enabled(ApacheSiteFeature::KeepaliveTuning) {
            contents.push_str(
                "\n\n    KeepAlive On\n    MaxKeepAliveRequests 1000\n    KeepAliveTimeout 5",
            );
        }

        if self.feature_enabled(ApacheSiteFeature::RequestReadTimeouts) {
            contents.push_str(
                "\n\n    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500",
            );
        }

        if self.feature_enabled(ApacheSiteFeature::Utf8Charset) {
            contents.push_str("\n\n    AddDefaultCharset UTF-8");
        }

        match &self.target {
            ApacheSiteTarget::Static(root) => self.push_static_target(&mut contents, root),
            ApacheSiteTarget::ReverseProxy(upstream) => {
                self.push_reverse_proxy_target(&mut contents, upstream)
            }
        }

        self.push_access_controls(&mut contents);
        contents.push_str("\n</VirtualHost>\n");

        validate_generated_document(&contents)?;
        Ok(GeneratedApacheConfig { contents })
    }

    fn push_static_target(&self, contents: &mut String, root: &ApacheStaticRoot) {
        contents.push_str("\n\n    DocumentRoot \"");
        contents.push_str(root.as_str());
        contents.push_str("\"\n\n    <Directory \"");
        contents.push_str(root.as_str());
        contents.push_str("\">\n        Options -ExecCGI");
        if self.feature_enabled(ApacheSiteFeature::DisableDirectoryListing) {
            contents.push_str(" -Indexes");
        }
        if self.feature_enabled(ApacheSiteFeature::DisableHtaccessOverrides) {
            contents.push_str("\n        AllowOverride None");
        }
        contents.push_str("\n        Require all granted");
        if self.feature_enabled(ApacheSiteFeature::IndexFiles) {
            contents.push_str(
                "\n        DirectoryIndex disabled\n        DirectoryIndex index.html index.htm",
            );
        }
        if self.feature_enabled(ApacheSiteFeature::SpaFallback) {
            contents.push_str("\n        FallbackResource /index.html");
        }
        if self.feature_enabled(ApacheSiteFeature::Sendfile) {
            contents.push_str("\n        EnableSendfile On");
        }
        if self.feature_enabled(ApacheSiteFeature::LimitRangeRequests) {
            contents.push_str("\n        MaxRanges 1");
        }
        contents.push_str("\n    </Directory>");

        if self.feature_enabled(ApacheSiteFeature::StaticAssetCaching)
            || self.feature_enabled(ApacheSiteFeature::SpaFallback)
        {
            contents.push_str("\n\n    <Directory \"");
            contents.push_str(root.as_str());
            contents.push_str("/assets\">");
            if self.feature_enabled(ApacheSiteFeature::SpaFallback) {
                contents.push_str("\n        FallbackResource disabled");
            }
            if self.feature_enabled(ApacheSiteFeature::StaticAssetCaching) {
                contents.push_str(
                    "\n        ExpiresActive On\n        ExpiresDefault \"access plus 7 days\"",
                );
            }
            contents.push_str("\n    </Directory>");
        }

        if self.feature_enabled(ApacheSiteFeature::DenySensitiveFiles) {
            contents.push_str(
                "\n\n    <FilesMatch \"(?i)\\.(?:bak|conf|dist|env|ini|log|old|orig|save|sql|swp|tmp)$\">\n        Require all denied\n    </FilesMatch>",
            );
        }
    }

    fn push_reverse_proxy_target(&self, contents: &mut String, upstream: &ApacheUpstream) {
        contents.push_str("\n\n    ProxyRequests Off\n    ProxyPreserveHost ");
        contents.push_str(
            if self.feature_enabled(ApacheSiteFeature::PreserveOriginalHost) {
                "On"
            } else {
                "Off"
            },
        );
        contents.push_str("\n    ProxyPass \"/\" \"");
        contents.push_str(upstream.as_str());
        contents.push('/');
        contents.push('"');
        if self.feature_enabled(ApacheSiteFeature::ProxyTimeouts) {
            contents.push_str(" connectiontimeout=5 timeout=60");
        }
        contents.push_str("\n    ProxyPassReverse \"/\" \"");
        contents.push_str(upstream.as_str());
        contents.push_str("/\"");
    }

    fn push_access_controls(&self, contents: &mut String) {
        let restrict_methods = self.feature_enabled(ApacheSiteFeature::RestrictRequestMethods);
        let allowed_source = self
            .feature_enabled(ApacheSiteFeature::RestrictSourceIp)
            .then_some(self.allowed_source_rule.as_ref())
            .flatten();
        if restrict_methods || allowed_source.is_some() {
            contents.push_str("\n\n    <Location \"/\">");
            match (restrict_methods, allowed_source) {
                (true, Some(source)) => {
                    // Apache combines sibling `Require` directives as an implicit
                    // `RequireAny`. Keep method and source restrictions inside an
                    // explicit conjunction so an allowed IP cannot bypass the
                    // method allowlist.
                    contents.push_str(
                        "\n        <RequireAll>\n            Require method GET HEAD\n            Require ip ",
                    );
                    contents.push_str(source.as_str());
                    contents.push_str("\n        </RequireAll>");
                }
                (true, None) => contents.push_str("\n        Require method GET HEAD"),
                (false, Some(source)) => {
                    contents.push_str("\n        Require ip ");
                    contents.push_str(source.as_str());
                }
                (false, None) => unreachable!("access control presence was checked"),
            }
            contents.push_str("\n    </Location>");
        }

        if self.feature_enabled(ApacheSiteFeature::DenyHiddenPaths) {
            contents.push_str(
                "\n\n    <LocationMatch \"(^|/)\\.(?!well-known(?:/|$))\">\n        Require all denied\n    </LocationMatch>",
            );
        }

        if self.feature_enabled(ApacheSiteFeature::ForbiddenPath403) {
            let rule = self
                .forbidden_path_rule
                .as_ref()
                .expect("feature completeness was validated");
            contents.push_str("\n\n    <LocationMatch \"");
            contents.push('^');
            push_apache_regex_literal(contents, rule.path().as_str());
            if rule.scope() == ApacheForbiddenPathScope::PathAndDescendants {
                contents.push_str("(?:/.*)?");
            }
            contents.push_str("$\">\n        Require all denied\n    </LocationMatch>");
        }
    }

    fn validate_features(&self) -> CoreResult<()> {
        self.validate_feature_compatibility()?;
        if self.feature_enabled(ApacheSiteFeature::ForbiddenPath403)
            && self.forbidden_path_rule.is_none()
        {
            return Err(CoreError::validation(
                "Apache forbidden path feature",
                "requires one validated forbidden path rule",
            ));
        }
        if self.feature_enabled(ApacheSiteFeature::RestrictSourceIp)
            && self.allowed_source_rule.is_none()
        {
            return Err(CoreError::validation(
                "Apache source restriction feature",
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
                "Apache site feature",
                format!(
                    "{} is not available for the {} baseline",
                    feature.title(),
                    self.kind().label()
                ),
            ));
        }
        if self.feature_enabled(ApacheSiteFeature::RestrictRequestMethods)
            && !self.feature_enabled(ApacheSiteFeature::DisableTrace)
        {
            return Err(CoreError::validation(
                "Apache request method features",
                format!(
                    "{} requires {} so TRACE keeps the Baseline's explicit 405 behavior",
                    ApacheSiteFeature::RestrictRequestMethods.title(),
                    ApacheSiteFeature::DisableTrace.title()
                ),
            ));
        }
        if !self.feature_enabled(ApacheSiteFeature::ForbiddenPath403) {
            return Ok(());
        }
        let Some(rule) = self.forbidden_path_rule.as_ref() else {
            return Ok(());
        };
        if self.feature_enabled(ApacheSiteFeature::SpaFallback)
            && rule.path().as_str() == SPA_FALLBACK_PATH
        {
            return Err(CoreError::validation(
                "Apache feature paths",
                format!(
                    "forbidden path {SPA_FALLBACK_PATH} conflicts with the fixed {} target",
                    ApacheSiteFeature::SpaFallback.title()
                ),
            ));
        }
        if rule.scope() == ApacheForbiddenPathScope::PathAndDescendants
            && rule.path().as_str() == STATIC_ASSET_PATH
            && (self.feature_enabled(ApacheSiteFeature::StaticAssetCaching)
                || self.feature_enabled(ApacheSiteFeature::SpaFallback))
        {
            return Err(CoreError::validation(
                "Apache feature paths",
                "forbidden descendants for /assets/ conflict with the generated static asset directory",
            ));
        }
        Ok(())
    }
}

fn push_apache_regex_literal(contents: &mut String, path: &str) {
    for character in path.chars() {
        if character == '.' {
            contents.push_str("\\.");
        } else {
            contents.push(character);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedApacheConfig {
    contents: String,
}

impl GeneratedApacheConfig {
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
                CoreError::io("create generated Apache configuration", destination, source)
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io("write generated Apache configuration", destination, source)
            })?;
            file.flush().map_err(|source| {
                CoreError::io("flush generated Apache configuration", destination, source)
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io("sync generated Apache configuration", destination, source)
            })
        })();
        drop(file);

        if let Err(error) = write_result {
            if let Err(cleanup_error) = fs::remove_file(destination) {
                tracing::error!(
                    error = %cleanup_error,
                    "failed to remove partial generated Apache configuration"
                );
            }
            return Err(error);
        }
        Ok(destination.to_path_buf())
    }
}

fn normalize_dns_name(subject: &'static str, value: &str) -> CoreResult<String> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
    {
        return Err(CoreError::validation(
            subject,
            "must be one bounded absolute DNS spelling without a trailing dot",
        ));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
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
            "Apache static root",
            "refuses to expose the remote filesystem root",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(CoreError::validation(
            "Apache static root",
            "must contain only ASCII letters, digits, slash, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

fn validate_generated_document(contents: &str) -> CoreResult<()> {
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_APACHE_CONFIG_BYTES
        || contents.contains('\0')
        || contents.contains('\r')
        || !contents.ends_with('\n')
    {
        return Err(CoreError::validation(
            "generated Apache configuration",
            format!(
                "must be non-empty LF-only UTF-8 with a terminal newline and at most {MAX_GENERATED_APACHE_CONFIG_BYTES} bytes"
            ),
        ));
    }
    let document = ApacheVisualDocument::parse(contents).map_err(|error| {
        CoreError::validation("generated Apache configuration", error.to_string())
    })?;
    if !document.is_structured()
        || document.has_opaque_regions()
        || document.contains_sensitive_values()
        || document.raw_bytes() != contents.as_bytes()
    {
        return Err(CoreError::validation(
            "generated Apache configuration",
            "closed template did not round-trip as one safe structured Apache document",
        ));
    }
    Ok(())
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated Apache configuration destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated Apache configuration destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
    {
        return Err(CoreError::validation(
            "generated Apache configuration destination",
            "must use the .conf extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated Apache configuration destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated Apache configuration destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("lovelyres-apache-config-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn static_config(security_headers: bool) -> ApacheSiteConfig {
        ApacheSiteConfig::new(
            ApacheServerName::parse("Example.COM").unwrap(),
            ApacheListenPort::parse("8080").unwrap(),
            ApacheSiteTarget::Static(ApacheStaticRoot::parse("/srv/www/example").unwrap()),
            security_headers,
        )
        .unwrap()
    }

    fn reverse_proxy_config(security_headers: bool) -> ApacheSiteConfig {
        ApacheSiteConfig::new(
            ApacheServerName::parse("api.example.com").unwrap(),
            ApacheListenPort::parse("80").unwrap(),
            ApacheSiteTarget::ReverseProxy(ApacheUpstream::parse("http://127.0.0.1:3000").unwrap()),
            security_headers,
        )
        .unwrap()
    }

    #[test]
    fn feature_metadata_is_complete_unique_and_has_exact_defaults() {
        assert_eq!(
            ApacheSiteFeature::ALL,
            [
                ApacheSiteFeature::ForbiddenPath403,
                ApacheSiteFeature::SecurityHeaders,
                ApacheSiteFeature::DisableDirectoryListing,
                ApacheSiteFeature::DisableHtaccessOverrides,
                ApacheSiteFeature::RestrictRequestMethods,
                ApacheSiteFeature::ReduceVersionDisclosure,
                ApacheSiteFeature::DisableTrace,
                ApacheSiteFeature::RestrictSourceIp,
                ApacheSiteFeature::GzipCompression,
                ApacheSiteFeature::StaticAssetCaching,
                ApacheSiteFeature::DenyHiddenPaths,
                ApacheSiteFeature::DenySensitiveFiles,
                ApacheSiteFeature::ClientBodyLimit,
                ApacheSiteFeature::KeepaliveTuning,
                ApacheSiteFeature::Utf8Charset,
                ApacheSiteFeature::IndexFiles,
                ApacheSiteFeature::Sendfile,
                ApacheSiteFeature::ProxyTimeouts,
                ApacheSiteFeature::PreserveOriginalHost,
                ApacheSiteFeature::SpaFallback,
                ApacheSiteFeature::RequestReadTimeouts,
                ApacheSiteFeature::LimitRangeRequests,
            ]
        );
        assert_eq!(ApacheSiteFeature::ALL.len(), 22);
        let keys = ApacheSiteFeature::ALL
            .into_iter()
            .map(ApacheSiteFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), ApacheSiteFeature::ALL.len());
        assert!(ApacheSiteFeature::ALL.into_iter().all(|feature| {
            !feature.key().is_empty()
                && !feature.title().is_empty()
                && !feature.summary().is_empty()
                && !feature.scope().is_empty()
                && !feature.aliases().is_empty()
        }));
        assert_eq!(
            ApacheSiteFeature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ApacheSiteFeature::SecurityHeaders,
                ApacheSiteFeature::DisableDirectoryListing,
                ApacheSiteFeature::DisableHtaccessOverrides,
                ApacheSiteFeature::ReduceVersionDisclosure,
                ApacheSiteFeature::DisableTrace,
                ApacheSiteFeature::IndexFiles,
            ])
        );
    }

    #[test]
    fn feature_support_and_module_matrices_are_explicit() {
        assert_eq!(
            ApacheSiteKind::Static.baseline_required_modules(),
            &["authz_core_module"]
        );
        assert_eq!(
            ApacheSiteKind::ReverseProxy.baseline_required_modules(),
            &["proxy_module", "proxy_http_module"]
        );
        let static_only = BTreeSet::from([
            ApacheSiteFeature::DisableDirectoryListing,
            ApacheSiteFeature::DisableHtaccessOverrides,
            ApacheSiteFeature::StaticAssetCaching,
            ApacheSiteFeature::DenySensitiveFiles,
            ApacheSiteFeature::Utf8Charset,
            ApacheSiteFeature::IndexFiles,
            ApacheSiteFeature::Sendfile,
            ApacheSiteFeature::SpaFallback,
            ApacheSiteFeature::LimitRangeRequests,
        ]);
        let proxy_only = BTreeSet::from([
            ApacheSiteFeature::ProxyTimeouts,
            ApacheSiteFeature::PreserveOriginalHost,
        ]);

        for feature in ApacheSiteFeature::ALL {
            assert_eq!(
                feature.supports_kind(ApacheSiteKind::Static),
                !proxy_only.contains(&feature),
                "{feature:?}"
            );
            assert_eq!(
                feature.supports_kind(ApacheSiteKind::ReverseProxy),
                !static_only.contains(&feature),
                "{feature:?}"
            );
            let modules = feature.required_modules();
            assert_eq!(
                modules.iter().copied().collect::<HashSet<_>>().len(),
                modules.len()
            );
            assert!(modules.iter().all(|module| module.ends_with("_module")));
        }
        assert_eq!(
            ApacheSiteFeature::RestrictSourceIp.required_modules(),
            &["authz_core_module", "authz_host_module"]
        );
        assert_eq!(
            ApacheSiteFeature::GzipCompression.required_modules(),
            &["filter_module", "deflate_module"]
        );
        assert_eq!(
            ApacheSiteFeature::ProxyTimeouts.required_modules(),
            &["proxy_module", "proxy_http_module"]
        );
    }

    #[test]
    fn constructor_builds_only_kind_compatible_baseline_defaults() {
        let static_baseline = static_config(true);
        assert_eq!(static_baseline.kind(), ApacheSiteKind::Static);
        assert!(static_baseline.security_headers());
        for feature in ApacheSiteFeature::ALL {
            assert_eq!(
                static_baseline.feature_enabled(feature),
                feature.default_enabled() && feature.supports_kind(ApacheSiteKind::Static),
                "{feature:?}"
            );
        }

        let reverse = reverse_proxy_config(false);
        assert_eq!(reverse.kind(), ApacheSiteKind::ReverseProxy);
        assert!(!reverse.security_headers());
        assert!(reverse.feature_enabled(ApacheSiteFeature::DisableTrace));
        assert!(reverse.feature_enabled(ApacheSiteFeature::ReduceVersionDisclosure));
        assert!(ApacheSiteFeature::ALL.into_iter().all(|feature| {
            !reverse.feature_enabled(feature)
                || (feature.default_enabled()
                    && feature.supports_kind(ApacheSiteKind::ReverseProxy))
        }));
    }

    #[test]
    fn static_baseline_is_exact_deterministic_and_does_not_declare_a_listener() {
        let config = static_config(false);
        let first = config.generate().unwrap();
        let second = config.generate().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.suggested_file_name(), "apache-site.conf");
        assert_eq!(
            first.contents(),
            "ServerTokens Prod\nServerSignature Off\n\n<VirtualHost *:8080>\n    ServerName example.com\n\n    TraceEnable Off\n\n    DocumentRoot \"/srv/www/example\"\n\n    <Directory \"/srv/www/example\">\n        Options -ExecCGI -Indexes\n        AllowOverride None\n        Require all granted\n        DirectoryIndex disabled\n        DirectoryIndex index.html index.htm\n    </Directory>\n</VirtualHost>\n"
        );
        assert!(!first.contents().contains("Listen "));
        assert!(!first.contents().contains("ErrorLog"));
        assert!(first.contents().len() <= MAX_GENERATED_APACHE_CONFIG_BYTES);
        validate_generated_document(first.contents()).unwrap();
    }

    #[test]
    fn reverse_proxy_baseline_is_exact_http_only_and_not_a_forward_proxy() {
        let generated = reverse_proxy_config(false).generate().unwrap();
        assert_eq!(
            generated.contents(),
            "ServerTokens Prod\nServerSignature Off\n\n<VirtualHost *:80>\n    ServerName api.example.com\n\n    TraceEnable Off\n\n    ProxyRequests Off\n    ProxyPreserveHost Off\n    ProxyPass \"/\" \"http://127.0.0.1:3000/\"\n    ProxyPassReverse \"/\" \"http://127.0.0.1:3000/\"\n</VirtualHost>\n"
        );
        assert!(!generated.contents().contains("ProxyRequests On"));
        assert!(!generated.contents().contains("SSLProxy"));
        assert!(!generated.contents().contains("<IfModule"));
    }

    #[test]
    fn security_headers_replace_both_apache_header_tables_and_keep_global_scope_explicit() {
        let generated = reverse_proxy_config(true).generate().unwrap();
        assert!(
            generated
                .contents()
                .starts_with("ServerTokens Prod\nServerSignature Off\n\n<VirtualHost *:80>")
        );
        for header in [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ] {
            assert!(
                generated
                    .contents()
                    .contains(&format!("Header onsuccess unset {header}"))
            );
            assert!(
                generated
                    .contents()
                    .contains(&format!("Header always set {header}"))
            );
        }
    }

    #[test]
    fn additive_features_are_order_independent_and_removal_restores_baseline() {
        let baseline = reverse_proxy_config(false).generate().unwrap();
        let first = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::GzipCompression, true)
            .unwrap()
            .with_feature(ApacheSiteFeature::ClientBodyLimit, true)
            .unwrap()
            .generate()
            .unwrap();
        let second = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::ClientBodyLimit, true)
            .unwrap()
            .with_feature(ApacheSiteFeature::GzipCompression, true)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(first, second);
        assert!(first.contents().contains("AddOutputFilterByType DEFLATE"));
        assert!(first.contents().contains("LimitRequestBody 10485760"));
        assert!(first.contents().contains("ProxyPass \"/\""));

        let restored = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::GzipCompression, true)
            .unwrap()
            .with_feature(ApacheSiteFeature::GzipCompression, false)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(restored, baseline);
    }

    #[test]
    fn apache_stack_remove_reset_and_structured_visual_prerequisite_are_byte_exact() {
        let baseline = reverse_proxy_config(true).generate().unwrap();
        let stacked = reverse_proxy_config(true)
            .with_feature(ApacheSiteFeature::RestrictRequestMethods, true)
            .unwrap()
            .with_feature(ApacheSiteFeature::ClientBodyLimit, true)
            .unwrap();
        let stacked_output = stacked.generate().unwrap();
        assert!(
            stacked_output
                .contents()
                .contains("Require method GET HEAD")
        );
        assert!(
            stacked_output
                .contents()
                .contains("LimitRequestBody 10485760")
        );
        assert!(stacked_output.contents().contains("ProxyPass \"/\""));

        assert!(
            stacked
                .clone()
                .with_feature(ApacheSiteFeature::DisableTrace, false)
                .is_err()
        );
        let remaining = stacked
            .with_feature(ApacheSiteFeature::RestrictRequestMethods, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!remaining.contents().contains("Require method GET HEAD"));
        assert!(remaining.contents().contains("LimitRequestBody 10485760"));
        assert!(remaining.contents().contains("TraceEnable Off"));
        assert!(remaining.contents().contains("ProxyPass \"/\""));

        let reset = reverse_proxy_config(true).generate().unwrap();
        assert_eq!(reset, baseline);
        let visual = ApacheVisualDocument::parse(reset.contents()).unwrap();
        assert!(visual.is_structured());
        assert!(!visual.has_opaque_regions());
        assert!(!visual.contains_sensitive_values());
        assert_eq!(visual.raw_bytes(), reset.contents().as_bytes());
        assert!(
            visual
                .rows()
                .iter()
                .any(|row| row.name() == Some("ProxyPass"))
        );
    }

    #[test]
    fn apache_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact() {
        let feature = ApacheSiteFeature::ClientBodyLimit;
        assert_eq!(feature.key(), "client-body-limit");
        assert_eq!(feature.title(), "限制请求体大小");
        assert_eq!(feature.summary(), "将客户端请求体上限固定为 10 MiB。");
        assert_eq!(feature.scope(), "虚拟主机");
        assert_eq!(
            feature.aliases(),
            &["请求体", "上传大小", "LimitRequestBody", "10 MiB"]
        );
        assert!(!feature.default_enabled());
        assert!(feature.supports_kind(ApacheSiteKind::Static));
        assert!(feature.supports_kind(ApacheSiteKind::ReverseProxy));
        assert!(feature.required_modules().is_empty());

        let baseline = reverse_proxy_config(false).generate().unwrap();
        let selected = reverse_proxy_config(false)
            .with_feature(feature, true)
            .unwrap();
        let selected_output = selected.generate().unwrap();
        const BODY_LIMIT_BLOCK: &str = "\n\n    LimitRequestBody 10485760";
        assert_eq!(
            selected_output.contents().matches(BODY_LIMIT_BLOCK).count(),
            1
        );
        assert_eq!(
            selected_output.contents().replace(BODY_LIMIT_BLOCK, ""),
            baseline.contents()
        );

        let removed = selected
            .with_feature(feature, false)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(removed, baseline);
        assert!(!removed.contents().contains("LimitRequestBody"));
    }

    #[test]
    fn forbidden_path_rules_are_segment_safe_and_escape_regex_metacharacters() {
        let descendants = reverse_proxy_config(false)
            .with_forbidden_path_rule(
                ApacheForbiddenPathRule::new(
                    ApacheForbiddenPath::parse("/admin.v1").unwrap(),
                    ApacheForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            descendants.forbidden_path_rule().unwrap().scope(),
            ApacheForbiddenPathScope::PathAndDescendants
        );
        let generated = descendants.generate().unwrap();
        assert!(
            generated
                .contents()
                .contains("<LocationMatch \"^/admin\\.v1(?:/.*)?$\">\n        Require all denied")
        );
        assert!(!generated.contents().contains("/administrator"));

        let exact = reverse_proxy_config(false)
            .with_forbidden_path_rule(
                ApacheForbiddenPathRule::new(
                    ApacheForbiddenPath::parse("/admin").unwrap(),
                    ApacheForbiddenPathScope::Exact,
                )
                .unwrap(),
            )
            .unwrap()
            .generate()
            .unwrap();
        assert!(exact.contents().contains("<LocationMatch \"^/admin$\">"));
        assert!(!exact.contents().contains("(?:/.*)?"));
    }

    #[test]
    fn forbidden_path_rejects_root_ambiguity_and_token_injection() {
        assert_eq!(
            ApacheForbiddenPath::parse("/admin/tools").unwrap().as_str(),
            "/admin/tools"
        );
        let maximum = format!("/{}", "a".repeat(MAX_FORBIDDEN_PATH_BYTES - 1));
        assert_eq!(
            ApacheForbiddenPath::parse(&maximum).unwrap().as_str(),
            maximum
        );
        let oversized = format!("/{}", "a".repeat(MAX_FORBIDDEN_PATH_BYTES));
        assert!(ApacheForbiddenPath::parse(&oversized).is_err());
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
            "/admin;Require",
            "/admin{",
            "/$admin",
            "/管理",
        ] {
            assert!(ApacheForbiddenPath::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn allowed_source_normalizes_ip_and_cidr_and_rejects_injection() {
        assert_eq!(
            ApacheAllowedSource::parse("192.0.2.129/24")
                .unwrap()
                .as_str(),
            "192.0.2.0/24"
        );
        assert_eq!(
            ApacheAllowedSource::parse("2001:db8:abcd::1234/48")
                .unwrap()
                .as_str(),
            "2001:db8:abcd::/48"
        );
        for invalid in [
            "",
            "0.0.0.0/33",
            "::/129",
            "192.0.2.1/24/1",
            "192.0.2.1 deny all",
            "example.com",
            " 192.0.2.1",
        ] {
            assert!(ApacheAllowedSource::parse(invalid).is_err(), "{invalid:?}");
        }

        let config = reverse_proxy_config(false)
            .with_allowed_source_rule(ApacheAllowedSource::parse("203.0.113.8/24").unwrap())
            .unwrap();
        assert_eq!(
            config.allowed_source_rule().unwrap().as_str(),
            "203.0.113.0/24"
        );
        assert!(
            config
                .generate()
                .unwrap()
                .contents()
                .contains("<Location \"/\">\n        Require ip 203.0.113.0/24")
        );
    }

    #[test]
    fn parameterized_features_fail_closed_when_their_typed_values_are_missing() {
        let forbidden = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::ForbiddenPath403, true)
            .unwrap();
        assert!(forbidden.generate().is_err());

        let source = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::RestrictSourceIp, true)
            .unwrap();
        assert!(source.generate().is_err());
    }

    #[test]
    fn kind_incompatible_features_are_rejected_before_generation() {
        assert!(
            static_config(false)
                .with_feature(ApacheSiteFeature::ProxyTimeouts, true)
                .is_err()
        );
        assert!(
            reverse_proxy_config(false)
                .with_feature(ApacheSiteFeature::SpaFallback, true)
                .is_err()
        );
        assert!(
            reverse_proxy_config(false)
                .with_feature(ApacheSiteFeature::IndexFiles, true)
                .is_err()
        );
    }

    #[test]
    fn request_method_restriction_requires_trace_to_remain_disabled() {
        let restricted = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::RestrictRequestMethods, true)
            .unwrap();
        assert!(
            restricted
                .generate()
                .unwrap()
                .contents()
                .contains("Require method GET HEAD")
        );
        assert!(
            restricted
                .with_feature(ApacheSiteFeature::DisableTrace, false)
                .is_err()
        );

        let without_trace = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::DisableTrace, false)
            .unwrap();
        assert!(
            without_trace
                .with_feature(ApacheSiteFeature::RestrictRequestMethods, true)
                .is_err()
        );
    }

    #[test]
    fn method_and_source_restrictions_use_an_explicit_require_all() {
        let generated = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::RestrictRequestMethods, true)
            .unwrap()
            .with_allowed_source_rule(ApacheAllowedSource::parse("203.0.113.8/24").unwrap())
            .unwrap()
            .generate()
            .unwrap();

        assert!(generated.contents().contains(
            "<Location \"/\">\n        <RequireAll>\n            Require method GET HEAD\n            Require ip 203.0.113.0/24\n        </RequireAll>\n    </Location>"
        ));
        assert_eq!(generated.contents().matches("Require method").count(), 1);
        assert_eq!(generated.contents().matches("Require ip").count(), 1);
        assert!(!generated.contents().contains("<LimitExcept"));
    }

    #[test]
    fn spa_and_fixed_asset_conflicts_fail_closed() {
        let spa = static_config(false)
            .with_feature(ApacheSiteFeature::SpaFallback, true)
            .unwrap();
        assert!(
            spa.clone()
                .with_forbidden_path_rule(
                    ApacheForbiddenPathRule::new(
                        ApacheForbiddenPath::parse("/index.html").unwrap(),
                        ApacheForbiddenPathScope::Exact,
                    )
                    .unwrap(),
                )
                .is_err()
        );
        assert!(
            spa.with_forbidden_path_rule(
                ApacheForbiddenPathRule::new(
                    ApacheForbiddenPath::parse("/assets").unwrap(),
                    ApacheForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .is_err()
        );

        let caching = static_config(false)
            .with_feature(ApacheSiteFeature::StaticAssetCaching, true)
            .unwrap();
        assert!(
            caching
                .with_forbidden_path_rule(
                    ApacheForbiddenPathRule::new(
                        ApacheForbiddenPath::parse("/assets").unwrap(),
                        ApacheForbiddenPathScope::PathAndDescendants,
                    )
                    .unwrap(),
                )
                .is_err()
        );
    }

    #[test]
    fn spa_and_asset_cache_share_one_directory_and_assets_keep_404_semantics() {
        let generated = static_config(false)
            .with_feature(ApacheSiteFeature::SpaFallback, true)
            .unwrap()
            .with_feature(ApacheSiteFeature::StaticAssetCaching, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(
            generated
                .contents()
                .contains("FallbackResource /index.html")
        );
        assert_eq!(
            generated
                .contents()
                .matches("<Directory \"/srv/www/example/assets\">")
                .count(),
            1
        );
        assert!(generated.contents().contains(
            "<Directory \"/srv/www/example/assets\">\n        FallbackResource disabled\n        ExpiresActive On\n        ExpiresDefault \"access plus 7 days\""
        ));
    }

    #[test]
    fn proxy_options_are_explicit_and_do_not_replace_the_baseline_mapping() {
        let generated = reverse_proxy_config(false)
            .with_feature(ApacheSiteFeature::ProxyTimeouts, true)
            .unwrap()
            .with_feature(ApacheSiteFeature::PreserveOriginalHost, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(generated.contents().contains("ProxyRequests Off"));
        assert!(generated.contents().contains("ProxyPreserveHost On"));
        assert!(
            generated.contents().contains(
                "ProxyPass \"/\" \"http://127.0.0.1:3000/\" connectiontimeout=5 timeout=60"
            )
        );
        assert!(
            generated
                .contents()
                .contains("ProxyPassReverse \"/\" \"http://127.0.0.1:3000/\"")
        );
    }

    #[test]
    fn typed_site_values_reject_token_boundaries_and_unsafe_roots() {
        assert_eq!(
            ApacheServerName::parse("EXAMPLE.com").unwrap().as_str(),
            "example.com"
        );
        assert_eq!(ApacheListenPort::parse("65535").unwrap().get(), 65535);
        assert_eq!(
            ApacheStaticRoot::parse("/srv/www/site").unwrap().as_str(),
            "/srv/www/site"
        );
        for invalid in [
            "",
            "example.com other.example",
            "example.com;ServerName evil",
            "127.0.0.1",
            "-example.com",
            "example.com.",
        ] {
            assert!(ApacheServerName::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["", "0", "65536", "80 ", "+80", "8O"] {
            assert!(ApacheListenPort::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in [
            "/",
            "srv/www",
            "/srv/www/",
            "/srv/../etc",
            "/srv/www site",
            "/srv/www\" Require all granted",
            "/srv/$site",
        ] {
            assert!(ApacheStaticRoot::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn upstream_is_a_canonical_http_origin_and_https_fails_closed() {
        assert_eq!(
            ApacheUpstream::parse("http://Backend.Example:8080")
                .unwrap()
                .as_str(),
            "http://backend.example:8080"
        );
        assert_eq!(
            ApacheUpstream::parse("http://[2001:db8::1]:3000")
                .unwrap()
                .as_str(),
            "http://[2001:db8::1]:3000"
        );
        for invalid in [
            "https://backend.example",
            "http://user:pass@backend.example",
            "http://backend.example/path",
            "http://backend.example/?query=1",
            "http://backend.example/#fragment",
            "http://0.0.0.0:3000",
            "http://[::]:3000",
            "file:///etc/passwd",
            "http://backend.example\\evil",
            " http://backend.example",
        ] {
            assert!(ApacheUpstream::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn every_compatible_feature_composes_into_bounded_structured_documents() {
        let mut static_all = static_config(false)
            .with_forbidden_path_rule(
                ApacheForbiddenPathRule::new(
                    ApacheForbiddenPath::parse("/private").unwrap(),
                    ApacheForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .unwrap()
            .with_allowed_source_rule(ApacheAllowedSource::parse("192.0.2.0/24").unwrap())
            .unwrap();
        for feature in ApacheSiteFeature::ALL {
            if feature.supports_kind(ApacheSiteKind::Static) {
                static_all = static_all.with_feature(feature, true).unwrap();
            }
        }
        let static_output = static_all.generate().unwrap();
        validate_generated_document(static_output.contents()).unwrap();
        assert!(static_output.contents().len() <= MAX_GENERATED_APACHE_CONFIG_BYTES);

        let mut proxy_all = reverse_proxy_config(false)
            .with_forbidden_path_rule(
                ApacheForbiddenPathRule::new(
                    ApacheForbiddenPath::parse("/private").unwrap(),
                    ApacheForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .unwrap()
            .with_allowed_source_rule(ApacheAllowedSource::parse("2001:db8::/32").unwrap())
            .unwrap();
        for feature in ApacheSiteFeature::ALL {
            if feature.supports_kind(ApacheSiteKind::ReverseProxy) {
                proxy_all = proxy_all.with_feature(feature, true).unwrap();
            }
        }
        let proxy_output = proxy_all.generate().unwrap();
        validate_generated_document(proxy_output.contents()).unwrap();
        assert!(proxy_output.contents().len() <= MAX_GENERATED_APACHE_CONFIG_BYTES);
        assert!(!proxy_output.contents().contains("<IfModule"));
    }

    #[test]
    fn generated_output_is_exclusively_created_and_never_overwrites() {
        let root = TestRoot::new();
        let destination = root.0.join("site.conf");
        let generated = static_config(false).generate().unwrap();
        assert_eq!(generated.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );

        fs::write(&destination, "owned-by-user\n").unwrap();
        assert!(generated.write_new(&destination).is_err());
        assert_eq!(fs::read_to_string(&destination).unwrap(), "owned-by-user\n");
    }

    #[test]
    fn export_destination_requires_existing_absolute_parent_and_conf_extension() {
        let root = TestRoot::new();
        let generated = reverse_proxy_config(false).generate().unwrap();
        assert!(generated.write_new(Path::new("relative.conf")).is_err());
        assert!(generated.write_new(&root.0.join("site.txt")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("site.conf"))
                .is_err()
        );
        assert!(
            generated
                .write_new(&root.0.join("child").join("..").join("site.conf"))
                .is_err()
        );
    }
}
