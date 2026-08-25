//! Deterministic, bounded HAProxy HTTP reverse-proxy drafts.
//!
//! The closed model emits one complete local draft for a single clear-text
//! frontend and one IP-literal upstream. It does not discover an installation,
//! generate credentials, deploy, run HAProxy's configuration check, reload a
//! process, or claim that a target accepted the file. TLS termination remains
//! fail-closed until certificate assets, key permissions, and target build
//! capabilities have their own typed boundary.
//!
//! Official references used by this model (checked on 2026-08-24):
//! - <https://www.haproxy.org/>
//! - <https://docs.haproxy.org/3.4/configuration.html>
//! - <https://docs.haproxy.org/3.3/configuration.html>
//! - <https://docs.haproxy.org/3.2/configuration.html>
//! - <https://docs.haproxy.org/3.0/configuration.html>
//! - <https://docs.haproxy.org/2.8/configuration.html>
//! - <https://docs.haproxy.org/2.6/configuration.html>

use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
};

use crate::{CoreError, CoreResult};

pub const MAX_GENERATED_HAPROXY_CONFIG_BYTES: usize = 32 * 1024;
pub const HAPROXY_RELEASES_REFERENCE: &str = "https://www.haproxy.org/";
pub const HAPROXY_34_CONFIGURATION_REFERENCE: &str =
    "https://docs.haproxy.org/3.4/configuration.html";
pub const HAPROXY_33_CONFIGURATION_REFERENCE: &str =
    "https://docs.haproxy.org/3.3/configuration.html";
pub const HAPROXY_32_CONFIGURATION_REFERENCE: &str =
    "https://docs.haproxy.org/3.2/configuration.html";
pub const HAPROXY_30_CONFIGURATION_REFERENCE: &str =
    "https://docs.haproxy.org/3.0/configuration.html";
pub const HAPROXY_28_CONFIGURATION_REFERENCE: &str =
    "https://docs.haproxy.org/2.8/configuration.html";
pub const HAPROXY_26_CONFIGURATION_REFERENCE: &str =
    "https://docs.haproxy.org/2.6/configuration.html";
pub const HAPROXY_OFFICIAL_REFERENCES: &[&str] = &[
    HAPROXY_RELEASES_REFERENCE,
    HAPROXY_34_CONFIGURATION_REFERENCE,
    HAPROXY_33_CONFIGURATION_REFERENCE,
    HAPROXY_32_CONFIGURATION_REFERENCE,
    HAPROXY_30_CONFIGURATION_REFERENCE,
    HAPROXY_28_CONFIGURATION_REFERENCE,
    HAPROXY_26_CONFIGURATION_REFERENCE,
];

pub const HAPROXY_TLS_FRONTEND_DEFERRED_REASON: &str = "TLS 前端需要真实证书链、私钥、文件权限、SNI/ALPN 策略和目标 HAProxy TLS build 能力；当前本地草稿模型不接收秘密或资产路径，因此拒绝启用且绝不输出 ssl/crt 占位。";
pub const HAPROXY_TARGET_VALIDATION_NOTICE: &str = "生成结果只是本地新草稿；必须在精确目标上使用同一分支的 HAProxy 二进制执行配置检查，并由独立发布流程决定是否安全 reload。";
pub const HAPROXY_DIRECT_CLIENT_NOTICE: &str = "来源 ACL、限速和转发身份只读取直接 TCP peer；当前模型不信任 PROXY protocol、Forwarded 或入站 X-Forwarded-For。";

const FRONTEND_NAME: &str = "lovelyres_http_in";
const BACKEND_NAME: &str = "lovelyres_app";
const SERVER_NAME: &str = "lovelyres_app";
const REQUEST_ID_FORMAT: &str = "%{+X}o\\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid";
const MAX_TIMEOUT_SECONDS: u32 = 86_400;
const MAX_CONNECTIONS: u32 = 1_000_000;
const MAX_QUEUE: u32 = 1_000_000;
const MAX_RETRIES: u8 = 10;
const MAX_RATE_LIMIT: u32 = 1_000_000;
const MAX_HTTP_PATH_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HaProxyVersion {
    #[default]
    V34Lts,
    V33Stable,
    V32Lts,
    V30Lts,
    V28Compatibility,
    V26Compatibility,
}

impl HaProxyVersion {
    pub const ALL: [Self; 6] = [
        Self::V34Lts,
        Self::V33Stable,
        Self::V32Lts,
        Self::V30Lts,
        Self::V28Compatibility,
        Self::V26Compatibility,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::V34Lts => "3.4",
            Self::V33Stable => "3.3",
            Self::V32Lts => "3.2",
            Self::V30Lts => "3.0",
            Self::V28Compatibility => "2.8",
            Self::V26Compatibility => "2.6",
        }
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "3.4" => Ok(Self::V34Lts),
            "3.3" => Ok(Self::V33Stable),
            "3.2" => Ok(Self::V32Lts),
            "3.0" => Ok(Self::V30Lts),
            "2.8" => Ok(Self::V28Compatibility),
            "2.6" => Ok(Self::V26Compatibility),
            _ => Err(CoreError::validation(
                "HAProxy branch",
                "must be exactly one audited branch: 3.4, 3.3, 3.2, 3.0, 2.8, or 2.6",
            )),
        }
    }

    pub const fn channel(self) -> &'static str {
        match self {
            Self::V34Lts => "LTS（默认建议）",
            Self::V33Stable => "stable（短支持周期）",
            Self::V32Lts | Self::V30Lts => "LTS",
            Self::V28Compatibility | Self::V26Compatibility => "compatibility（仅关键修复）",
        }
    }

    pub const fn support_horizon(self) -> &'static str {
        match self {
            Self::V34Lts => "2031-Q2",
            Self::V33Stable => "2027-Q1",
            Self::V32Lts => "2030-Q2",
            Self::V30Lts => "2029-Q2",
            Self::V28Compatibility => "2028-Q2",
            Self::V26Compatibility => "2027-Q2",
        }
    }

    pub const fn is_default_recommendation(self) -> bool {
        matches!(self, Self::V34Lts)
    }

    pub const fn official_documentation(self) -> &'static str {
        match self {
            Self::V34Lts => HAPROXY_34_CONFIGURATION_REFERENCE,
            Self::V33Stable => HAPROXY_33_CONFIGURATION_REFERENCE,
            Self::V32Lts => HAPROXY_32_CONFIGURATION_REFERENCE,
            Self::V30Lts => HAPROXY_30_CONFIGURATION_REFERENCE,
            Self::V28Compatibility => HAPROXY_28_CONFIGURATION_REFERENCE,
            Self::V26Compatibility => HAPROXY_26_CONFIGURATION_REFERENCE,
        }
    }

    pub const fn support_notice(self) -> &'static str {
        match self {
            Self::V34Lts => {
                "HAProxy 3.4 是当前默认建议的 LTS 分支；使用该分支最新补丁版本，并在目标二进制上重新检查配置。"
            }
            Self::V33Stable => "HAProxy 3.3 是短周期 stable 分支；只适合能够频繁升级和回退的目标。",
            Self::V32Lts => "HAProxy 3.2 是维护中的 LTS 分支；使用该分支最新补丁版本。",
            Self::V30Lts => "HAProxy 3.0 是维护中的 LTS 分支；使用该分支最新补丁版本。",
            Self::V28Compatibility => {
                "HAProxy 2.8 已处于仅关键修复阶段；只为现有兼容目标保留，不建议新部署。"
            }
            Self::V26Compatibility => {
                "HAProxy 2.6 已处于仅关键修复阶段且接近支持终点；只为现有兼容目标保留。"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HaProxyConfigFeature {
    HealthCheck,
    TimeoutGuards,
    AccessLogging,
    ResponseCompression,
    TlsFrontend,
    ForbiddenPath403,
    RestrictSourceIp,
    RestrictRequestMethods,
    WebSocketTunnel,
    ConnectionLimits,
    ConnectionRetries,
    RequestId,
    SecurityResponseHeaders,
    SourceRateLimit,
    HideUpstreamServerHeader,
    ForwardedHeaders,
}

impl HaProxyConfigFeature {
    pub const ALL: [Self; 16] = [
        Self::HealthCheck,
        Self::TimeoutGuards,
        Self::AccessLogging,
        Self::ResponseCompression,
        Self::TlsFrontend,
        Self::ForbiddenPath403,
        Self::RestrictSourceIp,
        Self::RestrictRequestMethods,
        Self::WebSocketTunnel,
        Self::ConnectionLimits,
        Self::ConnectionRetries,
        Self::RequestId,
        Self::SecurityResponseHeaders,
        Self::SourceRateLimit,
        Self::HideUpstreamServerHeader,
        Self::ForwardedHeaders,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::HealthCheck => "health-check",
            Self::TimeoutGuards => "timeout-guards",
            Self::AccessLogging => "access-logging",
            Self::ResponseCompression => "response-compression",
            Self::TlsFrontend => "tls-frontend",
            Self::ForbiddenPath403 => "forbidden-path-403",
            Self::RestrictSourceIp => "restrict-source-ip",
            Self::RestrictRequestMethods => "restrict-request-methods",
            Self::WebSocketTunnel => "websocket-tunnel",
            Self::ConnectionLimits => "connection-limits",
            Self::ConnectionRetries => "connection-retries",
            Self::RequestId => "request-id",
            Self::SecurityResponseHeaders => "security-response-headers",
            Self::SourceRateLimit => "source-rate-limit",
            Self::HideUpstreamServerHeader => "hide-upstream-server-header",
            Self::ForwardedHeaders => "forwarded-headers",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::HealthCheck => "启用 HTTP 上游健康检查",
            Self::TimeoutGuards => "添加请求与队列超时保护",
            Self::AccessLogging => "输出 HTTP 访问日志到 stdout",
            Self::ResponseCompression => "启用 Gzip 响应压缩",
            Self::TlsFrontend => "TLS 前端（当前拒绝启用）",
            Self::ForbiddenPath403 => "禁止指定访问路径（HTTP 403）",
            Self::RestrictSourceIp => "限制直接来源 IP",
            Self::RestrictRequestMethods => "仅允许 GET 与 HEAD",
            Self::WebSocketTunnel => "延长 WebSocket tunnel 空闲超时",
            Self::ConnectionLimits => "限制前端连接、上游并发与队列",
            Self::ConnectionRetries => "重试未发送的连接失败请求",
            Self::RequestId => "生成并传递请求 ID",
            Self::SecurityResponseHeaders => "覆盖固定安全响应头",
            Self::SourceRateLimit => "按直接来源 IP 限制请求速率",
            Self::HideUpstreamServerHeader => "移除上游 Server 响应头",
            Self::ForwardedHeaders => "覆盖直接客户端转发身份头",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::HealthCheck => {
                "以 HTTP/1.0 GET 探测固定 typed path，仅接受 200–399；不会探测响应正文。"
            }
            Self::TimeoutGuards => {
                "在必需的 connect/client/server 超时之外，限制完整请求头等待与上游排队时间。"
            }
            Self::AccessLogging => {
                "使用官方 stdout log target 和 httplog；是否被服务管理器持久化取决于目标运行方式。"
            }
            Self::ResponseCompression => {
                "对固定 MIME 类型请求 Gzip；目标 HAProxy 必须编译相应压缩支持。"
            }
            Self::TlsFrontend => HAPROXY_TLS_FRONTEND_DEFERRED_REASON,
            Self::ForbiddenPath403 => {
                "按 HAProxy 原始 URL path 精确匹配，并可选匹配其后代路径；不声称等同于后端解码后的文件路径。"
            }
            Self::RestrictSourceIp => {
                "仅允许一个 canonical IP/CIDR 的直接 TCP peer；不读取任何转发身份头。"
            }
            Self::RestrictRequestMethods => "前端 ACL 仅允许 GET 与 HEAD，其他方法返回 405。",
            Self::WebSocketTunnel => {
                "仅设置连接升级后接管的 timeout tunnel；HAProxy 的 HTTP 代理本身处理 WebSocket upgrade。"
            }
            Self::ConnectionLimits => "同时限制全局/前端连接数、单上游并发请求数和单上游队列长度。",
            Self::ConnectionRetries => {
                "显式仅重试 conn-failure，即请求尚未发给上游的连接失败；不启用响应或状态码重放。"
            }
            Self::RequestId => {
                "删除客户端同名头，使用 HAProxy unique-id-format 生成 X-Request-ID，并传给上游及客户端。"
            }
            Self::SecurityResponseHeaders => {
                "覆盖 nosniff、SAMEORIGIN 与 Referrer-Policy；可能与应用自己的嵌入或跨源策略冲突。"
            }
            Self::SourceRateLimit => {
                "使用有界 stick-table 统计直接 TCP peer 的十秒请求率，超过阈值返回 429。"
            }
            Self::HideUpstreamServerHeader => {
                "删除正常上游响应中的 Server 头；不承诺修改 HAProxy 自身提前生成的错误响应。"
            }
            Self::ForwardedHeaders => {
                "先删除客户端 Forwarded/X-Forwarded-*，再从直接 TCP peer 写入 X-Forwarded-For 与明文 http 协议。"
            }
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::AccessLogging | Self::ConnectionLimits => "global/frontend/backend",
            Self::TimeoutGuards | Self::WebSocketTunnel | Self::ConnectionRetries => "defaults",
            Self::HealthCheck | Self::ResponseCompression => "backend/server",
            Self::TlsFrontend => "frontend/bind（不可用）",
            Self::ForbiddenPath403
            | Self::RestrictSourceIp
            | Self::RestrictRequestMethods
            | Self::RequestId
            | Self::SecurityResponseHeaders
            | Self::SourceRateLimit
            | Self::HideUpstreamServerHeader
            | Self::ForwardedHeaders => "frontend HTTP rules",
        }
    }

    pub const fn risk(self) -> &'static str {
        match self {
            Self::HealthCheck => "错误 path、HTTP/1.0 不兼容或阈值过严会把健康上游标记为 DOWN。",
            Self::TimeoutGuards => "阈值过短会终止合法的慢请求或使排队请求提前失败。",
            Self::AccessLogging => {
                "日志包含请求、地址、状态和计时元数据，且可能增加 I/O 与隐私暴露。"
            }
            Self::ResponseCompression => {
                "增加 CPU 开销；敏感动态内容在 TLS 场景还需独立评估压缩侧信道。"
            }
            Self::TlsFrontend => {
                "缺少证书资产和目标能力闭环时生成占位会导致启动失败或错误安全承诺。"
            }
            Self::ForbiddenPath403 => {
                "后端若对编码、大小写或路径正规化采用不同语义，仍可能绕过该前端规则。"
            }
            Self::RestrictSourceIp => {
                "位于可信代理之后时，直接 peer 会是代理地址；误配会拒绝所有合法客户端。"
            }
            Self::RestrictRequestMethods => "会阻断 POST、PUT、PATCH、DELETE、OPTIONS 等应用端点。",
            Self::WebSocketTunnel => "较长空闲超时会让失效 tunnel 更久占用连接资源。",
            Self::ConnectionLimits => "过低会产生排队或 503；过高仍可能压垮进程和上游。",
            Self::ConnectionRetries => {
                "虽仅限未发送请求的连接失败，仍会增加故障期间连接负载与延迟。"
            }
            Self::RequestId => {
                "格式包含连接地址、时间、进程与请求计数元数据，响应公开前需确认可接受。"
            }
            Self::SecurityResponseHeaders => {
                "固定 SAMEORIGIN/Referrer-Policy 可能破坏应用原有浏览器策略。"
            }
            Self::SourceRateLimit => {
                "NAT 用户共享计数；阈值过低会拒绝合法突发流量，表项也占用有界内存。"
            }
            Self::HideUpstreamServerHeader => {
                "只处理经过正常 HTTP 响应规则的上游头，不能当作完整指纹隐藏。"
            }
            Self::ForwardedHeaders => {
                "只有 HAProxy 是直接边界时语义才正确；代理链部署会丢弃原始客户端身份。"
            }
        }
    }

    pub const fn activation(self) -> &'static str {
        match self {
            Self::TlsFrontend => "不可激活：必须先建立证书资产与权限模型",
            _ => "仅写入本地草稿；目标配置检查通过后才可由独立流程 reload",
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::HealthCheck => &["健康检查", "option httpchk", "http-check", "check"],
            Self::TimeoutGuards => &["超时", "timeout http-request", "timeout queue", "slowloris"],
            Self::AccessLogging => &["访问日志", "httplog", "stdout", "log global"],
            Self::ResponseCompression => &["gzip", "压缩", "compression algo", "MIME"],
            Self::TlsFrontend => &["TLS", "HTTPS", "SSL", "crt", "证书"],
            Self::ForbiddenPath403 => &["403", "禁止路径", "path_beg", "deny path"],
            Self::RestrictSourceIp => &["来源 IP", "CIDR", "src ACL", "直接 peer"],
            Self::RestrictRequestMethods => &["方法限制", "GET HEAD", "method ACL", "405"],
            Self::WebSocketTunnel => &["WebSocket", "timeout tunnel", "upgrade", "长连接"],
            Self::ConnectionLimits => &["maxconn", "maxqueue", "连接上限", "队列"],
            Self::ConnectionRetries => &["retries", "retry-on conn-failure", "连接重试"],
            Self::RequestId => &["请求 ID", "X-Request-ID", "unique-id-format", "%ID"],
            Self::SecurityResponseHeaders => {
                &["安全响应头", "nosniff", "SAMEORIGIN", "Referrer-Policy"]
            }
            Self::SourceRateLimit => &["限速", "stick-table", "http_req_rate", "429"],
            Self::HideUpstreamServerHeader => &["Server header", "隐藏版本", "del-header Server"],
            Self::ForwardedHeaders => &[
                "X-Forwarded-For",
                "X-Forwarded-Proto",
                "Forwarded",
                "直接客户端",
            ],
        }
    }

    pub const fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::TimeoutGuards
                | Self::SecurityResponseHeaders
                | Self::HideUpstreamServerHeader
                | Self::ForwardedHeaders
        )
    }

    pub const fn supports_version(self, _version: HaProxyVersion) -> bool {
        // Every emitted directive was checked in both endpoint manuals, 2.6
        // and 3.4. TLS is a product capability but remains unavailable because
        // this generator deliberately lacks certificate assets.
        true
    }

    pub const fn can_enable(self) -> bool {
        !matches!(self, Self::TlsFrontend)
    }

    pub const fn official_reference(self, version: HaProxyVersion) -> &'static str {
        version.official_documentation()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyListenAddress(IpAddr);

impl HaProxyListenAddress {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty() || value != value.trim() || !value.is_ascii() {
            return Err(CoreError::validation(
                "HAProxy listen address",
                "must be one exact IPv4 or IPv6 literal without surrounding whitespace",
            ));
        }
        let address = value.parse::<IpAddr>().map_err(|_| {
            CoreError::validation(
                "HAProxy listen address",
                "must be one valid IPv4 or IPv6 literal",
            )
        })?;
        Ok(Self(address))
    }

    pub const fn all_ipv4() -> Self {
        Self(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }

    pub const fn get(self) -> IpAddr {
        self.0
    }
}

impl Default for HaProxyListenAddress {
    fn default() -> Self {
        Self::all_ipv4()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyListenPort(u16);

impl HaProxyListenPort {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(
            parse_decimal_u32(value, 1, u32::from(u16::MAX), "HAProxy listen port")? as u16,
        ))
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    fn validate(self) -> CoreResult<()> {
        if self.0 == 0 {
            return Err(CoreError::validation(
                "HAProxy listen port",
                "must be in 1..=65535",
            ));
        }
        Ok(())
    }
}

/// One IP-literal upstream socket.
///
/// Hostnames are deliberately excluded: HAProxy resolves a server hostname at
/// startup unless a resolver is configured, and this draft does not pretend to
/// own a DNS refresh or failover policy. HAProxy's special wildcard addresses
/// are also rejected so the destination can never inherit the client address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyUpstream(SocketAddr);

impl HaProxyUpstream {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty() || value != value.trim() || !value.is_ascii() {
            return Err(CoreError::validation(
                "HAProxy upstream",
                "must be one exact IP-literal socket such as 127.0.0.1:3000 or [::1]:3000",
            ));
        }
        let address = value.parse::<SocketAddr>().map_err(|_| {
            CoreError::validation(
                "HAProxy upstream",
                "must be one valid IP-literal socket with a port",
            )
        })?;
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(CoreError::validation(
                "HAProxy upstream",
                "port zero, wildcard, multicast, and broadcast destinations are forbidden",
            ));
        }
        Ok(Self(address))
    }

    pub const fn get(self) -> SocketAddr {
        self.0
    }

    fn validate(self) -> CoreResult<()> {
        Self::parse(&self.0.to_string()).map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HaProxyForbiddenPath(String);

impl HaProxyForbiddenPath {
    pub fn parse(value: &str) -> CoreResult<Self> {
        Ok(Self(parse_canonical_http_path(
            value,
            "HAProxy forbidden path",
        )?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> CoreResult<()> {
        let parsed = Self::parse(&self.0)?;
        if parsed != *self {
            return Err(CoreError::validation(
                "HAProxy forbidden path",
                "stored path is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HaProxyForbiddenPathScope {
    Exact,
    PathAndDescendants,
}

impl HaProxyForbiddenPathScope {
    pub const ALL: [Self; 2] = [Self::Exact, Self::PathAndDescendants];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "仅此路径",
            Self::PathAndDescendants => "此路径及后代路径",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HaProxyForbiddenPathRule {
    path: HaProxyForbiddenPath,
    scope: HaProxyForbiddenPathScope,
}

impl HaProxyForbiddenPathRule {
    pub fn new(path: HaProxyForbiddenPath, scope: HaProxyForbiddenPathScope) -> CoreResult<Self> {
        path.validate()?;
        Ok(Self { path, scope })
    }

    pub fn path(&self) -> &HaProxyForbiddenPath {
        &self.path
    }

    pub const fn scope(&self) -> HaProxyForbiddenPathScope {
        self.scope
    }

    fn validate(&self) -> CoreResult<()> {
        self.path.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HaProxyAllowedSource(String);

impl HaProxyAllowedSource {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty()
            || value.len() > 64
            || value != value.trim()
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "HAProxy allowed source",
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
                    "HAProxy allowed source",
                    "CIDR must contain one IP address and one decimal prefix length",
                ));
            }
            let address = address.parse::<IpAddr>().map_err(|_| {
                CoreError::validation("HAProxy allowed source", "CIDR address is invalid")
            })?;
            let prefix = prefix.parse::<u8>().map_err(|_| {
                CoreError::validation("HAProxy allowed source", "CIDR prefix is invalid")
            })?;
            let network = canonical_cidr_network(address, prefix)?;
            format!("{network}/{prefix}")
        } else {
            value
                .parse::<IpAddr>()
                .map_err(|_| {
                    CoreError::validation(
                        "HAProxy allowed source",
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
                "HAProxy allowed source",
                "stored source is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyTimeoutProfile {
    connect_seconds: u32,
    client_seconds: u32,
    server_seconds: u32,
    http_request_seconds: u32,
    queue_seconds: u32,
    tunnel_seconds: u32,
}

impl HaProxyTimeoutProfile {
    pub fn new(
        connect_seconds: u32,
        client_seconds: u32,
        server_seconds: u32,
        http_request_seconds: u32,
        queue_seconds: u32,
        tunnel_seconds: u32,
    ) -> CoreResult<Self> {
        for (subject, value) in [
            ("HAProxy connect timeout", connect_seconds),
            ("HAProxy client timeout", client_seconds),
            ("HAProxy server timeout", server_seconds),
            ("HAProxy HTTP request timeout", http_request_seconds),
            ("HAProxy queue timeout", queue_seconds),
            ("HAProxy tunnel timeout", tunnel_seconds),
        ] {
            if !(1..=MAX_TIMEOUT_SECONDS).contains(&value) {
                return Err(CoreError::validation(
                    subject,
                    format!("must be in 1..={MAX_TIMEOUT_SECONDS} seconds"),
                ));
            }
        }
        Ok(Self {
            connect_seconds,
            client_seconds,
            server_seconds,
            http_request_seconds,
            queue_seconds,
            tunnel_seconds,
        })
    }

    pub fn parse(
        connect_seconds: &str,
        client_seconds: &str,
        server_seconds: &str,
        http_request_seconds: &str,
        queue_seconds: &str,
        tunnel_seconds: &str,
    ) -> CoreResult<Self> {
        Self::new(
            parse_decimal_u32(
                connect_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
                "HAProxy connect timeout",
            )?,
            parse_decimal_u32(
                client_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
                "HAProxy client timeout",
            )?,
            parse_decimal_u32(
                server_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
                "HAProxy server timeout",
            )?,
            parse_decimal_u32(
                http_request_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
                "HAProxy HTTP request timeout",
            )?,
            parse_decimal_u32(
                queue_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
                "HAProxy queue timeout",
            )?,
            parse_decimal_u32(
                tunnel_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
                "HAProxy tunnel timeout",
            )?,
        )
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self {
            connect_seconds: 5,
            client_seconds: 30,
            server_seconds: 30,
            http_request_seconds: 10,
            queue_seconds: 15,
            tunnel_seconds: 3_600,
        }
    }

    pub const fn connect_seconds(self) -> u32 {
        self.connect_seconds
    }

    pub const fn client_seconds(self) -> u32 {
        self.client_seconds
    }

    pub const fn server_seconds(self) -> u32 {
        self.server_seconds
    }

    pub const fn http_request_seconds(self) -> u32 {
        self.http_request_seconds
    }

    pub const fn queue_seconds(self) -> u32 {
        self.queue_seconds
    }

    pub const fn tunnel_seconds(self) -> u32 {
        self.tunnel_seconds
    }

    fn validate(self) -> CoreResult<()> {
        Self::new(
            self.connect_seconds,
            self.client_seconds,
            self.server_seconds,
            self.http_request_seconds,
            self.queue_seconds,
            self.tunnel_seconds,
        )
        .map(|_| ())
    }
}

impl Default for HaProxyTimeoutProfile {
    fn default() -> Self {
        Self::lovelyres_suggestion()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HaProxyHealthCheck {
    path: String,
    interval_seconds: u32,
    fall: u8,
    rise: u8,
}

impl HaProxyHealthCheck {
    pub fn new(path: &str, interval_seconds: u32, fall: u8, rise: u8) -> CoreResult<Self> {
        let path = parse_canonical_http_path(path, "HAProxy health-check path")?;
        if !(1..=300).contains(&interval_seconds) {
            return Err(CoreError::validation(
                "HAProxy health-check interval",
                "must be in 1..=300 seconds",
            ));
        }
        if !(1..=10).contains(&fall) || !(1..=10).contains(&rise) {
            return Err(CoreError::validation(
                "HAProxy health-check thresholds",
                "fall and rise must each be in 1..=10",
            ));
        }
        Ok(Self {
            path,
            interval_seconds,
            fall,
            rise,
        })
    }

    pub fn parse(path: &str, interval: &str, fall: &str, rise: &str) -> CoreResult<Self> {
        Self::new(
            path,
            parse_decimal_u32(interval, 1, 300, "HAProxy health-check interval")?,
            parse_decimal_u32(fall, 1, 10, "HAProxy health-check fall threshold")? as u8,
            parse_decimal_u32(rise, 1, 10, "HAProxy health-check rise threshold")? as u8,
        )
    }

    pub fn lovelyres_suggestion() -> Self {
        Self {
            path: "/healthz".to_owned(),
            interval_seconds: 5,
            fall: 3,
            rise: 2,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn interval_seconds(&self) -> u32 {
        self.interval_seconds
    }

    pub const fn fall(&self) -> u8 {
        self.fall
    }

    pub const fn rise(&self) -> u8 {
        self.rise
    }

    fn validate(&self) -> CoreResult<()> {
        Self::new(&self.path, self.interval_seconds, self.fall, self.rise).map(|_| ())
    }
}

impl Default for HaProxyHealthCheck {
    fn default() -> Self {
        Self::lovelyres_suggestion()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyConnectionLimits {
    frontend_max_connections: u32,
    server_max_connections: u32,
    server_max_queue: u32,
}

impl HaProxyConnectionLimits {
    pub fn new(
        frontend_max_connections: u32,
        server_max_connections: u32,
        server_max_queue: u32,
    ) -> CoreResult<Self> {
        if !(1..=MAX_CONNECTIONS).contains(&frontend_max_connections)
            || !(1..=MAX_CONNECTIONS).contains(&server_max_connections)
            || server_max_connections > frontend_max_connections
            || !(1..=MAX_QUEUE).contains(&server_max_queue)
        {
            return Err(CoreError::validation(
                "HAProxy connection limits",
                format!(
                    "frontend/server limits must be in 1..={MAX_CONNECTIONS}, server must not exceed frontend, and queue must be in 1..={MAX_QUEUE}"
                ),
            ));
        }
        Ok(Self {
            frontend_max_connections,
            server_max_connections,
            server_max_queue,
        })
    }

    pub fn parse(frontend: &str, server: &str, queue: &str) -> CoreResult<Self> {
        Self::new(
            parse_decimal_u32(frontend, 1, MAX_CONNECTIONS, "HAProxy frontend maxconn")?,
            parse_decimal_u32(server, 1, MAX_CONNECTIONS, "HAProxy server maxconn")?,
            parse_decimal_u32(queue, 1, MAX_QUEUE, "HAProxy server maxqueue")?,
        )
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self {
            frontend_max_connections: 2_000,
            server_max_connections: 500,
            server_max_queue: 1_000,
        }
    }

    pub const fn frontend_max_connections(self) -> u32 {
        self.frontend_max_connections
    }

    pub const fn server_max_connections(self) -> u32 {
        self.server_max_connections
    }

    pub const fn server_max_queue(self) -> u32 {
        self.server_max_queue
    }

    fn validate(self) -> CoreResult<()> {
        Self::new(
            self.frontend_max_connections,
            self.server_max_connections,
            self.server_max_queue,
        )
        .map(|_| ())
    }
}

impl Default for HaProxyConnectionLimits {
    fn default() -> Self {
        Self::lovelyres_suggestion()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyRetryPolicy(u8);

impl HaProxyRetryPolicy {
    pub fn new(retries: u8) -> CoreResult<Self> {
        if !(1..=MAX_RETRIES).contains(&retries) {
            return Err(CoreError::validation(
                "HAProxy connection retries",
                format!("must be in 1..={MAX_RETRIES}"),
            ));
        }
        Ok(Self(retries))
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        Self::new(parse_decimal_u32(
            value,
            1,
            u32::from(MAX_RETRIES),
            "HAProxy connection retries",
        )? as u8)
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(2)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    fn validate(self) -> CoreResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl Default for HaProxyRetryPolicy {
    fn default() -> Self {
        Self::lovelyres_suggestion()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HaProxyRateLimit(u32);

impl HaProxyRateLimit {
    pub fn new(requests_per_ten_seconds: u32) -> CoreResult<Self> {
        if !(1..=MAX_RATE_LIMIT).contains(&requests_per_ten_seconds) {
            return Err(CoreError::validation(
                "HAProxy source rate limit",
                format!("must be in 1..={MAX_RATE_LIMIT} requests per ten seconds"),
            ));
        }
        Ok(Self(requests_per_ten_seconds))
    }

    pub fn parse(value: &str) -> CoreResult<Self> {
        Self::new(parse_decimal_u32(
            value,
            1,
            MAX_RATE_LIMIT,
            "HAProxy source rate limit",
        )?)
    }

    pub const fn lovelyres_suggestion() -> Self {
        Self(100)
    }

    pub const fn requests_per_ten_seconds(self) -> u32 {
        self.0
    }

    fn validate(self) -> CoreResult<()> {
        Self::new(self.0).map(|_| ())
    }
}

impl Default for HaProxyRateLimit {
    fn default() -> Self {
        Self::lovelyres_suggestion()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HaProxyHttpConfig {
    version: HaProxyVersion,
    listen_address: HaProxyListenAddress,
    listen_port: HaProxyListenPort,
    upstream: HaProxyUpstream,
    features: BTreeSet<HaProxyConfigFeature>,
    forbidden_path_rule: Option<HaProxyForbiddenPathRule>,
    allowed_source: Option<HaProxyAllowedSource>,
    timeout_profile: HaProxyTimeoutProfile,
    health_check: HaProxyHealthCheck,
    connection_limits: HaProxyConnectionLimits,
    retry_policy: HaProxyRetryPolicy,
    rate_limit: HaProxyRateLimit,
}

impl HaProxyHttpConfig {
    pub fn baseline(
        version: HaProxyVersion,
        listen_address: HaProxyListenAddress,
        listen_port: HaProxyListenPort,
        upstream: HaProxyUpstream,
    ) -> CoreResult<Self> {
        listen_port.validate()?;
        upstream.validate()?;
        let features = HaProxyConfigFeature::ALL
            .into_iter()
            .filter(|feature| feature.default_enabled())
            .collect();
        let config = Self {
            version,
            listen_address,
            listen_port,
            upstream,
            features,
            forbidden_path_rule: None,
            allowed_source: None,
            timeout_profile: HaProxyTimeoutProfile::default(),
            health_check: HaProxyHealthCheck::default(),
            connection_limits: HaProxyConnectionLimits::default(),
            retry_policy: HaProxyRetryPolicy::default(),
            rate_limit: HaProxyRateLimit::default(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn new(
        version: HaProxyVersion,
        listen_address: HaProxyListenAddress,
        listen_port: HaProxyListenPort,
        upstream: HaProxyUpstream,
    ) -> CoreResult<Self> {
        Self::baseline(version, listen_address, listen_port, upstream)
    }

    pub const fn version(&self) -> HaProxyVersion {
        self.version
    }

    pub const fn listen_address(&self) -> HaProxyListenAddress {
        self.listen_address
    }

    pub const fn listen_port(&self) -> HaProxyListenPort {
        self.listen_port
    }

    pub const fn upstream(&self) -> HaProxyUpstream {
        self.upstream
    }

    pub fn features(&self) -> &BTreeSet<HaProxyConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: HaProxyConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn forbidden_path_rule(&self) -> Option<&HaProxyForbiddenPathRule> {
        self.forbidden_path_rule.as_ref()
    }

    pub fn allowed_source(&self) -> Option<&HaProxyAllowedSource> {
        self.allowed_source.as_ref()
    }

    pub const fn timeout_profile(&self) -> HaProxyTimeoutProfile {
        self.timeout_profile
    }

    pub fn health_check(&self) -> &HaProxyHealthCheck {
        &self.health_check
    }

    pub const fn connection_limits(&self) -> HaProxyConnectionLimits {
        self.connection_limits
    }

    pub const fn retry_policy(&self) -> HaProxyRetryPolicy {
        self.retry_policy
    }

    pub const fn rate_limit(&self) -> HaProxyRateLimit {
        self.rate_limit
    }

    pub fn with_feature(
        mut self,
        feature: HaProxyConfigFeature,
        enabled: bool,
    ) -> CoreResult<Self> {
        if enabled && !feature.can_enable() {
            return Err(CoreError::validation(
                "HAProxy TLS frontend feature",
                HAPROXY_TLS_FRONTEND_DEFERRED_REASON,
            ));
        }
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate()?;
        Ok(self)
    }

    pub fn without_feature(self, feature: HaProxyConfigFeature) -> CoreResult<Self> {
        self.with_feature(feature, false)
    }

    pub fn reset_feature(mut self, feature: HaProxyConfigFeature) -> CoreResult<Self> {
        match feature {
            HaProxyConfigFeature::ForbiddenPath403 => self.forbidden_path_rule = None,
            HaProxyConfigFeature::RestrictSourceIp => self.allowed_source = None,
            HaProxyConfigFeature::TimeoutGuards | HaProxyConfigFeature::WebSocketTunnel => {
                self.timeout_profile = HaProxyTimeoutProfile::default();
            }
            HaProxyConfigFeature::HealthCheck => {
                self.health_check = HaProxyHealthCheck::default();
            }
            HaProxyConfigFeature::ConnectionLimits => {
                self.connection_limits = HaProxyConnectionLimits::default();
            }
            HaProxyConfigFeature::ConnectionRetries => {
                self.retry_policy = HaProxyRetryPolicy::default();
            }
            HaProxyConfigFeature::SourceRateLimit => {
                self.rate_limit = HaProxyRateLimit::default();
            }
            HaProxyConfigFeature::AccessLogging
            | HaProxyConfigFeature::ResponseCompression
            | HaProxyConfigFeature::TlsFrontend
            | HaProxyConfigFeature::RestrictRequestMethods
            | HaProxyConfigFeature::RequestId
            | HaProxyConfigFeature::SecurityResponseHeaders
            | HaProxyConfigFeature::HideUpstreamServerHeader
            | HaProxyConfigFeature::ForwardedHeaders => {}
        }
        if feature.default_enabled() {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate()?;
        Ok(self)
    }

    pub fn reset_all_features(mut self) -> CoreResult<Self> {
        self.features = HaProxyConfigFeature::ALL
            .into_iter()
            .filter(|feature| feature.default_enabled())
            .collect();
        self.forbidden_path_rule = None;
        self.allowed_source = None;
        self.timeout_profile = HaProxyTimeoutProfile::default();
        self.health_check = HaProxyHealthCheck::default();
        self.connection_limits = HaProxyConnectionLimits::default();
        self.retry_policy = HaProxyRetryPolicy::default();
        self.rate_limit = HaProxyRateLimit::default();
        self.validate()?;
        Ok(self)
    }

    pub fn with_forbidden_path_rule(mut self, rule: HaProxyForbiddenPathRule) -> CoreResult<Self> {
        rule.validate()?;
        self.forbidden_path_rule = Some(rule);
        self.features.insert(HaProxyConfigFeature::ForbiddenPath403);
        self.validate()?;
        Ok(self)
    }

    pub fn with_allowed_source(mut self, source: HaProxyAllowedSource) -> CoreResult<Self> {
        source.validate()?;
        self.allowed_source = Some(source);
        self.features.insert(HaProxyConfigFeature::RestrictSourceIp);
        self.validate()?;
        Ok(self)
    }

    pub fn with_timeout_profile(mut self, profile: HaProxyTimeoutProfile) -> CoreResult<Self> {
        profile.validate()?;
        self.timeout_profile = profile;
        self.features.insert(HaProxyConfigFeature::TimeoutGuards);
        self.validate()?;
        Ok(self)
    }

    pub fn with_health_check(mut self, health_check: HaProxyHealthCheck) -> CoreResult<Self> {
        health_check.validate()?;
        self.health_check = health_check;
        self.features.insert(HaProxyConfigFeature::HealthCheck);
        self.validate()?;
        Ok(self)
    }

    pub fn with_connection_limits(mut self, limits: HaProxyConnectionLimits) -> CoreResult<Self> {
        limits.validate()?;
        self.connection_limits = limits;
        self.features.insert(HaProxyConfigFeature::ConnectionLimits);
        self.validate()?;
        Ok(self)
    }

    pub fn with_retry_policy(mut self, policy: HaProxyRetryPolicy) -> CoreResult<Self> {
        policy.validate()?;
        self.retry_policy = policy;
        self.features
            .insert(HaProxyConfigFeature::ConnectionRetries);
        self.validate()?;
        Ok(self)
    }

    pub fn with_rate_limit(mut self, limit: HaProxyRateLimit) -> CoreResult<Self> {
        limit.validate()?;
        self.rate_limit = limit;
        self.features.insert(HaProxyConfigFeature::SourceRateLimit);
        self.validate()?;
        Ok(self)
    }

    pub fn generate(&self) -> CoreResult<GeneratedHaProxyConfig> {
        self.validate()?;
        let contents = self.render_unchecked();
        parse_generated_config(self.version, &contents)?;
        Ok(GeneratedHaProxyConfig {
            version: self.version,
            contents,
        })
    }

    pub fn parse_generated(version: HaProxyVersion, contents: &str) -> CoreResult<Self> {
        parse_generated_config(version, contents)
    }

    fn validate(&self) -> CoreResult<()> {
        self.listen_port.validate()?;
        self.upstream.validate()?;
        self.timeout_profile.validate()?;
        self.health_check.validate()?;
        self.connection_limits.validate()?;
        self.retry_policy.validate()?;
        self.rate_limit.validate()?;
        if let Some(rule) = &self.forbidden_path_rule {
            rule.validate()?;
        }
        if let Some(source) = &self.allowed_source {
            source.validate()?;
        }
        for feature in &self.features {
            if !feature.supports_version(self.version) {
                return Err(CoreError::validation(
                    "HAProxy configuration feature",
                    format!(
                        "{} is not supported by HAProxy {}",
                        feature.title(),
                        self.version.label()
                    ),
                ));
            }
            if !feature.can_enable() {
                return Err(CoreError::validation(
                    "HAProxy TLS frontend feature",
                    HAPROXY_TLS_FRONTEND_DEFERRED_REASON,
                ));
            }
        }
        if self.feature_enabled(HaProxyConfigFeature::ForbiddenPath403)
            && self.forbidden_path_rule.is_none()
        {
            return Err(CoreError::validation(
                "HAProxy forbidden path feature",
                "requires one validated forbidden path rule",
            ));
        }
        if self.feature_enabled(HaProxyConfigFeature::RestrictSourceIp)
            && self.allowed_source.is_none()
        {
            return Err(CoreError::validation(
                "HAProxy source restriction feature",
                "requires one validated IP address or CIDR",
            ));
        }
        Ok(())
    }

    fn render_unchecked(&self) -> String {
        let logging = self.feature_enabled(HaProxyConfigFeature::AccessLogging);
        let limits = self.feature_enabled(HaProxyConfigFeature::ConnectionLimits);
        let mut contents = String::with_capacity(4_096);
        contents.push_str(
            "# LovelyRes local HAProxy draft; no deployment or runtime validation was performed.\n",
        );
        contents.push_str("# Target branch: ");
        contents.push_str(self.version.label());
        contents.push_str(" (");
        contents.push_str(self.version.channel());
        contents.push_str(")\n");
        contents.push_str("# Validate with the exact target HAProxy binary before any reload.\n\n");

        if logging || limits {
            contents.push_str("global\n");
            if logging {
                contents.push_str("    log stdout format raw local0\n");
            }
            if limits {
                contents.push_str("    maxconn ");
                contents.push_str(
                    &self
                        .connection_limits
                        .frontend_max_connections()
                        .to_string(),
                );
                contents.push('\n');
            }
            contents.push('\n');
        }

        contents.push_str("defaults\n    mode http\n");
        if logging {
            contents.push_str("    log global\n    option httplog\n");
        }
        push_timeout_line(
            &mut contents,
            "connect",
            self.timeout_profile.connect_seconds(),
        );
        push_timeout_line(
            &mut contents,
            "client",
            self.timeout_profile.client_seconds(),
        );
        push_timeout_line(
            &mut contents,
            "server",
            self.timeout_profile.server_seconds(),
        );
        if self.feature_enabled(HaProxyConfigFeature::TimeoutGuards) {
            push_timeout_line(
                &mut contents,
                "http-request",
                self.timeout_profile.http_request_seconds(),
            );
            push_timeout_line(&mut contents, "queue", self.timeout_profile.queue_seconds());
        }
        if self.feature_enabled(HaProxyConfigFeature::WebSocketTunnel) {
            push_timeout_line(
                &mut contents,
                "tunnel",
                self.timeout_profile.tunnel_seconds(),
            );
        }
        contents.push_str("    retries ");
        if self.feature_enabled(HaProxyConfigFeature::ConnectionRetries) {
            contents.push_str(&self.retry_policy.get().to_string());
            contents.push_str("\n    retry-on conn-failure\n");
        } else {
            contents.push_str("0\n");
        }

        contents.push_str("\nfrontend ");
        contents.push_str(FRONTEND_NAME);
        contents.push_str("\n    bind ");
        contents.push_str(
            &SocketAddr::new(self.listen_address.get(), self.listen_port.get()).to_string(),
        );
        contents.push('\n');
        if limits {
            contents.push_str("    maxconn ");
            contents.push_str(
                &self
                    .connection_limits
                    .frontend_max_connections()
                    .to_string(),
            );
            contents.push('\n');
        }
        if self.feature_enabled(HaProxyConfigFeature::SourceRateLimit) {
            contents.push_str(
                "    stick-table type ip size 100k expire 30s store http_req_rate(10s)\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::RequestId) {
            contents.push_str("    unique-id-format ");
            contents.push_str(REQUEST_ID_FORMAT);
            contents.push_str("\n    unique-id-header X-Request-ID\n");
        }
        if let Some(rule) = self
            .feature_enabled(HaProxyConfigFeature::ForbiddenPath403)
            .then_some(self.forbidden_path_rule.as_ref())
            .flatten()
        {
            contents.push_str("    acl lovelyres_forbidden_exact path -m str ");
            contents.push_str(rule.path().as_str());
            contents
                .push_str("\n    http-request deny deny_status 403 if lovelyres_forbidden_exact\n");
            if rule.scope() == HaProxyForbiddenPathScope::PathAndDescendants {
                contents.push_str("    acl lovelyres_forbidden_descendant path_beg ");
                contents.push_str(rule.path().as_str());
                contents.push_str(
                    "/\n    http-request deny deny_status 403 if lovelyres_forbidden_descendant\n",
                );
            }
        }
        if let Some(source) = self
            .feature_enabled(HaProxyConfigFeature::RestrictSourceIp)
            .then_some(self.allowed_source.as_ref())
            .flatten()
        {
            contents.push_str("    acl lovelyres_source_allowed src ");
            contents.push_str(source.as_str());
            contents.push_str(
                "\n    http-request deny deny_status 403 unless lovelyres_source_allowed\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::RestrictRequestMethods) {
            contents.push_str(
                "    acl lovelyres_method_allowed method GET HEAD\n    http-request deny deny_status 405 unless lovelyres_method_allowed\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::SourceRateLimit) {
            contents.push_str("    http-request track-sc0 src\n    http-request deny deny_status 429 if { sc_http_req_rate(0) gt ");
            contents.push_str(&self.rate_limit.requests_per_ten_seconds().to_string());
            contents.push_str(" }\n");
        }
        if self.feature_enabled(HaProxyConfigFeature::ForwardedHeaders) {
            contents.push_str(
                "    http-request del-header Forwarded\n    http-request del-header X-Forwarded-For\n    http-request del-header X-Forwarded-Proto\n    http-request set-header X-Forwarded-For %[src]\n    http-request set-header X-Forwarded-Proto http\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::RequestId) {
            contents.push_str(
                "    http-request del-header X-Request-ID\n    http-response set-header X-Request-ID %ID\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::SecurityResponseHeaders) {
            contents.push_str(
                "    http-response set-header X-Content-Type-Options nosniff\n    http-response set-header X-Frame-Options SAMEORIGIN\n    http-response set-header Referrer-Policy strict-origin-when-cross-origin\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::HideUpstreamServerHeader) {
            contents.push_str("    http-response del-header Server\n");
        }
        contents.push_str("    default_backend ");
        contents.push_str(BACKEND_NAME);
        contents.push_str("\n\nbackend ");
        contents.push_str(BACKEND_NAME);
        contents.push('\n');
        if self.feature_enabled(HaProxyConfigFeature::ResponseCompression) {
            contents.push_str(
                "    compression algo gzip\n    compression type text/html text/plain text/css application/javascript application/json application/xml image/svg+xml\n",
            );
        }
        if self.feature_enabled(HaProxyConfigFeature::HealthCheck) {
            contents.push_str("    option httpchk\n    http-check send meth GET uri ");
            contents.push_str(self.health_check.path());
            contents.push_str(" ver HTTP/1.0\n    http-check expect status 200-399\n");
        }
        contents.push_str("    server ");
        contents.push_str(SERVER_NAME);
        contents.push(' ');
        contents.push_str(&self.upstream.get().to_string());
        if self.feature_enabled(HaProxyConfigFeature::HealthCheck) {
            contents.push_str(" check inter ");
            contents.push_str(&self.health_check.interval_seconds().to_string());
            contents.push_str("s fall ");
            contents.push_str(&self.health_check.fall().to_string());
            contents.push_str(" rise ");
            contents.push_str(&self.health_check.rise().to_string());
        }
        if limits {
            contents.push_str(" maxconn ");
            contents.push_str(&self.connection_limits.server_max_connections().to_string());
            contents.push_str(" maxqueue ");
            contents.push_str(&self.connection_limits.server_max_queue().to_string());
        }
        contents.push('\n');
        contents
    }
}

fn push_timeout_line(contents: &mut String, keyword: &str, seconds: u32) {
    contents.push_str("    timeout ");
    contents.push_str(keyword);
    contents.push(' ');
    contents.push_str(&seconds.to_string());
    contents.push_str("s\n");
}

fn parse_generated_config(
    version: HaProxyVersion,
    contents: &str,
) -> CoreResult<HaProxyHttpConfig> {
    validate_generated_framing(contents)?;
    let mut cursor = HaProxyLineCursor::new(contents);
    cursor.expect(
        "# LovelyRes local HAProxy draft; no deployment or runtime validation was performed.",
    )?;
    cursor.expect(&format!(
        "# Target branch: {} ({})",
        version.label(),
        version.channel()
    ))?;
    cursor.expect("# Validate with the exact target HAProxy binary before any reload.")?;
    cursor.expect("")?;

    let mut logging = false;
    let mut global_maxconn = None;
    if cursor.peek() == Some("global") {
        cursor.expect("global")?;
        if cursor.peek() == Some("    log stdout format raw local0") {
            cursor.expect("    log stdout format raw local0")?;
            logging = true;
        }
        if let Some(value) = cursor.take_prefix("    maxconn ") {
            global_maxconn = Some(parse_decimal_u32(
                value,
                1,
                MAX_CONNECTIONS,
                "HAProxy global maxconn",
            )?);
        }
        if !logging && global_maxconn.is_none() {
            return Err(closed_document_error("empty global section is forbidden"));
        }
        cursor.expect("")?;
    }

    cursor.expect("defaults")?;
    cursor.expect("    mode http")?;
    if logging {
        cursor.expect("    log global")?;
        cursor.expect("    option httplog")?;
    } else if matches!(
        cursor.peek(),
        Some("    log global") | Some("    option httplog")
    ) {
        return Err(closed_document_error(
            "logging directives require the closed stdout global target",
        ));
    }
    let connect_seconds = cursor.take_timeout("connect")?;
    let client_seconds = cursor.take_timeout("client")?;
    let server_seconds = cursor.take_timeout("server")?;
    let mut features = BTreeSet::new();
    if logging {
        features.insert(HaProxyConfigFeature::AccessLogging);
    }

    let suggestion = HaProxyTimeoutProfile::default();
    let (http_request_seconds, queue_seconds) = if cursor.peek_prefix("    timeout http-request ") {
        let http_request = cursor.take_timeout("http-request")?;
        let queue = cursor.take_timeout("queue")?;
        features.insert(HaProxyConfigFeature::TimeoutGuards);
        (http_request, queue)
    } else {
        (
            suggestion.http_request_seconds(),
            suggestion.queue_seconds(),
        )
    };
    let tunnel_seconds = if cursor.peek_prefix("    timeout tunnel ") {
        let tunnel = cursor.take_timeout("tunnel")?;
        features.insert(HaProxyConfigFeature::WebSocketTunnel);
        tunnel
    } else {
        suggestion.tunnel_seconds()
    };
    let timeout_profile = HaProxyTimeoutProfile::new(
        connect_seconds,
        client_seconds,
        server_seconds,
        http_request_seconds,
        queue_seconds,
        tunnel_seconds,
    )?;

    let retry_value = cursor
        .take_prefix("    retries ")
        .ok_or_else(|| closed_document_error("defaults section is missing explicit retries"))?;
    let retry_number =
        parse_decimal_u32(retry_value, 0, u32::from(MAX_RETRIES), "HAProxy retries")?;
    let retry_policy = if retry_number == 0 {
        HaProxyRetryPolicy::default()
    } else {
        cursor.expect("    retry-on conn-failure")?;
        features.insert(HaProxyConfigFeature::ConnectionRetries);
        HaProxyRetryPolicy::new(retry_number as u8)?
    };
    cursor.expect("")?;

    cursor.expect(&format!("frontend {FRONTEND_NAME}"))?;
    let bind = cursor
        .take_prefix("    bind ")
        .ok_or_else(|| closed_document_error("frontend is missing one bind socket"))?;
    let bind = bind.parse::<SocketAddr>().map_err(|_| {
        CoreError::validation(
            "generated HAProxy bind",
            "must be one canonical IP-literal socket",
        )
    })?;
    if bind.port() == 0 {
        return Err(CoreError::validation(
            "generated HAProxy bind",
            "port zero is forbidden",
        ));
    }
    let listen_address = HaProxyListenAddress(bind.ip());
    let listen_port = HaProxyListenPort(bind.port());

    let frontend_maxconn = cursor
        .take_prefix("    maxconn ")
        .map(|value| parse_decimal_u32(value, 1, MAX_CONNECTIONS, "HAProxy frontend maxconn"))
        .transpose()?;
    if cursor.peek()
        == Some("    stick-table type ip size 100k expire 30s store http_req_rate(10s)")
    {
        cursor.expect("    stick-table type ip size 100k expire 30s store http_req_rate(10s)")?;
        features.insert(HaProxyConfigFeature::SourceRateLimit);
    }
    let request_id = cursor.peek_prefix("    unique-id-format ");
    if request_id {
        cursor.expect(&format!("    unique-id-format {REQUEST_ID_FORMAT}"))?;
        cursor.expect("    unique-id-header X-Request-ID")?;
        features.insert(HaProxyConfigFeature::RequestId);
    }

    let forbidden_path_rule =
        if let Some(path) = cursor.take_prefix("    acl lovelyres_forbidden_exact path -m str ") {
            let path = HaProxyForbiddenPath::parse(path)?;
            cursor.expect("    http-request deny deny_status 403 if lovelyres_forbidden_exact")?;
            let scope = if let Some(descendant) =
                cursor.take_prefix("    acl lovelyres_forbidden_descendant path_beg ")
            {
                let expected = format!("{}/", path.as_str());
                if descendant != expected {
                    return Err(closed_document_error(
                        "forbidden descendant ACL must use the exact path plus one slash",
                    ));
                }
                cursor.expect(
                    "    http-request deny deny_status 403 if lovelyres_forbidden_descendant",
                )?;
                HaProxyForbiddenPathScope::PathAndDescendants
            } else {
                HaProxyForbiddenPathScope::Exact
            };
            features.insert(HaProxyConfigFeature::ForbiddenPath403);
            Some(HaProxyForbiddenPathRule::new(path, scope)?)
        } else {
            None
        };

    let allowed_source = if let Some(source) =
        cursor.take_prefix("    acl lovelyres_source_allowed src ")
    {
        let source = HaProxyAllowedSource::parse(source)?;
        cursor.expect("    http-request deny deny_status 403 unless lovelyres_source_allowed")?;
        features.insert(HaProxyConfigFeature::RestrictSourceIp);
        Some(source)
    } else {
        None
    };
    if cursor.peek() == Some("    acl lovelyres_method_allowed method GET HEAD") {
        cursor.expect("    acl lovelyres_method_allowed method GET HEAD")?;
        cursor.expect("    http-request deny deny_status 405 unless lovelyres_method_allowed")?;
        features.insert(HaProxyConfigFeature::RestrictRequestMethods);
    }

    let rate_limit = if features.contains(&HaProxyConfigFeature::SourceRateLimit) {
        cursor.expect("    http-request track-sc0 src")?;
        let value = cursor
            .take_prefix("    http-request deny deny_status 429 if { sc_http_req_rate(0) gt ")
            .ok_or_else(|| closed_document_error("source rate limit is missing its deny rule"))?;
        let value = value
            .strip_suffix(" }")
            .ok_or_else(|| closed_document_error("source rate limit ACL is not canonical"))?;
        HaProxyRateLimit::parse(value)?
    } else {
        HaProxyRateLimit::default()
    };

    if cursor.peek() == Some("    http-request del-header Forwarded") {
        cursor.expect("    http-request del-header Forwarded")?;
        cursor.expect("    http-request del-header X-Forwarded-For")?;
        cursor.expect("    http-request del-header X-Forwarded-Proto")?;
        cursor.expect("    http-request set-header X-Forwarded-For %[src]")?;
        cursor.expect("    http-request set-header X-Forwarded-Proto http")?;
        features.insert(HaProxyConfigFeature::ForwardedHeaders);
    }
    if request_id {
        cursor.expect("    http-request del-header X-Request-ID")?;
        cursor.expect("    http-response set-header X-Request-ID %ID")?;
    }
    if cursor.peek() == Some("    http-response set-header X-Content-Type-Options nosniff") {
        cursor.expect("    http-response set-header X-Content-Type-Options nosniff")?;
        cursor.expect("    http-response set-header X-Frame-Options SAMEORIGIN")?;
        cursor.expect(
            "    http-response set-header Referrer-Policy strict-origin-when-cross-origin",
        )?;
        features.insert(HaProxyConfigFeature::SecurityResponseHeaders);
    }
    if cursor.peek() == Some("    http-response del-header Server") {
        cursor.expect("    http-response del-header Server")?;
        features.insert(HaProxyConfigFeature::HideUpstreamServerHeader);
    }
    cursor.expect(&format!("    default_backend {BACKEND_NAME}"))?;
    cursor.expect("")?;

    cursor.expect(&format!("backend {BACKEND_NAME}"))?;
    if cursor.peek() == Some("    compression algo gzip") {
        cursor.expect("    compression algo gzip")?;
        cursor.expect("    compression type text/html text/plain text/css application/javascript application/json application/xml image/svg+xml")?;
        features.insert(HaProxyConfigFeature::ResponseCompression);
    }
    let health_path = if cursor.peek() == Some("    option httpchk") {
        cursor.expect("    option httpchk")?;
        let line = cursor
            .take_prefix("    http-check send meth GET uri ")
            .ok_or_else(|| closed_document_error("health check is missing its request"))?;
        let path = line
            .strip_suffix(" ver HTTP/1.0")
            .ok_or_else(|| closed_document_error("health-check request is not canonical"))?;
        let path = parse_canonical_http_path(path, "HAProxy health-check path")?;
        cursor.expect("    http-check expect status 200-399")?;
        features.insert(HaProxyConfigFeature::HealthCheck);
        Some(path)
    } else {
        None
    };

    let server_line = cursor
        .take_prefix(&format!("    server {SERVER_NAME} "))
        .ok_or_else(|| closed_document_error("backend is missing its one typed server"))?;
    cursor.finish()?;
    let tokens = split_canonical_tokens(server_line)?;
    let upstream_token = tokens
        .first()
        .ok_or_else(|| closed_document_error("server address is missing"))?;
    let upstream = HaProxyUpstream::parse(upstream_token)?;
    let mut position = 1;

    let health_check = if let Some(path) = health_path {
        expect_token(&tokens, &mut position, "check")?;
        expect_token(&tokens, &mut position, "inter")?;
        let interval = take_seconds_token(
            &tokens,
            &mut position,
            1,
            300,
            "HAProxy health-check interval",
        )?;
        expect_token(&tokens, &mut position, "fall")?;
        let fall = take_decimal_token(
            &tokens,
            &mut position,
            1,
            10,
            "HAProxy health-check fall threshold",
        )? as u8;
        expect_token(&tokens, &mut position, "rise")?;
        let rise = take_decimal_token(
            &tokens,
            &mut position,
            1,
            10,
            "HAProxy health-check rise threshold",
        )? as u8;
        HaProxyHealthCheck::new(&path, interval, fall, rise)?
    } else {
        HaProxyHealthCheck::default()
    };

    let connection_limits = if let Some(frontend) = frontend_maxconn {
        let global = global_maxconn.ok_or_else(|| {
            closed_document_error("frontend maxconn requires the same global maxconn")
        })?;
        if global != frontend {
            return Err(closed_document_error(
                "global and frontend maxconn must be identical",
            ));
        }
        expect_token(&tokens, &mut position, "maxconn")?;
        let server = take_decimal_token(
            &tokens,
            &mut position,
            1,
            MAX_CONNECTIONS,
            "HAProxy server maxconn",
        )?;
        expect_token(&tokens, &mut position, "maxqueue")?;
        let queue = take_decimal_token(
            &tokens,
            &mut position,
            1,
            MAX_QUEUE,
            "HAProxy server maxqueue",
        )?;
        features.insert(HaProxyConfigFeature::ConnectionLimits);
        HaProxyConnectionLimits::new(frontend, server, queue)?
    } else {
        if global_maxconn.is_some() {
            return Err(closed_document_error(
                "global maxconn requires matching frontend and server limits",
            ));
        }
        HaProxyConnectionLimits::default()
    };
    if position != tokens.len() {
        return Err(closed_document_error(
            "server line contains an unknown or out-of-order option",
        ));
    }

    let config = HaProxyHttpConfig {
        version,
        listen_address,
        listen_port,
        upstream,
        features,
        forbidden_path_rule,
        allowed_source,
        timeout_profile,
        health_check,
        connection_limits,
        retry_policy,
        rate_limit,
    };
    config.validate()?;
    if config.render_unchecked() != contents {
        return Err(closed_document_error(
            "document is not the canonical rendering of its typed values",
        ));
    }
    Ok(config)
}

struct HaProxyLineCursor<'a> {
    lines: Vec<&'a str>,
    position: usize,
}

impl<'a> HaProxyLineCursor<'a> {
    fn new(contents: &'a str) -> Self {
        Self {
            lines: contents.split_terminator('\n').collect(),
            position: 0,
        }
    }

    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.position).copied()
    }

    fn peek_prefix(&self, prefix: &str) -> bool {
        self.peek().is_some_and(|line| line.starts_with(prefix))
    }

    fn expect(&mut self, expected: &str) -> CoreResult<()> {
        let line_number = self.position + 1;
        let actual = self.peek().ok_or_else(|| {
            closed_document_error(format!(
                "line {line_number} is missing; expected {expected:?}"
            ))
        })?;
        if actual != expected {
            return Err(closed_document_error(format!(
                "line {line_number} must be {expected:?}, got {actual:?}"
            )));
        }
        self.position += 1;
        Ok(())
    }

    fn take_prefix(&mut self, prefix: &str) -> Option<&'a str> {
        let suffix = self.peek()?.strip_prefix(prefix)?;
        self.position += 1;
        Some(suffix)
    }

    fn take_timeout(&mut self, keyword: &str) -> CoreResult<u32> {
        let prefix = format!("    timeout {keyword} ");
        let value = self.take_prefix(&prefix).ok_or_else(|| {
            closed_document_error(format!("missing canonical timeout {keyword} directive"))
        })?;
        parse_seconds(value, 1, MAX_TIMEOUT_SECONDS, "HAProxy timeout")
    }

    fn finish(&self) -> CoreResult<()> {
        if self.position != self.lines.len() {
            return Err(closed_document_error(format!(
                "unexpected content begins at line {}",
                self.position + 1
            )));
        }
        Ok(())
    }
}

fn split_canonical_tokens(line: &str) -> CoreResult<Vec<&str>> {
    if line.is_empty()
        || line.starts_with(' ')
        || line.ends_with(' ')
        || line.contains("  ")
        || line.contains('\t')
    {
        return Err(closed_document_error(
            "server options must use one ASCII space between non-empty tokens",
        ));
    }
    Ok(line.split(' ').collect())
}

fn expect_token(tokens: &[&str], position: &mut usize, expected: &str) -> CoreResult<()> {
    let actual = tokens
        .get(*position)
        .ok_or_else(|| closed_document_error(format!("missing server option {expected}")))?;
    if *actual != expected {
        return Err(closed_document_error(format!(
            "expected server option {expected}, got {actual}"
        )));
    }
    *position += 1;
    Ok(())
}

fn take_decimal_token(
    tokens: &[&str],
    position: &mut usize,
    minimum: u32,
    maximum: u32,
    subject: &'static str,
) -> CoreResult<u32> {
    let value = tokens
        .get(*position)
        .ok_or_else(|| closed_document_error(format!("missing {subject}")))?;
    *position += 1;
    parse_decimal_u32(value, minimum, maximum, subject)
}

fn take_seconds_token(
    tokens: &[&str],
    position: &mut usize,
    minimum: u32,
    maximum: u32,
    subject: &'static str,
) -> CoreResult<u32> {
    let value = tokens
        .get(*position)
        .ok_or_else(|| closed_document_error(format!("missing {subject}")))?;
    *position += 1;
    parse_seconds(value, minimum, maximum, subject)
}

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedHaProxyConfig {
    version: HaProxyVersion,
    contents: String,
}

impl fmt::Debug for GeneratedHaProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedHaProxyConfig")
            .field("version", &self.version)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

impl GeneratedHaProxyConfig {
    pub fn parse(version: HaProxyVersion, contents: &str) -> CoreResult<Self> {
        parse_generated_config(version, contents)?;
        Ok(Self {
            version,
            contents: contents.to_owned(),
        })
    }

    pub const fn version(&self) -> HaProxyVersion {
        self.version
    }

    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub fn suggested_file_name(&self) -> String {
        format!(
            "lovelyres-haproxy-{}-http-reverse-proxy.cfg",
            self.version.label()
        )
    }

    /// Writes a new local draft and never replaces an existing path.
    ///
    /// A failure after `create_new` triggers a best-effort removal. If that
    /// cleanup also fails, `PartialCleanup` exposes the exact path that may
    /// still contain a partial draft.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_export_destination(destination)?;
        parse_generated_config(self.version, &self.contents)?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|source| {
                CoreError::io(
                    "create generated HAProxy configuration draft",
                    destination,
                    source,
                )
            })?;
        let write_result = (|| {
            file.write_all(self.contents.as_bytes()).map_err(|source| {
                CoreError::io(
                    "write generated HAProxy configuration draft",
                    destination,
                    source,
                )
            })?;
            file.flush().map_err(|source| {
                CoreError::io(
                    "flush generated HAProxy configuration draft",
                    destination,
                    source,
                )
            })?;
            file.sync_all().map_err(|source| {
                CoreError::io(
                    "sync generated HAProxy configuration draft",
                    destination,
                    source,
                )
            })
        })();
        drop(file);

        if let Err(write_error) = write_result {
            return Err(combine_write_and_cleanup_result(
                destination,
                write_error,
                fs::remove_file(destination),
            ));
        }
        Ok(destination.to_path_buf())
    }
}

fn parse_decimal_u32(
    value: &str,
    minimum: u32,
    maximum: u32,
    subject: &'static str,
) -> CoreResult<u32> {
    if value.is_empty()
        || value.len() > 10
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(CoreError::validation(
            subject,
            format!("must be canonical decimal digits in {minimum}..={maximum}"),
        ));
    }
    let parsed = value
        .parse::<u32>()
        .map_err(|_| CoreError::validation(subject, "decimal value is out of range"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(CoreError::validation(
            subject,
            format!("must be in {minimum}..={maximum}"),
        ));
    }
    Ok(parsed)
}

fn parse_seconds(
    value: &str,
    minimum: u32,
    maximum: u32,
    subject: &'static str,
) -> CoreResult<u32> {
    let decimal = value.strip_suffix('s').ok_or_else(|| {
        CoreError::validation(subject, "must use an explicit whole-second s suffix")
    })?;
    parse_decimal_u32(decimal, minimum, maximum, subject)
}

fn parse_canonical_http_path(value: &str, subject: &'static str) -> CoreResult<String> {
    if value.len() < 2
        || value.len() > MAX_HTTP_PATH_BYTES
        || value != value.trim()
        || !value.is_ascii()
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
    {
        return Err(CoreError::validation(
            subject,
            "must be a bounded canonical ASCII path such as /healthz, without a trailing slash",
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
            subject,
            "each segment may contain only ASCII letters, digits, hyphen, underscore, dot, or tilde",
        ));
    }
    Ok(value.to_owned())
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
            "HAProxy allowed source",
            "CIDR prefix exceeds the address family width",
        )),
    }
}

fn validate_generated_framing(contents: &str) -> CoreResult<()> {
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_HAPROXY_CONFIG_BYTES
        || !contents.ends_with('\n')
        || contents.contains('\0')
        || contents.contains('\r')
        || contents.contains('\t')
        || contents
            .split_terminator('\n')
            .any(|line| line.len() > 2_048 || line.ends_with(' '))
    {
        return Err(CoreError::validation(
            "generated HAProxy configuration",
            format!(
                "must be non-empty LF-only UTF-8 without NUL, tabs, trailing spaces, oversized lines, and at most {MAX_GENERATED_HAPROXY_CONFIG_BYTES} bytes"
            ),
        ));
    }
    Ok(())
}

fn closed_document_error(message: impl Into<String>) -> CoreError {
    CoreError::validation("generated HAProxy configuration", message)
}

fn validate_export_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "generated HAProxy configuration destination",
            "must be an absolute path selected by the native save dialog",
        ));
    }
    if destination
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "generated HAProxy configuration destination",
            "must not contain current-directory or parent-directory components",
        ));
    }
    if !destination
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("cfg"))
    {
        return Err(CoreError::validation(
            "generated HAProxy configuration destination",
            "must use the .cfg extension",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation(
            "generated HAProxy configuration destination",
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "generated HAProxy configuration destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

fn combine_write_and_cleanup_result(
    destination: &Path,
    write_error: CoreError,
    cleanup_result: std::io::Result<()>,
) -> CoreError {
    match cleanup_result {
        Ok(()) => write_error,
        Err(cleanup_error) => CoreError::PartialCleanup {
            operation: "write generated HAProxy configuration draft",
            path: destination.to_path_buf(),
            primary: Box::new(write_error),
            cleanup_failures: format!(
                "removing the possible partial file failed: {cleanup_error}; inspect and remove this exact path manually"
            ),
        },
    }
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
                std::env::temp_dir().join(format!("lovelyres-haproxy-config-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn baseline(version: HaProxyVersion) -> HaProxyHttpConfig {
        HaProxyHttpConfig::baseline(
            version,
            HaProxyListenAddress::all_ipv4(),
            HaProxyListenPort::parse("8080").unwrap(),
            HaProxyUpstream::parse("127.0.0.1:3000").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn versions_are_explicit_and_34_lts_is_the_default_recommendation() {
        assert_eq!(HaProxyVersion::default(), HaProxyVersion::V34Lts);
        assert_eq!(
            HaProxyVersion::ALL,
            [
                HaProxyVersion::V34Lts,
                HaProxyVersion::V33Stable,
                HaProxyVersion::V32Lts,
                HaProxyVersion::V30Lts,
                HaProxyVersion::V28Compatibility,
                HaProxyVersion::V26Compatibility,
            ]
        );
        for version in HaProxyVersion::ALL {
            assert_eq!(HaProxyVersion::parse(version.label()).unwrap(), version);
            assert!(
                version
                    .official_documentation()
                    .starts_with("https://docs.haproxy.org/")
            );
            assert!(!version.support_horizon().is_empty());
            assert!(!version.support_notice().is_empty());
        }
        assert!(HaProxyVersion::V34Lts.is_default_recommendation());
        assert!(HaProxyVersion::V34Lts.channel().contains("LTS"));
        assert!(HaProxyVersion::V33Stable.channel().contains("stable"));
        assert!(
            HaProxyVersion::V28Compatibility
                .channel()
                .contains("compatibility")
        );
        for invalid in ["", "3.4.0", "v3.4", " 3.4", "3.1", "2.9", "3.5"] {
            assert!(HaProxyVersion::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn feature_metadata_is_complete_unique_and_bounded_to_sixteen_entries() {
        assert_eq!(HaProxyConfigFeature::ALL.len(), 16);
        let keys = HaProxyConfigFeature::ALL
            .into_iter()
            .map(HaProxyConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), HaProxyConfigFeature::ALL.len());
        for feature in HaProxyConfigFeature::ALL {
            assert!(!feature.key().is_empty());
            assert!(!feature.title().is_empty());
            assert!(!feature.summary().is_empty());
            assert!(!feature.scope().is_empty());
            assert!(!feature.risk().is_empty());
            assert!(!feature.activation().is_empty());
            assert!(!feature.aliases().is_empty());
            for version in HaProxyVersion::ALL {
                assert!(feature.supports_version(version));
                assert_eq!(
                    feature.official_reference(version),
                    version.official_documentation()
                );
            }
        }
        assert_eq!(
            HaProxyConfigFeature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                HaProxyConfigFeature::TimeoutGuards,
                HaProxyConfigFeature::SecurityResponseHeaders,
                HaProxyConfigFeature::HideUpstreamServerHeader,
                HaProxyConfigFeature::ForwardedHeaders,
            ])
        );
    }

    #[test]
    fn typed_network_and_path_fields_reject_token_and_path_boundaries() {
        assert_eq!(
            HaProxyListenAddress::parse("::1").unwrap().get(),
            "::1".parse::<IpAddr>().unwrap()
        );
        for invalid in ["", "localhost", "127.0.0.1 ", "127.0.0.1#x"] {
            assert!(HaProxyListenAddress::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in ["0", "080", "65536", "80 # injected", " 80"] {
            assert!(HaProxyListenPort::parse(invalid).is_err(), "{invalid:?}");
        }
        assert!(HaProxyUpstream::parse("[2001:db8::1]:8443").is_ok());
        for invalid in [
            "localhost:3000",
            "0.0.0.0:3000",
            "[::]:3000",
            "127.0.0.1:0",
            "224.0.0.1:80",
            "127.0.0.1:3000 check",
        ] {
            assert!(HaProxyUpstream::parse(invalid).is_err(), "{invalid:?}");
        }
        for invalid in [
            "/",
            "/admin/",
            "/admin//child",
            "/../admin",
            "/admin?x=1",
            "/admin%2fchild",
            "/admin # rule",
        ] {
            assert!(HaProxyForbiddenPath::parse(invalid).is_err(), "{invalid:?}");
            assert!(HaProxyHealthCheck::new(invalid, 5, 3, 2).is_err());
        }
    }

    #[test]
    fn source_cidr_is_canonical_and_strict() {
        assert_eq!(
            HaProxyAllowedSource::parse("192.0.2.129/24")
                .unwrap()
                .as_str(),
            "192.0.2.0/24"
        );
        assert_eq!(
            HaProxyAllowedSource::parse("2001:db8::7/64")
                .unwrap()
                .as_str(),
            "2001:db8::/64"
        );
        for invalid in [
            "192.0.2.1 10.0.0.1",
            "192.0.2.1/33",
            "2001:db8::1/129",
            "192.0.2.1 # comment",
            "192.0.2.1/24/1",
        ] {
            assert!(HaProxyAllowedSource::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn baseline_is_deterministic_strictly_parseable_and_contains_no_tls_placeholder() {
        let config = baseline(HaProxyVersion::V34Lts);
        let first = config.generate().unwrap();
        let second = config.generate().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.version(), HaProxyVersion::V34Lts);
        assert!(first.contents().ends_with('\n'));
        assert!(first.contents().len() <= MAX_GENERATED_HAPROXY_CONFIG_BYTES);
        assert!(first.contents().contains("frontend lovelyres_http_in"));
        assert!(first.contents().contains("bind 0.0.0.0:8080"));
        assert!(first.contents().contains("backend lovelyres_app"));
        assert!(
            first
                .contents()
                .contains("server lovelyres_app 127.0.0.1:3000")
        );
        assert!(first.contents().contains("timeout connect 5s"));
        assert!(first.contents().contains("retries 0"));
        assert!(!first.contents().contains(" crt "));
        assert!(!first.contents().contains(" ssl"));
        assert!(!first.contents().contains("password"));
        assert!(!first.contents().contains("secret"));
        assert_eq!(
            HaProxyHttpConfig::parse_generated(HaProxyVersion::V34Lts, first.contents())
                .unwrap()
                .generate()
                .unwrap(),
            first
        );
        assert_eq!(
            GeneratedHaProxyConfig::parse(HaProxyVersion::V34Lts, first.contents()).unwrap(),
            first
        );
    }

    #[test]
    fn all_enableable_features_compose_in_one_canonical_document() {
        let config = baseline(HaProxyVersion::V34Lts)
            .with_health_check(HaProxyHealthCheck::new("/ready", 7, 4, 2).unwrap())
            .unwrap()
            .with_feature(HaProxyConfigFeature::AccessLogging, true)
            .unwrap()
            .with_feature(HaProxyConfigFeature::ResponseCompression, true)
            .unwrap()
            .with_forbidden_path_rule(
                HaProxyForbiddenPathRule::new(
                    HaProxyForbiddenPath::parse("/admin").unwrap(),
                    HaProxyForbiddenPathScope::PathAndDescendants,
                )
                .unwrap(),
            )
            .unwrap()
            .with_allowed_source(HaProxyAllowedSource::parse("192.0.2.129/24").unwrap())
            .unwrap()
            .with_feature(HaProxyConfigFeature::RestrictRequestMethods, true)
            .unwrap()
            .with_feature(HaProxyConfigFeature::WebSocketTunnel, true)
            .unwrap()
            .with_connection_limits(HaProxyConnectionLimits::new(3_000, 700, 900).unwrap())
            .unwrap()
            .with_retry_policy(HaProxyRetryPolicy::new(2).unwrap())
            .unwrap()
            .with_feature(HaProxyConfigFeature::RequestId, true)
            .unwrap()
            .with_rate_limit(HaProxyRateLimit::new(250).unwrap())
            .unwrap();
        for feature in HaProxyConfigFeature::ALL {
            if feature.can_enable() {
                assert!(config.feature_enabled(feature), "{feature:?}");
            }
        }

        let generated = config.generate().unwrap();
        let contents = generated.contents();
        for expected in [
            "log stdout format raw local0",
            "option httplog",
            "compression algo gzip",
            "acl lovelyres_forbidden_exact path -m str /admin",
            "acl lovelyres_forbidden_descendant path_beg /admin/",
            "acl lovelyres_source_allowed src 192.0.2.0/24",
            "acl lovelyres_method_allowed method GET HEAD",
            "timeout tunnel 3600s",
            "maxconn 3000",
            "maxconn 700 maxqueue 900",
            "retry-on conn-failure",
            "unique-id-header X-Request-ID",
            "X-Content-Type-Options nosniff",
            "stick-table type ip size 100k expire 30s store http_req_rate(10s)",
            "sc_http_req_rate(0) gt 250",
            "http-response del-header Server",
            "http-request set-header X-Forwarded-For %[src]",
            "http-check send meth GET uri /ready ver HTTP/1.0",
            "http-check expect status 200-399",
            "check inter 7s fall 4 rise 2",
        ] {
            assert!(contents.contains(expected), "missing {expected:?}");
        }
        assert!(!contents.contains("empty-response"));
        assert!(!contents.contains("response-timeout"));
        assert!(!contents.contains("retry-on 5"));
        assert_eq!(
            HaProxyHttpConfig::parse_generated(HaProxyVersion::V34Lts, contents)
                .unwrap()
                .generate()
                .unwrap()
                .contents(),
            contents
        );
    }

    #[test]
    fn tls_frontend_fails_closed_without_emitting_placeholder_or_secret() {
        let error = baseline(HaProxyVersion::V34Lts)
            .with_feature(HaProxyConfigFeature::TlsFrontend, true)
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("证书"));
        assert!(message.contains("拒绝"));
        assert!(!HaProxyConfigFeature::TlsFrontend.can_enable());
        assert!(
            HaProxyConfigFeature::TlsFrontend
                .summary()
                .contains("绝不输出 ssl/crt 占位")
        );
        let contents = baseline(HaProxyVersion::V34Lts)
            .generate()
            .unwrap()
            .contents()
            .to_owned();
        assert!(!contents.contains("crt"));
        assert!(!contents.contains("private-key"));
    }

    #[test]
    fn features_can_be_removed_and_reset_independently() {
        let custom = baseline(HaProxyVersion::V34Lts)
            .with_forbidden_path_rule(
                HaProxyForbiddenPathRule::new(
                    HaProxyForbiddenPath::parse("/private").unwrap(),
                    HaProxyForbiddenPathScope::Exact,
                )
                .unwrap(),
            )
            .unwrap()
            .with_retry_policy(HaProxyRetryPolicy::new(5).unwrap())
            .unwrap()
            .without_feature(HaProxyConfigFeature::ConnectionRetries)
            .unwrap();
        let contents = custom.generate().unwrap();
        assert!(contents.contents().contains("path -m str /private"));
        assert!(contents.contents().contains("retries 0"));
        assert!(!contents.contents().contains("retry-on"));

        let reset_forbidden = custom
            .clone()
            .reset_feature(HaProxyConfigFeature::ForbiddenPath403)
            .unwrap();
        assert!(!reset_forbidden.feature_enabled(HaProxyConfigFeature::ForbiddenPath403));
        assert!(reset_forbidden.forbidden_path_rule().is_none());
        assert!(
            !reset_forbidden
                .generate()
                .unwrap()
                .contents()
                .contains("/private")
        );

        let removed_default = custom
            .clone()
            .without_feature(HaProxyConfigFeature::SecurityResponseHeaders)
            .unwrap();
        assert!(
            !removed_default
                .generate()
                .unwrap()
                .contents()
                .contains("X-Content-Type-Options")
        );
        let restored_default = removed_default
            .reset_feature(HaProxyConfigFeature::SecurityResponseHeaders)
            .unwrap();
        assert!(restored_default.feature_enabled(HaProxyConfigFeature::SecurityResponseHeaders));

        let reset_all = custom.reset_all_features().unwrap();
        assert_eq!(reset_all, baseline(HaProxyVersion::V34Lts));
    }

    #[test]
    fn every_audited_version_round_trips_the_same_closed_directive_surface() {
        for version in HaProxyVersion::ALL {
            let generated = baseline(version)
                .with_feature(HaProxyConfigFeature::ResponseCompression, true)
                .unwrap()
                .with_feature(HaProxyConfigFeature::RequestId, true)
                .unwrap()
                .generate()
                .unwrap();
            assert!(
                generated
                    .contents()
                    .contains(&format!("# Target branch: {}", version.label()))
            );
            assert!(generated.contents().contains("compression algo gzip"));
            assert!(generated.contents().contains("unique-id-format"));
            assert_eq!(
                GeneratedHaProxyConfig::parse(version, generated.contents()).unwrap(),
                generated
            );
        }
    }

    #[test]
    fn strict_parser_rejects_unknown_duplicate_incomplete_and_noncanonical_input() {
        let generated = baseline(HaProxyVersion::V34Lts)
            .with_feature(HaProxyConfigFeature::RequestId, true)
            .unwrap()
            .with_rate_limit(HaProxyRateLimit::new(100).unwrap())
            .unwrap()
            .generate()
            .unwrap();
        let contents = generated.contents();
        let cases = [
            contents.replace("    mode http\n", "    mode http\n    daemon\n"),
            contents.replace("    mode http\n", "    mode http\n    mode http\n"),
            contents.replace("    unique-id-header X-Request-ID\n", ""),
            contents.replace("    http-request track-sc0 src\n", ""),
            contents.replace("timeout connect 5s", "timeout connect 05s"),
            contents.replace("bind 0.0.0.0:8080", "bind 0.0.0.0:8080 "),
            contents.replace("\n", "\r\n"),
            contents.trim_end_matches('\n').to_owned(),
            contents.replace("Target branch: 3.4", "Target branch: 3.3"),
        ];
        for case in cases {
            assert!(
                GeneratedHaProxyConfig::parse(HaProxyVersion::V34Lts, &case).is_err(),
                "accepted tampered document:\n{case}"
            );
        }
    }

    #[test]
    fn numeric_models_enforce_bounds_and_relationships() {
        assert!(HaProxyTimeoutProfile::new(0, 30, 30, 10, 15, 3_600).is_err());
        assert!(HaProxyTimeoutProfile::new(5, 30, 30, 10, 15, MAX_TIMEOUT_SECONDS + 1).is_err());
        assert!(HaProxyHealthCheck::new("/ready", 0, 3, 2).is_err());
        assert!(HaProxyHealthCheck::new("/ready", 5, 0, 2).is_err());
        assert!(HaProxyConnectionLimits::new(100, 101, 10).is_err());
        assert!(HaProxyConnectionLimits::new(100, 50, 0).is_err());
        assert!(HaProxyRetryPolicy::new(0).is_err());
        assert!(HaProxyRetryPolicy::new(MAX_RETRIES + 1).is_err());
        assert!(HaProxyRateLimit::new(0).is_err());
        assert!(HaProxyRateLimit::new(MAX_RATE_LIMIT + 1).is_err());
        for noncanonical in ["01", "+1", "1.0", "1s", " 1"] {
            assert!(HaProxyRateLimit::parse(noncanonical).is_err());
        }
    }

    #[test]
    fn retries_are_explicitly_off_or_limited_to_unsent_connection_failures() {
        let disabled = baseline(HaProxyVersion::V26Compatibility)
            .generate()
            .unwrap();
        assert!(disabled.contents().contains("    retries 0\n"));
        assert!(!disabled.contents().contains("retry-on"));

        let enabled = baseline(HaProxyVersion::V26Compatibility)
            .with_retry_policy(HaProxyRetryPolicy::new(3).unwrap())
            .unwrap()
            .generate()
            .unwrap();
        assert!(enabled.contents().contains("    retries 3\n"));
        assert!(enabled.contents().contains("    retry-on conn-failure\n"));
        for unsafe_retry in ["empty-response", "junk-response", "response-timeout", "503"] {
            assert!(!enabled.contents().contains(unsafe_retry));
        }
    }

    #[test]
    fn write_new_round_trips_and_never_overwrites() {
        let root = TestRoot::new();
        let generated = baseline(HaProxyVersion::V34Lts).generate().unwrap();
        let destination = root.0.join(generated.suggested_file_name());
        assert_eq!(generated.write_new(&destination).unwrap(), destination);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );
        assert!(generated.write_new(&destination).is_err());
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            generated.contents()
        );
    }

    #[test]
    fn write_new_rejects_unsafe_destinations() {
        let root = TestRoot::new();
        let generated = baseline(HaProxyVersion::V34Lts).generate().unwrap();
        assert!(generated.write_new(Path::new("haproxy.cfg")).is_err());
        assert!(generated.write_new(&root.0.join("haproxy.conf")).is_err());
        assert!(
            generated
                .write_new(&root.0.join("missing").join("haproxy.cfg"))
                .is_err()
        );
        assert!(
            generated
                .write_new(&root.0.join("child").join("..").join("haproxy.cfg"))
                .is_err()
        );
    }

    #[test]
    fn cleanup_failure_reports_the_possible_partial_file_exactly() {
        let destination = PathBuf::from("C:\\tmp\\lovelyres-haproxy-partial.cfg");
        let write_error = CoreError::validation(
            "generated HAProxy configuration write",
            "simulated write failure",
        );
        let error = combine_write_and_cleanup_result(
            &destination,
            write_error,
            Err(std::io::Error::other("simulated cleanup failure")),
        );
        let message = error.to_string();
        assert!(matches!(error, CoreError::PartialCleanup { .. }));
        assert!(message.contains(destination.to_string_lossy().as_ref()));
        assert!(message.contains("simulated write failure"));
        assert!(message.contains("simulated cleanup failure"));
        assert!(message.contains("inspect and remove this exact path manually"));
    }

    #[test]
    fn generated_debug_output_does_not_expose_configuration_contents() {
        let generated = baseline(HaProxyVersion::V34Lts).generate().unwrap();
        let debug = format!("{generated:?}");
        assert!(debug.contains("bytes"));
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("frontend"));
    }
}
