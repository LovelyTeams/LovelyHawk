//! Deterministic, typed Tomcat configuration review bundles.
//!
//! This module deliberately generates a multi-file **configuration review
//! bundle** for an otherwise empty/new installation and a new ROOT application.
//! It is not a Tomcat distribution, a complete installation package, or a
//! directly deployable archive. It does not import, merge, or replace an
//! existing Tomcat installation: existing applications, Realms, Valves,
//! Listeners, credentials, and deployment state cannot be preserved by a static
//! template. TLS, Manager/HostManager accounts, arbitrary XML, remote exposure,
//! and deployment of an existing application remain explicit deferred
//! capabilities.
//!
//! The supported version families are the currently supported Tomcat lines:
//! 9.0 / Servlet 4.0, 10.1 / Servlet 6.0, and 11.0 / Servlet 6.1. In
//! particular, Tomcat 9 uses the Java EE `javax` deployment descriptor schema,
//! while Tomcat 10.1 and 11 use distinct Jakarta EE schemas.
//!
//! References:
//! - <https://tomcat.apache.org/whichversion.html>
//! - <https://tomcat.apache.org/tomcat-9.0-doc/config/http.html>
//! - <https://tomcat.apache.org/tomcat-10.1-doc/config/http.html>
//! - <https://tomcat.apache.org/tomcat-11.0-doc/config/http.html>
//! - <https://tomcat.apache.org/tomcat-11.0-doc/config/filter.html>
//! - <https://jakarta.ee/specifications/servlet/6.1/>

use std::{
    collections::{BTreeSet, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

use crate::{CoreError, CoreResult, structured_xml::parse_xml};

pub const MAX_GENERATED_TOMCAT_ARTIFACT_BYTES: usize = 16 * 1024;
pub const MAX_GENERATED_TOMCAT_BUNDLE_BYTES: usize = 48 * 1024;
pub const TOMCAT_BUNDLE_SCOPE_NOTICE: &str = "仅用于全新/空白 Tomcat 与新 ROOT 应用的配置审阅；不是完整安装包，不能覆盖或直接部署到现有安装。";

const CONF_DIRECTORY: &str = "conf";
const WEBAPPS_DIRECTORY: &str = "webapps";
const HTTP_NIO_PROTOCOL: &str = "org.apache.coyote.http11.Http11NioProtocol";
const HTTP_HEADER_SECURITY_FILTER: &str = "org.apache.catalina.filters.HttpHeaderSecurityFilter";
const DEFAULT_BODY_LIMIT_BYTES: u32 = 2 * 1024 * 1024;
const SUGGESTED_BUNDLE_DIRECTORY_NAME: &str = "lovelyhawk-tomcat-new-empty-review-bundle";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatVersionFamily {
    V9_0,
    V10_1,
    V11_0,
}

impl TomcatVersionFamily {
    pub const ALL: [Self; 3] = [Self::V9_0, Self::V10_1, Self::V11_0];

    pub const fn label(self) -> &'static str {
        match self {
            Self::V9_0 => "Tomcat 9.0.x",
            Self::V10_1 => "Tomcat 10.1.x",
            Self::V11_0 => "Tomcat 11.0.x",
        }
    }

    pub const fn servlet_specification(self) -> &'static str {
        match self {
            Self::V9_0 => "Servlet 4.0",
            Self::V10_1 => "Servlet 6.0",
            Self::V11_0 => "Servlet 6.1",
        }
    }

    pub const fn minimum_java(self) -> u8 {
        match self {
            Self::V9_0 => 8,
            Self::V10_1 => 11,
            Self::V11_0 => 17,
        }
    }

    pub const fn servlet_api_namespace(self) -> &'static str {
        match self {
            Self::V9_0 => "javax.servlet",
            Self::V10_1 | Self::V11_0 => "jakarta.servlet",
        }
    }

    pub const fn web_xml_namespace(self) -> &'static str {
        match self {
            Self::V9_0 => "http://xmlns.jcp.org/xml/ns/javaee",
            Self::V10_1 | Self::V11_0 => "https://jakarta.ee/xml/ns/jakartaee",
        }
    }

    pub const fn web_xml_schema(self) -> &'static str {
        match self {
            Self::V9_0 => "http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd",
            Self::V10_1 => "https://jakarta.ee/xml/ns/jakartaee/web-app_6_0.xsd",
            Self::V11_0 => "https://jakarta.ee/xml/ns/jakartaee/web-app_6_1.xsd",
        }
    }

    pub const fn web_xml_version(self) -> &'static str {
        match self {
            Self::V9_0 => "4.0",
            Self::V10_1 => "6.0",
            Self::V11_0 => "6.1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatArtifactKind {
    ServerXml,
    ContextXml,
    WebXml,
}

impl TomcatArtifactKind {
    pub const ALL: [Self; 3] = [Self::ServerXml, Self::ContextXml, Self::WebXml];

    pub const fn file_name(self) -> &'static str {
        match self {
            Self::ServerXml => "server.xml",
            Self::ContextXml => "context.xml",
            Self::WebXml => "web.xml",
        }
    }

    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::ServerXml => "conf/server.xml",
            Self::ContextXml => "webapps/ROOT/META-INF/context.xml",
            Self::WebXml => "webapps/ROOT/WEB-INF/web.xml",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ServerXml => "容器与 HTTP Connector",
            Self::ContextXml => "ROOT 应用 Context",
            Self::WebXml => "ROOT 应用部署描述符",
        }
    }
}

/// Search/display metadata for every typed HTTP Connector input.
///
/// Capacity values remain one atomic `ConnectorLimits` feature because they
/// are emitted and removed together. This field catalog lets a UI explain and
/// edit each value without misrepresenting those coupled attributes as five
/// independent configuration fragments.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatConnectorField {
    Address,
    Port,
    ConnectionTimeout,
    MaxThreads,
    AcceptCount,
    MaxConnections,
    MaxPostSize,
    MaxSwallowSize,
    CompressionMinSize,
}

impl TomcatConnectorField {
    pub const ALL: [Self; 9] = [
        Self::Address,
        Self::Port,
        Self::ConnectionTimeout,
        Self::MaxThreads,
        Self::AcceptCount,
        Self::MaxConnections,
        Self::MaxPostSize,
        Self::MaxSwallowSize,
        Self::CompressionMinSize,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Port => "port",
            Self::ConnectionTimeout => "connectionTimeout",
            Self::MaxThreads => "maxThreads",
            Self::AcceptCount => "acceptCount",
            Self::MaxConnections => "maxConnections",
            Self::MaxPostSize => "maxPostSize",
            Self::MaxSwallowSize => "maxSwallowSize",
            Self::CompressionMinSize => "compressionMinSize",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Address => "监听地址",
            Self::Port => "HTTP 监听端口",
            Self::ConnectionTimeout => "首个请求行等待超时",
            Self::MaxThreads => "最大请求处理线程数",
            Self::AcceptCount => "操作系统连接等待队列",
            Self::MaxConnections => "最大处理连接数",
            Self::MaxPostSize => "参数转换字节上限",
            Self::MaxSwallowSize => "中止上传吞咽字节上限",
            Self::CompressionMinSize => "响应压缩最小字节数",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::Address => {
                "闭合模型只允许 IPv4/IPv6 本机回环；非回环暴露必须等待 TLS、认证与代理信任模型。"
            }
            Self::Port => "NIO HTTP Connector 创建服务器套接字并等待连接的 TCP 端口。",
            Self::ConnectionTimeout => {
                "接受连接后等待客户端提交请求 URI 行的毫秒数；本 bundle 不启用独立上传超时，因此读取请求体时也使用该值。本模型拒绝 -1 无限等待。"
            }
            Self::MaxThreads => {
                "Connector 内部可创建的最大请求处理线程数；本模型不生成会使该值失效的共享 Executor。"
            }
            Self::AcceptCount => {
                "达到 maxConnections 后由操作系统提供的连接等待队列长度；操作系统可能采用不同的实际值。"
            }
            Self::MaxConnections => {
                "Connector 同时接受并处理的连接数量上限；达到上限后操作系统仍可能按 acceptCount 排队。"
            }
            Self::MaxPostSize => TomcatFormParameterBytes::meaning(),
            Self::MaxSwallowSize => TomcatAbortedUploadSwallowBytes::meaning(),
            Self::CompressionMinSize => {
                "compression=on 时尝试压缩响应的最小已知 Content-Length；未知长度的响应也可能被压缩。"
            }
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Address => &["bind", "127.0.0.1", "::1", "回环", "监听 IP"],
            Self::Port => &["8080", "listen", "HTTP 端口"],
            Self::ConnectionTimeout => &["timeout", "连接超时", "URI line"],
            Self::MaxThreads => &["threads", "线程池", "并发请求"],
            Self::AcceptCount => &["backlog", "队列", "等待连接"],
            Self::MaxConnections => &["connections", "最大连接", "并发连接"],
            Self::MaxPostSize => &["getParameter", "表单", "multipart", "参数解析"],
            Self::MaxSwallowSize => &["aborted upload", "中止上传", "吞咽"],
            Self::CompressionMinSize => &["gzip", "压缩阈值", "Content-Length"],
        }
    }

    pub const fn owner_feature(self) -> Option<TomcatConfigFeature> {
        match self {
            Self::Address | Self::Port | Self::ConnectionTimeout => None,
            Self::MaxThreads
            | Self::AcceptCount
            | Self::MaxConnections
            | Self::MaxPostSize
            | Self::MaxSwallowSize => Some(TomcatConfigFeature::ConnectorLimits),
            Self::CompressionMinSize => Some(TomcatConfigFeature::ResponseCompression),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatConfigFeature {
    ConnectorLimits,
    ResponseCompression,
    HostAutoDeploy,
    HostUnpackWars,
    AllowCrossContext,
    HttpOnlySessionCookies,
    HeaderSecurityFilter,
    AllowSafeMethodsOnly,
    DenyAllRequests,
}

impl TomcatConfigFeature {
    pub const ALL: [Self; 9] = [
        Self::ConnectorLimits,
        Self::ResponseCompression,
        Self::HostAutoDeploy,
        Self::HostUnpackWars,
        Self::AllowCrossContext,
        Self::HttpOnlySessionCookies,
        Self::HeaderSecurityFilter,
        Self::AllowSafeMethodsOnly,
        Self::DenyAllRequests,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ConnectorLimits => "connector-limits",
            Self::ResponseCompression => "response-compression",
            Self::HostAutoDeploy => "host-auto-deploy",
            Self::HostUnpackWars => "host-unpack-wars",
            Self::AllowCrossContext => "allow-cross-context",
            Self::HttpOnlySessionCookies => "http-only-session-cookies",
            Self::HeaderSecurityFilter => "header-security-filter",
            Self::AllowSafeMethodsOnly => "allow-safe-methods-only",
            Self::DenyAllRequests => "deny-all-requests",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ConnectorLimits => "限制 Connector 容量、参数转换与中止上传吞咽量",
            Self::ResponseCompression => "启用文本响应压缩",
            Self::HostAutoDeploy => "启用 Host 自动部署检查",
            Self::HostUnpackWars => "部署时解压 WAR",
            Self::AllowCrossContext => "允许跨 Context 调度",
            Self::HttpOnlySessionCookies => "Session Cookie 使用 HttpOnly",
            Self::HeaderSecurityFilter => "添加浏览器安全响应头",
            Self::AllowSafeMethodsOnly => "仅允许 GET 与 HEAD",
            Self::DenyAllRequests => "拒绝应用的全部请求 (HTTP 403)",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ConnectorLimits => {
                "显式设置 maxThreads、acceptCount 与 maxConnections。maxPostSize 只限制 Tomcat 将表单/Multipart 请求体数据转换为 getParameter() 参数的字节数，不是通用 POST、请求体或文件上传上限；maxSwallowSize 只限制中止上传后为送达响应而继续吞咽的请求体字节，也不是正常上传上限。关闭后使用对应 Tomcat 版本默认值。"
            }
            Self::ResponseCompression => {
                "为固定文本 MIME 类型启用 Gzip；会消耗 CPU，并且不配置 TLS/HSTS。"
            }
            Self::HostAutoDeploy => {
                "运行期间周期检查新应用或更新并触发部署/重载；默认关闭以避免文件变化产生隐式运行时效果。"
            }
            Self::HostUnpackWars => "将 WAR 展开到目录；关闭时直接从 WAR 运行可能有性能开销。",
            Self::AllowCrossContext => {
                "允许应用通过 ServletContext.getContext() 访问同一虚拟主机的其他应用；安全基线默认关闭。"
            }
            Self::HttpOnlySessionCookies => {
                "让 Tomcat 为 Session Cookie 设置 HttpOnly，降低客户端脚本读取 Session ID 的风险。"
            }
            Self::HeaderSecurityFilter => {
                "添加 X-Frame-Options: DENY 与 X-Content-Type-Options: nosniff；TLS 尚未建模，因此明确关闭 HSTS。"
            }
            Self::AllowSafeMethodsOnly => {
                "允许 GET/HEAD，并用 deny-uncovered-http-methods 对其他 HTTP 方法返回 403；会破坏需要写请求的应用。"
            }
            Self::DenyAllRequests => {
                "用覆盖所有 URL 和 HTTP 方法的空 auth-constraint 返回 403；与仅允许安全方法互斥。"
            }
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::ConnectorLimits | Self::ResponseCompression => "Connector / server.xml",
            Self::HostAutoDeploy | Self::HostUnpackWars => "Host / server.xml",
            Self::AllowCrossContext | Self::HttpOnlySessionCookies => "Context / context.xml",
            Self::HeaderSecurityFilter | Self::AllowSafeMethodsOnly | Self::DenyAllRequests => {
                "应用 / web.xml"
            }
        }
    }

    pub const fn artifact(self) -> TomcatArtifactKind {
        match self {
            Self::ConnectorLimits
            | Self::ResponseCompression
            | Self::HostAutoDeploy
            | Self::HostUnpackWars => TomcatArtifactKind::ServerXml,
            Self::AllowCrossContext | Self::HttpOnlySessionCookies => {
                TomcatArtifactKind::ContextXml
            }
            Self::HeaderSecurityFilter | Self::AllowSafeMethodsOnly | Self::DenyAllRequests => {
                TomcatArtifactKind::WebXml
            }
        }
    }

    pub const fn default_enabled(self) -> bool {
        matches!(
            self,
            Self::ConnectorLimits | Self::HttpOnlySessionCookies | Self::HeaderSecurityFilter
        )
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::ConnectorLimits => &[
                "maxThreads",
                "acceptCount",
                "maxConnections",
                "maxPostSize",
                "maxSwallowSize",
                "连接数",
                "表单参数",
                "参数转换",
                "中止上传吞咽",
            ],
            Self::ResponseCompression => &["compression", "compressionMinSize", "gzip", "压缩"],
            Self::HostAutoDeploy => &["autoDeploy", "热部署", "自动部署", "reload"],
            Self::HostUnpackWars => &["unpackWARs", "WAR", "解压"],
            Self::AllowCrossContext => &["crossContext", "跨应用", "RequestDispatcher"],
            Self::HttpOnlySessionCookies => &["useHttpOnly", "cookie", "session", "XSS"],
            Self::HeaderSecurityFilter => &[
                "HttpHeaderSecurityFilter",
                "X-Frame-Options",
                "nosniff",
                "安全响应头",
            ],
            Self::AllowSafeMethodsOnly => {
                &["GET", "HEAD", "deny-uncovered-http-methods", "限制请求方法"]
            }
            Self::DenyAllRequests => &["403", "auth-constraint", "全部拒绝", "维护"],
        }
    }

    pub const fn supports_version(self, _version: TomcatVersionFamily) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatDeferredCapability {
    ExistingInstallationOverlay,
    TlsConnector,
    ManagerAccounts,
    RealmSecrets,
    ArbitraryXml,
    ExistingApplicationDeployment,
    NonLoopbackExposure,
}

impl TomcatDeferredCapability {
    pub const ALL: [Self; 7] = [
        Self::ExistingInstallationOverlay,
        Self::TlsConnector,
        Self::ManagerAccounts,
        Self::RealmSecrets,
        Self::ArbitraryXml,
        Self::ExistingApplicationDeployment,
        Self::NonLoopbackExposure,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ExistingInstallationOverlay => "existing-installation-overlay",
            Self::TlsConnector => "tls-connector",
            Self::ManagerAccounts => "manager-host-manager-accounts",
            Self::RealmSecrets => "realm-secrets",
            Self::ArbitraryXml => "arbitrary-xml",
            Self::ExistingApplicationDeployment => "existing-application-deployment",
            Self::NonLoopbackExposure => "non-loopback-exposure",
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::ExistingInstallationOverlay => {
                "现有安装可能包含应用、Realm、Valve、Listener 和发行版专属默认项；静态模板无法证明语义保留。"
            }
            Self::TlsConnector => "TLS 需要证书/私钥托管、协议与密码套件策略、轮换和真实握手验证。",
            Self::ManagerAccounts => {
                "Manager/HostManager 账户属于秘密与授权生命周期，不能进入普通配置草稿。"
            }
            Self::RealmSecrets => "Realm 可能引用口令、密钥库或外部身份系统，需要独立秘密边界。",
            Self::ArbitraryXml => "任意 XML 会绕过类型、闭合结构、大小和危险组件限制。",
            Self::ExistingApplicationDeployment => {
                "部署现有应用需要备份、兼容性检查、不可变计划、验证与回滚。"
            }
            Self::NonLoopbackExposure => "非回环监听必须与 TLS、认证、代理信任和网络边界一起建模。",
        }
    }
}

/// Immutable settings that remain present even when every optional feature is removed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatBaselineInvariant {
    ReviewBundleOnly,
    ShutdownPortDisabled,
    LoopbackNioConnector,
    TraceDisabled,
    DeployOnStartup,
    VersionedWebSchema,
}

impl TomcatBaselineInvariant {
    pub const ALL: [Self; 6] = [
        Self::ReviewBundleOnly,
        Self::ShutdownPortDisabled,
        Self::LoopbackNioConnector,
        Self::TraceDisabled,
        Self::DeployOnStartup,
        Self::VersionedWebSchema,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::ReviewBundleOnly => "review-bundle-only",
            Self::ShutdownPortDisabled => "shutdown-port-disabled",
            Self::LoopbackNioConnector => "loopback-nio-connector",
            Self::TraceDisabled => "trace-disabled",
            Self::DeployOnStartup => "deploy-on-startup",
            Self::VersionedWebSchema => "versioned-web-schema",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ReviewBundleOnly => "仅生成全新/空白环境审阅 bundle",
            Self::ShutdownPortDisabled => "关闭明文 shutdown 端口",
            Self::LoopbackNioConnector => "使用回环 NIO HTTP Connector",
            Self::TraceDisabled => "关闭 HTTP TRACE",
            Self::DeployOnStartup => "启动时发现 ROOT 应用",
            Self::VersionedWebSchema => "按 Tomcat 家族固定 web.xml schema",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::ReviewBundleOnly => TOMCAT_BUNDLE_SCOPE_NOTICE,
            Self::ShutdownPortDisabled => {
                "server.xml 固定 port=-1；标准 shutdown/catalina 脚本将无法通过 shutdown 端口优雅停止，运行方式必须另行审阅。"
            }
            Self::LoopbackNioConnector => {
                "固定 Java NIO HTTP 协议并只允许 typed 回环地址；非回环网络暴露 deferred。"
            }
            Self::TraceDisabled => "Connector 固定 allowTrace=false，避免开放 TRACE 方法。",
            Self::DeployOnStartup => {
                "Host 固定 deployOnStartup=true 以在启动时发现新 ROOT 草稿；运行期间 autoDeploy 仍由可选 feature 控制。"
            }
            Self::VersionedWebSchema => {
                "Tomcat 9 使用 Java EE Servlet 4.0；Tomcat 10.1/11 分别使用 Jakarta Servlet 6.0/6.1。"
            }
        }
    }

    pub const fn scope(self) -> &'static str {
        match self {
            Self::ReviewBundleOnly => "bundle",
            Self::ShutdownPortDisabled
            | Self::LoopbackNioConnector
            | Self::TraceDisabled
            | Self::DeployOnStartup => "server.xml",
            Self::VersionedWebSchema => "web.xml",
        }
    }

    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::ReviewBundleOnly => &["新安装", "空白安装", "审阅", "不可覆盖"],
            Self::ShutdownPortDisabled => &["port=-1", "shutdown", "停止端口"],
            Self::LoopbackNioConnector => &["Http11NioProtocol", "127.0.0.1", "::1"],
            Self::TraceDisabled => &["allowTrace", "TRACE"],
            Self::DeployOnStartup => &["deployOnStartup", "启动部署"],
            Self::VersionedWebSchema => &["javax", "jakarta", "web.xml", "XSD"],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TomcatConnectorAddress {
    Ipv4Loopback,
    Ipv6Loopback,
}

impl TomcatConnectorAddress {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4Loopback => "127.0.0.1",
            Self::Ipv6Loopback => "::1",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ipv4Loopback => "IPv4 本机回环 (127.0.0.1)",
            Self::Ipv6Loopback => "IPv6 本机回环 (::1)",
        }
    }

    pub const fn summary(self) -> &'static str {
        match self {
            Self::Ipv4Loopback => "仅接受经 IPv4 本机回环接口到达的连接，不暴露到外部网络。",
            Self::Ipv6Loopback => "仅接受经 IPv6 本机回环接口到达的连接；不会同时监听 IPv4。",
        }
    }
}

macro_rules! bounded_decimal_type {
    ($name:ident, $subject:literal, $minimum:expr, $maximum:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u32);

        impl $name {
            pub fn new(value: u32) -> CoreResult<Self> {
                validate_u32_range($subject, value, $minimum, $maximum)?;
                Ok(Self(value))
            }

            pub fn parse(value: &str) -> CoreResult<Self> {
                Self::new(parse_decimal($subject, value)?)
            }

            pub const fn get(self) -> u32 {
                self.0
            }
        }
    };
}

bounded_decimal_type!(TomcatConnectorPort, "Tomcat Connector port", 1, 65_535);
bounded_decimal_type!(
    TomcatConnectionTimeoutMillis,
    "Tomcat connection timeout",
    1,
    3_600_000
);
bounded_decimal_type!(TomcatMaxThreads, "Tomcat maxThreads", 1, 10_000);
bounded_decimal_type!(TomcatAcceptCount, "Tomcat acceptCount", 1, 100_000);
bounded_decimal_type!(TomcatMaxConnections, "Tomcat maxConnections", 1, 1_000_000);
bounded_decimal_type!(
    TomcatFormParameterBytes,
    "Tomcat maxPostSize parameter conversion byte limit",
    1,
    1_073_741_824
);
bounded_decimal_type!(
    TomcatAbortedUploadSwallowBytes,
    "Tomcat maxSwallowSize aborted-upload swallow byte limit",
    1,
    1_073_741_824
);
bounded_decimal_type!(
    TomcatCompressionMinBytes,
    "Tomcat compression minimum bytes",
    1,
    1_048_576
);

impl TomcatFormParameterBytes {
    pub const fn meaning() -> &'static str {
        "maxPostSize：仅限制 Tomcat 将 application/x-www-form-urlencoded 或 multipart/form-data 数据转换为 getParameter() 参数的字节数；不是通用请求体或上传大小上限。"
    }
}

impl TomcatAbortedUploadSwallowBytes {
    pub const fn meaning() -> &'static str {
        "maxSwallowSize：仅限制 Tomcat 在上传已中止后继续吞咽、以便客户端看到响应的请求体字节数；不是正常上传大小上限。"
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TomcatApplicationName(String);

impl TomcatApplicationName {
    pub fn parse(value: &str) -> CoreResult<Self> {
        if value.is_empty() || value.trim() != value {
            return Err(CoreError::validation(
                "Tomcat application name",
                "must be non-empty and must not have leading or trailing whitespace",
            ));
        }
        if value.chars().count() > 128 || value.len() > 512 {
            return Err(CoreError::validation(
                "Tomcat application name",
                "must be at most 128 Unicode scalar values and 512 UTF-8 bytes",
            ));
        }
        if !value.chars().all(is_safe_xml_text_character) {
            return Err(CoreError::validation(
                "Tomcat application name",
                "contains a control character or a character disallowed by XML 1.0",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TomcatApplicationName {
    fn default() -> Self {
        Self("LovelyHawk ROOT application".to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TomcatConnectorConfig {
    address: TomcatConnectorAddress,
    port: TomcatConnectorPort,
    connection_timeout: TomcatConnectionTimeoutMillis,
    max_threads: TomcatMaxThreads,
    accept_count: TomcatAcceptCount,
    max_connections: TomcatMaxConnections,
    max_post_parameter_bytes: TomcatFormParameterBytes,
    max_aborted_upload_swallow_bytes: TomcatAbortedUploadSwallowBytes,
}

impl TomcatConnectorConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: TomcatConnectorAddress,
        port: TomcatConnectorPort,
        connection_timeout: TomcatConnectionTimeoutMillis,
        max_threads: TomcatMaxThreads,
        accept_count: TomcatAcceptCount,
        max_connections: TomcatMaxConnections,
        max_post_parameter_bytes: TomcatFormParameterBytes,
        max_aborted_upload_swallow_bytes: TomcatAbortedUploadSwallowBytes,
    ) -> CoreResult<Self> {
        let value = Self {
            address,
            port,
            connection_timeout,
            max_threads,
            accept_count,
            max_connections,
            max_post_parameter_bytes,
            max_aborted_upload_swallow_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn loopback_baseline() -> Self {
        Self {
            address: TomcatConnectorAddress::Ipv4Loopback,
            port: TomcatConnectorPort(8080),
            connection_timeout: TomcatConnectionTimeoutMillis(20_000),
            max_threads: TomcatMaxThreads(200),
            accept_count: TomcatAcceptCount(100),
            max_connections: TomcatMaxConnections(8_192),
            max_post_parameter_bytes: TomcatFormParameterBytes(DEFAULT_BODY_LIMIT_BYTES),
            max_aborted_upload_swallow_bytes: TomcatAbortedUploadSwallowBytes(
                DEFAULT_BODY_LIMIT_BYTES,
            ),
        }
    }

    pub const fn address(&self) -> TomcatConnectorAddress {
        self.address
    }

    pub const fn port(&self) -> TomcatConnectorPort {
        self.port
    }

    pub const fn connection_timeout(&self) -> TomcatConnectionTimeoutMillis {
        self.connection_timeout
    }

    pub const fn max_threads(&self) -> TomcatMaxThreads {
        self.max_threads
    }

    pub const fn accept_count(&self) -> TomcatAcceptCount {
        self.accept_count
    }

    pub const fn max_connections(&self) -> TomcatMaxConnections {
        self.max_connections
    }

    /// Typed value rendered as `maxPostSize`; see [`TomcatFormParameterBytes::meaning`].
    pub const fn max_post_parameter_bytes(&self) -> TomcatFormParameterBytes {
        self.max_post_parameter_bytes
    }

    /// Typed value rendered as `maxSwallowSize`; see
    /// [`TomcatAbortedUploadSwallowBytes::meaning`].
    pub const fn max_aborted_upload_swallow_bytes(&self) -> TomcatAbortedUploadSwallowBytes {
        self.max_aborted_upload_swallow_bytes
    }

    fn validate(&self) -> CoreResult<()> {
        if self.max_threads.get() > self.max_connections.get() {
            return Err(CoreError::validation(
                "Tomcat Connector capacity",
                "maxThreads must not exceed maxConnections in this closed profile",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TomcatConfig {
    version: TomcatVersionFamily,
    application_name: TomcatApplicationName,
    connector: TomcatConnectorConfig,
    compression_min_size: TomcatCompressionMinBytes,
    features: BTreeSet<TomcatConfigFeature>,
}

impl TomcatConfig {
    pub fn baseline(version: TomcatVersionFamily) -> Self {
        Self {
            version,
            application_name: TomcatApplicationName::default(),
            connector: TomcatConnectorConfig::loopback_baseline(),
            compression_min_size: TomcatCompressionMinBytes(2_048),
            features: TomcatConfigFeature::ALL
                .into_iter()
                .filter(|feature| feature.default_enabled())
                .collect(),
        }
    }

    pub const fn version(&self) -> TomcatVersionFamily {
        self.version
    }

    pub fn application_name(&self) -> &TomcatApplicationName {
        &self.application_name
    }

    pub fn connector(&self) -> &TomcatConnectorConfig {
        &self.connector
    }

    pub const fn compression_min_size(&self) -> TomcatCompressionMinBytes {
        self.compression_min_size
    }

    pub fn features(&self) -> &BTreeSet<TomcatConfigFeature> {
        &self.features
    }

    pub fn feature_enabled(&self, feature: TomcatConfigFeature) -> bool {
        self.features.contains(&feature)
    }

    pub fn with_application_name(mut self, name: TomcatApplicationName) -> Self {
        self.application_name = name;
        self
    }

    pub fn with_connector(mut self, connector: TomcatConnectorConfig) -> CoreResult<Self> {
        connector.validate()?;
        self.connector = connector;
        Ok(self)
    }

    pub fn with_compression_min_size(mut self, value: TomcatCompressionMinBytes) -> Self {
        self.compression_min_size = value;
        self.features
            .insert(TomcatConfigFeature::ResponseCompression);
        self
    }

    pub fn with_feature(mut self, feature: TomcatConfigFeature, enabled: bool) -> CoreResult<Self> {
        if enabled {
            self.features.insert(feature);
        } else {
            self.features.remove(&feature);
        }
        self.validate()?;
        Ok(self)
    }

    pub fn generate(&self) -> CoreResult<GeneratedTomcatConfigBundle> {
        self.validate()?;

        let artifacts = [
            TomcatConfigArtifact::new(TomcatArtifactKind::ServerXml, self.render_server_xml()),
            TomcatConfigArtifact::new(TomcatArtifactKind::ContextXml, self.render_context_xml()),
            TomcatConfigArtifact::new(TomcatArtifactKind::WebXml, self.render_web_xml()),
        ];
        let bundle = GeneratedTomcatConfigBundle {
            version: self.version,
            artifacts,
        };
        validate_generated_bundle(&bundle)?;
        Ok(bundle)
    }

    fn validate(&self) -> CoreResult<()> {
        self.connector.validate()?;
        for feature in &self.features {
            if !feature.supports_version(self.version) {
                return Err(CoreError::validation(
                    "Tomcat configuration feature",
                    format!(
                        "{} is not supported by {}",
                        feature.title(),
                        self.version.label()
                    ),
                ));
            }
        }
        if self.feature_enabled(TomcatConfigFeature::AllowSafeMethodsOnly)
            && self.feature_enabled(TomcatConfigFeature::DenyAllRequests)
        {
            return Err(CoreError::validation(
                "Tomcat web security features",
                "allow-safe-methods-only and deny-all-requests are mutually exclusive",
            ));
        }
        Ok(())
    }

    fn render_server_xml(&self) -> String {
        let mut contents = String::with_capacity(1_500);
        contents.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        contents.push_str("<!-- Configuration review draft for an otherwise empty/new Tomcat installation. Not an installation package; never overlay an existing installation. -->\n");
        contents.push_str("<Server port=\"-1\">\n");
        contents.push_str("  <Service name=\"Catalina\">\n");
        contents.push_str("    <Connector address=\"");
        contents.push_str(self.connector.address().as_str());
        contents.push_str("\" port=\"");
        contents.push_str(&self.connector.port().get().to_string());
        contents.push_str("\" protocol=\"");
        contents.push_str(HTTP_NIO_PROTOCOL);
        contents.push_str("\" allowTrace=\"false\" connectionTimeout=\"");
        contents.push_str(&self.connector.connection_timeout().get().to_string());
        contents.push('"');

        if self.feature_enabled(TomcatConfigFeature::ConnectorLimits) {
            contents.push_str("\n      maxThreads=\"");
            contents.push_str(&self.connector.max_threads().get().to_string());
            contents.push_str("\" acceptCount=\"");
            contents.push_str(&self.connector.accept_count().get().to_string());
            contents.push_str("\" maxConnections=\"");
            contents.push_str(&self.connector.max_connections().get().to_string());
            contents.push_str("\" maxPostSize=\"");
            contents.push_str(&self.connector.max_post_parameter_bytes().get().to_string());
            contents.push_str("\" maxSwallowSize=\"");
            contents.push_str(
                &self
                    .connector
                    .max_aborted_upload_swallow_bytes()
                    .get()
                    .to_string(),
            );
            contents.push('"');
        }
        if self.feature_enabled(TomcatConfigFeature::ResponseCompression) {
            contents.push_str("\n      compression=\"on\" compressionMinSize=\"");
            contents.push_str(&self.compression_min_size.get().to_string());
            contents.push_str("\" compressibleMimeType=\"text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json,application/xml,image/svg+xml\"");
        }
        contents.push_str(" />\n");
        contents.push_str("    <Engine name=\"Catalina\" defaultHost=\"localhost\">\n");
        contents.push_str("      <Host name=\"localhost\" appBase=\"webapps\" deployOnStartup=\"true\" autoDeploy=\"");
        contents.push_str(boolean_literal(
            self.feature_enabled(TomcatConfigFeature::HostAutoDeploy),
        ));
        contents.push_str("\" unpackWARs=\"");
        contents.push_str(boolean_literal(
            self.feature_enabled(TomcatConfigFeature::HostUnpackWars),
        ));
        contents.push_str("\" />\n");
        contents.push_str("    </Engine>\n");
        contents.push_str("  </Service>\n");
        contents.push_str("</Server>\n");
        contents
    }

    fn render_context_xml(&self) -> String {
        let mut contents = String::with_capacity(400);
        contents.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        contents.push_str("<!-- Configuration review draft for a new ROOT application; not a deployable archive and never a migration of an existing application. -->\n");
        contents.push_str("<Context crossContext=\"");
        contents.push_str(boolean_literal(
            self.feature_enabled(TomcatConfigFeature::AllowCrossContext),
        ));
        contents.push_str("\" useHttpOnly=\"");
        contents.push_str(boolean_literal(
            self.feature_enabled(TomcatConfigFeature::HttpOnlySessionCookies),
        ));
        contents.push_str("\" />\n");
        contents
    }

    fn render_web_xml(&self) -> String {
        let mut contents = String::with_capacity(2_000);
        contents.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        contents.push_str("<!-- Configuration review draft for a new application; not a deployable archive. Schema is pinned to the selected Tomcat family. -->\n");
        contents.push_str("<web-app xmlns=\"");
        contents.push_str(self.version.web_xml_namespace());
        contents.push_str("\"\n  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n  xsi:schemaLocation=\"");
        contents.push_str(self.version.web_xml_namespace());
        contents.push(' ');
        contents.push_str(self.version.web_xml_schema());
        contents.push_str("\"\n  version=\"");
        contents.push_str(self.version.web_xml_version());
        contents.push_str("\">\n");
        contents.push_str("  <display-name>");
        push_xml_escaped(&mut contents, self.application_name.as_str());
        contents.push_str("</display-name>\n");

        if self.feature_enabled(TomcatConfigFeature::HeaderSecurityFilter) {
            contents.push_str("  <filter>\n");
            contents.push_str("    <filter-name>LovelyHawkHeaderSecurity</filter-name>\n");
            contents.push_str("    <filter-class>");
            contents.push_str(HTTP_HEADER_SECURITY_FILTER);
            contents.push_str("</filter-class>\n");
            contents.push_str("    <async-supported>true</async-supported>\n");
            contents.push_str("    <init-param><param-name>hstsEnabled</param-name><param-value>false</param-value></init-param>\n");
            contents.push_str("    <init-param><param-name>antiClickJackingEnabled</param-name><param-value>true</param-value></init-param>\n");
            contents.push_str("    <init-param><param-name>antiClickJackingOption</param-name><param-value>DENY</param-value></init-param>\n");
            contents.push_str("    <init-param><param-name>blockContentTypeSniffingEnabled</param-name><param-value>true</param-value></init-param>\n");
            contents.push_str("  </filter>\n");
            contents.push_str("  <filter-mapping>\n");
            contents.push_str("    <filter-name>LovelyHawkHeaderSecurity</filter-name>\n");
            contents.push_str("    <url-pattern>/*</url-pattern>\n");
            contents.push_str("  </filter-mapping>\n");
        }

        if self.feature_enabled(TomcatConfigFeature::AllowSafeMethodsOnly) {
            contents.push_str("  <security-constraint>\n");
            contents.push_str("    <web-resource-collection>\n");
            contents
                .push_str("      <web-resource-name>LovelyHawk safe methods</web-resource-name>\n");
            contents.push_str("      <url-pattern>/*</url-pattern>\n");
            contents.push_str("      <http-method>GET</http-method>\n");
            contents.push_str("      <http-method>HEAD</http-method>\n");
            contents.push_str("    </web-resource-collection>\n");
            contents.push_str("  </security-constraint>\n");
            contents.push_str("  <deny-uncovered-http-methods />\n");
        } else if self.feature_enabled(TomcatConfigFeature::DenyAllRequests) {
            contents.push_str("  <security-constraint>\n");
            contents.push_str("    <web-resource-collection>\n");
            contents.push_str("      <web-resource-name>LovelyHawk deny all</web-resource-name>\n");
            contents.push_str("      <url-pattern>/*</url-pattern>\n");
            contents.push_str("    </web-resource-collection>\n");
            contents.push_str("    <auth-constraint />\n");
            contents.push_str("  </security-constraint>\n");
        }
        contents.push_str("</web-app>\n");
        contents
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TomcatConfigArtifact {
    kind: TomcatArtifactKind,
    contents: String,
}

impl TomcatConfigArtifact {
    fn new(kind: TomcatArtifactKind, contents: String) -> Self {
        Self { kind, contents }
    }

    pub const fn kind(&self) -> TomcatArtifactKind {
        self.kind
    }

    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub const fn relative_path(&self) -> &'static str {
        self.kind.relative_path()
    }

    pub const fn file_name(&self) -> &'static str {
        self.kind.file_name()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedTomcatConfigBundle {
    version: TomcatVersionFamily,
    artifacts: [TomcatConfigArtifact; 3],
}

impl GeneratedTomcatConfigBundle {
    pub const fn version(&self) -> TomcatVersionFamily {
        self.version
    }

    pub fn artifacts(&self) -> &[TomcatConfigArtifact; 3] {
        &self.artifacts
    }

    pub fn artifact(&self, kind: TomcatArtifactKind) -> &TomcatConfigArtifact {
        self.artifacts
            .iter()
            .find(|artifact| artifact.kind() == kind)
            .expect("generated Tomcat bundle always has all three artifacts")
    }

    pub fn total_bytes(&self) -> usize {
        self.artifacts
            .iter()
            .map(|artifact| artifact.contents.len())
            .sum()
    }

    /// Suggested name for the new directory that will contain all three
    /// review artifacts. It deliberately does not look like a Tomcat
    /// distribution or a single XML file.
    pub const fn suggested_directory_name(&self) -> &'static str {
        SUGGESTED_BUNDLE_DIRECTORY_NAME
    }

    /// Writes the three-artifact configuration review bundle below one new directory.
    ///
    /// The destination itself must not exist. Every artifact is written with
    /// `create_new`, and only paths created by this invocation are considered
    /// for best-effort cleanup after an error. The output remains a review
    /// draft, not a complete Tomcat installation package; this method never
    /// installs or deploys Tomcat.
    pub fn write_new(&self, destination: &Path) -> CoreResult<PathBuf> {
        validate_bundle_destination(destination)?;
        validate_generated_bundle(self)?;

        fs::create_dir(destination).map_err(|source| {
            CoreError::io(
                "create generated Tomcat bundle directory",
                destination,
                source,
            )
        })?;
        let mut created = vec![CreatedBundlePath::Directory(destination.to_path_buf())];

        let write_result = (|| {
            for relative in [
                CONF_DIRECTORY,
                WEBAPPS_DIRECTORY,
                "webapps/ROOT",
                "webapps/ROOT/META-INF",
                "webapps/ROOT/WEB-INF",
            ] {
                let directory = destination.join(relative);
                fs::create_dir(&directory).map_err(|source| {
                    CoreError::io(
                        "create generated Tomcat bundle subdirectory",
                        &directory,
                        source,
                    )
                })?;
                created.push(CreatedBundlePath::Directory(directory));
            }

            for artifact in &self.artifacts {
                let path = destination.join(artifact.relative_path());
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|source| {
                        CoreError::io("create generated Tomcat artifact", &path, source)
                    })?;
                created.push(CreatedBundlePath::File(path.clone()));
                file.write_all(artifact.contents.as_bytes())
                    .map_err(|source| {
                        CoreError::io("write generated Tomcat artifact", &path, source)
                    })?;
                file.flush().map_err(|source| {
                    CoreError::io("flush generated Tomcat artifact", &path, source)
                })?;
                file.sync_all().map_err(|source| {
                    CoreError::io("sync generated Tomcat artifact", &path, source)
                })?;
            }
            Ok(())
        })();

        if let Err(error) = write_result {
            let cleanup_failures = cleanup_created_bundle_paths(&created);
            if cleanup_failures.is_empty() {
                return Err(error);
            }
            return Err(CoreError::partial_cleanup(
                "write generated Tomcat bundle and remove partial paths",
                destination,
                error,
                cleanup_failures.join("; "),
            ));
        }
        Ok(destination.to_path_buf())
    }
}

#[derive(Debug)]
enum CreatedBundlePath {
    File(PathBuf),
    Directory(PathBuf),
}

fn cleanup_created_bundle_paths(created: &[CreatedBundlePath]) -> Vec<String> {
    cleanup_created_bundle_paths_with(
        created,
        |path| fs::remove_file(path),
        |path| fs::remove_dir(path),
    )
}

fn cleanup_created_bundle_paths_with<RemoveFile, RemoveDirectory>(
    created: &[CreatedBundlePath],
    mut remove_file: RemoveFile,
    mut remove_directory: RemoveDirectory,
) -> Vec<String>
where
    RemoveFile: FnMut(&Path) -> std::io::Result<()>,
    RemoveDirectory: FnMut(&Path) -> std::io::Result<()>,
{
    let mut failures = Vec::new();
    for created_path in created.iter().rev() {
        let (path, result) = match created_path {
            CreatedBundlePath::File(path) => (path, remove_file(path)),
            CreatedBundlePath::Directory(path) => (path, remove_directory(path)),
        };
        if let Err(error) = result {
            tracing::error!(
                path = %path.display(),
                error = %error,
                "failed to remove a partial generated Tomcat bundle path"
            );
            failures.push(format!("{}: {error}", path.display()));
        }
    }
    failures
}

fn validate_generated_bundle(bundle: &GeneratedTomcatConfigBundle) -> CoreResult<()> {
    if bundle.total_bytes() > MAX_GENERATED_TOMCAT_BUNDLE_BYTES {
        return Err(CoreError::validation(
            "generated Tomcat bundle",
            format!("bundle exceeds the {MAX_GENERATED_TOMCAT_BUNDLE_BYTES}-byte limit"),
        ));
    }

    let mut kinds = HashSet::with_capacity(bundle.artifacts.len());
    let mut paths = HashSet::with_capacity(bundle.artifacts.len());
    for artifact in &bundle.artifacts {
        if !kinds.insert(artifact.kind()) || !paths.insert(artifact.relative_path()) {
            return Err(CoreError::validation(
                "generated Tomcat bundle",
                "artifact kinds and relative paths must be unique",
            ));
        }
        validate_artifact_relative_path(artifact.relative_path())?;
        validate_generated_artifact(artifact, bundle.version)?;
    }
    if !TomcatArtifactKind::ALL
        .into_iter()
        .all(|kind| kinds.contains(&kind))
    {
        return Err(CoreError::validation(
            "generated Tomcat bundle",
            "server.xml, context.xml, and web.xml are all required",
        ));
    }
    Ok(())
}

fn validate_generated_artifact(
    artifact: &TomcatConfigArtifact,
    version: TomcatVersionFamily,
) -> CoreResult<()> {
    let contents = artifact.contents();
    if contents.is_empty()
        || contents.len() > MAX_GENERATED_TOMCAT_ARTIFACT_BYTES
        || !contents.ends_with('\n')
        || contents.contains('\0')
    {
        return Err(CoreError::validation(
            "generated Tomcat XML artifact",
            format!(
                "{} must be non-empty, newline-terminated, NUL-free, and at most {} bytes",
                artifact.relative_path(),
                MAX_GENERATED_TOMCAT_ARTIFACT_BYTES
            ),
        ));
    }
    if ["<!DOCTYPE", "<!ENTITY", "<![CDATA[", "<?xml-stylesheet"]
        .into_iter()
        .any(|forbidden| contents.contains(forbidden))
    {
        return Err(CoreError::validation(
            "generated Tomcat XML artifact",
            format!(
                "{} contains a deferred XML construct",
                artifact.relative_path()
            ),
        ));
    }
    parse_xml(contents.as_bytes()).map_err(|()| {
        CoreError::validation(
            "generated Tomcat XML artifact",
            format!("{} is not closed, bounded XML", artifact.relative_path()),
        )
    })?;

    match artifact.kind() {
        TomcatArtifactKind::ServerXml => validate_server_xml(contents),
        TomcatArtifactKind::ContextXml => validate_context_xml(contents),
        TomcatArtifactKind::WebXml => validate_web_xml(contents, version),
    }
}

fn validate_server_xml(contents: &str) -> CoreResult<()> {
    if !contents.contains("<Server port=\"-1\">")
        || !contents.contains("<Service name=\"Catalina\">")
        || !contents.contains("<Engine name=\"Catalina\" defaultHost=\"localhost\">")
        || !contents.contains("<Host name=\"localhost\" appBase=\"webapps\"")
        || !contents.contains("protocol=\"org.apache.coyote.http11.Http11NioProtocol\"")
        || !contents.contains("allowTrace=\"false\"")
        || !(contents.contains("address=\"127.0.0.1\"") || contents.contains("address=\"::1\""))
    {
        return Err(CoreError::validation(
            "generated Tomcat server.xml",
            "missing the fixed disabled-shutdown, loopback NIO Connector, Engine, or Host baseline",
        ));
    }
    if [
        "<Realm",
        "<Valve",
        "<Listener",
        "<GlobalNamingResources",
        "SSLEnabled=",
        "<SSLHostConfig",
    ]
    .into_iter()
    .any(|forbidden| contents.contains(forbidden))
    {
        return Err(CoreError::validation(
            "generated Tomcat server.xml",
            "contains a deferred existing-installation, Realm, Valve, Listener, naming, or TLS component",
        ));
    }
    Ok(())
}

fn validate_context_xml(contents: &str) -> CoreResult<()> {
    if !contents.contains("<Context crossContext=") || !contents.contains("useHttpOnly=") {
        return Err(CoreError::validation(
            "generated Tomcat context.xml",
            "must explicitly own crossContext and useHttpOnly",
        ));
    }
    if ["docBase=", "<Realm", "<Valve", "<Listener", "<Resource"]
        .into_iter()
        .any(|forbidden| contents.contains(forbidden))
    {
        return Err(CoreError::validation(
            "generated Tomcat context.xml",
            "contains a deferred deployment, Realm, Valve, Listener, or resource component",
        ));
    }
    Ok(())
}

fn validate_web_xml(contents: &str, version: TomcatVersionFamily) -> CoreResult<()> {
    let expected_namespace = format!("xmlns=\"{}\"", version.web_xml_namespace());
    let expected_schema = format!(
        "xsi:schemaLocation=\"{} {}\"",
        version.web_xml_namespace(),
        version.web_xml_schema()
    );
    let expected_version = format!("version=\"{}\"", version.web_xml_version());
    if !contents.contains(&expected_namespace)
        || !contents.contains(&expected_schema)
        || !contents.contains(&expected_version)
    {
        return Err(CoreError::validation(
            "generated Tomcat web.xml",
            format!(
                "does not use the exact {} descriptor namespace, schema, and version",
                version.servlet_specification()
            ),
        ));
    }
    match version {
        TomcatVersionFamily::V9_0 if contents.contains("jakarta.ee/xml/ns/jakartaee") => {
            return Err(CoreError::validation(
                "generated Tomcat web.xml",
                "Tomcat 9 must not use a Jakarta Servlet deployment descriptor schema",
            ));
        }
        TomcatVersionFamily::V10_1 | TomcatVersionFamily::V11_0
            if contents.contains("xmlns.jcp.org/xml/ns/javaee") =>
        {
            return Err(CoreError::validation(
                "generated Tomcat web.xml",
                "Tomcat 10.1/11 must not use the Java EE Servlet 4.0 schema",
            ));
        }
        _ => {}
    }
    if contents.contains(HTTP_HEADER_SECURITY_FILTER)
        && (!contents.contains("<param-name>hstsEnabled</param-name><param-value>false</param-value>")
            || !contents.contains("<param-name>antiClickJackingOption</param-name><param-value>DENY</param-value>")
            || !contents.contains("<param-name>blockContentTypeSniffingEnabled</param-name><param-value>true</param-value>"))
    {
        return Err(CoreError::validation(
            "generated Tomcat web.xml",
            "header security filter must disable unmodeled HSTS and close the fixed anti-clickjacking/nosniff settings",
        ));
    }
    if contents.contains("<deny-uncovered-http-methods")
        && !(contents.contains("<http-method>GET</http-method>")
            && contents.contains("<http-method>HEAD</http-method>"))
    {
        return Err(CoreError::validation(
            "generated Tomcat web.xml",
            "deny-uncovered-http-methods requires the closed GET/HEAD allow-list constraint",
        ));
    }
    if [
        "<login-config",
        "<security-role",
        "<env-entry",
        "<resource-ref",
    ]
    .into_iter()
    .any(|forbidden| contents.contains(forbidden))
    {
        return Err(CoreError::validation(
            "generated Tomcat web.xml",
            "contains a deferred identity, secret, or resource component",
        ));
    }
    Ok(())
}

fn validate_artifact_relative_path(relative: &str) -> CoreResult<()> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CoreError::validation(
            "generated Tomcat artifact path",
            "must contain only fixed relative normal path components",
        ));
    }
    Ok(())
}

fn validate_bundle_destination(destination: &Path) -> CoreResult<()> {
    if !destination.is_absolute() {
        return Err(CoreError::validation(
            "Tomcat bundle destination",
            "path must be absolute and selected by the native directory dialog",
        ));
    }
    if destination.file_name().is_none()
        || destination
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CoreError::validation(
            "Tomcat bundle destination",
            "path must name a new child directory without current-directory or parent-directory components",
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        CoreError::validation("Tomcat bundle destination", "path has no parent directory")
    })?;
    if !parent.is_dir() {
        return Err(CoreError::validation(
            "Tomcat bundle destination",
            "parent directory does not exist",
        ));
    }
    Ok(())
}

fn parse_decimal(subject: &'static str, value: &str) -> CoreResult<u32> {
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CoreError::validation(
            subject,
            "must be an unsigned base-10 integer without whitespace or signs",
        ));
    }
    value.parse::<u32>().map_err(|_| {
        CoreError::validation(subject, "is outside the supported unsigned integer range")
    })
}

fn validate_u32_range(
    subject: &'static str,
    value: u32,
    minimum: u32,
    maximum: u32,
) -> CoreResult<()> {
    if !(minimum..=maximum).contains(&value) {
        return Err(CoreError::validation(
            subject,
            format!("must be in {minimum}..={maximum}, got {value}"),
        ));
    }
    Ok(())
}

fn is_safe_xml_text_character(character: char) -> bool {
    matches!(
        character as u32,
        0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

fn push_xml_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
}

const fn boolean_literal(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lovelyres-tomcat-config-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn server(bundle: &GeneratedTomcatConfigBundle) -> &str {
        bundle.artifact(TomcatArtifactKind::ServerXml).contents()
    }

    fn context(bundle: &GeneratedTomcatConfigBundle) -> &str {
        bundle.artifact(TomcatArtifactKind::ContextXml).contents()
    }

    fn web(bundle: &GeneratedTomcatConfigBundle) -> &str {
        bundle.artifact(TomcatArtifactKind::WebXml).contents()
    }

    #[test]
    fn supported_version_families_pin_distinct_servlet_schemas() {
        assert_eq!(TomcatVersionFamily::ALL.len(), 3);
        assert_eq!(TomcatVersionFamily::V9_0.minimum_java(), 8);
        assert_eq!(TomcatVersionFamily::V10_1.minimum_java(), 11);
        assert_eq!(TomcatVersionFamily::V11_0.minimum_java(), 17);
        assert_eq!(
            TomcatVersionFamily::V9_0.servlet_api_namespace(),
            "javax.servlet"
        );
        assert_eq!(
            TomcatVersionFamily::V10_1.servlet_api_namespace(),
            "jakarta.servlet"
        );
        assert_eq!(
            TomcatVersionFamily::V11_0.servlet_api_namespace(),
            "jakarta.servlet"
        );

        let schemas = TomcatVersionFamily::ALL
            .into_iter()
            .map(TomcatVersionFamily::web_xml_schema)
            .collect::<HashSet<_>>();
        assert_eq!(schemas.len(), 3);
        assert!(
            TomcatVersionFamily::V9_0
                .web_xml_schema()
                .ends_with("web-app_4_0.xsd")
        );
        assert!(
            TomcatVersionFamily::V10_1
                .web_xml_schema()
                .ends_with("web-app_6_0.xsd")
        );
        assert!(
            TomcatVersionFamily::V11_0
                .web_xml_schema()
                .ends_with("web-app_6_1.xsd")
        );
    }

    #[test]
    fn feature_and_deferred_catalogs_are_complete_unique_and_searchable() {
        let baseline_keys = TomcatBaselineInvariant::ALL
            .into_iter()
            .map(TomcatBaselineInvariant::key)
            .collect::<HashSet<_>>();
        assert_eq!(baseline_keys.len(), TomcatBaselineInvariant::ALL.len());
        for invariant in TomcatBaselineInvariant::ALL {
            assert!(!invariant.title().is_empty());
            assert!(!invariant.summary().is_empty());
            assert!(!invariant.scope().is_empty());
            assert!(!invariant.aliases().is_empty());
        }

        let feature_keys = TomcatConfigFeature::ALL
            .into_iter()
            .map(TomcatConfigFeature::key)
            .collect::<HashSet<_>>();
        assert_eq!(feature_keys.len(), TomcatConfigFeature::ALL.len());
        for feature in TomcatConfigFeature::ALL {
            assert!(!feature.key().is_empty());
            assert!(!feature.title().is_empty());
            assert!(!feature.summary().is_empty());
            assert!(!feature.scope().is_empty());
            assert!(!feature.aliases().is_empty());
            assert!(
                TomcatVersionFamily::ALL
                    .into_iter()
                    .all(|version| feature.supports_version(version))
            );
        }
        assert_eq!(
            TomcatConfigFeature::ConnectorLimits.artifact(),
            TomcatArtifactKind::ServerXml
        );
        assert_eq!(
            TomcatConfigFeature::AllowCrossContext.artifact(),
            TomcatArtifactKind::ContextXml
        );
        assert_eq!(
            TomcatConfigFeature::DenyAllRequests.artifact(),
            TomcatArtifactKind::WebXml
        );
        assert!(
            !TomcatConfigFeature::ConnectorLimits
                .aliases()
                .contains(&"请求体")
        );
        assert!(
            TomcatConfigFeature::ConnectorLimits
                .aliases()
                .contains(&"表单参数")
        );
        assert!(
            TomcatConfigFeature::ConnectorLimits
                .summary()
                .contains("不是通用 POST、请求体或文件上传上限")
        );

        let deferred_keys = TomcatDeferredCapability::ALL
            .into_iter()
            .map(TomcatDeferredCapability::key)
            .collect::<HashSet<_>>();
        assert_eq!(deferred_keys.len(), TomcatDeferredCapability::ALL.len());
        for capability in TomcatDeferredCapability::ALL {
            assert!(!capability.key().is_empty());
            assert!(!capability.reason().is_empty());
        }
        assert!(TOMCAT_BUNDLE_SCOPE_NOTICE.contains("不是完整安装包"));
        for address in [
            TomcatConnectorAddress::Ipv4Loopback,
            TomcatConnectorAddress::Ipv6Loopback,
        ] {
            assert!(!address.label().is_empty());
            assert!(!address.summary().is_empty());
            assert!(address.summary().contains("本机回环"));
        }

        let connector_field_keys = TomcatConnectorField::ALL
            .into_iter()
            .map(TomcatConnectorField::key)
            .collect::<HashSet<_>>();
        assert_eq!(connector_field_keys.len(), TomcatConnectorField::ALL.len());
        for field in TomcatConnectorField::ALL {
            assert!(!field.title().is_empty());
            assert!(!field.summary().is_empty());
            assert!(!field.aliases().is_empty());
        }
        assert_eq!(TomcatConnectorField::Address.owner_feature(), None);
        assert_eq!(
            TomcatConnectorField::MaxPostSize.owner_feature(),
            Some(TomcatConfigFeature::ConnectorLimits)
        );
        assert_eq!(
            TomcatConnectorField::CompressionMinSize.owner_feature(),
            Some(TomcatConfigFeature::ResponseCompression)
        );
    }

    #[test]
    fn every_baseline_is_a_three_artifact_bounded_closed_bundle() {
        for version in TomcatVersionFamily::ALL {
            let config = TomcatConfig::baseline(version);
            assert_eq!(config.features().len(), 3);
            assert!(config.feature_enabled(TomcatConfigFeature::ConnectorLimits));
            assert!(config.feature_enabled(TomcatConfigFeature::HttpOnlySessionCookies));
            assert!(config.feature_enabled(TomcatConfigFeature::HeaderSecurityFilter));

            let bundle = config.generate().unwrap();
            assert_eq!(bundle.version(), version);
            assert_eq!(bundle.artifacts().len(), 3);
            assert_eq!(
                bundle.suggested_directory_name(),
                "lovelyhawk-tomcat-new-empty-review-bundle"
            );
            assert!(bundle.total_bytes() <= MAX_GENERATED_TOMCAT_BUNDLE_BYTES);
            for (artifact, expected_kind) in bundle.artifacts().iter().zip(TomcatArtifactKind::ALL)
            {
                assert_eq!(artifact.kind(), expected_kind);
                assert!(artifact.contents().len() <= MAX_GENERATED_TOMCAT_ARTIFACT_BYTES);
                parse_xml(artifact.contents().as_bytes()).unwrap();
            }

            assert!(server(&bundle).contains("<Server port=\"-1\">"));
            assert!(server(&bundle).contains("address=\"127.0.0.1\""));
            assert!(server(&bundle).contains("allowTrace=\"false\""));
            assert!(server(&bundle).contains("autoDeploy=\"false\""));
            assert!(server(&bundle).contains("unpackWARs=\"false\""));
            assert!(context(&bundle).contains("crossContext=\"false\""));
            assert!(context(&bundle).contains("useHttpOnly=\"true\""));
            assert!(web(&bundle).contains(version.web_xml_schema()));
            assert!(web(&bundle).contains(HTTP_HEADER_SECURITY_FILTER));
            assert!(
                web(&bundle).contains(
                    "<param-name>hstsEnabled</param-name><param-value>false</param-value>"
                )
            );
        }
    }

    #[test]
    fn schemas_do_not_leak_across_javax_and_jakarta_families() {
        let tomcat_9 = TomcatConfig::baseline(TomcatVersionFamily::V9_0)
            .generate()
            .unwrap();
        let tomcat_10 = TomcatConfig::baseline(TomcatVersionFamily::V10_1)
            .generate()
            .unwrap();
        let tomcat_11 = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .generate()
            .unwrap();

        assert!(web(&tomcat_9).contains("xmlns=\"http://xmlns.jcp.org/xml/ns/javaee\""));
        assert!(!web(&tomcat_9).contains("jakarta.ee/xml/ns/jakartaee"));
        assert!(web(&tomcat_10).contains("web-app_6_0.xsd"));
        assert!(!web(&tomcat_10).contains("web-app_6_1.xsd"));
        assert!(web(&tomcat_11).contains("web-app_6_1.xsd"));
        assert!(!web(&tomcat_11).contains("web-app_6_0.xsd"));
        assert!(!web(&tomcat_10).contains("xmlns.jcp.org/xml/ns/javaee"));
        assert!(!web(&tomcat_11).contains("xmlns.jcp.org/xml/ns/javaee"));
    }

    #[test]
    fn static_bundle_never_claims_existing_installation_components() {
        for version in TomcatVersionFamily::ALL {
            let bundle = TomcatConfig::baseline(version).generate().unwrap();
            let combined = bundle
                .artifacts()
                .iter()
                .map(TomcatConfigArtifact::contents)
                .collect::<String>();
            for forbidden in [
                "<Realm",
                "<Valve",
                "<Listener",
                "<GlobalNamingResources",
                "SSLEnabled=",
                "<SSLHostConfig",
                "<login-config",
                "<security-role",
                "docBase=",
            ] {
                assert!(!combined.contains(forbidden), "found {forbidden}");
            }
        }
    }

    #[test]
    fn features_stack_by_artifact_and_remove_atomically() {
        let configured = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .with_compression_min_size(TomcatCompressionMinBytes::new(4_096).unwrap())
            .with_feature(TomcatConfigFeature::HostAutoDeploy, true)
            .unwrap()
            .with_feature(TomcatConfigFeature::HostUnpackWars, true)
            .unwrap()
            .with_feature(TomcatConfigFeature::AllowCrossContext, true)
            .unwrap()
            .with_feature(TomcatConfigFeature::AllowSafeMethodsOnly, true)
            .unwrap();
        let with_all = configured.generate().unwrap();
        assert!(server(&with_all).contains("compression=\"on\""));
        assert!(server(&with_all).contains("compressionMinSize=\"4096\""));
        assert!(server(&with_all).contains("autoDeploy=\"true\""));
        assert!(server(&with_all).contains("unpackWARs=\"true\""));
        assert!(context(&with_all).contains("crossContext=\"true\""));
        assert!(web(&with_all).contains("<http-method>GET</http-method>"));
        assert!(web(&with_all).contains("<deny-uncovered-http-methods />"));

        let without_compression = configured
            .clone()
            .with_feature(TomcatConfigFeature::ResponseCompression, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!server(&without_compression).contains("compression=\"on\""));
        assert!(server(&without_compression).contains("autoDeploy=\"true\""));
        assert!(context(&without_compression).contains("crossContext=\"true\""));
        assert!(web(&without_compression).contains("<deny-uncovered-http-methods />"));

        let without_method_policy = configured
            .with_feature(TomcatConfigFeature::AllowSafeMethodsOnly, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!web(&without_method_policy).contains("<security-constraint>"));
        assert!(web(&without_method_policy).contains(HTTP_HEADER_SECURITY_FILTER));
    }

    #[test]
    fn removing_every_feature_preserves_the_immutable_baseline() {
        let mut config = TomcatConfig::baseline(TomcatVersionFamily::V10_1);
        for feature in TomcatConfigFeature::ALL {
            config = config.with_feature(feature, false).unwrap();
        }
        let bundle = config.generate().unwrap();
        assert!(config.features().is_empty());
        assert!(server(&bundle).contains("<Server port=\"-1\">"));
        assert!(server(&bundle).contains("address=\"127.0.0.1\""));
        assert!(server(&bundle).contains("port=\"8080\""));
        assert!(server(&bundle).contains("connectionTimeout=\"20000\""));
        assert!(server(&bundle).contains("allowTrace=\"false\""));
        assert!(!server(&bundle).contains("maxThreads="));
        assert!(!web(&bundle).contains(HTTP_HEADER_SECURITY_FILTER));
        assert!(context(&bundle).contains("crossContext=\"false\""));
        assert!(context(&bundle).contains("useHttpOnly=\"false\""));
    }

    #[test]
    fn a_fresh_baseline_is_an_exact_reset_target() {
        for version in TomcatVersionFamily::ALL {
            let changed = TomcatConfig::baseline(version)
                .with_application_name(TomcatApplicationName::parse("Changed application").unwrap())
                .with_feature(TomcatConfigFeature::HostAutoDeploy, true)
                .unwrap()
                .with_feature(TomcatConfigFeature::HeaderSecurityFilter, false)
                .unwrap();
            assert_ne!(changed, TomcatConfig::baseline(version));
            let reset = TomcatConfig::baseline(version);
            assert_eq!(reset, TomcatConfig::baseline(version));
        }
    }

    #[test]
    fn mutually_exclusive_method_policies_fail_closed() {
        let error = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .with_feature(TomcatConfigFeature::AllowSafeMethodsOnly, true)
            .unwrap()
            .with_feature(TomcatConfigFeature::DenyAllRequests, true)
            .unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));

        let deny_all = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .with_feature(TomcatConfigFeature::DenyAllRequests, true)
            .unwrap()
            .generate()
            .unwrap();
        assert!(web(&deny_all).contains("<auth-constraint />"));
        assert!(!web(&deny_all).contains("<deny-uncovered-http-methods"));
        assert!(!web(&deny_all).contains("<http-method>"));
    }

    #[test]
    fn numeric_inputs_are_strictly_bounded_and_connector_relation_is_checked() {
        assert!(TomcatConnectorPort::new(0).is_err());
        assert!(TomcatConnectorPort::new(65_536).is_err());
        assert!(TomcatConnectorPort::parse("8080").is_ok());
        assert!(TomcatConnectorPort::parse(" 8080").is_err());
        assert!(TomcatConnectorPort::parse("+8080").is_err());
        assert!(TomcatConnectionTimeoutMillis::new(0).is_err());
        assert!(TomcatConnectionTimeoutMillis::new(3_600_001).is_err());
        assert!(TomcatMaxThreads::new(10_001).is_err());
        assert!(TomcatAcceptCount::new(100_001).is_err());
        assert!(TomcatMaxConnections::new(1_000_001).is_err());
        assert!(TomcatFormParameterBytes::new(0).is_err());
        assert!(TomcatAbortedUploadSwallowBytes::new(0).is_err());
        assert!(TomcatCompressionMinBytes::new(1_048_577).is_err());
        assert!(TomcatFormParameterBytes::meaning().contains("不是通用请求体"));
        assert!(TomcatAbortedUploadSwallowBytes::meaning().contains("不是正常上传"));
        assert!(
            TomcatConfigFeature::ConnectorLimits
                .summary()
                .contains("不是通用 POST")
        );

        let incompatible = TomcatConnectorConfig::new(
            TomcatConnectorAddress::Ipv6Loopback,
            TomcatConnectorPort::new(8_080).unwrap(),
            TomcatConnectionTimeoutMillis::new(20_000).unwrap(),
            TomcatMaxThreads::new(201).unwrap(),
            TomcatAcceptCount::new(100).unwrap(),
            TomcatMaxConnections::new(200).unwrap(),
            TomcatFormParameterBytes::new(DEFAULT_BODY_LIMIT_BYTES).unwrap(),
            TomcatAbortedUploadSwallowBytes::new(DEFAULT_BODY_LIMIT_BYTES).unwrap(),
        );
        assert!(incompatible.is_err());
    }

    #[test]
    fn typed_application_name_is_xml_escaped_and_controls_are_rejected() {
        let name = TomcatApplicationName::parse("A&B <ROOT> \"quoted\" 'single'").unwrap();
        let bundle = TomcatConfig::baseline(TomcatVersionFamily::V9_0)
            .with_application_name(name)
            .generate()
            .unwrap();
        assert!(web(&bundle).contains(
            "<display-name>A&amp;B &lt;ROOT&gt; &quot;quoted&quot; &apos;single&apos;</display-name>"
        ));
        assert!(!web(&bundle).contains("<ROOT>"));
        parse_xml(web(&bundle).as_bytes()).unwrap();

        assert!(TomcatApplicationName::parse("").is_err());
        assert!(TomcatApplicationName::parse(" leading").is_err());
        assert!(TomcatApplicationName::parse("line\nbreak").is_err());
        assert!(TomcatApplicationName::parse("nul\0byte").is_err());
        assert!(TomcatApplicationName::parse(&"界".repeat(129)).is_err());
    }

    #[test]
    fn generation_is_deterministic_independent_of_feature_toggle_order() {
        let features = [
            TomcatConfigFeature::ResponseCompression,
            TomcatConfigFeature::HostAutoDeploy,
            TomcatConfigFeature::HostUnpackWars,
            TomcatConfigFeature::AllowCrossContext,
            TomcatConfigFeature::AllowSafeMethodsOnly,
        ];
        let mut forward = TomcatConfig::baseline(TomcatVersionFamily::V10_1);
        for feature in features {
            forward = forward.with_feature(feature, true).unwrap();
        }
        let mut reverse = TomcatConfig::baseline(TomcatVersionFamily::V10_1);
        for feature in features.into_iter().rev() {
            reverse = reverse.with_feature(feature, true).unwrap();
        }
        assert_eq!(forward.generate().unwrap(), reverse.generate().unwrap());
    }

    #[test]
    fn every_non_conflicting_feature_combination_is_bounded_and_closed() {
        for version in TomcatVersionFamily::ALL {
            for mask in 0_u16..(1_u16 << TomcatConfigFeature::ALL.len()) {
                let safe_index = TomcatConfigFeature::ALL
                    .iter()
                    .position(|feature| *feature == TomcatConfigFeature::AllowSafeMethodsOnly)
                    .unwrap();
                let deny_index = TomcatConfigFeature::ALL
                    .iter()
                    .position(|feature| *feature == TomcatConfigFeature::DenyAllRequests)
                    .unwrap();
                if mask & (1 << safe_index) != 0 && mask & (1 << deny_index) != 0 {
                    continue;
                }
                let mut config = TomcatConfig::baseline(version);
                for (index, feature) in TomcatConfigFeature::ALL.into_iter().enumerate() {
                    config = config
                        .with_feature(feature, mask & (1 << index) != 0)
                        .unwrap();
                }
                let bundle = config.generate().unwrap();
                validate_generated_bundle(&bundle).unwrap();
            }
        }
    }

    #[test]
    fn artifact_paths_are_fixed_unique_and_never_traverse() {
        let paths = TomcatArtifactKind::ALL
            .into_iter()
            .map(TomcatArtifactKind::relative_path)
            .collect::<HashSet<_>>();
        assert_eq!(paths.len(), 3);
        for path in paths {
            validate_artifact_relative_path(path).unwrap();
        }
        assert!(validate_artifact_relative_path("../server.xml").is_err());
        assert!(validate_artifact_relative_path("conf/../server.xml").is_err());
    }

    #[test]
    fn tomcat_catalog_inline_editor_and_preview_prerequisites_are_typed_and_byte_exact() {
        let feature = TomcatConfigFeature::ConnectorLimits;
        assert_eq!(feature.key(), "connector-limits");
        assert_eq!(
            feature.title(),
            "限制 Connector 容量、参数转换与中止上传吞咽量"
        );
        assert_eq!(feature.scope(), "Connector / server.xml");
        assert_eq!(feature.artifact(), TomcatArtifactKind::ServerXml);
        assert_eq!(
            feature.aliases(),
            [
                "maxThreads",
                "acceptCount",
                "maxConnections",
                "maxPostSize",
                "maxSwallowSize",
                "连接数",
                "表单参数",
                "参数转换",
                "中止上传吞咽",
            ]
        );
        assert!(feature.default_enabled());
        assert!(
            TomcatVersionFamily::ALL
                .into_iter()
                .all(|version| feature.supports_version(version))
        );
        assert_eq!(
            TomcatConnectorField::ALL
                .into_iter()
                .filter(|field| field.owner_feature() == Some(feature))
                .map(TomcatConnectorField::key)
                .collect::<Vec<_>>(),
            [
                "maxThreads",
                "acceptCount",
                "maxConnections",
                "maxPostSize",
                "maxSwallowSize",
            ]
        );

        let baseline_config = TomcatConfig::baseline(TomcatVersionFamily::V11_0);
        let baseline = baseline_config.generate().unwrap();
        let connector = TomcatConnectorConfig::new(
            TomcatConnectorAddress::Ipv4Loopback,
            TomcatConnectorPort::new(8_080).unwrap(),
            TomcatConnectionTimeoutMillis::new(20_000).unwrap(),
            TomcatMaxThreads::new(320).unwrap(),
            TomcatAcceptCount::new(400).unwrap(),
            TomcatMaxConnections::new(12_000).unwrap(),
            TomcatFormParameterBytes::new(3_000_000).unwrap(),
            TomcatAbortedUploadSwallowBytes::new(4_000_000).unwrap(),
        )
        .unwrap();
        let selected_config = baseline_config.with_connector(connector).unwrap();
        let selected = selected_config.generate().unwrap();
        const DEFAULT_LIMITS: &str = "\n      maxThreads=\"200\" acceptCount=\"100\" maxConnections=\"8192\" maxPostSize=\"2097152\" maxSwallowSize=\"2097152\"";
        const SELECTED_LIMITS: &str = "\n      maxThreads=\"320\" acceptCount=\"400\" maxConnections=\"12000\" maxPostSize=\"3000000\" maxSwallowSize=\"4000000\"";
        assert_eq!(
            server(&selected),
            server(&baseline).replace(DEFAULT_LIMITS, SELECTED_LIMITS)
        );
        assert_eq!(context(&selected), context(&baseline));
        assert_eq!(web(&selected), web(&baseline));

        let removed = selected_config
            .with_feature(TomcatConfigFeature::ConnectorLimits, false)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(
            server(&removed),
            server(&baseline).replace(DEFAULT_LIMITS, "")
        );
        assert_eq!(context(&removed), context(&baseline));
        assert_eq!(web(&removed), web(&baseline));

        assert!(TomcatMaxThreads::new(0).is_err());
        assert!(TomcatMaxThreads::new(10_001).is_err());
        assert!(TomcatAcceptCount::new(0).is_err());
        assert!(TomcatAcceptCount::new(100_001).is_err());
        assert!(TomcatMaxConnections::new(0).is_err());
        assert!(TomcatMaxConnections::new(1_000_001).is_err());
        assert!(TomcatFormParameterBytes::new(0).is_err());
        assert!(TomcatFormParameterBytes::new(1_073_741_825).is_err());
        assert!(TomcatAbortedUploadSwallowBytes::new(0).is_err());
        assert!(TomcatAbortedUploadSwallowBytes::new(1_073_741_825).is_err());
        assert!(
            TomcatConnectorConfig::new(
                TomcatConnectorAddress::Ipv4Loopback,
                TomcatConnectorPort::new(8_080).unwrap(),
                TomcatConnectionTimeoutMillis::new(20_000).unwrap(),
                TomcatMaxThreads::new(500).unwrap(),
                TomcatAcceptCount::new(100).unwrap(),
                TomcatMaxConnections::new(400).unwrap(),
                TomcatFormParameterBytes::new(2_097_152).unwrap(),
                TomcatAbortedUploadSwallowBytes::new(2_097_152).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn tomcat_quick_bundle_stack_exclude_remove_reset_and_save_prerequisite_is_byte_exact() {
        let baseline = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .generate()
            .unwrap();
        assert_eq!(
            baseline.suggested_directory_name(),
            "lovelyhawk-tomcat-new-empty-review-bundle"
        );
        assert!(server(&baseline).contains("address=\"127.0.0.1\""));
        assert!(server(&baseline).contains("port=\"8080\""));
        assert!(server(&baseline).contains("connectionTimeout=\"20000\""));
        assert!(server(&baseline).contains("maxThreads=\"200\""));
        assert!(web(&baseline).contains("web-app_6_1.xsd"));
        assert!(!web(&baseline).contains("javax.servlet"));

        let connector = TomcatConnectorConfig::new(
            TomcatConnectorAddress::Ipv6Loopback,
            TomcatConnectorPort::new(8_181).unwrap(),
            TomcatConnectionTimeoutMillis::new(25_000).unwrap(),
            TomcatMaxThreads::new(320).unwrap(),
            TomcatAcceptCount::new(400).unwrap(),
            TomcatMaxConnections::new(12_000).unwrap(),
            TomcatFormParameterBytes::new(3_000_000).unwrap(),
            TomcatAbortedUploadSwallowBytes::new(4_000_000).unwrap(),
        )
        .unwrap();
        let stacked_config = TomcatConfig::baseline(TomcatVersionFamily::V10_1)
            .with_application_name(TomcatApplicationName::parse("Operations ROOT").unwrap())
            .with_connector(connector)
            .unwrap()
            .with_compression_min_size(TomcatCompressionMinBytes::new(1_024).unwrap())
            .with_feature(TomcatConfigFeature::HostAutoDeploy, true)
            .unwrap()
            .with_feature(TomcatConfigFeature::AllowSafeMethodsOnly, true)
            .unwrap();
        let stacked = stacked_config.generate().unwrap();
        for expected in [
            "address=\"::1\"",
            "port=\"8181\"",
            "connectionTimeout=\"25000\"",
            "maxThreads=\"320\"",
            "acceptCount=\"400\"",
            "maxConnections=\"12000\"",
            "maxPostSize=\"3000000\"",
            "maxSwallowSize=\"4000000\"",
            "compressionMinSize=\"1024\"",
            "autoDeploy=\"true\"",
        ] {
            assert!(server(&stacked).contains(expected), "{expected}");
        }
        assert!(web(&stacked).contains("web-app_6_0.xsd"));
        assert!(web(&stacked).contains("<display-name>Operations ROOT</display-name>"));
        assert!(web(&stacked).contains("<http-method>GET</http-method>"));
        assert!(web(&stacked).contains("<deny-uncovered-http-methods />"));
        let version_baseline = TomcatConfig::baseline(TomcatVersionFamily::V10_1)
            .generate()
            .unwrap();
        assert_eq!(context(&stacked), context(&version_baseline));

        assert!(
            stacked_config
                .clone()
                .with_feature(TomcatConfigFeature::DenyAllRequests, true)
                .is_err()
        );
        let deny_all_config = stacked_config
            .with_feature(TomcatConfigFeature::AllowSafeMethodsOnly, false)
            .unwrap()
            .with_feature(TomcatConfigFeature::DenyAllRequests, true)
            .unwrap();
        let deny_all = deny_all_config.generate().unwrap();
        assert_eq!(server(&deny_all), server(&stacked));
        assert_eq!(context(&deny_all), context(&stacked));
        assert!(!web(&deny_all).contains("<http-method>GET</http-method>"));
        assert!(
            web(&deny_all).contains("<web-resource-name>LovelyHawk deny all</web-resource-name>")
        );
        assert!(web(&deny_all).contains("<auth-constraint />"));

        let without_deny_config = deny_all_config
            .with_feature(TomcatConfigFeature::DenyAllRequests, false)
            .unwrap();
        let without_deny = without_deny_config.generate().unwrap();
        assert_eq!(server(&without_deny), server(&deny_all));
        assert_eq!(context(&without_deny), context(&deny_all));
        assert!(!web(&without_deny).contains("LovelyHawk deny all"));
        let without_compression = without_deny_config
            .with_feature(TomcatConfigFeature::ResponseCompression, false)
            .unwrap()
            .generate()
            .unwrap();
        assert!(!server(&without_compression).contains("compressionMinSize"));
        assert!(server(&without_compression).contains("autoDeploy=\"true\""));
        assert_eq!(context(&without_compression), context(&without_deny));
        assert_eq!(web(&without_compression), web(&without_deny));

        let reset = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .generate()
            .unwrap();
        assert_eq!(reset, baseline);
        let root = TestRoot::new();
        let destination = root.0.join(reset.suggested_directory_name());
        assert_eq!(reset.write_new(&destination).unwrap(), destination);
        for artifact in reset.artifacts() {
            assert_eq!(
                fs::read(destination.join(artifact.relative_path())).unwrap(),
                artifact.contents().as_bytes()
            );
        }
        assert!(reset.write_new(&destination).is_err());
        for artifact in reset.artifacts() {
            assert_eq!(
                fs::read(destination.join(artifact.relative_path())).unwrap(),
                artifact.contents().as_bytes()
            );
        }
    }

    #[test]
    fn write_new_creates_the_exact_bundle_and_never_overwrites() {
        let root = TestRoot::new();
        let destination = root.0.join("tomcat-review-bundle");
        let bundle = TomcatConfig::baseline(TomcatVersionFamily::V11_0)
            .generate()
            .unwrap();
        assert_eq!(bundle.write_new(&destination).unwrap(), destination);

        for artifact in bundle.artifacts() {
            let path = destination.join(artifact.relative_path());
            assert_eq!(fs::read_to_string(path).unwrap(), artifact.contents());
        }
        assert!(bundle.write_new(&destination).is_err());
        assert_eq!(
            fs::read_to_string(destination.join("conf/server.xml")).unwrap(),
            server(&bundle)
        );
    }

    #[test]
    fn write_new_rejects_untrusted_destination_shapes_before_creating_anything() {
        let root = TestRoot::new();
        let bundle = TomcatConfig::baseline(TomcatVersionFamily::V10_1)
            .generate()
            .unwrap();
        assert!(bundle.write_new(Path::new("relative-bundle")).is_err());
        assert!(
            bundle
                .write_new(&root.0.join("missing-parent").join("bundle"))
                .is_err()
        );
        assert!(
            bundle
                .write_new(&root.0.join("child").join("..").join("bundle"))
                .is_err()
        );
        assert!(!root.0.join("missing-parent").exists());
        assert!(!root.0.join("bundle").exists());
    }

    #[test]
    fn write_new_revalidates_private_artifacts_before_creating_destination() {
        let root = TestRoot::new();
        let destination = root.0.join("corrupt-bundle");
        let mut bundle = TomcatConfig::baseline(TomcatVersionFamily::V9_0)
            .generate()
            .unwrap();
        bundle.artifacts[0].contents.push_str("<unclosed>");
        assert!(bundle.write_new(&destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn cleanup_helper_reports_every_failure_and_composite_error_is_visible() {
        let created = [
            CreatedBundlePath::Directory(PathBuf::from("bundle")),
            CreatedBundlePath::Directory(PathBuf::from("bundle/conf")),
            CreatedBundlePath::File(PathBuf::from("bundle/conf/server.xml")),
        ];
        let failures = cleanup_created_bundle_paths_with(
            &created,
            |path| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("file locked: {}", path.display()),
                ))
            },
            |path| {
                Err(std::io::Error::other(format!(
                    "directory busy: {}",
                    path.display()
                )))
            },
        );
        assert_eq!(failures.len(), 3);
        assert!(failures[0].contains("bundle/conf/server.xml"));
        assert!(failures[1].contains("bundle/conf"));
        assert!(failures[2].contains("bundle"));

        let primary = CoreError::validation("Tomcat test write", "simulated write failure");
        let composite = CoreError::partial_cleanup(
            "write Tomcat test bundle",
            Path::new("bundle"),
            primary,
            failures.join("; "),
        );
        let message = composite.to_string();
        assert!(message.contains("simulated write failure"));
        assert!(message.contains("file locked"));
        assert!(message.contains("directory busy"));
        assert!(message.contains("bundle/conf/server.xml"));
    }
}
