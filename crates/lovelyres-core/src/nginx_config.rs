//! Deterministic generation of bounded Nginx site configuration snippets.
//!
//! User-provided values cross typed validation boundaries before rendering.
//! The generated document contains only a closed set of directives and can be
//! saved locally only through a non-overwriting, native-dialog path contract.

use std::{
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

/// One exact DNS name accepted by the first generator version.
///
/// Wildcards, regex server names, IP literals, variables and multiple names
/// are deliberately excluded so input cannot cross an Nginx token boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxServerNames(String);

impl NginxServerNames {
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
    security_headers: bool,
    forbidden_path_rule: Option<NginxForbiddenPathRule>,
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
        Ok(Self {
            names,
            port,
            target,
            security_headers,
            forbidden_path_rule: None,
        })
    }

    pub fn with_forbidden_path_rule(mut self, rule: NginxForbiddenPathRule) -> CoreResult<Self> {
        rule.validate()?;
        self.forbidden_path_rule = Some(rule);
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

    pub const fn security_headers(&self) -> bool {
        self.security_headers
    }

    pub fn forbidden_path_rule(&self) -> Option<&NginxForbiddenPathRule> {
        self.forbidden_path_rule.as_ref()
    }

    pub fn generate(&self) -> CoreResult<GeneratedNginxConfig> {
        self.names.validate()?;
        self.port.validate()?;
        self.target.validate()?;
        if let Some(rule) = &self.forbidden_path_rule {
            rule.validate()?;
        }

        let mut contents = String::with_capacity(1_024);
        contents.push_str("server {\n    listen ");
        contents.push_str(&self.port.get().to_string());
        contents.push_str(";\n    server_name ");
        contents.push_str(self.names.as_str());
        contents.push(';');

        if self.security_headers {
            contents.push_str(
                "\n\n    server_tokens off;\n    add_header X-Content-Type-Options \"nosniff\" always;\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            );
        }

        if let Some(rule) = &self.forbidden_path_rule {
            contents.push_str("\n\n    location = ");
            contents.push_str(rule.path().as_str());
            contents.push_str(" {\n        return 403;\n    }");
            if rule.scope() == NginxForbiddenPathScope::PathAndDescendants {
                contents.push_str("\n\n    location ^~ ");
                contents.push_str(rule.path().as_str());
                contents.push_str("/ {\n        return 403;\n    }");
            }
        }

        match &self.target {
            NginxSiteTarget::Static(root) => {
                contents.push_str("\n\n    root \"");
                contents.push_str(root.as_str());
                contents.push_str(
                    "\";\n    index index.html index.htm;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n",
                );
            }
            NginxSiteTarget::ReverseProxy(upstream) => {
                contents.push_str("\n\n    location / {\n        proxy_pass ");
                contents.push_str(upstream.as_str());
                contents.push_str(
                    ";\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n",
                );
            }
        }

        validate_generated_document(&contents)?;
        Ok(GeneratedNginxConfig { contents })
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
            "server {\n    listen 8080;\n    server_name example.com;\n\n    root \"/srv/www/example\";\n    index index.html index.htm;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n}\n"
        );
        assert!(first.contents().len() <= MAX_GENERATED_NGINX_CONFIG_BYTES);
    }

    #[test]
    fn reverse_proxy_template_has_only_fixed_security_directives() {
        let generated = reverse_proxy_config(true).generate().unwrap();
        assert_eq!(
            generated.contents(),
            "server {\n    listen 80;\n    server_name api.example.com;\n\n    server_tokens off;\n    add_header X-Content-Type-Options \"nosniff\" always;\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n"
        );
        assert_eq!(
            reverse_proxy_config(false).kind(),
            NginxSiteKind::ReverseProxy
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
