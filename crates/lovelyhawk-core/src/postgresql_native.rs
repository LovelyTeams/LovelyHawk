//! Native PostgreSQL runtime inspection over an already authenticated SSH stream.
//! Only the reviewed identity and runtime queries can reach this transport.

use futures::StreamExt;
use native_tls::{Certificate, Protocol};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    future::{Future, poll_fn},
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::{
    Client, Config, NoTls, SimpleQueryMessage,
    config::SslMode,
    tls::{ChannelBinding, TlsConnect, TlsStream},
};
use zeroize::Zeroizing;

use crate::{
    CoreError, CoreResult,
    crypto::SecretValue,
    database::{DatabaseConnection, DatabaseEngine},
    database_config::DatabaseConfigProduct,
    database_config_runtime::{
        DatabaseConfigRuntimeDocument, DatabaseConfigRuntimeIdentity,
        MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES, MAX_DATABASE_CONFIG_RUNTIME_ROWS,
        MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES, database_config_runtime_identity_plan,
        database_config_runtime_query_plan,
    },
    postgresql_wire::{FrameGuard, WireBudget},
};

pub(crate) const NATIVE_READ_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_CA_BYTES: usize = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 16 * 1024;
const MAX_NOTICES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresqlTlsMode {
    #[default]
    VerifyFull,
    /// Requires an explicit literal loopback destination behind the SSH host.
    SshLoopback,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PostgresqlTlsSettings {
    #[serde(default)]
    pub mode: PostgresqlTlsMode,
    /// One public CA certificate. Private keys and extra PEM blocks are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_pem: Option<String>,
}

impl PostgresqlTlsSettings {
    pub fn validate(&self, connection: &DatabaseConnection) -> CoreResult<()> {
        connection.validate()?;
        let host = endpoint_host(&connection.host);
        if host.is_empty()
            || host.contains(['[', ']'])
            || ((connection.host.starts_with('[') || connection.host.ends_with(']'))
                && host.parse::<std::net::Ipv6Addr>().is_err())
        {
            return Err(invalid("请填写有效的数据库主机名或 IP 地址"));
        }
        if connection.engine != DatabaseEngine::Postgresql {
            return Err(invalid("TLS 配置只适用于 PostgreSQL 连接"));
        }
        if self.mode == PostgresqlTlsMode::SshLoopback {
            if !endpoint_host(&connection.host)
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            {
                return Err(invalid(
                    "仅使用 SSH 保护时，数据库必须位于该 SSH 主机的回环 IP 地址",
                ));
            }
            if self.ca_certificate_pem.is_some() {
                return Err(invalid("未启用数据库 TLS 时不能配置 CA 证书"));
            }
        }
        if let Some(pem) = &self.ca_certificate_pem {
            parse_ca(pem)?;
        }
        Ok(())
    }
}

fn parse_ca(pem: &str) -> CoreResult<Certificate> {
    if pem.len() > MAX_CA_BYTES {
        return Err(invalid("请提供一份不超过 64 KiB 的 PEM 格式 CA 证书"));
    }
    let pem = pem.trim();
    if !pem.starts_with("-----BEGIN CERTIFICATE-----")
        || !pem.ends_with("-----END CERTIFICATE-----")
        || pem.matches("-----BEGIN ").count() != 1
        || pem.matches("-----END ").count() != 1
        || pem.contains("PRIVATE KEY")
    {
        return Err(invalid("请提供一份不超过 64 KiB 的 PEM 格式 CA 证书"));
    }
    Certificate::from_pem(pem.as_bytes()).map_err(|_| invalid("CA 证书无法解析"))
}

fn invalid(reason: &'static str) -> CoreError {
    CoreError::validation("PostgreSQL native transport", reason)
}

fn endpoint_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}

pub(crate) struct NativeRuntimeRequest {
    connection: DatabaseConnection,
    tls: PostgresqlTlsSettings,
    password: Option<SecretValue>,
}

impl fmt::Debug for NativeRuntimeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativePostgresqlRuntimeRequest")
            .field("tls_mode", &self.tls.mode)
            .finish_non_exhaustive()
    }
}

impl NativeRuntimeRequest {
    pub(crate) fn new(
        connection: DatabaseConnection,
        tls: PostgresqlTlsSettings,
        password: Option<SecretValue>,
    ) -> CoreResult<Self> {
        tls.validate(&connection)?;
        if connection
            .username
            .as_deref()
            .is_none_or(|name| name.is_empty() || name.contains('\0'))
            || connection
                .database
                .as_deref()
                .is_some_and(|name| name.is_empty() || name.contains('\0'))
        {
            return Err(invalid("请填写 PostgreSQL 用户名和有效的数据库名称"));
        }
        if password.as_ref().is_some_and(|value| {
            value.expose().len() > MAX_PASSWORD_BYTES || value.expose().contains('\0')
        }) {
            return Err(invalid("数据库口令超过长度限制或包含不支持的字符"));
        }
        Ok(Self {
            connection,
            tls,
            password,
        })
    }

    pub(crate) fn host(&self) -> &str {
        endpoint_host(&self.connection.host)
    }
    pub(crate) fn port(&self) -> u16 {
        self.connection.port
    }
}

#[derive(Debug)]
pub(crate) struct NativeRuntimeRead {
    pub identity_plan_id: &'static str,
    pub query_plan_id: &'static str,
    pub identity: DatabaseConfigRuntimeIdentity,
    pub document: DatabaseConfigRuntimeDocument,
    pub tls_mode: PostgresqlTlsMode,
    pub notice_count: usize,
    pub observation: crate::postgresql_observation::PostgresqlObservation,
    pub host_process: crate::postgresql_process::PostgresqlHostInspection,
    pub access: crate::postgresql_access::PostgresqlAccessReview,
}

/// The SSH actor owns this entire future. Dropping it drops the connection and
/// closes the SSH channel; no detached database driver or remote CLI is created.
pub(crate) async fn read_over_stream<S, F, P>(
    stream: S,
    request: NativeRuntimeRequest,
    probe: F,
) -> CoreResult<NativeRuntimeRead>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(crate::postgresql_process::ProcessProbeInput) -> P + Send,
    P: Future<Output = crate::postgresql_process::PostgresqlHostInspection> + Send,
{
    let mut config = Config::new();
    // connect_raw uses the supplied SSH stream, but still requires a hostname
    // in Config before it permits TLS. The connector verifies this same host.
    config.host(request.host());
    config.user(
        request
            .connection
            .username
            .as_deref()
            .expect("validated username"),
    );
    config.dbname(request.connection.database.as_deref().unwrap_or("postgres"));
    config.application_name("LovelyHawk runtime review");
    config.options("-c default_transaction_read_only=on -c statement_timeout=20000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog");
    if let Some(password) = &request.password {
        config.password(password.expose());
    }
    let mode = request.tls.mode;
    match mode {
        PostgresqlTlsMode::VerifyFull => {
            let mut builder = native_tls::TlsConnector::builder();
            builder.min_protocol_version(Some(Protocol::Tlsv12));
            if let Some(pem) = &request.tls.ca_certificate_pem {
                builder.add_root_certificate(parse_ca(pem)?);
            }
            let connector = builder
                .build()
                .map_err(|_| invalid("无法建立数据库 TLS 验证器"))?;
            let connector = postgres_native_tls::TlsConnector::new(connector, request.host());
            config.ssl_mode(SslMode::Require);
            drop(request);
            connect_and_read(
                WireBudget::new(stream),
                GuardedTls(connector),
                config,
                mode,
                probe,
            )
            .await
        }
        PostgresqlTlsMode::SshLoopback => {
            config.ssl_mode(SslMode::Disable);
            drop(request);
            connect_and_read(
                FrameGuard::new(WireBudget::new(stream)),
                NoTls,
                config,
                mode,
                probe,
            )
            .await
        }
    }
}

struct GuardedTls(postgres_native_tls::TlsConnector);

impl<S> TlsConnect<S> for GuardedTls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = FrameGuard<postgres_native_tls::TlsStream<S>>;
    type Error = native_tls::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;
    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move { self.0.connect(stream).await.map(FrameGuard::new) })
    }
}

impl<S: TlsStream + Unpin> TlsStream for FrameGuard<S> {
    fn channel_binding(&self) -> ChannelBinding {
        self.inner().channel_binding()
    }
}

async fn connect_and_read<S, T, F, P>(
    stream: S,
    tls: T,
    mut config: Config,
    mode: PostgresqlTlsMode,
    probe: F,
) -> CoreResult<NativeRuntimeRead>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: TlsConnect<S>,
    F: FnOnce(crate::postgresql_process::ProcessProbeInput) -> P + Send,
    P: Future<Output = crate::postgresql_process::PostgresqlHostInspection> + Send,
{
    let connected =
        tokio::time::timeout(Duration::from_secs(12), config.connect_raw(stream, tls)).await;
    // Our credential type is zeroizing. The driver owns its authentication
    // copies; discard the Config's password as soon as authentication ends.
    config.password(b"");
    let (client, mut connection) = connected
        .map_err(|_| invalid("数据库连接或认证超时"))?
        .map_err(|error| {
            database_error(
                "数据库连接或认证失败，请核对地址、口令、证书及访问规则",
                error,
            )
        })?;
    let notices = Arc::new(AtomicUsize::new(0));
    let driver_notices = notices.clone();
    // Connection's default Future logs server NOTICE text. Poll messages here
    // instead, counting notices without allowing server-chosen text into logs.
    let driver = async {
        while let Some(message) = poll_fn(|cx| connection.poll_message(cx)).await {
            message.map_err(|error| database_error("数据库连接中断，未取得完整结果", error))?;
            if driver_notices.fetch_add(1, Ordering::Relaxed) >= MAX_NOTICES {
                return Err(invalid("数据库返回的额外通知超过上限，检查已停止"));
            }
        }
        Ok(())
    };
    tokio::pin!(driver);
    let result = tokio::select! {
        result = read_queries(&client, mode, probe) => result,
        stopped = &mut driver => { stopped?; return Err(invalid("数据库在检查完成前关闭了连接")); }
    };
    drop(client);
    if result.is_ok() {
        tokio::time::timeout(Duration::from_secs(2), &mut driver)
            .await
            .map_err(|_| invalid("数据库连接关闭超时，结果尚未完成确认"))??;
    }
    result.map(|mut read| {
        read.notice_count = notices.load(Ordering::Relaxed);
        read
    })
}

async fn read_queries<F, P>(
    client: &Client,
    tls_mode: PostgresqlTlsMode,
    probe: F,
) -> CoreResult<NativeRuntimeRead>
where
    F: FnOnce(crate::postgresql_process::ProcessProbeInput) -> P + Send,
    P: Future<Output = crate::postgresql_process::PostgresqlHostInspection> + Send,
{
    let identity_plan = database_config_runtime_identity_plan(DatabaseConfigProduct::PostgreSql)
        .map_err(|_| invalid("没有适用的 PostgreSQL 身份检查"))?;
    let identity_bytes = collect_tsv(
        client,
        identity_plan.query(),
        3,
        1,
        MAX_DATABASE_CONFIG_RUNTIME_IDENTITY_TSV_BYTES,
    )
    .await?;
    let identity = identity_plan.parse_tsv(identity_bytes).map_err(|error| {
        CoreError::validation(
            "PostgreSQL native identity",
            format!("数据库产品或版本未通过身份核对（{error}）"),
        )
    })?;
    let plan = database_config_runtime_query_plan(identity.runtime_target())
        .map_err(|_| invalid("该 PostgreSQL 版本尚未适配运行参数检查"))?;
    let before = read_observation(client).await?;
    let bytes = collect_tsv(
        client,
        plan.query(),
        9,
        MAX_DATABASE_CONFIG_RUNTIME_ROWS,
        MAX_DATABASE_CONFIG_RUNTIME_TSV_BYTES,
    )
    .await?;
    let document = plan
        .parse_native_postgresql_tsv(bytes)
        // These parser errors contain only closed variants and numeric offsets,
        // never server text. Keep that diagnostic so real incompatibilities can
        // be identified without exporting raw or possibly sensitive settings.
        .map_err(|error| {
            CoreError::validation(
                "PostgreSQL native parameters",
                format!("数据库返回的运行参数未能完整解析（{error}）"),
            )
        })?;
    let observation = read_observation(client).await?;
    before.verify_stable(&observation, &document)?;
    let host_process = if let Some(input) = observation.process_input() {
        probe(input).await
    } else {
        crate::postgresql_process::PostgresqlHostInspection::unavailable(
            crate::postgresql_process::ProcessUnavailableReason::NoTcpObservation,
        )
    };
    let access =
        crate::postgresql_access::read(client, identity.version(), observation.database_identity())
            .await;
    let after = read_observation(client).await?;
    observation.verify_stable(&after, &document)?;
    Ok(NativeRuntimeRead {
        identity_plan_id: identity_plan.id(),
        query_plan_id: plan.id(),
        identity,
        document,
        tls_mode,
        notice_count: 0,
        observation: after,
        host_process,
        access,
    })
}

async fn read_observation(
    client: &Client,
) -> CoreResult<crate::postgresql_observation::PostgresqlObservation> {
    use crate::postgresql_observation::{CONTROL_QUERY, MAX_BYTES, PostgresqlObservation, QUERY};
    let pending =
        PostgresqlObservation::parse_pending(collect_tsv(client, QUERY, 1, 1, MAX_BYTES).await?)?;
    // PostgreSQL can check SRF privileges while initializing even an unchosen
    // CASE subplan. Never include the protected function in the base query.
    let identifier = if pending.control_readable() {
        Some(collect_tsv(client, CONTROL_QUERY, 1, 1, 41).await?)
    } else {
        None
    };
    pending.finish(identifier)
}

pub(crate) async fn collect_tsv(
    client: &Client,
    query: &'static str,
    columns: usize,
    maximum_rows: usize,
    maximum_bytes: usize,
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let stream = client
        .simple_query_raw(query)
        .await
        .map_err(|error| database_error("数据库检查未能执行", error))?;
    tokio::pin!(stream);
    let mut output = Zeroizing::new(Vec::new());
    let mut rows = 0_usize;
    let mut described = false;
    let mut completed = false;
    while let Some(message) = stream.next().await {
        match message.map_err(|error| database_error("数据库检查未能取得完整结果", error))?
        {
            SimpleQueryMessage::RowDescription(description)
                if !described && !completed && description.len() == columns =>
            {
                described = true
            }
            SimpleQueryMessage::Row(row)
                if described && !completed && row.len() == columns && rows < maximum_rows =>
            {
                for column in 0..columns {
                    let cell = row
                        .get(column)
                        .ok_or_else(|| invalid("数据库检查返回了未编码的空值"))?;
                    if cell != "-"
                        && (cell.len() % 2 != 0
                            || !cell.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    {
                        return Err(invalid("数据库检查返回了不符合约定的字段"));
                    }
                    if output.len().saturating_add(cell.len()).saturating_add(1) > maximum_bytes {
                        return Err(invalid("数据库检查结果超过读取上限"));
                    }
                    output.extend_from_slice(cell.as_bytes());
                    output.push(if column + 1 == columns { b'\n' } else { b'\t' });
                }
                rows += 1;
            }
            SimpleQueryMessage::CommandComplete(count)
                if described && !completed && count == rows as u64 =>
            {
                completed = true
            }
            _ => return Err(invalid("数据库检查返回了额外语句或不完整的数据")),
        }
    }
    if !completed {
        return Err(invalid("数据库检查尚未完成"));
    }
    Ok(output)
}

fn database_error(fallback: &'static str, error: tokio_postgres::Error) -> CoreError {
    // Never include server detail, NOTICE, SQL text, usernames or authentication
    // payloads. Only these closed SQLSTATE mappings can affect public text.
    let reason = match error.code().map(|code| code.code()) {
        Some("28P01") => "数据库口令认证失败，请核对该连接的口令",
        Some("28000") => "数据库拒绝该连接，请核对账号与 pg_hba.conf 访问规则",
        Some("42501") => "数据库账号权限不足，无法完成此项检查",
        Some("57014") => "数据库检查已取消或达到执行时限",
        Some("55P03") => "数据库锁等待达到时限，请稍后重试",
        _ => fallback,
    };
    invalid(reason)
}

#[cfg(test)]
#[path = "postgresql_native_lab.rs"]
mod lab;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn loopback_request() -> NativeRuntimeRequest {
        NativeRuntimeRequest::new(
            connection("127.0.0.1"),
            PostgresqlTlsSettings {
                mode: PostgresqlTlsMode::SshLoopback,
                ca_certificate_pem: None,
            },
            Some(SecretValue::new("NativeWireSecretCanary")),
        )
        .unwrap()
    }

    fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    async fn startup(server: &mut DuplexStream) {
        let length = server.read_u32().await.unwrap() as usize;
        assert!((8..4096).contains(&length));
        let mut bytes = vec![0_u8; length - 4];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..4], &196608_u32.to_be_bytes());
        let settings = std::str::from_utf8(&bytes[4..]).unwrap();
        assert!(settings.contains("-c default_transaction_read_only=on -c statement_timeout=20000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog"));
        assert!(!settings.contains("NativeWireSecretCanary"));
    }

    #[tokio::test]
    async fn server_errors_and_oversized_frames_never_become_public_error_text() {
        for response in [
            frame(
                b'E',
                b"SFATAL\0C28P01\0MNativeWireSecretCanary\nserver-controlled detail\0\0",
            ),
            vec![b'R', 0xff, 0xff, 0xff, 0xff],
            // Refuse a cleartext-password challenge before sending any secret.
            frame(b'R', &3_u32.to_be_bytes()),
        ] {
            let (client, mut server) = tokio::io::duplex(8192);
            let peer = async {
                startup(&mut server).await;
                server.write_all(&response).await.unwrap();
                let mut remaining = Vec::new();
                server.read_to_end(&mut remaining).await.unwrap();
                assert!(remaining.is_empty());
            };
            let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(
                    read_over_stream(client, loopback_request(), |_| async {
                        panic!("malformed protocol must fail before process inspection")
                    }),
                    peer
                )
            })
            .await
            .unwrap();
            let error = result.unwrap_err();
            assert!(!error.to_string().contains("NativeWireSecretCanary"));
            assert!(!format!("{error:?}").contains("server-controlled"));
        }
    }

    #[tokio::test]
    async fn startup_notices_are_counted_and_bounded_without_using_the_logging_driver() {
        let (client, mut server) = tokio::io::duplex(16384);
        let peer = async {
            startup(&mut server).await;
            server
                .write_all(&frame(b'R', &0_u32.to_be_bytes()))
                .await
                .unwrap();
            for _ in 0..=MAX_NOTICES {
                server
                    .write_all(&frame(
                        b'N',
                        b"SNOTICE\0C00000\0MNativeWireSecretCanary\0\0",
                    ))
                    .await
                    .unwrap();
            }
            server.write_all(&frame(b'Z', b"I")).await.unwrap();
            let mut query = Vec::new();
            server.read_to_end(&mut query).await.unwrap();
            assert!(!String::from_utf8_lossy(&query).contains("NativeWireSecretCanary"));
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                read_over_stream(client, loopback_request(), |_| async {
                    panic!("malformed protocol must fail before process inspection")
                }),
                peer
            )
        })
        .await
        .unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("额外通知超过上限"));
        assert!(!error.contains("NativeWireSecretCanary"));
    }

    #[tokio::test]
    async fn native_scram_rejects_excessive_work_before_sending_a_password_proof() {
        let (client, mut server) = tokio::io::duplex(8192);
        let peer = async {
            startup(&mut server).await;
            let mut authentication = 10_u32.to_be_bytes().to_vec();
            authentication.extend_from_slice(b"SCRAM-SHA-256\0\0");
            server
                .write_all(&frame(b'R', &authentication))
                .await
                .unwrap();
            assert_eq!(server.read_u8().await.unwrap(), b'p');
            let length = server.read_u32().await.unwrap() as usize;
            assert!((8..4096).contains(&length));
            let mut initial = vec![0; length - 4];
            server.read_exact(&mut initial).await.unwrap();
            let mechanism_end = initial.iter().position(|byte| *byte == 0).unwrap();
            let first = std::str::from_utf8(&initial[mechanism_end + 5..]).unwrap();
            let nonce = first
                .split(',')
                .find_map(|field| field.strip_prefix("r="))
                .unwrap();
            let mut challenge = 11_u32.to_be_bytes().to_vec();
            challenge
                .extend_from_slice(format!("r={nonce}server,s=YWJjZA==,i=2147483647").as_bytes());
            server.write_all(&frame(b'R', &challenge)).await.unwrap();
            let mut proof = Vec::new();
            server.read_to_end(&mut proof).await.unwrap();
            assert!(proof.is_empty());
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                read_over_stream(client, loopback_request(), |_| async {
                    panic!("malformed protocol must fail before process inspection")
                }),
                peer
            )
        })
        .await
        .unwrap();
        assert!(result.is_err());
    }

    fn connection(host: &str) -> DatabaseConnection {
        DatabaseConnection {
            engine: DatabaseEngine::Postgresql,
            host: host.to_owned(),
            port: 5432,
            username: Some("postgres".to_owned()),
            database: Some("postgres".to_owned()),
        }
    }

    #[test]
    fn tls_defaults_verify_identity_and_ssh_only_requires_explicit_loopback() {
        assert_eq!(
            PostgresqlTlsSettings::default().mode,
            PostgresqlTlsMode::VerifyFull
        );
        let settings = PostgresqlTlsSettings {
            mode: PostgresqlTlsMode::SshLoopback,
            ca_certificate_pem: None,
        };
        for host in ["127.0.0.1", "127.0.0.2", "::1", "[::1]"] {
            settings.validate(&connection(host)).unwrap();
        }
        for host in ["localhost", "172.20.0.2", "example.org", "0.0.0.0", "::"] {
            assert!(settings.validate(&connection(host)).is_err());
        }
    }

    #[test]
    fn certificate_input_cannot_contain_private_keys_or_extra_pem_blocks() {
        for pem in [
            "",
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\naA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\naA==\n-----END CERTIFICATE-----",
        ] {
            let error = parse_ca(pem)
                .err()
                .expect("invalid certificate rejected")
                .to_string();
            assert!(!error.contains("secret"));
        }
        assert!(
            serde_json::from_str::<PostgresqlTlsSettings>(
                r#"{"mode":"verify-full","acceptInvalidCertificate":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn native_request_debug_does_not_include_credentials_or_connection_fields() {
        let request = NativeRuntimeRequest::new(
            connection("private-database.invalid"),
            PostgresqlTlsSettings::default(),
            Some(SecretValue::new("database-secret-sentinel")),
        )
        .unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("database-secret-sentinel"));
        assert!(!debug.contains("private-database.invalid"));
    }
}
