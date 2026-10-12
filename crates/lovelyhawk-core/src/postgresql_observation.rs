//! Server-reported session and configuration origins, never filesystem authority.
use crate::{
    CoreError, CoreResult,
    database::{DatabaseProfileSnapshot, DatabaseRuntimeParametersSnapshot},
    database_config_runtime::DatabaseConfigRuntimeDocument,
    investigation::{AddEvidence, EvidenceKind, MAX_EVIDENCE_PREVIEW_CHARS},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use zeroize::Zeroizing;

pub(crate) const QUERY: &str = include_str!("postgresql_observation.sql");
pub(crate) const CONTROL_QUERY: &str = "SELECT pg_catalog.encode(pg_catalog.convert_to(system_identifier::text, 'UTF8'), 'hex') FROM pg_catalog.pg_control_system()";
pub(crate) const MAX_BYTES: usize = 128 * 1024;
pub const REVIEW_NAMES: [&str; 10] = [
    "ssl",
    "logging_collector",
    "log_connections",
    "log_disconnections",
    "password_encryption",
    "log_statement",
    "listen_addresses",
    "ssl_min_protocol_version",
    "ssl_max_protocol_version",
    "default_transaction_read_only",
];
const PATH_NAMES: [&str; 4] = ["config_file", "data_directory", "hba_file", "ident_file"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresqlReportedPath {
    name: String,
    #[serde(deserialize_with = "required_option")]
    path: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum PostgresqlReviewOutcome {
    Completed,
    Failed,
    Cancelled,
}

/// A deliberately scoped, immutable case summary. It does not export the full
/// settings document (which includes secret fingerprints) or configuration paths.
pub fn case_summary(
    observation_id: uuid::Uuid,
    profile: &DatabaseProfileSnapshot,
    source_label: &str,
    started: chrono::DateTime<chrono::Utc>,
    finished: chrono::DateTime<chrono::Utc>,
    outcome: PostgresqlReviewOutcome,
    snapshot: Option<&DatabaseRuntimeParametersSnapshot>,
) -> CoreResult<AddEvidence> {
    if !text(source_label, 1024)
        || matches!(outcome, PostgresqlReviewOutcome::Completed) != snapshot.is_some()
    {
        return Err(invalid());
    }
    let config = &profile.view().config;
    if snapshot.is_some_and(|s| {
        s.profile_id() != config.id
            || s.postgresql_observation().is_none()
            || s.postgresql_host_process().is_none()
            || s.postgresql_access().is_none()
    }) {
        return Err(invalid());
    }
    let status = match outcome {
        PostgresqlReviewOutcome::Completed => "读取完成",
        PostgresqlReviewOutcome::Failed => "读取失败，未取得完整结果",
        PostgresqlReviewOutcome::Cancelled => "用户取消，未取得完整结果",
    };
    let requested_host =
        if config.connection.host.contains(':') && !config.connection.host.starts_with('[') {
            format!("[{}]", config.connection.host)
        } else {
            config.connection.host.clone()
        };
    let mut preview = format!(
        "PostgreSQL 检查摘要 v5\n观察编号：{observation_id}\n检查开始（UTC）：{}\n检查结束（UTC）：{}\nSSH 来源：{source_label}\n连接名称：{}\n请求数据库：{}@{}:{}/{}\n结果：{status}\n",
        started.to_rfc3339(),
        finished.to_rfc3339(),
        config.name,
        config.connection.username.as_deref().unwrap_or("postgres"),
        requested_host,
        config.connection.port,
        config.connection.database.as_deref().unwrap_or("postgres"),
    );
    if let Some(snapshot) = snapshot {
        preview.push_str(&format!(
            "PostgreSQL {}.{}；参数总数：{}；通知数：{}（正文未保留）\n连接保护：{}\n",
            snapshot.version().major(),
            snapshot.version().minor(),
            snapshot.document().rows().len(),
            snapshot.notice_count(),
            if snapshot.postgresql_tls_mode()
                == Some(crate::postgresql_native::PostgresqlTlsMode::VerifyFull)
            {
                "TLS 校验证书和地址，经 SSH 转发"
            } else {
                "SSH 加密，数据库使用字面回环地址，无数据库 TLS"
            }
        ));
        preview.push_str(
            &snapshot
                .postgresql_observation()
                .expect("checked observation")
                .case_identity(),
        );
        preview.push_str(
            &snapshot
                .postgresql_host_process()
                .expect("checked host observation")
                .case_identity(),
        );
        preview.push_str(
            &snapshot
                .postgresql_access()
                .expect("checked access diagnostics")
                .case_summary(),
        );
        for name in REVIEW_NAMES {
            if let Some(row) = snapshot.document().rows().iter().find(|r| r.name() == name) {
                let value = row
                    .value()
                    .public_value()
                    .map(|s| if s.is_empty() { "（空值）" } else { s })
                    .unwrap_or("未公开");
                preview.push_str(&format!(
                    "{name}：{value}；等待重启={}\n",
                    row.pending_restart().unwrap_or(false)
                ));
            } else {
                preview.push_str(&format!("{name}：未取得\n"));
            }
        }
    }
    preview.push_str("\n范围：原生只读检查会话、主机进程对应状态、十项参数与访问诊断数量摘要。未包含全部参数、配置内容、来源路径、HBA/ident 规则全文、角色明细或秘密值。当前文件视图不等于已加载规则；视图比较不保留原始引号语义。主机对应仅反映采集时的 socket、进程与命名空间，不能授权之后的文件或进程操作；复制集群可能共用标识。查询前后核对加载时间和来源，不能证明磁盘原子快照。本次会话的只读设置不代表业务账号权限，SSL 开启不代表业务强制加密；观察不构成完整合规或恢复结论。案件 SHA-256 校验此保存记录，不是原始协议数据摘要。\n");
    if preview.chars().count() > MAX_EVIDENCE_PREVIEW_CHARS {
        return Err(invalid());
    }
    Ok(AddEvidence {
        kind: EvidenceKind::Snapshot,
        label: "PostgreSQL 检查摘要".into(),
        source: "postgresql-runtime-summary/v5".into(),
        preview,
        locator: Some(format!("postgresql-observation:{observation_id}")),
        external_sha256: None,
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresqlParameterOrigin {
    name: String,
    #[serde(deserialize_with = "required_option")]
    source: Option<String>,
    #[serde(deserialize_with = "required_option")]
    source_file: Option<String>,
    #[serde(deserialize_with = "required_option")]
    source_line: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    pending_restart: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresqlObservation {
    observed_at: String,
    database_name: String,
    database_oid: u32,
    session_user: String,
    effective_user: String,
    backend_pid: u32,
    #[serde(deserialize_with = "required_option")]
    server_address: Option<IpAddr>,
    #[serde(deserialize_with = "required_option")]
    server_port: Option<u16>,
    #[serde(deserialize_with = "required_option")]
    client_address: Option<IpAddr>,
    #[serde(deserialize_with = "required_option")]
    client_port: Option<u16>,
    server_started_at: String,
    configuration_loaded_at: String,
    in_recovery: bool,
    cluster_identifier_readable: bool,
    #[serde(deserialize_with = "required_option")]
    cluster_identifier: Option<String>,
    settings_readable: bool,
    paths: Vec<PostgresqlReportedPath>,
    origins: Vec<PostgresqlParameterOrigin>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

fn invalid() -> CoreError {
    CoreError::validation(
        "PostgreSQL native observation",
        "数据库会话或参数来源未能完整核对，请重新读取。",
    )
}
fn text(value: &str, cap: usize) -> bool {
    !value.is_empty() && value.len() <= cap && !value.chars().any(char::is_control)
}
fn timestamp(value: &str) -> bool {
    value.len() <= 40 && value.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}
impl PostgresqlObservation {
    pub(crate) fn database_identity(&self) -> (u32, &str) {
        (self.database_oid, &self.database_name)
    }
    pub(crate) fn process_input(&self) -> Option<crate::postgresql_process::ProcessProbeInput> {
        Some(crate::postgresql_process::ProcessProbeInput {
            backend_pid: self.backend_pid,
            server_address: self.server_address?,
            server_port: self.server_port?,
            client_address: self.client_address?,
            client_port: self.client_port?,
            data_directory: self
                .paths
                .iter()
                .find(|p| p.name == "data_directory")
                .and_then(|p| p.path.clone()),
        })
    }
    fn decode(encoded: Zeroizing<Vec<u8>>) -> CoreResult<Self> {
        let encoded = encoded.strip_suffix(b"\n").ok_or_else(invalid)?;
        if encoded.len() > MAX_BYTES || encoded.len() % 2 != 0 {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(encoded.len() / 2));
        for pair in encoded.chunks_exact(2) {
            let cell = std::str::from_utf8(pair).map_err(|_| invalid())?;
            bytes.push(u8::from_str_radix(cell, 16).map_err(|_| invalid())?);
        }
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }
    #[cfg(test)]
    fn parse(encoded: Zeroizing<Vec<u8>>) -> CoreResult<Self> {
        let observation = Self::decode(encoded)?;
        observation.validate()?;
        Ok(observation)
    }
    pub(crate) fn parse_pending(
        encoded: Zeroizing<Vec<u8>>,
    ) -> CoreResult<PendingPostgresqlObservation> {
        let mut observation = Self::decode(encoded)?;
        if observation.cluster_identifier.is_some() {
            return Err(invalid());
        }
        let readable = observation.cluster_identifier_readable;
        // Validate every other field before requesting any additional data.
        // Only PendingPostgresqlObservation can restore the reported privilege
        // and produce a complete public observation.
        observation.cluster_identifier_readable = false;
        observation.validate()?;
        Ok(PendingPostgresqlObservation {
            observation,
            readable,
        })
    }
    fn validate(&self) -> CoreResult<()> {
        let valid = timestamp(&self.observed_at)
            && timestamp(&self.server_started_at)
            && timestamp(&self.configuration_loaded_at)
            && text(&self.database_name, 256)
            && text(&self.session_user, 256)
            && text(&self.effective_user, 256)
            && self.database_oid > 0
            && self.backend_pid > 0
            && self.backend_pid <= i32::MAX as u32
            && self.server_address.is_some() == self.server_port.is_some()
            && self.client_address.is_some() == self.client_port.is_some()
            && self.server_port != Some(0)
            && self.client_port != Some(0)
            && self.cluster_identifier_readable == self.cluster_identifier.is_some()
            && self.cluster_identifier.as_ref().is_none_or(|id| {
                id.len() <= 20
                    && !id.starts_with('0')
                    && id.bytes().all(|c| c.is_ascii_digit())
                    && id.parse::<u64>().is_ok_and(|v| v > 0)
            })
            && self.paths.len() == PATH_NAMES.len()
            && self.paths.iter().zip(PATH_NAMES).all(|(path, name)| {
                path.name == name && path.path.as_ref().is_none_or(|s| text(s, 2048))
            })
            && self.origins.len() == REVIEW_NAMES.len()
            && self.origins.iter().zip(REVIEW_NAMES).all(|(origin, name)| {
                origin.name == name
                    && origin.source.as_ref().is_none_or(|s| text(s, 128))
                    && origin.source_file.as_ref().is_none_or(|s| text(s, 2048))
                    && origin
                        .source_line
                        .is_none_or(|line| line > 0 && line <= i32::MAX as u32)
                    && (origin.source_line.is_none() || origin.source_file.is_some())
                    && (origin.source.is_some() == origin.pending_restart.is_some())
                    && (origin.source.is_some() || origin.source_file.is_none())
            });
        if valid { Ok(()) } else { Err(invalid()) }
    }
    /// The two observations bracket the parameter query on the same connection.
    /// Detects reported reload/session/origin changes, not an atomic disk snapshot.
    pub(crate) fn verify_stable(
        &self,
        after: &Self,
        document: &DatabaseConfigRuntimeDocument,
    ) -> CoreResult<()> {
        let mut before = self.clone();
        before.observed_at.clone_from(&after.observed_at);
        if before != *after {
            return Err(invalid());
        }
        for origin in &self.origins {
            let row = document.rows().iter().find(|r| r.name() == origin.name);
            // pg_settings omits parameters hidden from the current role. The
            // closed LEFT JOIN preserves these as explicit, fully null origins.
            if row.is_some() != origin.source.is_some()
                || row.and_then(|r| r.source()) != origin.source.as_deref()
                || row.and_then(|r| r.pending_restart()) != origin.pending_restart
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    /// Compact historical identity for a case summary; no paths or secret settings.
    pub fn case_identity(&self) -> String {
        let endpoint = |address: Option<IpAddr>, port: Option<u16>| {
            address
                .zip(port)
                .map(|(address, port)| std::net::SocketAddr::new(address, port).to_string())
                .unwrap_or_else(|| "未提供".into())
        };
        format!(
            "服务端观察（UTC）：{}\n数据库：{}（OID {}）；登录身份：{}；执行身份：{}\n服务端地址：{}；客户端地址：{}\n本次会话 PID：{}；服务启动（UTC）：{}；配置加载（UTC）：{}\n恢复模式：{}；集群标识：{}\n",
            self.observed_at,
            self.database_name,
            self.database_oid,
            self.session_user,
            self.effective_user,
            endpoint(self.server_address, self.server_port),
            endpoint(self.client_address, self.client_port),
            self.backend_pid,
            self.server_started_at,
            self.configuration_loaded_at,
            self.in_recovery,
            self.cluster_identifier.as_deref().unwrap_or("无读取权限"),
        )
    }
}

pub(crate) struct PendingPostgresqlObservation {
    observation: PostgresqlObservation,
    readable: bool,
}
impl PendingPostgresqlObservation {
    pub(crate) fn control_readable(&self) -> bool {
        self.readable
    }
    pub(crate) fn finish(
        mut self,
        identifier: Option<Zeroizing<Vec<u8>>>,
    ) -> CoreResult<PostgresqlObservation> {
        self.observation.cluster_identifier_readable = self.readable;
        if let Some(identifier) = identifier {
            let hex = identifier.strip_suffix(b"\n").ok_or_else(invalid)?;
            if hex.is_empty() || hex.len() > 40 || hex.len() % 2 != 0 {
                return Err(invalid());
            }
            let mut digits = String::new();
            for pair in hex.chunks_exact(2) {
                let byte =
                    u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| invalid())?, 16)
                        .map_err(|_| invalid())?;
                if !byte.is_ascii_digit() {
                    return Err(invalid());
                }
                digits.push(char::from(byte));
            }
            self.observation.cluster_identifier = Some(digits);
        }
        self.observation.validate()?;
        Ok(self.observation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn fixture() -> Value {
        json!({"observedAt":"2026-09-08T08:00:00.000000Z","databaseName":"postgres","databaseOid":5,
            "sessionUser":"audit","effectiveUser":"audit","backendPid":42,"serverAddress":"::1","serverPort":5432,
            "clientAddress":"::1","clientPort":42000,"serverStartedAt":"2026-09-08T01:00:00Z","configurationLoadedAt":"2026-09-08T02:00:00Z",
            "inRecovery":false,"clusterIdentifierReadable":true,"clusterIdentifier":"7612345678123456789","settingsReadable":true,
            "paths":PATH_NAMES.map(|name| json!({"name":name,"path":format!("/srv/pg/{name}")})),
            "origins":REVIEW_NAMES.map(|name| json!({"name":name,"source":"configuration file","sourceFile":"/srv/pg/included.conf","sourceLine":7,"pendingRestart":false}))})
    }
    fn wire(value: &Value) -> Zeroizing<Vec<u8>> {
        let encoded: String = value
            .to_string()
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        Zeroizing::new(format!("{encoded}\n").into_bytes())
    }
    fn document() -> DatabaseConfigRuntimeDocument {
        document_without(&[])
    }
    fn document_without(hidden: &[&str]) -> DatabaseConfigRuntimeDocument {
        use crate::database_config::{DatabaseConfigComponent, DatabaseConfigProduct};
        use crate::database_config_runtime::*;
        use crate::database_config_schema::DatabaseConfigVersion;
        let plan = database_config_runtime_query_plan(DatabaseConfigRuntimeTarget {
            provider: DatabaseConfigRuntimeSqlProvider::PostgreSqlPgSettings,
            product: DatabaseConfigProduct::PostgreSql,
            version: DatabaseConfigVersion::new(16, 15, 0),
            edition_key: Some("community"),
            component: DatabaseConfigComponent::RuntimeParameters,
            artifact_key: "postgresql-runtime-parameters",
        })
        .unwrap();
        let rows = REVIEW_NAMES
            .into_iter()
            .filter(|name| !hidden.contains(name))
            .map(|name| {
                [
                    Some(name),
                    Some("on"),
                    Some("server-or-session"),
                    Some("sighup"),
                    Some("configuration file"),
                    Some("false"),
                    None,
                    None,
                    None,
                ]
                .map(|cell| {
                    cell.map(|s| s.bytes().map(|b| format!("{b:02x}")).collect::<String>())
                        .unwrap_or_else(|| "-".into())
                })
                .join("\t")
            })
            .collect::<Vec<_>>()
            .join("\n");
        plan.parse_native_postgresql_tsv(Zeroizing::new(rows.into_bytes()))
            .unwrap()
    }
    #[test]
    fn preserves_reported_origins_and_explicit_permission_gaps() {
        let full = PostgresqlObservation::parse(wire(&fixture())).unwrap();
        assert_eq!(full.database_oid, 5);
        assert!(full.case_identity().contains("[::1]:5432"));
        assert_eq!(full.server_address, Some("::1".parse().unwrap()));
        assert_eq!(full.origins[0].source_line, Some(7));
        let mut value = fixture();
        value["clusterIdentifierReadable"] = json!(false);
        value["clusterIdentifier"] = Value::Null;
        value["settingsReadable"] = json!(false);
        for p in value["paths"].as_array_mut().unwrap() {
            p["path"] = Value::Null;
        }
        for p in value["origins"].as_array_mut().unwrap() {
            p["sourceFile"] = Value::Null;
            p["sourceLine"] = Value::Null;
        }
        let restricted = PostgresqlObservation::parse(wire(&value)).unwrap();
        assert!(!restricted.settings_readable);
        assert!(restricted.cluster_identifier.is_none());
        assert_eq!(restricted.origins.len(), 10);
        assert!(restricted.paths.iter().all(|p| p.path.is_none()));
    }
    #[test]
    fn pending_observations_require_exactly_the_authorized_control_result() {
        let mut value = fixture();
        value["clusterIdentifier"] = Value::Null;
        let pending = PostgresqlObservation::parse_pending(wire(&value)).unwrap();
        assert!(pending.control_readable());
        assert!(pending.finish(None).is_err());
        let id: String = "7612345678123456789"
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let encoded = Zeroizing::new(format!("{id}\n").into_bytes());
        let complete = PostgresqlObservation::parse_pending(wire(&value))
            .unwrap()
            .finish(Some(encoded.clone()))
            .unwrap();
        assert_eq!(
            complete.cluster_identifier.as_deref(),
            Some("7612345678123456789")
        );
        value["clusterIdentifierReadable"] = json!(false);
        let pending = PostgresqlObservation::parse_pending(wire(&value)).unwrap();
        assert!(!pending.control_readable());
        assert!(pending.finish(None).unwrap().cluster_identifier.is_none());
        assert!(
            PostgresqlObservation::parse_pending(wire(&value))
                .unwrap()
                .finish(Some(encoded))
                .is_err()
        );
        for encoded in [
            b"31\n31\n".to_vec(),
            b"ff\n".to_vec(),
            b"30\n".to_vec(),
            vec![b'0'; 43],
        ] {
            assert!(
                PostgresqlObservation::parse_pending(wire(&value))
                    .unwrap()
                    .finish(Some(Zeroizing::new(encoded)))
                    .is_err()
            );
        }
        assert!(PostgresqlObservation::parse_pending(wire(&fixture())).is_err());
    }
    #[test]
    fn malformed_or_partial_server_metadata_is_rejected_without_echoing_it() {
        let mut cases = vec![];
        for (key, value) in [
            ("backendPid", json!(0)),
            ("databaseOid", json!(4294967296_u64)),
            ("observedAt", json!("not-a-time-secret-canary")),
            ("serverAddress", json!("bad-secret-canary")),
            ("serverPort", json!(null)),
            ("clusterIdentifier", json!("18446744073709551616")),
            ("databaseName", json!("\nsecret-canary")),
            ("sessionUser", json!("x".repeat(257))),
        ] {
            let mut item = fixture();
            item[key] = value;
            cases.push(item);
        }
        let mut item = fixture();
        item["paths"][0]["path"] = json!("x".repeat(2049));
        cases.push(item);
        let mut item = fixture();
        item["origins"][0]["sourceLine"] = json!(0);
        cases.push(item);
        let mut item = fixture();
        item["origins"][0]["sourceFile"] = Value::Null;
        cases.push(item);
        let mut item = fixture();
        item["origins"].as_array_mut().unwrap().pop();
        cases.push(item);
        let mut item = fixture();
        item["paths"][0]["name"] = json!("hba_file");
        cases.push(item);
        let mut item = fixture();
        item.as_object_mut().unwrap().remove("clusterIdentifier");
        cases.push(item);
        let mut item = fixture();
        item["paths"][0].as_object_mut().unwrap().remove("path");
        cases.push(item);
        let mut item = fixture();
        item["rawPassword"] = json!("secret-canary");
        cases.push(item);
        for value in cases {
            let error = PostgresqlObservation::parse(wire(&value))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret-canary"));
        }
        for bytes in [
            vec![],
            b"00\n00\n".to_vec(),
            b"gg\n".to_vec(),
            vec![b'0'; MAX_BYTES + 1],
        ] {
            assert!(PostgresqlObservation::parse(Zeroizing::new(bytes)).is_err());
        }
    }
    #[test]
    fn bracketing_rejects_session_reload_origin_or_parameter_changes() {
        let before = PostgresqlObservation::parse(wire(&fixture())).unwrap();
        let document = document();
        let mut after = before.clone();
        after.observed_at = "2026-09-08T07:00:00Z".into();
        before.verify_stable(&after, &document).unwrap(); // Clocks can step backwards.
        let mut cases = vec![];
        let mut changed = before.clone();
        changed.backend_pid += 1;
        cases.push(changed);
        let mut changed = before.clone();
        changed.configuration_loaded_at = "2026-09-08T03:00:00Z".into();
        cases.push(changed);
        let mut changed = before.clone();
        changed.database_oid += 1;
        cases.push(changed);
        let mut changed = before.clone();
        changed.origins[0].source_line = Some(8);
        cases.push(changed);
        let mut changed = before.clone();
        changed.paths[0].path = Some("/another/config".into());
        cases.push(changed);
        for changed in cases {
            assert!(before.verify_stable(&changed, &document).is_err());
        }
        let mut different_source = before.clone();
        different_source.origins[0].source = Some("default".into());
        assert!(
            different_source
                .verify_stable(&different_source, &document)
                .is_err()
        );
        assert!(!before.case_identity().contains("/srv/pg/"));
    }
    #[test]
    fn hidden_parameters_require_matching_explicit_gaps_in_both_observations_and_values() {
        let hidden = ["ssl_min_protocol_version", "ssl_max_protocol_version"];
        let mut value = fixture();
        for origin in value["origins"].as_array_mut().unwrap() {
            if hidden.contains(&origin["name"].as_str().unwrap()) {
                for field in ["source", "sourceFile", "sourceLine", "pendingRestart"] {
                    origin[field] = Value::Null;
                }
            }
        }
        let observation = PostgresqlObservation::parse(wire(&value)).unwrap();
        observation
            .verify_stable(&observation, &document_without(&hidden))
            .unwrap();
        assert!(
            observation
                .verify_stable(&observation, &document())
                .is_err()
        );
        let visible = PostgresqlObservation::parse(wire(&fixture())).unwrap();
        assert!(
            visible
                .verify_stable(&visible, &document_without(&hidden))
                .is_err()
        );
        assert!(
            visible
                .verify_stable(&observation, &document_without(&hidden))
                .is_err()
        );
        for (field, partial) in [
            ("sourceFile", json!("/unexpected.conf")),
            ("pendingRestart", json!(false)),
        ] {
            let mut changed = value.clone();
            changed["origins"][7][field] = partial;
            assert!(PostgresqlObservation::parse(wire(&changed)).is_err());
        }
    }
}
