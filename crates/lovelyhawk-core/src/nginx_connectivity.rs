//! Read-only TLS/HTTP observations of sockets owned by a captured Nginx master.
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{
    CoreError, CoreResult,
    investigation::{AddEvidence, EvidenceKind, MAX_EVIDENCE_PREVIEW_CHARS},
    nginx_process::{self, NginxProcessEvidence},
    ssh::{BoundSshSession, SshService},
    target::TargetContext,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerEvidence {
    address: IpAddr,
    port: u16,
    inode: u64,
    network_namespace: u64,
}

#[derive(Clone, Debug)]
pub struct NginxListener {
    evidence: ListenerEvidence,
    runtime_fingerprint: String,
}
impl NginxListener {
    pub fn address(&self) -> String {
        self.evidence.address.to_string()
    }
    pub fn port(&self) -> u16 {
        self.evidence.port
    }
    pub fn connect_address(&self) -> String {
        let address = self.evidence.address;
        match address {
            IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_owned(),
            IpAddr::V6(ip) if ip.is_unspecified() => "::1".to_owned(),
            _ => address.to_string(),
        }
    }
    pub fn label(&self) -> String {
        SocketAddr::new(self.evidence.address, self.evidence.port).to_string()
    }
}

#[derive(Clone, Debug)]
pub struct NginxConnectivityInput {
    server_name: String,
    path: String,
}
impl NginxConnectivityInput {
    pub fn new(server_name: &str, path: &str) -> CoreResult<Self> {
        let dns_name = || {
            !server_name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && server_name.split('.').all(|part| {
                    !part.is_empty()
                        && part.len() <= 63
                        && part.as_bytes()[0].is_ascii_alphanumeric()
                        && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        };
        if server_name.is_empty()
            || server_name.len() > 253
            || !server_name.is_ascii()
            || !(server_name.parse::<IpAddr>().is_ok() || dns_name())
            || path.len() > 1024
            || !path.starts_with('/')
            || path.starts_with("//")
            || !path
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && !b"?#\\".contains(&b))
        {
            return Err(invalid("invalid site name or HTTP path"));
        }
        Ok(Self {
            server_name: server_name.to_owned(),
            path: path.to_owned(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NginxTlsOutcome {
    Accepted,
    ProtocolRejected,
    CertificateRejected,
    LocalUnavailable,
    Inconclusive,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NginxTlsObservation {
    pub version: String,
    pub outcome: NginxTlsOutcome,
    pub detail: String,
    pub certificate_sha256: Option<String>,
    pub http_outcome: String,
    pub http_status: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NginxConnectivityReport {
    #[serde(skip, default = "chrono::Utc::now")]
    checked_at: chrono::DateTime<chrono::Utc>,
    pub client_version: String,
    pub rows: Vec<NginxTlsObservation>,
}
impl NginxConnectivityReport {
    pub fn checked_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.checked_at
    }

    pub(crate) fn case_evidence(
        &self,
        process: &NginxProcessEvidence,
        listener: &NginxListener,
        input: &NginxConnectivityInput,
        source_label: &str,
    ) -> CoreResult<AddEvidence> {
        self.validate()?;
        let fingerprint = process.fingerprint()?;
        if fingerprint != listener.runtime_fingerprint
            || source_label.is_empty()
            || source_label.len() > 1024
            || source_label.chars().any(char::is_control)
        {
            return Err(invalid("invalid evidence source"));
        }
        // A new measurement gets a new identifier even when its outcomes match
        // an older measurement. Retrying this exact AddEvidence stays idempotent.
        let observation_id = uuid::Uuid::new_v4();
        let mut preview = format!(
            "Nginx TLS/HTTP 连接观察 v1\n观察编号：{observation_id}\n观察完成（UTC）：{}\n来源主机：{source_label}\n实例：{}；PID {}；启动时钟 {}\n进程身份 SHA-256：{fingerprint}\n监听：{}；实际连接地址：{}\n网络命名空间 inode：{}；监听 socket inode：{}\n站点名称：{}\nHTTP 路径：{}\n目标客户端：{}\n",
            self.checked_at.to_rfc3339(),
            process.version,
            process.pid,
            process.start_time_ticks,
            listener.label(),
            SocketAddr::new(
                listener
                    .connect_address()
                    .parse()
                    .map_err(|_| invalid("invalid connect address"))?,
                listener.port()
            ),
            listener.evidence.network_namespace,
            listener.evidence.inode,
            input.server_name,
            input.path,
            self.client_version,
        );
        for row in &self.rows {
            let version = match row.version.as_str() {
                "TLSv1" => "TLS 1.0",
                "TLSv1_1" => "TLS 1.1",
                "TLSv1_2" => "TLS 1.2",
                _ => "TLS 1.3",
            };
            let result = match row.outcome {
                NginxTlsOutcome::Accepted if row.detail == "legacy-accepted" => "接受旧协议",
                NginxTlsOutcome::Accepted => "握手与证书校验已通过",
                NginxTlsOutcome::ProtocolRejected => "服务端明确拒绝此版本",
                NginxTlsOutcome::CertificateRejected => "证书校验失败",
                NginxTlsOutcome::LocalUnavailable => "本机无法测试",
                NginxTlsOutcome::Inconclusive => "未能判断",
            };
            let http = row
                .http_status
                .map(|status| format!("HTTP {status}"))
                .unwrap_or_else(|| {
                    if row.http_outcome == "unavailable" {
                        "未取得状态码"
                    } else {
                        "未发送"
                    }
                    .to_owned()
                });
            preview.push_str(&format!(
                "\n{version}：{result}；原因码={}；HTTP={http}\n",
                row.detail
            ));
            if let Some(hash) = &row.certificate_sha256 {
                preview.push_str(&format!("叶证书 SHA-256：{hash}\n"));
            } else {
                preview.push_str("证书：未完成可信验证；没有已验证的叶证书摘要。\n");
            }
        }
        preview.push_str("\n方法与范围：从目标本机连接所选监听；DNS 名称用于 SNI/证书匹配，IP 用于证书 IP 匹配。旧协议只做握手，不校验证书或发送 HTTP。现代协议依目标客户端默认信任库校验后发送 HEAD，不跟随重定向、不发送凭据；仅记录首个 HTTP 状态码及公开叶证书摘要。未检查撤销状态。连接可能产生访问日志，观察不证明公网、负载均衡或业务数据已恢复。案件摘要校验此记录内容，不是原始网络包摘要。\n");
        if preview.chars().count() > MAX_EVIDENCE_PREVIEW_CHARS {
            return Err(invalid("connectivity evidence exceeds case capacity"));
        }
        Ok(AddEvidence {
            kind: EvidenceKind::Snapshot,
            label: "Nginx TLS/HTTP 连接复核".to_owned(),
            source: "nginx-tls-http/v1".to_owned(),
            preview,
            locator: Some(format!("nginx-connectivity:{observation_id}")),
            external_sha256: None,
        })
    }
    fn validate(&self) -> CoreResult<()> {
        if self.client_version.is_empty()
            || self.client_version.len() > 128
            || self.client_version.chars().any(char::is_control)
            || self.rows.len() != 4
        {
            return Err(invalid("invalid TLS observation bounds"));
        }
        for (index, row) in self.rows.iter().enumerate() {
            if row.version != ["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"][index] {
                return Err(invalid("missing, duplicate or reordered TLS observations"));
            }
            let modern_accepted = row.outcome == NginxTlsOutcome::Accepted && index >= 2;
            let detail_valid = match row.outcome {
                NginxTlsOutcome::Accepted => {
                    row.detail
                        == if index < 2 {
                            "legacy-accepted"
                        } else {
                            "identity-verified"
                        }
                }
                NginxTlsOutcome::ProtocolRejected => row.detail == "server-protocol-alert",
                NginxTlsOutcome::CertificateRejected => {
                    index >= 2 && row.detail == "certificate-verification-failed"
                }
                NginxTlsOutcome::LocalUnavailable => {
                    ["local-tls-unavailable", "local-protocol-unavailable"]
                        .contains(&row.detail.as_str())
                }
                NginxTlsOutcome::Inconclusive => {
                    ["timeout", "handshake-failed", "connection-failed"]
                        .contains(&row.detail.as_str())
                }
            };
            let transport_valid = if modern_accepted {
                row.certificate_sha256.as_ref().is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                }) && match row.http_outcome.as_str() {
                    "status" => row
                        .http_status
                        .is_some_and(|status| (100..=599).contains(&status)),
                    "unavailable" => row.http_status.is_none(),
                    _ => false,
                }
            } else {
                row.certificate_sha256.is_none()
                    && row.http_status.is_none()
                    && row.http_outcome == "not-sent"
            };
            if !detail_valid || !transport_valid {
                return Err(invalid("inconsistent TLS or HTTP observation"));
            }
        }
        Ok(())
    }
}

fn invalid(message: &str) -> CoreError {
    CoreError::validation("Nginx connectivity", message)
}

pub(crate) async fn listeners(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    process: &NginxProcessEvidence,
) -> CoreResult<Vec<NginxListener>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Inventory {
        listeners: Vec<ListenerEvidence>,
    }
    let fingerprint = process.fingerprint()?;
    let response: Inventory = serde_json::from_value(
        nginx_process::call(
            target,
            ssh,
            session,
            serde_json::json!({"mode":"listeners", "evidence":process}),
        )
        .await?,
    )
    .map_err(|_| invalid("invalid listener inventory"))?;
    if response.listeners.len() > 64 {
        return Err(invalid("too many listeners"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in &response.listeners {
        if item.port == 0
            || item.inode == 0
            || item.network_namespace == 0
            || item.address.is_multicast()
            || !seen.insert(item.inode)
        {
            return Err(invalid("invalid or duplicate listener identity"));
        }
    }
    Ok(response
        .listeners
        .into_iter()
        .map(|evidence| NginxListener {
            evidence,
            runtime_fingerprint: fingerprint.clone(),
        })
        .collect())
}

pub(crate) async fn probe(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    process: &NginxProcessEvidence,
    listener: &NginxListener,
    input: &NginxConnectivityInput,
) -> CoreResult<NginxConnectivityReport> {
    if listener.runtime_fingerprint != process.fingerprint()? {
        return Err(invalid("listener belongs to a different runtime"));
    }
    let report: NginxConnectivityReport = serde_json::from_value(nginx_process::call(target, ssh, session,
        serde_json::json!({"mode":"connectivity", "evidence":process, "endpoint":listener.evidence,
            "server_name":input.server_name,"path":input.path})).await?)
        .map_err(|_| invalid("invalid TLS observation response"))?;
    report.validate()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_material(source: &str, maximum: bool) -> AddEvidence {
        let mut process = crate::nginx_process::tests::evidence();
        let listener = NginxListener {
            evidence: ListenerEvidence {
                address: "2001:db8::1234".parse().unwrap(),
                port: 8443,
                inode: 900,
                network_namespace: 123,
            },
            runtime_fingerprint: process.fingerprint().unwrap(),
        };
        let mut observation = report();
        observation.rows[0].outcome = NginxTlsOutcome::Accepted;
        observation.rows[0].detail = "legacy-accepted".into();
        for row in &mut observation.rows[2..] {
            row.outcome = NginxTlsOutcome::Accepted;
            row.detail = "identity-verified".into();
            row.certificate_sha256 = Some("f".repeat(64));
            row.http_outcome = "status".into();
            row.http_status = Some(404);
        }
        let name = if maximum {
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61),
            ]
            .join(".")
        } else {
            "site.example.test".into()
        };
        let path = if maximum {
            format!("/{}", "x".repeat(1023))
        } else {
            "/missing".into()
        };
        if maximum {
            process.version = format!(
                "nginx version: nginx/{}",
                "1".repeat(128 - "nginx version: nginx/".len())
            );
            observation.client_version = "X".repeat(128);
        }
        let listener = NginxListener {
            runtime_fingerprint: process.fingerprint().unwrap(),
            ..listener
        };
        observation
            .case_evidence(
                &process,
                &listener,
                &NginxConnectivityInput::new(&name, &path).unwrap(),
                source,
            )
            .unwrap()
    }

    #[test]
    fn full_connectivity_evidence_preserves_source_and_fits_the_case_bound_without_truncation() {
        let material = evidence_material("root@[2001:db8::4]:22", false);
        for text in [
            "root@[2001:db8::4]:22",
            "PID 42",
            "启动时钟 1000",
            "[2001:db8::1234]:8443",
            "socket inode：900",
            "site.example.test",
            "/missing",
            "TLS 1.0：接受旧协议",
            "TLS 1.1：未能判断",
            "HTTP 404",
            "不证明公网",
            &"f".repeat(64),
        ] {
            assert!(material.preview.contains(text), "missing {text}");
        }
        assert_eq!(material.kind, EvidenceKind::Snapshot);
        assert!(material.external_sha256.is_none());
        assert_ne!(
            material.locator,
            evidence_material("root@[2001:db8::4]:22", false).locator
        );
        let maximum = evidence_material(&"s".repeat(1024), true);
        assert!(maximum.preview.chars().count() <= MAX_EVIDENCE_PREVIEW_CHARS);
        assert!(maximum.preview.contains(&"x".repeat(1023)));
    }

    #[test]
    fn archived_observations_stay_in_the_original_case_and_retry_is_idempotent() {
        use crate::{
            PortableStore,
            investigation::{EvidenceHashScope, InvestigationRepositories},
            target::TargetIdentity,
        };
        let root = std::env::temp_dir().join(format!(
            "lovelyres-nginx-retention-{}",
            uuid::Uuid::new_v4()
        ));
        let store = PortableStore::prepare(root.clone()).unwrap();
        let repositories = InvestigationRepositories::new(store.clone());
        let cases = repositories.cases();
        let target = TargetIdentity::new("ssh:nginx-evidence-test").unwrap();
        let original = cases.create(&target, Some("原案件".into())).unwrap();
        let reservation = cases.reserve_collection(&target, &original.id).unwrap();
        let later = cases
            .create(&target, Some("后来选择的案件".into()))
            .unwrap();
        let material = evidence_material("operator@original.example:22", false);
        let saved = cases
            .add_evidence_to_case(&target, &original.id, material.clone())
            .unwrap();
        let retry = cases
            .add_evidence_to_case(&target, &original.id, material.clone())
            .unwrap();
        assert_eq!(saved, retry);
        assert_eq!(saved.hash_scope, EvidenceHashScope::StoredPreview);
        assert_eq!(saved.preview, material.preview);
        assert!(
            cases
                .export(&target, &later.id)
                .unwrap()
                .incident_case
                .evidence
                .is_empty()
        );
        assert_eq!(cases.active(&target).unwrap().unwrap().id, later.id);
        let changed = TargetIdentity::new("ssh:other-target").unwrap();
        assert!(
            cases
                .add_evidence_to_case(&changed, &original.id, material)
                .is_err()
        );
        drop(reservation);
        let reopened = InvestigationRepositories::new(store);
        let exported = reopened.cases().export(&target, &original.id).unwrap();
        assert_eq!(
            exported.incident_case.evidence,
            std::slice::from_ref(&saved)
        );
        assert_eq!(exported.incident_case.timeline.len(), 2);
        let snapshot = crate::report::DisposalReportSnapshot::new(
            crate::target::TargetGuard {
                identity: target,
                generation: 1,
            },
            "后来编辑的连接名称",
            chrono::Utc::now(),
            vec![],
            Some(exported.incident_case),
            None,
        )
        .unwrap();
        let rendered = crate::report::DisposalReport::render(snapshot).unwrap();
        for text in [
            "operator@original.example:22",
            "TLS 1.0：接受旧协议",
            "TLS 1.1：未能判断",
            "HTTP 404",
            "nginx-tls-http/v1",
            saved.sha256.as_str(),
            "不是原始网络包摘要",
        ] {
            assert!(rendered.markdown.contains(text), "Markdown lost {text}");
            assert!(rendered.html.contains(text), "HTML lost {text}");
        }
        let canonical = std::fs::canonicalize(&root).unwrap();
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(canonical.starts_with(&temp) && canonical != temp);
        std::fs::remove_dir_all(canonical).unwrap();
    }
    #[test]
    fn input_is_a_site_identity_and_origin_path_never_a_destination_or_header() {
        for name in [
            "example.test",
            "xn--fiqs8s.test",
            "127.0.0.1",
            "::1",
            "2001:db8::1",
        ] {
            NginxConnectivityInput::new(name, "/health/ready%20here").unwrap();
        }
        for name in [
            "",
            "https://example.test",
            "example.test:443",
            "a\r\nHost:x",
            "*.test",
            "a..test",
            "a.",
            "256.1.1.1",
            "::invalid",
            "例子.test",
        ] {
            assert!(NginxConnectivityInput::new(name, "/").is_err(), "{name}");
        }
        for path in [
            "",
            "//other.test",
            "/x?token=secret",
            "/x#fragment",
            "/x\\y",
            "/a b",
            "/x\r\nCookie:secret",
        ] {
            assert!(
                NginxConnectivityInput::new("example.test", path).is_err(),
                "{path}"
            );
        }
    }
    fn report() -> NginxConnectivityReport {
        serde_json::from_value(serde_json::json!({"clientVersion":"OpenSSL test", "rows":
        (["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"].map(|version| serde_json::json!({
            "version":version,"outcome":"inconclusive","detail":"handshake-failed",
            "certificateSha256":null,"httpOutcome":"not-sent","httpStatus":null
        })))}))
        .unwrap()
    }
    #[test]
    fn incomplete_or_contradictory_probe_results_cannot_become_success() {
        report().validate().unwrap();
        let mut missing = report();
        missing.rows.pop();
        assert!(missing.validate().is_err());
        let mut duplicate = report();
        duplicate.rows[1].version = "TLSv1".into();
        assert!(duplicate.validate().is_err());
        let mut forged = report();
        forged.rows[0].http_status = Some(200);
        assert!(forged.validate().is_err());
        let mut rejected = report();
        rejected.rows[0].outcome = NginxTlsOutcome::ProtocolRejected;
        assert!(rejected.validate().is_err());
        rejected.rows[0].detail = "server-protocol-alert".into();
        rejected.validate().unwrap();
        let mut accepted = report();
        let row = &mut accepted.rows[2];
        row.outcome = NginxTlsOutcome::Accepted;
        row.detail = "identity-verified".into();
        row.http_outcome = "status".into();
        row.http_status = Some(404);
        assert!(accepted.validate().is_err());
        accepted.rows[2].certificate_sha256 = Some("a".repeat(64));
        accepted.validate().unwrap();
    }
}
