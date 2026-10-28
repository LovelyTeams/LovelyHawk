//! Nginx masters in an ordinary Linux process namespace, without systemd.
//! Remote evidence is retained in core, never promoted to an executable command.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CoreError, CoreResult,
    sftp::RemotePath,
    shell_escape::shq,
    ssh::{BoundSshSession, SshService},
    target::TargetContext,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NginxProcessEvidence {
    pub(crate) pid: u32,
    pub(crate) start_time_ticks: u64,
    boot_id: String,
    pub(crate) executable: RemotePath,
    executable_sha256: String,
    cmdline_sha256: String,
    environment_sha256: String,
    mount_namespace: u64,
    cwd: RemotePath,
    #[serde(deserialize_with = "deserialize_arguments")]
    arguments: Vec<String>,
    prefix: RemotePath,
    pub(crate) config: RemotePath,
    pub(crate) version: String,
}

fn deserialize_arguments<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    struct Arguments;
    impl<'de> serde::de::Visitor<'de> for Arguments {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("at most two closed Nginx launch arguments")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = Vec::with_capacity(2);
            while values.len() < 2 {
                let Some(value) = sequence.next_element::<String>()? else {
                    return Ok(values);
                };
                if value.len() > 32 {
                    return Err(serde::de::Error::custom("Nginx argument exceeds its bound"));
                }
                values.push(value);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("too many Nginx arguments"));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Arguments)
}

impl NginxProcessEvidence {
    pub(crate) fn validate(&self) -> CoreResult<()> {
        let hash = |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
        let path = |value: &RemotePath| {
            value.as_str().len() <= 4096
                && value
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-.+".contains(&b))
        };
        if self.pid == 0
            || self.start_time_ticks == 0
            || self.mount_namespace == 0
            || uuid::Uuid::parse_str(&self.boot_id).is_err()
            || !hash(&self.executable_sha256)
            || !hash(&self.cmdline_sha256)
            || !hash(&self.environment_sha256)
            || self.executable.file_name()? != "nginx"
            || ![&self.executable, &self.config, &self.prefix, &self.cwd]
                .into_iter()
                .all(path)
            || self.config.as_str() == "/"
            || self.prefix.as_str() == "/"
            || !(self.arguments.is_empty() || self.arguments == ["-g", "daemon off;"])
            || !self.version.starts_with("nginx version: nginx/")
            || self.version.len() > 128
            || self.version.chars().any(char::is_control)
        {
            return Err(CoreError::validation(
                "Nginx process evidence",
                "invalid bounded runtime identity",
            ));
        }
        Ok(())
    }

    pub(crate) fn fingerprint(&self) -> CoreResult<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| {
            CoreError::validation(
                "Nginx process evidence",
                "could not encode runtime evidence",
            )
        })?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub(crate) fn label(&self) -> String {
        format!("nginx-process-{}", self.pid)
    }

    pub(crate) fn proc_executable(&self) -> CoreResult<RemotePath> {
        RemotePath::new(format!("/proc/{}/exe", self.pid))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum NginxProcessAction {
    Verify,
    ConfigTest,
    Reload,
    Health,
}

pub(crate) async fn call(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    request: serde_json::Value,
) -> CoreResult<serde_json::Value> {
    target.validate(session.target())?;
    let command = format!(
        "python3 -I -c {} {}",
        shq(include_str!("nginx_process.py")),
        shq(&request.to_string())
    );
    let output = ssh
        .execute_bound(session, command, Duration::from_secs(45))
        .await?;
    target.validate(session.target())?;
    if output.timed_out || output.output.len() > 256 * 1024 {
        return Err(CoreError::validation(
            "Nginx process runtime",
            "runtime probe timed out or exceeded its output bound",
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(output.output.trim()).map_err(|_| {
        CoreError::validation(
            "Nginx process runtime",
            "需要目标具备 Python 3.9+、Linux pidfd 和读取 Nginx 进程的权限；未自动安装或更改目标。",
        )
    })?;
    if output.exit_code != Some(0) {
        let reason = match value.get("refused").and_then(serde_json::Value::as_str) {
            Some("unsupported-master-arguments") => {
                "当前仅支持默认启动与 -g 'daemon off;'；该实例启动参数无法无歧义还原，不能继续验证或重载。"
            }
            Some("runtime-identity-changed" | "process-exited") => {
                "Nginx 进程身份发生变化，请重新发现实例并生成计划。"
            }
            Some("native-configuration-rejected") => "Nginx 原生配置检查未通过；未重载服务。",
            Some("reload-worker-transition-unverified") => {
                "未能核实 Nginx 已切换到新工作进程，不能判定重载成功。"
            }
            Some("no-serving-workers") => "未发现可服务的 Nginx 工作进程。",
            Some("shared-master-configuration") => {
                "多个 Nginx 主进程共用同一配置，尚不能按单实例计划修改；请先明确共同影响范围。"
            }
            _ => {
                "无法核实 Nginx 进程能力、权限或配置来源；需要 Python 3.9+、Linux pidfd 和可读取的同一进程文件系统。"
            }
        };
        return Err(CoreError::validation("Nginx process runtime", reason));
    }
    Ok(value)
}

pub(crate) async fn discover(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
) -> CoreResult<Vec<NginxProcessEvidence>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Inventory {
        instances: Vec<NginxProcessEvidence>,
    }
    let result: Inventory = serde_json::from_value(
        call(
            target,
            ssh,
            session,
            serde_json::json!({"mode": "discover"}),
        )
        .await?,
    )
    .map_err(|_| {
        CoreError::validation(
            "Nginx process inventory",
            "invalid bounded inventory response",
        )
    })?;
    if result.instances.len() > 32 {
        return Err(CoreError::validation(
            "Nginx process inventory",
            "too many instances",
        ));
    }
    let mut pids = std::collections::BTreeSet::new();
    for instance in &result.instances {
        instance.validate()?;
        if !pids.insert(instance.pid) {
            return Err(CoreError::validation(
                "Nginx process inventory",
                "duplicate process identity",
            ));
        }
    }
    Ok(result.instances)
}

pub(crate) async fn execute(
    target: &TargetContext,
    ssh: &SshService,
    session: &BoundSshSession,
    evidence: &NginxProcessEvidence,
    action: NginxProcessAction,
) -> CoreResult<()> {
    evidence.validate()?;
    let mode = match action {
        NginxProcessAction::Verify => "verify",
        NginxProcessAction::ConfigTest => "config-test",
        NginxProcessAction::Reload => "reload",
        NginxProcessAction::Health => "health",
    };
    let value = call(
        target,
        ssh,
        session,
        serde_json::json!({"mode": mode, "evidence": evidence}),
    )
    .await?;
    if value != serde_json::json!({"verified": true}) {
        return Err(CoreError::validation(
            "Nginx process result",
            "invalid runtime verification response",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn evidence() -> NginxProcessEvidence {
        serde_json::from_value(serde_json::json!({
            "pid": 42, "start_time_ticks": 1000, "boot_id": "c1bf0d9c-bcbc-44e4-a3f5-52cc0857c4a7",
            "executable": "/usr/sbin/nginx", "executable_sha256": "a".repeat(64),
            "cmdline_sha256": "b".repeat(64), "environment_sha256": "c".repeat(64),
            "mount_namespace": 4026531840_u64, "cwd": "/", "arguments": ["-g", "daemon off;"],
            "prefix": "/etc/nginx", "config": "/etc/nginx/nginx.conf", "version": "nginx version: nginx/1.27.5"
        })).unwrap()
    }

    #[test]
    fn runtime_evidence_is_bounded_and_does_not_admit_arbitrary_arguments() {
        let original = evidence();
        original.validate().unwrap();
        for arguments in [
            vec!["-g".to_owned(), "include /tmp/untrusted;".to_owned()],
            vec!["-c".to_owned(), "/etc/nginx/other.conf".to_owned()],
            vec!["x".repeat(100000)],
        ] {
            let mut forged = original.clone();
            forged.arguments = arguments;
            assert!(forged.validate().is_err());
        }
        let mut forged = original.clone();
        forged.executable_sha256 = "x".repeat(64);
        assert!(forged.validate().is_err());
        forged = original;
        forged.config = RemotePath::new("/etc/nginx/a;touch-pwned.conf").unwrap();
        assert!(forged.validate().is_err());
    }

    #[test]
    fn fingerprint_binds_boot_start_executable_and_configuration() {
        let original = evidence();
        let fingerprint = original.fingerprint().unwrap();
        for field in [
            "boot_id",
            "start_time_ticks",
            "executable_sha256",
            "config",
            "environment_sha256",
        ] {
            let mut forged = serde_json::to_value(&original).unwrap();
            forged[field] = match field {
                "boot_id" => serde_json::json!("ef0094fa-7e09-4dfb-8524-80ea1c4466ea"),
                "start_time_ticks" => serde_json::json!(1001),
                "config" => serde_json::json!("/etc/nginx/other.conf"),
                _ => serde_json::json!("d".repeat(64)),
            };
            let forged: NginxProcessEvidence = serde_json::from_value(forged).unwrap();
            assert_ne!(forged.fingerprint().unwrap(), fingerprint);
        }
    }

    #[test]
    fn evidence_deserialization_rejects_added_execution_fields() {
        let mut forged = serde_json::to_value(evidence()).unwrap();
        forged["command"] = serde_json::json!("touch /tmp/pwned");
        assert!(serde_json::from_value::<NginxProcessEvidence>(forged).is_err());
        for arguments in [
            serde_json::json!(["-g", "daemon off;", "-q"]),
            serde_json::json!(["x".repeat(33)]),
        ] {
            let mut forged = serde_json::to_value(evidence()).unwrap();
            forged["arguments"] = arguments;
            assert!(serde_json::from_value::<NginxProcessEvidence>(forged).is_err());
        }
    }
}
