use crate::ssh_manager_russh::{SSHManagerRussh, TerminalOutput};
use crate::types::{
    DockerActionResult, DockerContainerSummary, DockerCopyDirection, DockerCopyRequest,
    DockerLogsOptions, DockerMountInfo, DockerNetworkAttachment, DockerPortMapping,
    DockerQuickCheck, LovelyResError, LovelyResResult,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub trait DockerCommandRunner {
    fn is_connected(&self) -> bool;
    fn execute_command(&self, command: &str) -> Result<TerminalOutput, String>;
    fn write_sftp_file(&self, path: &str, content: &[u8]) -> Result<(), String>;
}

pub struct SessionDockerRunner<'a> {
    manager: &'a SSHManagerRussh,
    session_id: &'a str,
}

impl<'a> SessionDockerRunner<'a> {
    pub fn new(manager: &'a SSHManagerRussh, session_id: &'a str) -> Self {
        Self {
            manager,
            session_id,
        }
    }
}

impl DockerCommandRunner for SessionDockerRunner<'_> {
    fn is_connected(&self) -> bool {
        self.manager.is_session_connected(self.session_id)
    }

    fn execute_command(&self, command: &str) -> Result<TerminalOutput, String> {
        self.manager
            .execute_dashboard_command_as_user_on_session_with_timeout(
                self.session_id,
                command,
                None,
                std::time::Duration::from_secs(120),
            )
    }

    fn write_sftp_file(&self, path: &str, content: &[u8]) -> Result<(), String> {
        self.manager
            .write_sftp_file_on_session(self.session_id, path, content)
    }
}

/// Docker 管理器，封装通过 SSH 执行的 Docker 操作
pub struct DockerManager;

impl DockerManager {
    pub fn new() -> Self {
        Self
    }

    /// 获取容器列表并汇总统计信息
    pub fn list_containers(
        &self,
        ssh: &impl DockerCommandRunner,
    ) -> LovelyResResult<Vec<DockerContainerSummary>> {
        if !ssh.is_connected() {
            return Err(LovelyResError::ConnectionError(
                "未建立 SSH 连接".to_string(),
            ));
        }

        let ps_output = ensure_success(
            run_command(ssh, "docker ps -a --format '{{json .}}'")?,
            "获取 Docker 容器列表失败",
        )?;

        let mut rows = Vec::new();
        for line in ps_output.output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<DockerPsRow>(trimmed) {
                Ok(row) => rows.push(row),
                Err(err) => {
                    crate::alog_info!("解析 docker ps 输出失败: {} => {}", trimmed, err);
                }
            }
        }

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let stats_map = self.fetch_stats_map(ssh)?;
        let inspect_map = self.fetch_inspect_map(ssh, &rows)?;

        let mut summaries = Vec::with_capacity(rows.len());
        for row in &rows {
            if let Some(inspect) = self.lookup_inspect(&inspect_map, row) {
                let stats = self.lookup_stats(&stats_map, row, inspect);
                let summary = build_summary(row, inspect, stats);
                summaries.push(summary);
            } else {
                crate::alog_info!(
                    "未找到容器 {} 的 inspect 结果，跳过该条目",
                    row.primary_ref()
                );
            }
        }

        Ok(summaries)
    }

    /// 对容器执行 start/stop 等操作
    pub fn perform_action(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
        action: &str,
    ) -> LovelyResResult<DockerActionResult> {
        const ALLOWED: [&str; 6] = ["start", "stop", "restart", "kill", "pause", "unpause"];
        let action = action.trim();
        if !ALLOWED.contains(&action) {
            return Err(LovelyResError::InvalidInput(format!(
                "不支持的容器操作: {}",
                action
            )));
        }

        let command = format!("docker {} {}", action, shell_quote(container_ref));
        ensure_success(
            run_command(ssh, &command)?,
            &format!("执行 {} 操作失败", action),
        )?;

        let inspect = self.fetch_inspect(ssh, container_ref)?;
        let state = normalize_string(inspect.state.status.as_deref())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(DockerActionResult {
            success: true,
            message: format!("容器 {} 已执行 {}", container_ref, action),
            updated_state: Some(state.clone()),
            updated_status: Some(state),
            command: Some(command),
            backup_info: None,
            restore_command: None,
            verify_command: Some(format!(
                "docker inspect --format '{{{{.State.Status}}}}' {}",
                shell_quote(container_ref)
            )),
            verify_output: None,
            verified: None,
            restore_verify_command: None,
            restore_verify_expected: None,
        })
    }

    /// 获取容器日志
    pub fn get_logs(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
        options: Option<DockerLogsOptions>,
    ) -> LovelyResResult<String> {
        let opts = options.unwrap_or_default();
        let mut parts = vec!["docker".to_string(), "logs".to_string()];

        if let Some(tail) = opts.tail {
            parts.push(format!("--tail {}", tail));
        }
        if let Some(since) = opts.since.as_ref().and_then(|s| normalize_string(Some(s))) {
            parts.push(format!("--since {}", shell_quote(&since)));
        }
        if opts.timestamps {
            parts.push("--timestamps".to_string());
        }
        parts.push(shell_quote(container_ref));

        let mut command = parts.join(" ");
        match (opts.stdout, opts.stderr) {
            (true, false) => command.push_str(" 2>/dev/null"),
            (false, true) => command.push_str(" 1>/dev/null"),
            (false, false) => command.push_str(" >/dev/null 2>&1"),
            _ => {}
        }

        let output = ensure_success(run_command(ssh, &command)?, "获取容器日志失败")?;

        Ok(output.output)
    }

    /// 获取容器 inspect 原始数据
    pub fn inspect(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
    ) -> LovelyResResult<Value> {
        self.fetch_inspect_raw(ssh, container_ref)
    }

    /// 读取容器内文件
    pub fn read_file(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
        path: &str,
    ) -> LovelyResResult<String> {
        let inner = format!("cat {}", shell_quote(path));
        let command = format!(
            "docker exec {} sh -c {}",
            shell_quote(container_ref),
            shell_quote(&inner)
        );
        let output = ensure_success(
            run_command(ssh, &command)?,
            &format!("读取容器文件 {} 失败", path),
        )?;
        Ok(output.output)
    }

    /// 在容器内执行命令
    pub fn exec_command(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
        command: &str,
        shell: &str,
    ) -> LovelyResResult<TerminalOutput> {
        // 安全检查：确保容器引用和命令不包含危险字符
        if container_ref.is_empty() || command.is_empty() {
            return Err(LovelyResError::InvalidInput(
                "容器引用和命令不能为空".to_string(),
            ));
        }

        // 规范化 shell（仅允许 bash/sh/zsh），默认 sh
        let shell = match shell.to_lowercase().as_str() {
            "bash" => "bash",
            "zsh" => "zsh",
            _ => "sh",
        };

        // 构建 docker exec 命令（非交互TTY环境，去掉 -t）
        let docker_command = format!(
            "docker exec -i {} {} -c {}",
            shell_quote(container_ref),
            shell,
            shell_quote(command)
        );

        // 执行命令
        run_command(ssh, &docker_command)
    }

    /// 写入容器内文件
    pub fn write_file(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
        path: &str,
        content: &str,
    ) -> LovelyResResult<DockerActionResult> {
        validate_container_file_path(path)?;
        if content.len() > 2 * 1024 * 1024 {
            return Err(LovelyResError::InvalidInput(
                "容器文件编辑上限为 2 MiB".to_string(),
            ));
        }

        let operation_id = Uuid::new_v4().simple().to_string();
        let host_temp_path = generate_temp_path();
        let container_temp_path = format!("{}.lovelyres.tmp.{}", path, operation_id);
        let backup_path = format!("{}.lovelyres.bak.{}", path, operation_id);
        let parent = derive_parent_path(path).unwrap_or_else(|| "/".to_string());
        let quoted_path = shell_quote(path);
        let quoted_temp = shell_quote(&container_temp_path);
        let quoted_backup = shell_quote(&backup_path);

        let prepare_inner = format!(
            "set -eu; mkdir -p {parent}; if [ -L {path} ] || {{ [ -e {path} ] && [ ! -f {path} ]; }}; then echo unsafe-target; exit 42; fi; if [ -e {path} ]; then cp -a {path} {backup}; echo exists; else echo missing; fi",
            parent = shell_quote(&parent),
            path = quoted_path,
            backup = quoted_backup,
        );
        let prepare_command = format!(
            "docker exec {} sh -c {}",
            shell_quote(container_ref),
            shell_quote(&prepare_inner),
        );
        let prepare = ensure_success(
            run_command(ssh, &prepare_command)?,
            "容器目标不是普通文件或备份创建失败",
        )?;
        let existed = prepare.output.lines().any(|line| line.trim() == "exists");

        ssh.write_sftp_file(&host_temp_path, content.as_bytes())
            .map_err(LovelyResError::SSHError)?;
        let copy_command = format!(
            "docker cp {} {}",
            shell_quote(&host_temp_path),
            shell_quote(&format!("{}:{}", container_ref, container_temp_path)),
        );
        let copy_result = run_command(ssh, &copy_command);
        let cleanup_host = format!("rm -f {}", shell_quote(&host_temp_path));
        let _ = run_command(ssh, &cleanup_host);
        let copy_output = copy_result?;
        if let Err(error) = ensure_success(copy_output, "复制容器临时文件失败") {
            let cleanup_inner = format!("rm -f {}", quoted_temp);
            let cleanup_container = format!(
                "docker exec {} sh -c {}",
                shell_quote(container_ref),
                shell_quote(&cleanup_inner),
            );
            let _ = run_command(ssh, &cleanup_container);
            return Err(error);
        }

        let preserve_metadata = if existed {
            format!(
                "mode=$(stat -c %a {backup}) && owner=$(stat -c %u:%g {backup}) && chmod \"$mode\" {temp} && chown \"$owner\" {temp} && ",
                backup = quoted_backup,
                temp = quoted_temp,
            )
        } else {
            String::new()
        };
        let install_inner = format!(
            "set -eu; {preserve}mv -f {temp} {path}",
            preserve = preserve_metadata,
            temp = quoted_temp,
            path = quoted_path,
        );
        let install_command = format!(
            "docker exec {} sh -c {}",
            shell_quote(container_ref),
            shell_quote(&install_inner),
        );
        ensure_success(
            run_command(ssh, &install_command)?,
            "安装容器文件失败，原文件仍保留在备份路径",
        )?;

        let restore_inner = if existed {
            format!("cp -a {} {}", quoted_backup, quoted_path)
        } else {
            format!("rm -f {}", quoted_path)
        };
        let restore_command = format!(
            "docker exec {} sh -c {}",
            shell_quote(container_ref),
            shell_quote(&restore_inner),
        );
        let verify_command = format!(
            "docker exec {} cat {}",
            shell_quote(container_ref),
            quoted_path,
        );
        let verify_matches = run_command(ssh, &verify_command)
            .map(|output| output.is_success() && output.output == content)
            .unwrap_or(false);
        if !verify_matches {
            let restore_result = run_command(ssh, &restore_command)
                .map(|output| output.is_success())
                .unwrap_or(false);
            return Err(LovelyResError::DockerError(if restore_result {
                "容器文件读回不一致，已自动恢复原状态".to_string()
            } else {
                "容器文件读回不一致且自动恢复失败，请立即人工检查备份".to_string()
            }));
        }

        let (restore_verify_inner, restore_verify_expected) = if existed {
            (
                format!("cmp -s {} {} && echo restored", quoted_backup, quoted_path),
                "restored".to_string(),
            )
        } else {
            (
                format!("[ ! -e {} ] && echo absent", quoted_path),
                "absent".to_string(),
            )
        };
        let restore_verify_command = format!(
            "docker exec {} sh -c {}",
            shell_quote(container_ref),
            shell_quote(&restore_verify_inner),
        );

        Ok(DockerActionResult {
            success: true,
            message: format!("容器文件 {} 已保存并读回验证", path),
            updated_state: None,
            updated_status: None,
            command: Some(format!("{} && {}", copy_command, install_command)),
            backup_info: Some(if existed {
                backup_path
            } else {
                "原路径不存在；回滚将删除新文件".to_string()
            }),
            restore_command: Some(restore_command),
            verify_command: Some(verify_command),
            verify_output: Some(format!("exact-content-match: {} bytes", content.len())),
            verified: Some(true),
            restore_verify_command: Some(restore_verify_command),
            restore_verify_expected: Some(restore_verify_expected),
        })
    }

    /// 执行宿主机与容器之间的文件复制
    pub fn copy(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
        request: &DockerCopyRequest,
    ) -> LovelyResResult<DockerActionResult> {
        let source = request.source.trim();
        let target = request.target.trim();
        if source.is_empty() || target.is_empty() {
            return Err(LovelyResError::InvalidInput(
                "源路径和目标路径不能为空".to_string(),
            ));
        }

        let command = match request.direction {
            DockerCopyDirection::ContainerToHost => {
                format!(
                    "docker cp {} {}",
                    shell_quote(&format!("{}:{}", container_ref, source)),
                    shell_quote(target)
                )
            }
            DockerCopyDirection::HostToContainer => {
                if let Some(parent) = derive_parent_path(target) {
                    let mkdir_inner = format!("mkdir -p {}", shell_quote(&parent));
                    let mkdir_command = format!(
                        "docker exec {} sh -c {}",
                        shell_quote(container_ref),
                        shell_quote(&mkdir_inner)
                    );
                    ensure_success(run_command(ssh, &mkdir_command)?, "创建容器目录失败")?;
                }
                format!(
                    "docker cp {} {}",
                    shell_quote(source),
                    shell_quote(&format!("{}:{}", container_ref, target))
                )
            }
            DockerCopyDirection::InContainer => {
                let inner = format!("cp -a {} {}", shell_quote(source), shell_quote(target));
                format!(
                    "docker exec {} sh -c {}",
                    shell_quote(container_ref),
                    shell_quote(&inner)
                )
            }
        };

        ensure_success(run_command(ssh, &command)?, "执行容器文件复制失败")?;

        Ok(DockerActionResult {
            success: true,
            message: "Docker 文件复制任务已完成".to_string(),
            updated_state: None,
            updated_status: None,
            command: Some(command),
            backup_info: None,
            restore_command: None,
            verify_command: None,
            verify_output: None,
            verified: None,
            restore_verify_command: None,
            restore_verify_expected: None,
        })
    }

    fn fetch_stats_map(
        &self,
        ssh: &impl DockerCommandRunner,
    ) -> LovelyResResult<HashMap<String, StatsSnapshot>> {
        let result = run_command(ssh, "docker stats --no-stream --format '{{json .}}'")?;
        if !is_success(&result) {
            crate::alog_info!("docker stats 执行失败: {}", result.output.trim());
            return Ok(HashMap::new());
        }

        let mut map = HashMap::new();
        for line in result.output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<DockerStatsRow>(trimmed) {
                Ok(row) => {
                    let snapshot = StatsSnapshot {
                        cpu_percent: parse_percent(row.cpu_perc.as_deref()),
                        memory_usage: normalize_string(row.mem_usage.as_deref()),
                        memory_percent: parse_percent(row.mem_perc.as_deref()),
                        net_io: normalize_string(row.net_io.as_deref()),
                        block_io: normalize_string(row.block_io.as_deref()),
                        pids: row
                            .pids
                            .as_deref()
                            .and_then(|value| value.trim().parse::<u32>().ok()),
                    };

                    if let Some(id) = normalize_string(row.id.as_deref()) {
                        map.insert(id, snapshot.clone());
                    }
                    if let Some(name) = normalize_string(row.name.as_deref()) {
                        map.insert(name.clone(), snapshot.clone());
                    }
                }
                Err(err) => {
                    crate::alog_info!("解析 docker stats 输出失败: {} => {}", trimmed, err);
                }
            }
        }

        Ok(map)
    }

    fn fetch_inspect_map(
        &self,
        ssh: &impl DockerCommandRunner,
        rows: &[DockerPsRow],
    ) -> LovelyResResult<HashMap<String, DockerInspect>> {
        let mut refs = HashSet::new();
        for row in rows {
            refs.insert(row.primary_ref());
        }
        if refs.is_empty() {
            return Ok(HashMap::new());
        }

        let joined = refs
            .iter()
            .map(|item| shell_quote(item))
            .collect::<Vec<_>>()
            .join(" ");
        let command = format!(
            "docker inspect --type container --format '{{{{json .}}}}' {}",
            joined
        );
        let result = ensure_success(run_command(ssh, &command)?, "获取容器详情失败")?;

        let mut map = HashMap::new();
        for line in result.output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<DockerInspect>(trimmed) {
                Ok(inspect) => {
                    let mut keys = Vec::new();
                    keys.push(inspect.id.clone());
                    keys.push(short_id(&inspect.id));
                    keys.push(inspect.name.clone());
                    keys.push(sanitize_name(&inspect.name));

                    if let Some(settings) = inspect.network_settings.as_ref() {
                        if let Some(networks) = settings.networks.as_ref() {
                            for name in networks.keys() {
                                keys.push(name.clone());
                            }
                        }
                    }

                    for key in keys {
                        map.insert(key, inspect.clone());
                    }
                }
                Err(err) => {
                    crate::alog_info!("解析 docker inspect 输出失败: {} => {}", trimmed, err);
                }
            }
        }

        Ok(map)
    }

    fn lookup_inspect<'a>(
        &self,
        inspect_map: &'a HashMap<String, DockerInspect>,
        row: &DockerPsRow,
    ) -> Option<&'a DockerInspect> {
        let mut candidates = Vec::new();
        candidates.push(row.primary_ref());
        candidates.push(row.id.clone());
        if let Some(names) = row.names.as_ref() {
            for name in names.split(',') {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    candidates.push(trimmed.to_string());
                }
            }
        }

        for candidate in candidates {
            if let Some(inspect) = inspect_map.get(&candidate) {
                return Some(inspect);
            }
        }
        None
    }

    fn lookup_stats(
        &self,
        stats_map: &HashMap<String, StatsSnapshot>,
        row: &DockerPsRow,
        inspect: &DockerInspect,
    ) -> Option<StatsSnapshot> {
        let mut candidates = Vec::new();
        candidates.push(row.id.clone());
        candidates.push(row.primary_ref());
        candidates.push(short_id(&inspect.id));
        candidates.push(inspect.id.clone());
        candidates.push(sanitize_name(&inspect.name));

        if let Some(names) = row.names.as_ref() {
            for name in names.split(',') {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    candidates.push(trimmed.to_string());
                }
            }
        }

        for candidate in candidates {
            if let Some(stats) = stats_map.get(&candidate) {
                return Some(stats.clone());
            }
        }
        None
    }

    fn fetch_inspect(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
    ) -> LovelyResResult<DockerInspect> {
        let value = self.fetch_inspect_raw(ssh, container_ref)?;
        serde_json::from_value::<DockerInspect>(value).map_err(|err| {
            LovelyResError::DockerError(format!("解析 Docker inspect 输出失败: {}", err))
        })
    }

    fn fetch_inspect_raw(
        &self,
        ssh: &impl DockerCommandRunner,
        container_ref: &str,
    ) -> LovelyResResult<Value> {
        let command = format!(
            "docker inspect --type container --format '{{{{json .}}}}' {}",
            shell_quote(container_ref)
        );
        let result = ensure_success(run_command(ssh, &command)?, "获取容器详情失败")?;

        let payload = result.output.trim();
        if payload.is_empty() {
            return Err(LovelyResError::DockerError(
                "未获取到容器 inspect 数据".to_string(),
            ));
        }

        serde_json::from_str::<Value>(payload).map_err(|err| {
            LovelyResError::DockerError(format!("解析 Docker inspect 输出失败: {}", err))
        })
    }
}

#[derive(Debug, Clone, Default)]
struct StatsSnapshot {
    cpu_percent: Option<f64>,
    memory_usage: Option<String>,
    memory_percent: Option<f64>,
    net_io: Option<String>,
    block_io: Option<String>,
    pids: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerPsRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: Option<String>,
    #[serde(rename = "Command")]
    command: Option<String>,
    #[serde(rename = "RunningFor")]
    running_for: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
}

impl DockerPsRow {
    fn primary_ref(&self) -> String {
        if let Some(names) = self.names.as_ref() {
            if let Some(first) = names.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        self.id.clone()
    }
}

#[derive(Debug, Deserialize, Clone)]
struct DockerStatsRow {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "CPUPerc")]
    cpu_perc: Option<String>,
    #[serde(rename = "MemUsage")]
    mem_usage: Option<String>,
    #[serde(rename = "MemPerc")]
    mem_perc: Option<String>,
    #[serde(rename = "NetIO")]
    net_io: Option<String>,
    #[serde(rename = "BlockIO")]
    block_io: Option<String>,
    #[serde(rename = "PIDs")]
    pids: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Created")]
    created: String,
    #[serde(rename = "Config")]
    config: DockerInspectConfig,
    #[serde(rename = "State")]
    state: DockerInspectState,
    #[serde(rename = "HostConfig")]
    host_config: DockerInspectHostConfig,
    #[serde(rename = "NetworkSettings")]
    network_settings: Option<DockerInspectNetworkSettings>,
    #[serde(rename = "Mounts")]
    mounts: Vec<DockerInspectMount>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectConfig {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectState {
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Health")]
    health: Option<DockerInspectHealth>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectHealth {
    #[serde(rename = "Status")]
    status: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectHostConfig {
    #[serde(rename = "Privileged")]
    privileged: Option<bool>,
    #[serde(rename = "NetworkMode")]
    network_mode: Option<String>,
    #[serde(rename = "PidMode")]
    pid_mode: Option<String>,
    #[serde(rename = "IpcMode")]
    ipc_mode: Option<String>,
    #[serde(rename = "CapAdd")]
    cap_add: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectNetworkSettings {
    #[serde(rename = "NetworkMode")]
    network_mode: Option<String>,
    #[serde(rename = "Networks")]
    networks: Option<HashMap<String, DockerInspectNetwork>>,
    #[serde(rename = "Ports")]
    ports: Option<HashMap<String, Option<Vec<DockerPortBinding>>>>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectNetwork {
    #[serde(rename = "NetworkID")]
    network_id: Option<String>,
    #[serde(rename = "EndpointID")]
    endpoint_id: Option<String>,
    #[serde(rename = "MacAddress")]
    mac_address: Option<String>,
    #[serde(rename = "IPAddress")]
    ipv4_address: Option<String>,
    #[serde(rename = "GlobalIPv6Address")]
    ipv6_address: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerPortBinding {
    #[serde(rename = "HostIp")]
    host_ip: Option<String>,
    #[serde(rename = "HostPort")]
    host_port: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct DockerInspectMount {
    #[serde(rename = "Type")]
    mount_type: Option<String>,
    #[serde(rename = "Source")]
    source: Option<String>,
    #[serde(rename = "Destination")]
    destination: Option<String>,
    #[serde(rename = "Mode")]
    mode: Option<String>,
    #[serde(rename = "RW")]
    rw: Option<bool>,
}

fn build_summary(
    row: &DockerPsRow,
    inspect: &DockerInspect,
    stats: Option<StatsSnapshot>,
) -> DockerContainerSummary {
    let name = sanitize_name(&inspect.name);
    let state =
        normalize_string(inspect.state.status.as_deref()).unwrap_or_else(|| "unknown".to_string());
    let status = normalize_string(row.status.as_deref()).unwrap_or_else(|| state.clone());

    let command = if let Some(cmd) = inspect.config.cmd.as_ref() {
        if !cmd.is_empty() {
            Some(cmd.join(" "))
        } else {
            None
        }
    } else {
        normalize_command(row.command.as_deref())
    };

    let created_at = to_iso_string(&inspect.created);
    let ports = extract_ports(inspect);
    let networks = extract_networks(inspect);
    let mounts = extract_mounts(inspect);

    let (cpu_percent, memory_usage, memory_percent, net_io, block_io, pids) = match stats {
        Some(snapshot) => (
            snapshot.cpu_percent,
            snapshot.memory_usage,
            snapshot.memory_percent,
            snapshot.net_io,
            snapshot.block_io,
            snapshot.pids,
        ),
        None => (None, None, None, None, None, None),
    };

    // 命名空间共享:PidMode/IpcMode 为 "host" 即与宿主机共享(容器逃逸前置条件)
    let host_pid = inspect
        .host_config
        .pid_mode
        .as_deref()
        .map(|m| m == "host")
        .unwrap_or(false);
    let host_ipc = inspect
        .host_config
        .ipc_mode
        .as_deref()
        .map(|m| m == "host")
        .unwrap_or(false);
    // 危险 capabilities:可用于容器逃逸/宿主机操作,兼容带或不带 CAP_ 前缀
    const DANGEROUS_CAPS: &[&str] = &[
        "ALL",
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "NET_ADMIN",
        "DAC_READ_SEARCH",
        "DAC_OVERRIDE",
        "BPF",
        "SYS_CHROOT",
    ];
    let dangerous_caps = inspect
        .host_config
        .cap_add
        .as_ref()
        .map(|caps| {
            caps.iter()
                .filter(|c| {
                    let up = c.trim().to_uppercase();
                    let bare = up.strip_prefix("CAP_").unwrap_or(&up);
                    DANGEROUS_CAPS.contains(&bare)
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let quick_checks = DockerQuickCheck {
        network_attached: !networks.is_empty(),
        privileged: inspect.host_config.privileged.unwrap_or(false),
        health: inspect
            .state
            .health
            .as_ref()
            .and_then(|h| normalize_string(h.status.as_deref())),
        host_pid,
        host_ipc,
        dangerous_caps,
    };

    let network_mode = inspect
        .host_config
        .network_mode
        .as_ref()
        .and_then(|s| normalize_string(Some(s)))
        .or_else(|| {
            inspect
                .network_settings
                .as_ref()
                .and_then(|settings| settings.network_mode.as_ref())
                .and_then(|s| normalize_string(Some(s)))
        });

    DockerContainerSummary {
        id: inspect.id.clone(),
        short_id: short_id(&inspect.id),
        name,
        image: inspect.config.image.clone(),
        state,
        status,
        created_at,
        uptime: normalize_string(row.running_for.as_deref()),
        command,
        ports,
        cpu_percent,
        memory_usage,
        memory_percent,
        net_io,
        block_io,
        pids,
        network_mode,
        networks,
        mounts,
        quick_checks,
    }
}

fn extract_ports(inspect: &DockerInspect) -> Vec<DockerPortMapping> {
    let mut mappings = Vec::new();
    let settings = match inspect.network_settings.as_ref() {
        Some(value) => value,
        None => return mappings,
    };

    if let Some(port_map) = settings.ports.as_ref() {
        for (container_port, bindings_opt) in port_map {
            let (private_port, protocol) = split_port(container_port);
            match bindings_opt {
                Some(bindings) if !bindings.is_empty() => {
                    for binding in bindings {
                        mappings.push(DockerPortMapping {
                            ip: normalize_string(binding.host_ip.as_deref()),
                            private_port: private_port.clone(),
                            public_port: normalize_string(binding.host_port.as_deref()),
                            protocol: protocol.clone(),
                        });
                    }
                }
                _ => {
                    mappings.push(DockerPortMapping {
                        ip: None,
                        private_port: private_port.clone(),
                        public_port: None,
                        protocol: protocol.clone(),
                    });
                }
            }
        }
    }

    mappings
}

fn extract_networks(inspect: &DockerInspect) -> Vec<DockerNetworkAttachment> {
    let mut networks = Vec::new();
    let settings = match inspect.network_settings.as_ref() {
        Some(value) => value,
        None => return networks,
    };

    if let Some(items) = settings.networks.as_ref() {
        for (name, details) in items {
            networks.push(DockerNetworkAttachment {
                name: name.clone(),
                network_id: normalize_string(details.network_id.as_deref()),
                endpoint_id: normalize_string(details.endpoint_id.as_deref()),
                mac_address: normalize_string(details.mac_address.as_deref()),
                ipv4_address: normalize_string(details.ipv4_address.as_deref()),
                ipv6_address: normalize_string(details.ipv6_address.as_deref()),
            });
        }
    }

    networks
}

fn extract_mounts(inspect: &DockerInspect) -> Vec<DockerMountInfo> {
    inspect
        .mounts
        .iter()
        .map(|mount| DockerMountInfo {
            mount_type: normalize_string(mount.mount_type.as_deref())
                .unwrap_or_else(|| "volume".to_string()),
            source: normalize_string(mount.source.as_deref()),
            destination: normalize_string(mount.destination.as_deref())
                .unwrap_or_else(|| "".to_string()),
            mode: normalize_string(mount.mode.as_deref()),
            rw: mount.rw.unwrap_or(false),
        })
        .collect()
}

fn run_command(ssh: &impl DockerCommandRunner, command: &str) -> LovelyResResult<TerminalOutput> {
    // 使用命令执行
    ssh.execute_command(command)
        .map_err(|e| LovelyResError::SSHError(e))
}

fn ensure_success(
    result: TerminalOutput,
    fallback_message: &str,
) -> LovelyResResult<TerminalOutput> {
    if is_success(&result) {
        Ok(result)
    } else {
        let message = result.output.trim();
        if message.is_empty() {
            Err(LovelyResError::DockerError(fallback_message.to_string()))
        } else {
            Err(LovelyResError::DockerError(message.to_string()))
        }
    }
}

fn is_success(result: &TerminalOutput) -> bool {
    result.is_success()
}

fn normalize_string(value: Option<&str>) -> Option<String> {
    value
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn normalize_command(value: Option<&str>) -> Option<String> {
    normalize_string(value).map(|mut command| {
        if command.starts_with('"') && command.ends_with('"') && command.len() >= 2 {
            command = command[1..command.len() - 1].to_string();
        }
        command
    })
}

fn parse_percent(value: Option<&str>) -> Option<f64> {
    value
        .map(|v| v.trim().trim_end_matches('%').replace(',', "."))
        .and_then(|v| v.parse::<f64>().ok())
}

fn short_id(value: &str) -> String {
    value.chars().take(12).collect()
}

fn to_iso_string(value: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(value) {
        Ok(dt) => dt.to_rfc3339(),
        Err(_) => value.to_string(),
    }
}

// 统一实现见 crate::shell_escape —— 此前本函数在 6 个文件里各存一份复制。
// 本处原有的空串特判是冗余的：format!("'{}'", "") 本就产出 ''。
use crate::shell_escape::shq as shell_quote;

fn sanitize_name(name: &str) -> String {
    name.trim_start_matches('/').to_string()
}

fn split_port(value: &str) -> (String, String) {
    let mut parts = value.split('/');
    let private = parts.next().unwrap_or("").to_string();
    let protocol = parts.next().unwrap_or("").to_string();
    (private, protocol)
}

fn derive_parent_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let mut segments: Vec<&str> = normalized.split('/').collect();
    if segments.len() <= 1 {
        return None;
    }
    segments.pop();
    let parent = segments.join("/");
    if parent.is_empty() {
        None
    } else {
        Some(parent)
    }
}

fn validate_container_file_path(path: &str) -> LovelyResResult<()> {
    let trimmed = path.trim();
    if !trimmed.starts_with('/')
        || trimmed.contains('\0')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.split('/').any(|segment| segment == "..")
    {
        return Err(LovelyResError::InvalidInput(
            "容器文件路径必须是无父级跳转的绝对路径".to_string(),
        ));
    }
    Ok(())
}

fn generate_temp_path() -> String {
    format!("/tmp/lovelyres_{}.tmp", Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeRunner {
        outputs: Mutex<VecDeque<TerminalOutput>>,
        commands: Mutex<Vec<String>>,
    }

    impl FakeRunner {
        fn new(outputs: Vec<TerminalOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                commands: Mutex::new(Vec::new()),
            }
        }
    }

    impl DockerCommandRunner for FakeRunner {
        fn is_connected(&self) -> bool {
            true
        }

        fn execute_command(&self, command: &str) -> Result<TerminalOutput, String> {
            self.commands
                .lock()
                .expect("commands mutex")
                .push(command.to_string());
            self.outputs
                .lock()
                .expect("outputs mutex")
                .pop_front()
                .ok_or_else(|| "missing fake output".to_string())
        }

        fn write_sftp_file(&self, _path: &str, _content: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn container_file_paths_must_be_safe_absolute_paths() {
        assert!(validate_container_file_path("/etc/nginx/nginx.conf").is_ok());
        assert!(validate_container_file_path("etc/passwd").is_err());
        assert!(validate_container_file_path("/etc/../root/.ssh/authorized_keys").is_err());
        assert!(validate_container_file_path("/tmp/a\nmalicious").is_err());
    }

    #[test]
    fn write_file_returns_verified_restore_receipt_and_quotes_container_ref() {
        let runner = FakeRunner::new(vec![
            TerminalOutput::new("prepare", "exists\n", Some(0)),
            TerminalOutput::new("copy", "", Some(0)),
            TerminalOutput::new("cleanup", "", Some(0)),
            TerminalOutput::new("install", "", Some(0)),
            TerminalOutput::new("verify", "hello", Some(0)),
        ]);
        let result = DockerManager::new()
            .write_file(&runner, "web; touch /tmp/pwn", "/etc/app.conf", "hello")
            .expect("verified write receipt");

        assert!(result.success);
        assert_eq!(result.verified, Some(true));
        assert!(result
            .restore_command
            .as_deref()
            .unwrap_or_default()
            .contains("lovelyres.bak"));
        assert!(runner
            .commands
            .lock()
            .expect("commands mutex")
            .iter()
            .all(|command| !command.contains("docker exec web;")));
    }
}
