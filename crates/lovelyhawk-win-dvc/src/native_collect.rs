//! Incident response collectors for the remote RDP session agent.
//! Accounts and event logs use bounded PowerShell queries to preserve actual
//! identities, record IDs, localized text and explicit permission failures.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Local};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Dispatch a `__NATIVE_COLLECT__:<spec>` command and return `[exit=0]\n<json>`.
pub fn handle_native_collect(spec: &str) -> String {
    let result = if spec == "overview" || spec == "overview-v2" {
        collect_overview()
    } else if matches!(spec, "baseline" | "baseline-v2" | "baseline-v3") {
        collect_baseline()
    } else if spec == "processes" || spec == "processes-v2" {
        collect_processes()
    } else if let Some(query) = spec.strip_prefix("inspect-process:") {
        query
            .split_once(':')
            .and_then(|(pid, time)| {
                pid.parse()
                    .ok()
                    .and_then(|pid| crate::windows_read_queries::process_inspection(pid, time))
            })
            .ok_or_else(|| "进程身份无效".to_owned())
            .and_then(|script| query_powershell_json(&script))
    } else if spec == "network" || spec == "network-v2" {
        collect_network()
    } else if spec == "startup" {
        collect_startup()
    } else if spec == "accounts" || spec == "accounts-v2" {
        collect_accounts()
    } else if let Some(cat) = spec
        .strip_prefix("logs-v2:")
        .or_else(|| spec.strip_prefix("logs:"))
    {
        collect_logs(cat)
    } else if let Some(path) = spec
        .strip_prefix("files-v2:")
        .or_else(|| spec.strip_prefix("files:"))
    {
        collect_files(path)
    } else if let Some(key) = spec
        .strip_prefix("registry-v2:")
        .or_else(|| spec.strip_prefix("registry:"))
    {
        collect_registry(key)
    } else if let Some(file_path) = spec.strip_prefix("pull-file:") {
        pull_file_json(file_path)
    } else if let Some(file_path) = spec.strip_prefix("preview-file:") {
        preview_file_json(file_path)
    } else if spec == "defender" || spec == "defender-v1" {
        collect_defender()
    } else if spec == "commands" || spec == "commands-v1" {
        collect_commands()
    } else if let Some(scan_path) = spec.strip_prefix("webshell-scan:") {
        scan_webshells(scan_path)
    } else {
        Err(format!("未知原生采集指令: {spec}"))
    };

    match result {
        Ok(val) => format!("[exit=0]\n{}", val),
        Err(err) => format!("[error] {err}"),
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut out = input.to_owned();
    for var in [
        "TEMP",
        "TMP",
        "APPDATA",
        "LOCALAPPDATA",
        "USERPROFILE",
        "ProgramData",
        "SystemRoot",
        "SystemDrive",
    ] {
        let token = format!("%{var}%");
        if out
            .to_ascii_lowercase()
            .contains(&token.to_ascii_lowercase())
            && let Ok(val) = std::env::var(var)
        {
            out = replace_case_insensitive(&out, &token, &val);
        }
    }
    out
}

fn replace_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    let h_lower = haystack.to_ascii_lowercase();
    let n_lower = needle.to_ascii_lowercase();
    if let Some(pos) = h_lower.find(&n_lower) {
        let mut res = String::new();
        res.push_str(&haystack[..pos]);
        res.push_str(replacement);
        res.push_str(&haystack[pos + needle.len()..]);
        res
    } else {
        haystack.to_owned()
    }
}

fn collect_overview() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::OVERVIEW)
}

fn collect_baseline() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::BASELINE)
}

fn collect_processes() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::PROCESSES)
}

fn collect_network() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::NETWORK)
}

fn collect_startup() -> Result<Value, String> {
    let mut items = Vec::new();
    let run_keys = [
        (
            RegRoot::Hklm,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
        (
            RegRoot::Hklm,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ),
        (
            RegRoot::Hkcu,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
        (
            RegRoot::Hkcu,
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ),
    ];
    for (root, subkey, display_loc) in run_keys {
        for (name, _kind, data) in reg_enum_values(root, subkey) {
            items.push(json!({
                "sourceType": "registry",
                "name": name,
                "location": display_loc,
                "command": data,
                "runAs": "",
                "state": "Enabled",
            }));
        }
    }

    // Check Winlogon Userinit & Shell
    let wl_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    for field in ["Shell", "Userinit"] {
        if let Some(val) = reg_get_string(RegRoot::Hklm, wl_key, field) {
            items.push(json!({
                "sourceType": "registry",
                "name": format!("Winlogon\\{field}"),
                "location": format!("HKLM:\\{wl_key}"),
                "command": val,
                "runAs": "SYSTEM",
                "state": "Enabled",
            }));
        }
    }

    // Startup folders
    let mut startup_dirs = vec![PathBuf::from(
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    )];
    if let Ok(appdata) = std::env::var("APPDATA") {
        startup_dirs
            .push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    for dir in startup_dirs {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                items.push(json!({
                    "sourceType": "startup-folder",
                    "name": name,
                    "location": dir.to_string_lossy(),
                    "command": entry.path().to_string_lossy(),
                    "runAs": "",
                    "state": "Enabled",
                }));
            }
        }
    }

    // Custom Scheduled Tasks in C:\Windows\System32\Tasks (excluding Microsoft)
    if let Ok(rd) = std::fs::read_dir("C:\\Windows\\System32\\Tasks") {
        for entry in rd.flatten().take(25) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("Microsoft") {
                continue;
            }
            items.push(json!({
                "sourceType": "scheduled-task",
                "name": name,
                "location": "C:\\Windows\\System32\\Tasks",
                "command": entry.path().to_string_lossy(),
                "runAs": "TaskScheduler",
                "state": "Ready",
            }));
        }
    }

    Ok(Value::Array(items))
}

fn collect_accounts() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::ACCOUNTS)
}

fn collect_logs(category: &str) -> Result<Value, String> {
    let script =
        crate::windows_read_queries::logs(category).ok_or_else(|| "不支持的日志类别".to_owned())?;
    query_powershell_json(&script)
}

fn collect_defender() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::DEFENDER_ANALYSIS)
}

fn collect_commands() -> Result<Value, String> {
    query_powershell_json(crate::windows_read_queries::COMMAND_MONITOR)
}

struct WarmPsWorker {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    rx: std::sync::mpsc::Receiver<std::io::Result<String>>,
}

static WARM_PS: parking_lot::Mutex<Option<WarmPsWorker>> = parking_lot::Mutex::new(None);

fn system_powershell_exe() -> Result<PathBuf, String> {
    std::env::var_os("SystemRoot")
        .map(|root| Path::new(&root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| "系统 PowerShell 不可用，无法完成只读查询".to_owned())
}

impl WarmPsWorker {
    fn spawn() -> Result<Self, String> {
        use std::io::BufRead;
        use std::process::Stdio;
        let executable = system_powershell_exe()?;
        let mut command = Command::new(executable);
        command
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("无法启动常驻查询进程: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "无法打开查询输入管道".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "无法打开查询输出管道".to_owned())?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self { child, stdin, rx })
    }

    fn execute(
        &mut self,
        script: &str,
        limit: usize,
        timeout: std::time::Duration,
    ) -> Result<String, (bool, String)> {
        use std::io::Write;
        if let Ok(Some(_)) = self.child.try_wait() {
            return Err((true, "常驻 PowerShell 已退出".to_owned()));
        }
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let b64 = BASE64.encode(script.as_bytes());
        let line = format!(
            "$__lh_id='{marker}'; try {{ [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; $ErrorActionPreference = 'Stop'; $__lh_s = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64}')); $__lh_r = & ([scriptblock]::Create($__lh_s)) | Out-String -Width 2147483647; [Console]::Out.WriteLine('__LH_OK_' + $__lh_id + '__'); [Console]::Out.WriteLine($__lh_r.TrimEnd()); }} catch {{ [Console]::Out.WriteLine('__LH_ERR_' + $__lh_id + '__:' + $_.Exception.Message) }} finally {{ [Console]::Out.WriteLine('__LH_END_' + $__lh_id + '__'); [Console]::Out.Flush() }}\n"
        );
        if self.stdin.write_all(line.as_bytes()).is_err() || self.stdin.flush().is_err() {
            return Err((true, "写入常驻 PowerShell 失败".to_owned()));
        }
        let ok_tag = format!("__LH_OK_{marker}__");
        let err_tag = format!("__LH_ERR_{marker}__:");
        let end_tag = format!("__LH_END_{marker}__");
        let deadline = std::time::Instant::now() + timeout;
        let mut started = false;
        let mut err_msg: Option<String> = None;
        let mut out = String::new();
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err((true, "查询超时".to_owned()));
            }
            match self.rx.recv_timeout(deadline.duration_since(now)) {
                Ok(Ok(line_str)) => {
                    let trimmed = line_str.trim_end_matches('\r');
                    if trimmed == end_tag {
                        if let Some(err) = err_msg {
                            return Err((false, err));
                        }
                        return Ok(out);
                    }
                    if trimmed == ok_tag {
                        started = true;
                        continue;
                    }
                    if let Some(rest) = trimmed.strip_prefix(&err_tag) {
                        err_msg = Some(rest.trim().to_owned());
                        continue;
                    }
                    if started && err_msg.is_none() {
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        out.push_str(trimmed);
                        if out.len() > limit {
                            return Err((true, format!("查询输出超过 {limit} 字节上限")));
                        }
                    }
                }
                Ok(Err(e)) => return Err((true, format!("读取管道失败: {e}"))),
                Err(_) => return Err((true, "查询超时".to_owned())),
            }
        }
    }
}

impl Drop for WarmPsWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Execute a UTF-8 PowerShell script using the warm persistent worker, falling back to cold process if needed.
pub fn run_powershell_utf8(
    script: &str,
    limit: usize,
    timeout: std::time::Duration,
) -> Result<String, String> {
    {
        let mut guard = WARM_PS.lock();
        if guard.is_none() {
            *guard = WarmPsWorker::spawn().ok();
        }
        if let Some(worker) = guard.as_mut() {
            match worker.execute(script, limit, timeout) {
                Ok(output) => return Ok(output),
                Err((kill_worker, _err)) => {
                    if kill_worker {
                        *guard = None;
                    }
                }
            }
        }
    }
    let script = format!(
        "# LovelyHawk-IR-Query\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\n{script}"
    );
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let executable = system_powershell_exe()?;
    let mut command = Command::new(executable);
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        &BASE64.encode(bytes),
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = crate::agent_runtime::bounded_output(&mut command, limit, timeout)?;
    if !output.status.success() {
        return Err("Windows 查询未完成，请检查当前账户的读取权限及 PowerShell 组件".to_owned());
    }
    if output.stdout.len() > limit {
        return Err(format!("Windows 查询结果超过 {limit} 字节上限"));
    }
    String::from_utf8(output.stdout).map_err(|_| "Windows 查询结果编码无效".to_owned())
}

/// Execute an `-EncodedCommand <UTF-16LE Base64>` payload via the warm persistent worker when possible.
pub fn run_encoded_powershell(
    encoded_b64: &str,
    limit: usize,
    timeout: std::time::Duration,
) -> Result<String, String> {
    if let Ok(raw_bytes) = BASE64.decode(encoded_b64.trim())
        && raw_bytes.len().is_multiple_of(2)
    {
        let words: Vec<u16> = raw_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if let Ok(script) = String::from_utf16(&words) {
            return run_powershell_utf8(&script, limit, timeout);
        }
    }
    let executable = system_powershell_exe()?;
    let mut command = Command::new(executable);
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded_b64.trim(),
    ]);
    let output = crate::agent_runtime::bounded_output(&mut command, limit, timeout)?;
    let code = output.status.code().unwrap_or(-1);
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(stderr.trim());
    }
    if code != 0 && combined.trim().is_empty() {
        return Err(format!("PowerShell 退出码 {code}"));
    }
    Ok(combined)
}

fn query_powershell_json(script: &str) -> Result<Value, String> {
    let stdout = run_powershell_utf8(script, 2 * 1024 * 1024, std::time::Duration::from_secs(35))?;
    let trimmed = stdout.trim();
    let slice = if let Some(idx) = trimmed.find(['{', '[']) {
        &trimmed[idx..]
    } else {
        trimmed
    };
    serde_json::from_str(slice).map_err(|_| "Windows 查询结果不是有效 JSON".to_owned())
}

fn collect_files(dir_path: &str) -> Result<Value, String> {
    let target = if dir_path.trim().is_empty() {
        "C:\\Users\\Public".to_owned()
    } else {
        expand_env_vars(dir_path.trim())
    };
    let rd = std::fs::read_dir(&target).map_err(|e| format!("无法读取目录 '{target}': {e}"))?;
    // Folders first, then by name, so a capped listing keeps the folders.
    let mut items = rd
        .take(10_001)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "目录枚举未完成，请检查权限后重试".to_owned())?;
    let total_entries = items.len();
    items.sort_by_cached_key(|item| {
        let is_dir = item.file_type().map(|t| t.is_dir()).unwrap_or(false);
        (!is_dir, item.file_name().to_string_lossy().to_lowercase())
    });
    let mut pending = Vec::with_capacity(items.len().min(MAX_LISTED_FILES));
    let mut hash_jobs: Vec<(usize, PathBuf, u64)> = Vec::new();
    for item in items.into_iter().take(MAX_LISTED_FILES) {
        let path = item.path();
        let name = item.file_name().to_string_lossy().into_owned();
        let meta = Some(
            item.metadata()
                .map_err(|_| "读取目录项属性失败，请刷新后重试".to_owned())?,
        );
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let (hidden, system) = file_attribute_flags(meta.as_ref());
        let size_bytes = if is_dir {
            0
        } else {
            meta.as_ref().map(|m| m.len()).unwrap_or(0)
        };
        let last_write = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                let dt: DateTime<Local> = t.into();
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            })
            .unwrap_or_default();

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !is_dir
            && hash_jobs.len() < 24
            && size_bytes > 0
            && size_bytes <= 5 * 1024 * 1024
            && matches!(
                ext.as_str(),
                "exe" | "dll" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "jsp" | "aspx" | "php"
            )
        {
            hash_jobs.push((pending.len(), path.clone(), size_bytes));
        }

        pending.push((
            name,
            path,
            is_dir,
            size_bytes,
            last_write,
            hidden,
            system,
            String::new(),
        ));
    }

    if !hash_jobs.is_empty() {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get().clamp(2, 4))
            .unwrap_or(2)
            .min(hash_jobs.len());
        let chunk_size = hash_jobs.len().div_ceil(workers);
        let computed: Vec<(usize, String)> = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in hash_jobs.chunks(chunk_size) {
                handles.push(scope.spawn(move || {
                    use std::io::Read;
                    let mut out = Vec::with_capacity(chunk.len());
                    for (idx, path, expected_size) in chunk {
                        let mut bytes = Vec::new();
                        let read = std::fs::File::open(path).and_then(|file| {
                            file.take(5 * 1024 * 1024 + 1).read_to_end(&mut bytes)
                        });
                        let digest = if read.is_ok() && bytes.len() as u64 == *expected_size {
                            format!("{:x}", Sha256::digest(&bytes))
                        } else {
                            String::new()
                        };
                        out.push((*idx, digest));
                    }
                    out
                }));
            }
            let mut results = Vec::new();
            for h in handles {
                if let Ok(part) = h.join() {
                    results.extend(part);
                }
            }
            results
        });
        for (idx, digest) in computed {
            if let Some(slot) = pending.get_mut(idx) {
                slot.7 = digest;
            }
        }
    }

    let entries: Vec<Value> = pending
        .into_iter()
        .map(
            |(name, path, is_dir, size_bytes, last_write, hidden, system, sha256)| {
                json!({
                    "name": name,
                    "fullPath": path.to_string_lossy(),
                    "entryType": if is_dir { "dir" } else { "file" },
                    "sizeBytes": size_bytes,
                    "lastWriteTime": last_write,
                    "sha256": sha256,
                    "hidden": hidden,
                    "system": system,
                })
            },
        )
        .collect();

    Ok(json!({
        "currentPath": target,
        "totalEntries": total_entries,
        "truncated": total_entries > MAX_LISTED_FILES,
        "entries": entries,
    }))
}

const MAX_LISTED_FILES: usize = 1000;
const PREVIEW_BYTES: u64 = 16 * 1024;

#[cfg(windows)]
fn file_attribute_flags(meta: Option<&std::fs::Metadata>) -> (bool, bool) {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    meta.map(|m| {
        let attributes = m.file_attributes();
        (
            attributes & FILE_ATTRIBUTE_HIDDEN != 0,
            attributes & FILE_ATTRIBUTE_SYSTEM != 0,
        )
    })
    .unwrap_or((false, false))
}

#[cfg(not(windows))]
fn file_attribute_flags(_meta: Option<&std::fs::Metadata>) -> (bool, bool) {
    (false, false)
}

/// The first bytes of a file for the text / hex preview; never the whole file.
fn preview_file_json(file_path: &str) -> Result<Value, String> {
    use std::io::Read;
    let expanded = expand_env_vars(file_path.trim());
    let path = Path::new(&expanded);
    let meta = std::fs::metadata(path).map_err(|e| format!("无法访问文件 '{expanded}': {e}"))?;
    if !meta.is_file() {
        return Err(format!("路径不是普通文件: {expanded}"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(PREVIEW_BYTES).read_to_end(&mut bytes))
        .map_err(|e| format!("读取文件失败: {e}"))?;
    let last_write = meta
        .modified()
        .ok()
        .map(|t| {
            let dt: DateTime<Local> = t.into();
            dt.format("%Y-%m-%d %H:%M:%S").to_string()
        })
        .unwrap_or_default();
    Ok(json!({
        "fullPath": path.to_string_lossy(),
        "sizeBytes": meta.len(),
        "lastWriteTime": last_write,
        "b64": BASE64.encode(&bytes),
        "truncated": meta.len() > bytes.len() as u64,
    }))
}

fn pull_file_json(file_path: &str) -> Result<Value, String> {
    let expanded = expand_env_vars(file_path.trim());
    let path = Path::new(&expanded);
    let meta = std::fs::metadata(path).map_err(|e| format!("无法访问文件 '{expanded}': {e}"))?;
    if !meta.is_file() {
        return Err(format!("路径不是普通文件: {expanded}"));
    }
    if meta.len() > 8 * 1024 * 1024 {
        return Err(format!("单次取证文件超过 8MB 上限 ({} 字节)", meta.len()));
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("读取文件失败: {e}"))?;
    if bytes.len() > 8 * 1024 * 1024 || bytes.len() as u64 != meta.len() {
        return Err("读取期间文件大小变化，请重新采集。".to_owned());
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha = format!("{:x}", hasher.finalize());
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.bin".to_owned());
    Ok(json!({
        "name": name,
        "b64": BASE64.encode(&bytes),
        "sha256": sha,
    }))
}

fn collect_registry(key_path: &str) -> Result<Value, String> {
    let script = crate::windows_read_queries::registry(key_path).ok_or_else(|| {
        "注册表路径无效，请使用 HKLM:\\、HKCU:\\、HKU:\\、HKCR:\\ 或 HKCC:\\".to_owned()
    })?;
    query_powershell_json(&script)
}

const WEBSHELL_EXTENSIONS: &[&str] = &[
    "php", "phtml", "inc", "php3", "php4", "php5", "php7", "phar", "asp", "asa", "cer", "cdx",
    "aspx", "ashx", "asmx", "ascx", "cshtml", "config", "jsp", "jspx", "jspf", "py", "ps1", "vbs",
    "hta", "cgi", "bat", "cmd", "js",
];

fn discover_webroots(target: &str) -> Result<Vec<PathBuf>, String> {
    let trimmed = target.trim();
    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("auto") {
        let expanded = expand_env_vars(trimmed);
        let p = PathBuf::from(&expanded);
        let meta =
            std::fs::metadata(&p).map_err(|e| format!("无法访问扫描目录 '{expanded}': {e}"))?;
        if !meta.is_dir() {
            return Err(format!("扫描路径不是文件夹: {expanded}"));
        }
        return Ok(vec![p]);
    }
    let mut roots = Vec::new();
    for candidate in [
        "C:\\inetpub\\wwwroot",
        "C:\\wwwroot",
        "D:\\wwwroot",
        "E:\\wwwroot",
        "C:\\phpstudy_pro\\WWW",
        "D:\\phpstudy_pro\\WWW",
        "C:\\phpStudy\\WWW",
        "C:\\xampp\\htdocs",
        "D:\\xampp\\htdocs",
        "C:\\wamp64\\www",
        "C:\\bt_panel\\wwwroot",
        "D:\\bt_panel\\wwwroot",
        "C:\\Users\\Public",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_dir() && !roots.contains(&path) {
            roots.push(path);
        }
    }
    if roots.is_empty() {
        roots.push(PathBuf::from("C:\\Users\\Public"));
    }
    Ok(roots)
}

/// Multi-threaded D-Shield style Webshell & script backdoor scanner.
pub fn scan_webshells(target_path: &str) -> Result<Value, String> {
    use std::collections::VecDeque;
    use std::io::Read;
    let started = std::time::Instant::now();
    let roots = discover_webroots(target_path)?;
    let scanned_paths: Vec<String> = roots
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut queue: VecDeque<(PathBuf, usize)> = roots.into_iter().map(|r| (r, 0)).collect();
    let mut candidates: Vec<(PathBuf, String, String, u64, String)> = Vec::new();
    let mut scanned_dirs = 0u32;
    let mut truncated = false;
    let warnings: Vec<String> = Vec::new();

    while let Some((dir, depth)) = queue.pop_front() {
        if scanned_dirs >= 2000 || candidates.len() >= 10_000 {
            truncated = true;
            break;
        }
        scanned_dirs += 1;
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if ft.is_dir() {
                if depth < 12
                    && !matches!(
                        name.to_ascii_lowercase().as_str(),
                        "node_modules" | ".git" | "winsxs" | "installer" | "$recycle.bin"
                    )
                {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !WEBSHELL_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let len = meta.len();
            if len == 0 || len > 2 * 1024 * 1024 {
                continue;
            }
            let mtime = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: DateTime<Local> = t.into();
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_default();
            candidates.push((path, name, format!(".{ext}"), len, mtime));
            if candidates.len() >= 10_000 {
                truncated = true;
                break;
            }
        }
    }

    let scanned_files = candidates.len() as u32;
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4);

    let hits: Vec<(u32, Value)> = if candidates.is_empty() {
        Vec::new()
    } else {
        let chunk_size = candidates.len().div_ceil(worker_threads);
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in candidates.chunks(chunk_size) {
                handles.push(scope.spawn(move || {
                    let mut local_hits = Vec::new();
                    for (path, name, ext, size_bytes, last_write) in chunk {
                        let mut bytes = Vec::new();
                        if std::fs::File::open(path)
                            .and_then(|f| f.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes))
                            .is_err()
                        {
                            continue;
                        }
                        if let Some((confidence, risk, threat_type, rules, snippet)) =
                            inspect_webshell_bytes(&bytes, ext)
                        {
                            let sha256 = format!("{:x}", Sha256::digest(&bytes));
                            local_hits.push((
                                confidence,
                                json!({
                                    "fullPath": path.to_string_lossy(),
                                    "name": name,
                                    "extension": ext,
                                    "sizeBytes": *size_bytes,
                                    "lastWriteTime": last_write,
                                    "sha256": sha256,
                                    "riskLevel": risk,
                                    "confidenceLevel": confidence,
                                    "threatType": threat_type,
                                    "matchedRules": rules,
                                    "lineSnippet": snippet,
                                }),
                            ));
                        }
                    }
                    local_hits
                }));
            }
            let mut merged = Vec::new();
            for h in handles {
                if let Ok(part) = h.join() {
                    merged.extend(part);
                }
            }
            merged
        })
    };

    let mut sorted = hits;
    sorted.sort_by_key(|a| std::cmp::Reverse(a.0));
    if sorted.len() > 500 {
        sorted.truncate(500);
        truncated = true;
    }
    let entries: Vec<Value> = sorted.into_iter().map(|(_, v)| v).collect();

    Ok(json!({
        "scannedPaths": scanned_paths,
        "observedAt": chrono::Utc::now().to_rfc3339(),
        "scannedFiles": scanned_files,
        "scannedDirs": scanned_dirs,
        "elapsedMs": started.elapsed().as_millis() as u64,
        "workerThreads": worker_threads as u32,
        "truncated": truncated,
        "warnings": warnings,
        "entries": entries,
    }))
}

pub fn inspect_webshell_bytes(
    bytes: &[u8],
    ext: &str,
) -> Option<(u32, &'static str, String, Vec<String>, String)> {
    let sample = &bytes[..bytes.len().min(512 * 1024)];
    let text = String::from_utf8_lossy(sample);
    let lower = text.to_ascii_lowercase();
    let mut rules = Vec::new();
    let mut confidence = 0u32;
    let mut threat_type = String::new();

    let has_input = [
        "$_post",
        "$_get",
        "$_request",
        "$_cookie",
        "php://input",
        "$_server",
        "request[",
        "request.form",
        "request.querystring",
        "request.getparameter",
        "request.binaryread",
        "page_load",
    ]
    .iter()
    .any(|k| lower.contains(k));

    // 1. Behinder / Godzilla / AntSword encrypted / memory shells
    if (lower.contains("openssl_decrypt") || lower.contains("mcrypt_decrypt"))
        && (lower.contains("session_start")
            || lower.contains("php://input")
            || lower.contains("base64_decode"))
    {
        rules.push("冰蝎 (Behinder) / 哥斯拉 PHP 加密通道后门特征".to_owned());
        confidence = confidence.max(5);
        threat_type = "冰蝎/哥斯拉加密 Webshell".to_owned();
    }
    if (lower.contains("rijndaelmanaged")
        || lower.contains("aesmanaged")
        || lower.contains("descryptoserviceprovider"))
        && (lower.contains("createdecryptor") || lower.contains("frombase64string"))
        && (lower.contains("assembly.load") || lower.contains("createinstance"))
    {
        rules.push("冰蝎/哥斯拉 ASP.NET 反射字节码内存加载后门特征".to_owned());
        confidence = confidence.max(5);
        threat_type = "ASP.NET 加密反射 Webshell".to_owned();
    }
    if lower.contains("defineclass")
        && (lower.contains("cipher")
            || lower.contains("classloader")
            || lower.contains("getdeclaredmethod"))
    {
        rules.push("JSP 自定义 ClassLoader 字节码加载特征 (冰蝎/哥斯拉/内存马)".to_owned());
        confidence = confidence.max(5);
        threat_type = "JSP 字节码加载 Webshell".to_owned();
    }
    if lower.contains("@ini_set(\"display_errors\"")
        && (lower.contains("@set_time_limit") || has_input)
    {
        rules.push("蚁剑 (AntSword) / 菜刀典型错误抑制与连接头特征".to_owned());
        confidence = confidence.max(5);
        if threat_type.is_empty() {
            threat_type = "蚁剑/菜刀特征 Webshell".to_owned();
        }
    }

    // 2. Classic PHP one-liner & dynamic code evaluation
    if (lower.contains("eval(")
        || lower.contains("eval (")
        || lower.contains("assert(")
        || lower.contains("assert (")
        || lower.contains("create_function("))
        && (has_input
            || lower.contains("base64_decode")
            || lower.contains("gzinflate")
            || lower.contains("gzuncompress")
            || lower.contains("str_rot13"))
    {
        rules.push("PHP 动态代码执行一句话后门 (eval/assert + 外部输入或编码解码)".to_owned());
        confidence = confidence.max(5);
        if threat_type.is_empty() {
            threat_type = "PHP 一句话执行后门".to_owned();
        }
    }

    // 3. PHP callback / variable function obfuscated backdoors
    if has_input
        && [
            "call_user_func",
            "call_user_func_array",
            "array_map",
            "array_filter",
            "usort",
            "uksort",
            "register_shutdown_function",
            "preg_replace",
        ]
        .iter()
        .any(|f| lower.contains(f))
    {
        rules.push("PHP 回调函数构造的免杀动态执行后门 (Callback Webshell)".to_owned());
        confidence = confidence.max(4);
        if threat_type.is_empty() {
            threat_type = "PHP 回调免杀后门".to_owned();
        }
    }
    if lower.contains("${$_")
        || lower.contains("$$_")
        || (lower.contains("$_get[") && lower.contains("]($_post["))
    {
        rules.push("PHP 可变变量/动态函数直接调用特征 (${$_} / $$)".to_owned());
        confidence = confidence.max(4);
        if threat_type.is_empty() {
            threat_type = "PHP 可变变量混淆后门".to_owned();
        }
    }

    // 4. ASP / ASP.NET script & command execution
    if matches!(
        ext,
        ".asp" | ".asa" | ".cer" | ".cdx" | ".aspx" | ".ashx" | ".asmx" | ".cshtml"
    ) && (lower.contains("execute(request")
        || lower.contains("executeglobal(request")
        || lower.contains("eval(request")
        || lower.contains("wscript.shell")
        || lower.contains("shell.application")
        || lower.contains("compileassemblyfromsource")
        || (lower.contains("processstartinfo")
            && (lower.contains("cmd.exe") || lower.contains("powershell"))))
    {
        rules.push("ASP/ASP.NET 命令执行组件或动态编译后门特征".to_owned());
        confidence = confidence.max(5);
        if threat_type.is_empty() {
            threat_type = "ASP/ASP.NET 脚本木马".to_owned();
        }
    }

    // 5. JSP / Java command execution & memory shells
    if matches!(ext, ".jsp" | ".jspx" | ".jspf")
        && (lower.contains("runtime.getruntime().exec")
            || lower.contains("processbuilder")
            || lower.contains("$$bcel$$")
            || lower.contains("scriptenginemanager")
            || (lower.contains("applicationfilterconfig") && lower.contains("addfilter")))
    {
        rules.push("JSP 系统命令执行、BCEL 或 Filter/Servlet 内存马注入特征".to_owned());
        confidence = confidence.max(5);
        if threat_type.is_empty() {
            threat_type = "JSP 命令执行/内存马后门".to_owned();
        }
    }

    // 6. Direct OS command execution in web scripts
    if has_input
        && [
            "shell_exec(",
            "passthru(",
            "proc_open(",
            "popen(",
            "pcntl_exec(",
            "system(",
        ]
        .iter()
        .any(|f| lower.contains(f))
    {
        rules.push("Web 脚本直接将外部请求参数传入系统命令执行函数".to_owned());
        confidence = confidence.max(5);
        if threat_type.is_empty() {
            threat_type = "Web 命令执行后门".to_owned();
        }
    }

    // 7. PowerShell / VBS / HTA dropper scripts in web or public dirs
    if matches!(ext, ".ps1" | ".vbs" | ".hta" | ".bat" | ".cmd")
        && !text.contains("LovelyHawkDvcNative")
        && !text.contains("# LovelyHawk")
        && (lower.contains("downloadstring")
            || lower.contains("invoke-expression")
            || lower.contains("frombase64string")
            || lower.contains("-enc ")
            || lower.contains("-encodedcommand")
            || lower.contains("net.webclient"))
    {
        rules.push("脚本包含远程下载执行、Base64 解码或无文件载荷特征".to_owned());
        confidence = confidence.max(4);
        if threat_type.is_empty() {
            threat_type = "可疑下载器/执行脚本".to_owned();
        }
    }

    // 8. Obfuscation / chr() chain heuristic in web scripts
    if matches!(ext, ".php" | ".phtml" | ".asp" | ".aspx" | ".jsp") {
        let chr_count = lower.matches("chr(").count();
        if chr_count >= 12
            && (has_input
                || lower.contains("eval")
                || lower.contains("assert")
                || lower.contains("execute"))
        {
            rules.push(format!(
                "检测到密集的字符拼接混淆 (chr 调用 {chr_count} 次)"
            ));
            confidence = confidence.max(3);
            if threat_type.is_empty() {
                threat_type = "疑似字符拼接混淆 Webshell".to_owned();
            }
        }
    }

    if rules.is_empty() {
        return None;
    }

    let risk = if confidence >= 5 {
        "high"
    } else if confidence >= 3 {
        "medium"
    } else {
        "low"
    };

    let mut snippet = String::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let l = trimmed.to_ascii_lowercase();
        if [
            "eval",
            "assert",
            "openssl_decrypt",
            "base64_decode",
            "rijndael",
            "defineclass",
            "getruntime",
            "processbuilder",
            "wscript.shell",
            "shell_exec",
            "system(",
            "passthru",
            "call_user_func",
            "downloadstring",
            "invoke-expression",
            "$_post",
            "$_get",
            "$_request",
        ]
        .iter()
        .any(|k| l.contains(k))
        {
            let clipped: String = trimmed.chars().take(200).collect();
            snippet = format!("L{}: {}", idx + 1, clipped);
            break;
        }
    }
    if snippet.is_empty()
        && let Some(first) = text.lines().map(str::trim).find(|l| !l.is_empty())
    {
        let clipped: String = first.chars().take(200).collect();
        snippet = format!("L1: {clipped}");
    }

    Some((confidence, risk, threat_type, rules, snippet))
}

#[derive(Clone, Copy)]
enum RegRoot {
    Hklm,
    Hkcu,
}

#[cfg(windows)]
mod win_native {
    use super::RegRoot;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ,
        REG_MULTI_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegEnumValueW, RegOpenKeyExW,
        RegQueryValueExW,
    };

    use windows_core::{PCWSTR, PWSTR};

    fn to_hkey(root: RegRoot) -> HKEY {
        match root {
            RegRoot::Hklm => HKEY_LOCAL_MACHINE,
            RegRoot::Hkcu => HKEY_CURRENT_USER,
        }
    }

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn reg_get_string(root: RegRoot, subkey: &str, value_name: &str) -> Option<String> {
        let sub_w = wide_null(subkey);
        let name_w = wide_null(value_name);
        let mut h = HKEY::default();
        // SAFETY: standard Win32 registry query.
        unsafe {
            if RegOpenKeyExW(
                to_hkey(root),
                PCWSTR(sub_w.as_ptr()),
                Some(0),
                KEY_READ,
                &mut h,
            )
            .is_err()
            {
                return None;
            }
            let mut size: u32 = 0;
            if RegQueryValueExW(
                h,
                PCWSTR(name_w.as_ptr()),
                None,
                None,
                None,
                Some(&mut size),
            )
            .is_err()
                || size < 2
            {
                let _ = RegCloseKey(h);
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            let ok = RegQueryValueExW(
                h,
                PCWSTR(name_w.as_ptr()),
                None,
                None,
                Some(buf.as_mut_ptr()),
                Some(&mut size),
            )
            .is_ok();
            let _ = RegCloseKey(h);
            if !ok {
                return None;
            }
            let words: Vec<u16> = (0..(size as usize / 2))
                .map(|i| u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&words))
        }
    }

    pub fn reg_enum_values(root: RegRoot, subkey: &str) -> Vec<(String, String, String)> {
        let sub_w = wide_null(subkey);
        let mut h = HKEY::default();
        let mut out = Vec::new();
        // SAFETY: enumerating values with bounded buffers.
        unsafe {
            if RegOpenKeyExW(
                to_hkey(root),
                PCWSTR(sub_w.as_ptr()),
                Some(0),
                KEY_READ,
                &mut h,
            )
            .is_err()
            {
                return out;
            }
            for idx in 0..100u32 {
                let mut name_buf = vec![0u16; 512];
                let mut name_len = name_buf.len() as u32;
                let mut val_type = REG_VALUE_TYPE::default();
                let mut data_buf = vec![0u8; 2048];
                let mut data_len = data_buf.len() as u32;
                if RegEnumValueW(
                    h,
                    idx,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut val_type.0),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
                .is_err()
                {
                    break;
                }
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let slice = &data_buf[..(data_len as usize).min(data_buf.len())];
                let (kind_str, val_str) = match val_type {
                    REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
                        let words: Vec<u16> = (0..(slice.len() / 2))
                            .map(|i| u16::from_le_bytes([slice[i * 2], slice[i * 2 + 1]]))
                            .take_while(|&c| c != 0)
                            .collect();
                        let k = if val_type == REG_EXPAND_SZ {
                            "ExpandString"
                        } else {
                            "String"
                        };
                        (k.to_owned(), String::from_utf16_lossy(&words))
                    }
                    REG_DWORD if slice.len() >= 4 => (
                        "DWord".to_owned(),
                        u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]).to_string(),
                    ),
                    REG_QWORD if slice.len() >= 8 => (
                        "QWord".to_owned(),
                        u64::from_le_bytes([
                            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                            slice[7],
                        ])
                        .to_string(),
                    ),
                    _ => (
                        format!("Type({})", val_type.0),
                        slice
                            .iter()
                            .take(32)
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" "),
                    ),
                };
                out.push((name, kind_str, val_str));
            }
            let _ = RegCloseKey(h);
        }
        out
    }
}

#[cfg(not(windows))]
mod win_native {
    use super::RegRoot;

    pub fn reg_get_string(_root: RegRoot, _subkey: &str, _value_name: &str) -> Option<String> {
        None
    }

    pub fn reg_enum_values(_root: RegRoot, _subkey: &str) -> Vec<(String, String, String)> {
        Vec::new()
    }
}

use win_native::{reg_enum_values, reg_get_string};
