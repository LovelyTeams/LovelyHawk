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
    } else if spec == "baseline" || spec == "baseline-v2" {
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

fn query_powershell_json(script: &str) -> Result<Value, String> {
    let script =
        format!("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\n{script}");
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let executable = std::env::var_os("SystemRoot")
        .map(|root| Path::new(&root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| "系统 PowerShell 不可用，无法完成只读查询".to_owned())?;
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
    let output = crate::agent_runtime::bounded_output(
        &mut command,
        2 * 1024 * 1024,
        std::time::Duration::from_secs(35),
    )?;
    if !output.status.success() {
        return Err("Windows 查询未完成，请检查当前账户的读取权限及 PowerShell 组件".to_owned());
    }
    if output.stdout.len() > 2 * 1024 * 1024 {
        return Err("Windows 查询结果超过 2 MB 上限".to_owned());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "Windows 查询结果不是有效 JSON".to_owned())
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
    let mut entries = Vec::new();
    let mut hashes_remaining = 24usize;
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
        let sha256 = if !is_dir
            && hashes_remaining > 0
            && size_bytes > 0
            && size_bytes <= 5 * 1024 * 1024
            && matches!(
                ext.as_str(),
                "exe" | "dll" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "jsp" | "aspx" | "php"
            ) {
            use std::io::Read;
            hashes_remaining -= 1;
            let mut bytes = Vec::new();
            let read = std::fs::File::open(&path)
                .and_then(|file| file.take(5 * 1024 * 1024 + 1).read_to_end(&mut bytes));
            if read.is_ok() && bytes.len() as u64 == size_bytes {
                format!("{:x}", Sha256::digest(&bytes))
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        entries.push(json!({
            "name": name,
            "fullPath": path.to_string_lossy(),
            "entryType": if is_dir { "dir" } else { "file" },
            "sizeBytes": size_bytes,
            "lastWriteTime": last_write,
            "sha256": sha256,
            "hidden": hidden,
            "system": system,
        }));
    }

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
