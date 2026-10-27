//! Fixed autorun categories. A category is an observation scope, not a malware verdict.
use super::{WindowsIncidentService, WindowsStartupSnapshot, parse_startup_json};
use crate::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupCategory {
    #[default]
    Logon,
    Explorer,
    InternetExplorer,
    Services,
    Drivers,
    Codecs,
    Winsock,
    Print,
    Lsa,
    Network,
    BootExecute,
    ImageHijacks,
    AppInit,
    KnownDlls,
    Winlogon,
    Ime,
    Tasks,
    Gadgets,
    FolderExtensions,
}
pub const STARTUP_CATEGORIES: [StartupCategory; 19] = [
    StartupCategory::Logon,
    StartupCategory::Explorer,
    StartupCategory::InternetExplorer,
    StartupCategory::Services,
    StartupCategory::Drivers,
    StartupCategory::Codecs,
    StartupCategory::Winsock,
    StartupCategory::Print,
    StartupCategory::Lsa,
    StartupCategory::Network,
    StartupCategory::BootExecute,
    StartupCategory::ImageHijacks,
    StartupCategory::AppInit,
    StartupCategory::KnownDlls,
    StartupCategory::Winlogon,
    StartupCategory::Ime,
    StartupCategory::Tasks,
    StartupCategory::Gadgets,
    StartupCategory::FolderExtensions,
];
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupCoverage {
    Complete,
    Partial,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartupCategoryResult {
    pub category: StartupCategory,
    pub count: u32,
    pub status: StartupCoverage,
    pub message: String,
}

pub fn parse_startup_catalog(raw: &str) -> CoreResult<WindowsStartupSnapshot> {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Entry {
        category: StartupCategory,
        source_type: String,
        name: String,
        location: String,
        command: String,
        run_as: String,
        state: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Raw {
        observed_at: String,
        truncated: bool,
        warnings: Vec<String>,
        categories: Vec<StartupCategoryResult>,
        entries: Vec<Entry>,
    }
    let invalid = || {
        CoreError::validation(
            "windows startup catalog",
            "启动项响应不完整或超过上限，请重新采集并核对权限。",
        )
    };
    if raw.len() > 4_500_000 {
        return Err(invalid());
    }
    let data: Raw = serde_json::from_str(raw).map_err(|_| invalid())?;
    if data.entries.len() > 20000
        || data.categories.len() != 19
        || data.warnings.len() > 32
        || data.warnings.iter().any(|s| s.len() > 2048)
        || data.observed_at.len() > 64
        || data.entries.iter().any(|e| e.source_type.len() > 128)
        || chrono::DateTime::parse_from_rfc3339(&data.observed_at).is_err()
    {
        return Err(invalid());
    }
    let mut result =
        parse_startup_json(&serde_json::to_string(&data.entries).map_err(|_| invalid())?)?;
    for category in STARTUP_CATEGORIES {
        let matches: Vec<_> = data
            .categories
            .iter()
            .filter(|r| r.category == category)
            .collect();
        if matches.len() != 1
            || matches[0].message.len() > 2048
            || matches[0].count > 5000
            || matches[0].count as usize
                != result
                    .entries
                    .iter()
                    .filter(|e| e.category == category)
                    .count()
        {
            return Err(invalid());
        }
    }
    if result.entries.iter().any(|e| {
        e.name.len() > 2048
            || e.location.len() > 8192
            || e.command.len() > 8192
            || e.run_as.len() > 1024
            || e.state.len() > 256
    }) {
        return Err(invalid());
    }
    result.categories = data.categories;
    result.warnings = data.warnings;
    result.observed_at = data.observed_at;
    result.truncated = data.truncated;
    if serde_json::to_vec(&result).map_err(|_| invalid())?.len() > 8 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(result)
}
impl WindowsIncidentService {
    pub fn collect_startup_catalog(&self, session: &str) -> CoreResult<WindowsStartupSnapshot> {
        let raw = self.run_bounded_script(include_str!("startup_catalog.ps1"), session)?;
        parse_startup_catalog(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_catalog_keeps_rows_beyond_the_old_limit_and_bounds_the_total() {
        let entries: Vec<_> = (0..1200).map(|i| serde_json::json!({
            "category":"codecs","sourceType":"registry","name":format!("codec-{i}"),
            "location":"HKLM:\\Software\\Fixture","command":"codec.dll","runAs":"","state":"String"
        })).collect();
        let categories: Vec<_> = STARTUP_CATEGORIES
            .iter()
            .map(|c| StartupCategoryResult {
                category: *c,
                count: if *c == StartupCategory::Codecs {
                    1200
                } else {
                    0
                },
                status: StartupCoverage::Complete,
                message: "固定测试位置".into(),
            })
            .collect();
        let mut raw = serde_json::json!({"observedAt":"2026-10-27T00:00:00Z","truncated":false,"warnings":[],"categories":categories,"entries":entries});
        let parsed = parse_startup_catalog(&raw.to_string()).unwrap();
        assert_eq!(parsed.entries.len(), 1200);
        assert_eq!(parsed.entries.last().unwrap().name, "codec-1199");
        assert!(!parsed.truncated);
        raw["categories"][5]["count"] = 5001.into();
        assert!(parse_startup_catalog(&raw.to_string()).is_err());
        assert!(parse_startup_catalog(&" ".repeat(4_500_001)).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn native_powershell_catalog_round_trips_all_categories() {
        use std::os::windows::process::CommandExt;
        let script = format!(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);\n{}",
            include_str!("startup_catalog.ps1")
        );
        let invocation = super::super::script_transport::compressed_command(&script).unwrap();
        let output = std::process::Command::new(
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        )
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            invocation.split_whitespace().last().unwrap(),
        ])
        .creation_flags(0x08000000)
        .output()
        .unwrap();
        assert!(output.status.success(), "read-only catalog failed");
        let parsed = parse_startup_catalog(std::str::from_utf8(&output.stdout).unwrap())
            .expect("catalog must satisfy the exact response contract");
        assert_eq!(parsed.categories.len(), 19);
        assert_eq!(parsed.total_count as usize, parsed.entries.len());
    }
    #[test]
    fn every_category_requires_explicit_coverage_and_consistent_counts() {
        let categories: Vec<_> = STARTUP_CATEGORIES
            .iter()
            .map(|category| StartupCategoryResult {
                category: *category,
                count: 0,
                status: StartupCoverage::Unavailable,
                message: "拒绝访问".into(),
            })
            .collect();
        let mut raw = serde_json::json!({"observedAt":"2026-10-27T00:00:00Z","truncated":false,"warnings":[],"categories":categories,"entries":[]});
        assert_eq!(
            parse_startup_catalog(&raw.to_string())
                .unwrap()
                .categories
                .len(),
            19
        );
        raw["categories"][0]["count"] = 1.into();
        assert!(parse_startup_catalog(&raw.to_string()).is_err());
        raw["categories"][0]["count"] = 0.into();
        raw["categories"][1] = raw["categories"][0].clone();
        assert!(parse_startup_catalog(&raw.to_string()).is_err());
    }
}
