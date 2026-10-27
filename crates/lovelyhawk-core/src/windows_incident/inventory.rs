//! Read-only service, driver and scheduled-task inventories with visible gaps.
use super::{WindowsIncidentService, WindowsRiskLevel};
use crate::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsInventoryKind {
    Services,
    Drivers,
    Tasks,
}
impl WindowsInventoryKind {
    fn key(self) -> &'static str {
        match self {
            Self::Services => "services",
            Self::Drivers => "drivers",
            Self::Tasks => "tasks",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsInventoryEntry {
    pub name: String,
    pub display_name: String,
    pub location: String,
    pub command: String,
    pub account: String,
    pub state: String,
    pub start_mode: String,
    pub pid: u32,
    pub details: Vec<String>,
    pub risk_level: WindowsRiskLevel,
    pub risk_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsInventorySnapshot {
    pub kind: WindowsInventoryKind,
    pub observed_at: String,
    pub total_count: u32,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub entries: Vec<WindowsInventoryEntry>,
}
pub fn parse_inventory_json(
    raw: &str,
    kind: WindowsInventoryKind,
) -> CoreResult<WindowsInventorySnapshot> {
    let invalid = || {
        CoreError::validation(
            "windows inventory",
            "清单响应不完整或超过上限，请核对采集权限后重试。",
        )
    };
    if raw.len() > 2 * 1024 * 1024 {
        return Err(invalid());
    }
    let mut result: WindowsInventorySnapshot = serde_json::from_str(raw).map_err(|_| invalid())?;
    if result.kind != kind
        || result.entries.len() > 2000
        || result.total_count < result.entries.len() as u32
        || result.observed_at.len() > 64
        || chrono::DateTime::parse_from_rfc3339(&result.observed_at).is_err()
        || (result.total_count as usize != result.entries.len()
            && !result.truncated
            && result.warnings.is_empty())
        || result.warnings.len() > 32
        || result.warnings.iter().any(|v| v.len() > 1024)
        || result.entries.iter().any(|v| {
            v.name.is_empty()
                || v.name.len() > 1024
                || v.display_name.len() > 1024
                || v.location.len() > 2048
                || v.command.len() > 8192
                || v.account.len() > 1024
                || v.state.len() > 256
                || v.start_mode.len() > 256
                || v.details.len() > 32
                || v.details.iter().any(|d| d.len() > 4096)
        })
    {
        return Err(invalid());
    }
    for entry in &mut result.entries {
        // Indicators are leads, not a verdict on an installed product or driver.
        let command = entry.command.to_ascii_lowercase();
        if [
            "\\temp\\",
            "\\users\\public\\",
            " -encodedcommand",
            " -enc ",
        ]
        .iter()
        .any(|p| command.contains(p))
        {
            entry.risk_level = WindowsRiskLevel::Medium;
            entry.risk_reason = "执行位置或参数需关注，请结合签名、来源、账户和行为核实。".into();
        } else {
            entry.risk_level = WindowsRiskLevel::Normal;
            entry.risk_reason = String::new();
        }
    }
    Ok(result)
}
impl WindowsIncidentService {
    pub fn collect_inventory(
        &self,
        kind: WindowsInventoryKind,
        session: &str,
    ) -> CoreResult<WindowsInventorySnapshot> {
        let script = include_str!("inventory.ps1").replace("__KIND__", kind.key());
        let raw =
            self.run_native_or_ps(&format!("inventory-v1:{}", kind.key()), &script, session)?;
        parse_inventory_json(&raw, kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_preserves_gaps_and_rejects_mismatched_or_incomplete_shapes() {
        let raw = r#"{"kind":"drivers","observedAt":"2026-10-27T00:00:00Z","totalCount":0,"truncated":false,"warnings":["权限不足"],"entries":[]}"#;
        assert_eq!(
            parse_inventory_json(raw, WindowsInventoryKind::Drivers)
                .unwrap()
                .warnings
                .len(),
            1
        );
        assert!(parse_inventory_json(raw, WindowsInventoryKind::Services).is_err());
        assert!(parse_inventory_json("[]", WindowsInventoryKind::Tasks).is_err());
    }
}
