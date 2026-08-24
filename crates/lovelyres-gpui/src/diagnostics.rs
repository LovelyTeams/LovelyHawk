use std::{
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, bail};
use gpui::AssetSource as _;
use lovelyres_terminal::{TerminalConfig, TerminalModel};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    assets::{Assets, embedded_fonts},
    pages::{PAGE_DESCRIPTORS, PageId},
    theme::ThemeId,
};

pub const FEASIBILITY_SCHEMA: &str = "lovelyres-gpui-feasibility/v1";
const DEFAULT_STRESS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STRESS_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct FeasibilityRequest {
    pub result_file: PathBuf,
    pub terminal_stress_bytes: u64,
}

impl FeasibilityRequest {
    pub fn from_environment() -> Result<Option<Self>> {
        let Some(mode) = env::var_os("LOVELYRES_FEASIBILITY_MODE") else {
            return Ok(None);
        };
        if mode != "windows-v1" {
            bail!(
                "unsupported LOVELYRES_FEASIBILITY_MODE: {}",
                mode.to_string_lossy()
            );
        }
        let result_file = env::var_os("LOVELYRES_FEASIBILITY_RESULT_FILE")
            .ok_or_else(|| anyhow!("LOVELYRES_FEASIBILITY_RESULT_FILE is required"))?;
        if result_file.is_empty() {
            bail!("LOVELYRES_FEASIBILITY_RESULT_FILE is empty");
        }
        let result_file = PathBuf::from(result_file);
        if !result_file.is_absolute() {
            bail!("LOVELYRES_FEASIBILITY_RESULT_FILE must be absolute");
        }

        let terminal_stress_bytes = env::var("LOVELYRES_TERMINAL_STRESS_BYTES")
            .ok()
            .map(|value| {
                value
                    .parse::<u64>()
                    .context("LOVELYRES_TERMINAL_STRESS_BYTES must be an integer")
            })
            .transpose()?
            .unwrap_or(DEFAULT_STRESS_BYTES);
        if terminal_stress_bytes == 0 || terminal_stress_bytes > MAX_STRESS_BYTES {
            bail!("LOVELYRES_TERMINAL_STRESS_BYTES must be between 1 and {MAX_STRESS_BYTES}");
        }

        Ok(Some(Self {
            result_file,
            terminal_stress_bytes,
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CheckStatus {
    Pass,
    Fail,
    NotRun,
}

#[derive(Debug, Serialize)]
struct CheckResult {
    id: &'static str,
    status: CheckStatus,
    evidence: String,
}

#[derive(Debug, Serialize)]
struct TerminalStressResult {
    requested_bytes: u64,
    processed_bytes: u64,
    elapsed_ms: u128,
    throughput_mib_per_second: f64,
    no_loss: bool,
}

#[derive(Debug, Serialize)]
struct FeasibilityResult {
    schema: &'static str,
    status: &'static str,
    generated_unix_ms: u128,
    app_version: &'static str,
    gpui_version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    portable_data_root: String,
    automatic_checks: Vec<CheckResult>,
    terminal_stress: TerminalStressResult,
    manual_checks: Vec<CheckResult>,
}

pub fn execute(request: FeasibilityRequest, portable_data_root: &Path) -> Result<()> {
    let stress = terminal_stress(request.terminal_stress_bytes)?;
    let terminal_status = if stress.no_loss {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    };
    let automatic_checks = vec![
        check(
            "root_window",
            CheckStatus::Pass,
            "first GPUI frame callback invoked diagnostics",
        ),
        evaluated_check("portable_store", verify_portable_store(portable_data_root)),
        evaluated_check("page_registry", verify_page_registry()),
        evaluated_check("theme_registry", verify_theme_registry()),
        evaluated_check("embedded_assets", verify_embedded_assets()),
        evaluated_check("font_assets", verify_font_assets()),
        check(
            "terminal_no_loss",
            terminal_status,
            format!(
                "TerminalModel processed {} of {} parser bytes in {} ms",
                stress.processed_bytes, stress.requested_bytes, stress.elapsed_ms
            ),
        ),
    ];
    let automatic_passed = automatic_checks
        .iter()
        .all(|check| check.status == CheckStatus::Pass);
    let result = FeasibilityResult {
        schema: FEASIBILITY_SCHEMA,
        status: if automatic_passed { "READY" } else { "FAILED" },
        generated_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates UNIX epoch")?
            .as_millis(),
        app_version: env!("CARGO_PKG_VERSION"),
        gpui_version: "0.2.2",
        operating_system: env::consts::OS,
        architecture: env::consts::ARCH,
        portable_data_root: portable_data_root.display().to_string(),
        automatic_checks,
        manual_checks: [
            "d3d11_gpu_driver",
            "custom_titlebar",
            "native_multi_window",
            "chinese_ime",
            "clipboard",
            "file_dialog",
            "folder_dialog",
            "theme_switch",
            "virtual_large_table",
            "mixed_dpi",
            "rdp",
            "virtual_machine",
            "integrated_gpu",
            "offline_startup",
        ]
        .into_iter()
        .map(|id| {
            check(
                id,
                CheckStatus::NotRun,
                "requires harness/operator evidence",
            )
        })
        .collect(),
        terminal_stress: stress,
    };
    write_atomic_json(&request.result_file, &result)
}

fn evaluated_check(id: &'static str, result: Result<String>) -> CheckResult {
    match result {
        Ok(evidence) => check(id, CheckStatus::Pass, evidence),
        Err(error) => check(id, CheckStatus::Fail, format!("{error:#}")),
    }
}

fn verify_portable_store(portable_data_root: &Path) -> Result<String> {
    let metadata = fs::metadata(portable_data_root).with_context(|| {
        format!(
            "portable data root is unavailable at {}",
            portable_data_root.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!(
            "portable data root is not a directory: {}",
            portable_data_root.display()
        );
    }
    Ok(format!(
        "portable data directory initialized at {}",
        portable_data_root.display()
    ))
}

fn verify_page_registry() -> Result<String> {
    let mut ids = std::collections::HashSet::new();
    for (expected, descriptor) in PageId::ALL.into_iter().zip(PAGE_DESCRIPTORS.iter()) {
        if descriptor.id != expected || !ids.insert(descriptor.id) {
            bail!("page descriptor order or uniqueness is invalid")
        }
        if descriptor.title.is_empty() || descriptor.icon.is_empty() {
            bail!(
                "page descriptor {:?} has an empty title or icon",
                descriptor.id
            )
        }
    }
    if ids.len() != 20 || PAGE_DESCRIPTORS.len() != 20 {
        bail!("expected exactly 20 page descriptors, found {}", ids.len())
    }
    Ok("validated 20 ordered, unique native page descriptors".to_owned())
}

fn verify_theme_registry() -> Result<String> {
    let labels: std::collections::HashSet<_> =
        ThemeId::ALL.into_iter().map(ThemeId::label).collect();
    if ThemeId::ALL.len() != 4 || labels.len() != 4 {
        bail!("expected four uniquely labelled native themes")
    }
    Ok("validated light/dark/sakura/incident-canvas registry".to_owned())
}

fn verify_embedded_assets() -> Result<String> {
    let logo = Assets
        .load("logo.png")?
        .ok_or_else(|| anyhow!("embedded logo.png is missing"))?;
    if logo.is_empty() {
        bail!("embedded logo.png is empty")
    }
    Ok(format!("resolved embedded logo.png ({} bytes)", logo.len()))
}

fn verify_font_assets() -> Result<String> {
    let fonts = embedded_fonts();
    if fonts.len() != 3 || fonts.iter().any(|font| font.is_empty()) {
        bail!("expected three non-empty embedded font assets")
    }
    Ok("validated embedded Inter Regular/SemiBold and Cascadia Mono bytes".to_owned())
}

fn check(id: &'static str, status: CheckStatus, evidence: impl Into<String>) -> CheckResult {
    CheckResult {
        id,
        status,
        evidence: evidence.into(),
    }
}

fn terminal_stress(requested_bytes: u64) -> Result<TerminalStressResult> {
    let config = TerminalConfig {
        scrollback_limit: 2_000,
        ..TerminalConfig::default()
    };
    let mut terminal = TerminalModel::new(config)?;
    let payload =
        b"\x1b[38;2;91;140;255mLovelyRes\x1b[0m CJK:\xe4\xb8\xad\xe6\x96\x87 comb:e\xcc\x81\r\n";
    let started = Instant::now();
    let mut processed = 0_u64;
    while processed < requested_bytes {
        let remaining = (requested_bytes - processed) as usize;
        let chunk = &payload[..remaining.min(payload.len())];
        let report = terminal.feed_output(chunk);
        processed = processed.saturating_add(report.bytes_processed as u64);
    }
    let elapsed = started.elapsed();
    let elapsed_seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    Ok(TerminalStressResult {
        requested_bytes,
        processed_bytes: processed,
        elapsed_ms: elapsed.as_millis().max(1),
        throughput_mib_per_second: (processed as f64 / 1_048_576.0) / elapsed_seconds,
        no_loss: processed == requested_bytes && terminal.total_bytes() == requested_bytes,
    })
}

fn write_atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("feasibility result path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "cannot create feasibility result directory {}",
            parent.display()
        )
    })?;
    let temp = parent.join(format!(".lovelyres-feasibility-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temp, path)
        .with_context(|| format!("cannot publish feasibility result {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_stress_accounts_for_every_byte() {
        let result = terminal_stress(64 * 1024).unwrap();
        assert!(result.no_loss);
        assert_eq!(result.processed_bytes, result.requested_bytes);
    }

    #[test]
    fn automatic_registry_and_asset_checks_are_real() {
        verify_page_registry().unwrap();
        verify_theme_registry().unwrap();
        verify_embedded_assets().unwrap();
        verify_font_assets().unwrap();
    }
}
