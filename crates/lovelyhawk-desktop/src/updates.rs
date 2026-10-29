//! GitHub Release discovery and verified portable-package download.
//! URLs and asset names come from the fixed repository, never from the page.
use std::{io::Write, path::Path, time::Duration};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{Runtime, State, WebviewWindow};

use crate::{
    host::MAIN_LABEL,
    local_files::{self, DialogKind, Filter},
};

const API: &str = "https://api.github.com/repos/LovelyTeams/LovelyHawk/releases/latest";
const DOWNLOAD_ROOT: &str = "https://github.com/LovelyTeams/LovelyHawk/releases/download/";
const MAX_PACKAGE: usize = 128 * 1024 * 1024;

#[derive(Default)]
pub struct Updates {
    release: Mutex<Option<Release>>,
    operation: tokio::sync::Mutex<()>,
    progress: Mutex<Progress>,
}

#[derive(Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    handle: String,
    received: u64,
    total: u64,
    cancelled: bool,
}

#[derive(Clone)]
struct Release {
    handle: String,
    version: String,
    name: String,
    url: String,
    checksum_url: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Info {},
    Check {},
    Download { handle: String },
    Progress { handle: String },
    Cancel { handle: String },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Response {
    Info {
        version: String,
    },
    Check {
        version: String,
        available: bool,
        handle: Option<String>,
        notes: String,
    },
    Download {
        filename: Option<String>,
    },
    Progress {
        received: u64,
        total: u64,
    },
    Cancel {
        cancelled: bool,
    },
}

#[derive(Clone, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    body: Option<String>,
    assets: Vec<Asset>,
}

#[derive(Clone, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("LovelyHawk/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            // GitHub redirects release assets to this dedicated CDN.
            if attempt.previous().len() < 5
                && attempt.url().scheme() == "https"
                && matches!(
                    attempt.url().host_str(),
                    Some("github.com" | "release-assets.githubusercontent.com")
                )
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|_| "无法初始化更新连接。".to_owned())
}

async fn bounded_get(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "无法连接 GitHub，请检查网络后重试。")?
        .error_for_status()
        .map_err(|_| "GitHub 未提供可用的发布文件，可能尚未发布或请求受限。")?;
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err("发布数据超出允许大小。".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "读取发布文件失败，请重试。")?
    {
        if bytes.len() + chunk.len() > limit {
            return Err("发布数据超出允许大小。".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn select_release(
    data: GithubRelease,
    current: &str,
) -> Result<(Response, Option<Release>), String> {
    let version = data.tag_name.strip_prefix('v').unwrap_or(&data.tag_name);
    let parsed = semver::Version::parse(version).map_err(|_| "发布版本号无效。")?;
    if version.len() > 64 || data.draft || data.prerelease || !parsed.pre.is_empty() {
        return Err("最新发布不是可用的稳定版本。".into());
    }
    let available = parsed > semver::Version::parse(current).map_err(|_| "当前版本号无效。")?;
    let name = format!("LovelyHawk-{version}-windows-x64.zip");
    let asset_url = format!("{DOWNLOAD_ROOT}{}/{name}", data.tag_name);
    let package = data.assets.iter().find(|a| {
        a.name == name
            && a.browser_download_url == asset_url
            && a.size > 0
            && a.size <= MAX_PACKAGE as u64
    });
    let checksum = data.assets.iter().find(|a| {
        a.name == format!("{name}.sha256")
            && a.browser_download_url == format!("{asset_url}.sha256")
            && a.size <= 4096
    });
    let release = if available && cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        package.zip(checksum).map(|(package, checksum)| Release {
            handle: uuid::Uuid::new_v4().to_string(),
            version: version.into(),
            name,
            url: package.browser_download_url.clone(),
            checksum_url: checksum.browser_download_url.clone(),
            size: package.size,
        })
    } else {
        None
    };
    let result = Response::Check {
        version: version.into(),
        available,
        handle: release.as_ref().map(|r| r.handle.clone()),
        notes: data.body.unwrap_or_default().chars().take(8000).collect(),
    };
    Ok((result, release))
}

async fn discover_release(
    client: &reqwest::Client,
    current: &str,
) -> Result<(Response, Option<Release>), String> {
    // Anonymous API quotas are shared by everyone behind a NAT.
    // /releases/latest resolves a stable release without consuming that quota.
    if let Ok(Ok(bytes)) = tokio::time::timeout(
        Duration::from_secs(8),
        bounded_get(client, API, 1024 * 1024),
    )
    .await
        && let Ok(data) = serde_json::from_slice(&bytes)
        && let Ok(selected) = select_release(data, current)
    {
        return Ok(selected);
    }
    let response = client
        .head("https://github.com/LovelyTeams/LovelyHawk/releases/latest")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| "无法连接 GitHub Release，请检查网络后重试。")?
        .error_for_status()
        .map_err(|_| "GitHub 尚未提供可用的稳定发布。")?;
    let tag = response
        .url()
        .path()
        .strip_prefix("/LovelyTeams/LovelyHawk/releases/tag/")
        .filter(|_| response.url().host_str() == Some("github.com"))
        .ok_or("GitHub 发布地址无效。")?;
    let mut data = GithubRelease {
        tag_name: tag.to_owned(),
        draft: false,
        prerelease: false,
        body: Some("已通过 GitHub Release 地址确认版本；更新说明暂时无法读取。".into()),
        assets: vec![],
    };
    let (summary, _) = select_release(data.clone(), current)?;
    if !matches!(
        summary,
        Response::Check {
            available: true,
            ..
        }
    ) || !cfg!(all(target_os = "windows", target_arch = "x86_64"))
    {
        return Ok((summary, None));
    }
    let version = tag.strip_prefix('v').unwrap_or(tag);
    let name = format!("LovelyHawk-{version}-windows-x64.zip");
    let package_url = format!("{DOWNLOAD_ROOT}{tag}/{name}");
    let checksum_url = format!("{package_url}.sha256");
    let head_size = async |url: &str| -> Option<u64> {
        client
            .head(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    };
    let (package_size, checksum_size) =
        tokio::join!(head_size(&package_url), head_size(&checksum_url));
    if let (Some(size), Some(checksum_size)) = (package_size, checksum_size) {
        data.assets = vec![
            Asset {
                name: name.clone(),
                browser_download_url: package_url,
                size,
            },
            Asset {
                name: format!("{name}.sha256"),
                browser_download_url: checksum_url,
                size: checksum_size,
            },
        ];
    }
    select_release(data, current)
}

fn verify_checksum(bytes: &[u8], text: &[u8], name: &str) -> Result<(), String> {
    let text = std::str::from_utf8(text).map_err(|_| "校验文件格式无效。")?;
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() != 2
        || fields[1] != name
        || fields[0].len() != 64
        || !fields[0].bytes().all(|c| c.is_ascii_hexdigit())
        || format!("{:x}", Sha256::digest(bytes)) != fields[0].to_ascii_lowercase()
    {
        return Err("安装包 SHA-256 校验失败，未保存文件。请重新检查更新。".into());
    }
    Ok(())
}

async fn download_package(
    client: &reqwest::Client,
    release: &Release,
    progress: &Mutex<Progress>,
) -> Result<Vec<u8>, String> {
    let checksum = bounded_get(client, &release.checksum_url, 4096).await?;
    let mut response = client
        .get(&release.url)
        .send()
        .await
        .map_err(|_| "下载失败，请检查网络。")?
        .error_for_status()
        .map_err(|_| "GitHub 未能提供此更新包。")?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "下载中断，请重试。")? {
        if bytes.len() + chunk.len() > release.size as usize {
            return Err("更新包大小与发布信息不一致。".into());
        }
        bytes.extend_from_slice(&chunk);
        progress.lock().received = bytes.len() as u64;
    }
    if bytes.len() != release.size as usize {
        return Err("更新包下载不完整。".into());
    }
    verify_checksum(&bytes, &checksum, &release.name)?;
    Ok(bytes)
}

fn save_package(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("保存目录无效。")?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| local_files::WRITE_FAILED)?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|_| local_files::WRITE_FAILED)?;
    file.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            local_files::FILE_EXISTS.to_owned()
        } else {
            local_files::WRITE_FAILED.to_owned()
        }
    })?;
    Ok(())
}

#[tauri::command]
pub async fn app_update<R: Runtime>(
    window: WebviewWindow<R>,
    updates: State<'_, Updates>,
    request: Request,
) -> Result<Response, String> {
    if window.label() != MAIN_LABEL {
        return Err("此窗口不能管理应用更新。".into());
    }
    let state = updates.inner();
    match &request {
        Request::Info {} => {
            return Ok(Response::Info {
                version: env!("CARGO_PKG_VERSION").into(),
            });
        }
        Request::Progress { handle } | Request::Cancel { handle } => {
            let mut progress = state.progress.lock();
            if handle.is_empty() || handle.len() > 64 || progress.handle != *handle {
                return Err("下载任务已结束或已过期。".into());
            }
            return if matches!(request, Request::Cancel { .. }) {
                progress.cancelled = true;
                Ok(Response::Cancel { cancelled: true })
            } else {
                Ok(Response::Progress {
                    received: progress.received,
                    total: progress.total,
                })
            };
        }
        _ => {}
    }
    let _operation = state
        .operation
        .try_lock()
        .map_err(|_| "更新任务正在进行，请稍后重试。")?;
    let client = client()?;
    match request {
        Request::Check {} => {
            *state.release.lock() = None;
            let (response, release) = tokio::time::timeout(
                Duration::from_secs(30),
                discover_release(&client, env!("CARGO_PKG_VERSION")),
            )
            .await
            .map_err(|_| "检查更新超时，请重试。")??;
            *state.release.lock() = release;
            Ok(response)
        }
        Request::Download { handle } => {
            let release = state
                .release
                .lock()
                .as_ref()
                .filter(|r| r.handle == handle && handle.len() <= 64)
                .cloned()
                .ok_or("此更新已过期，请重新检查。")?;
            *state.progress.lock() = Progress {
                handle,
                received: 0,
                total: 0,
                cancelled: false,
            };
            let path = local_files::choose(
                &window,
                &format!("保存 LovelyHawk {} 更新包", release.version),
                DialogKind::Save {
                    default_name: &release.name,
                },
                Some(Filter {
                    name: "ZIP 更新包",
                    extensions: &["zip"],
                }),
            )
            .await;
            let Some(path) = path else {
                *state.progress.lock() = Progress::default();
                return Ok(Response::Download { filename: None });
            };
            if !local_files::has_extension(&path, "zip") {
                *state.progress.lock() = Progress::default();
                return Err("请选择 .zip 文件名。".into());
            }
            if path.exists() {
                *state.progress.lock() = Progress::default();
                return Err(local_files::FILE_EXISTS.into());
            }
            state.progress.lock().total = release.size;
            let download = download_package(&client, &release, &state.progress);
            let cancelled = async {
                loop {
                    if state.progress.lock().cancelled {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            };
            let result = tokio::select! {
                biased;
                () = cancelled => Err("下载已取消，没有保存更新包。".into()),
                result = tokio::time::timeout(Duration::from_secs(180), download) =>
                    result.map_err(|_| "更新包下载超时，请重试。".to_owned()).and_then(|r| r),
            };
            *state.progress.lock() = Progress::default();
            let bytes = result?;
            let filename = local_files::display_name(&path, &release.name);
            tokio::task::spawn_blocking(move || save_package(&path, &bytes))
                .await
                .map_err(|_| "保存更新包失败。")??;
            Ok(Response::Download {
                filename: Some(filename),
            })
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str) -> GithubRelease {
        GithubRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            body: None,
            assets: vec![],
        }
    }

    #[test]
    fn versions_compare_numerically_and_never_offer_downgrades_or_prereleases() {
        assert!(matches!(
            select_release(release("v0.0.10"), "0.0.9").unwrap().0,
            Response::Check {
                available: true,
                handle: None,
                ..
            }
        ));
        assert!(matches!(
            select_release(release("v0.0.1"), "0.0.2").unwrap().0,
            Response::Check {
                available: false,
                ..
            }
        ));
        assert!(select_release(release("v1.0.0-rc.1"), "0.0.1").is_err());
        assert!(select_release(release("../1.0.0"), "0.0.1").is_err());
    }

    #[test]
    fn checksum_binds_content_and_filename() {
        let digest = format!("{:x}  update.zip\n", Sha256::digest(b"package"));
        assert!(verify_checksum(b"package", digest.as_bytes(), "update.zip").is_ok());
        assert!(verify_checksum(b"tampered", digest.as_bytes(), "update.zip").is_err());
        assert!(verify_checksum(b"package", digest.as_bytes(), "other.zip").is_err());
    }

    #[test]
    fn requests_refuse_extra_fields_and_unknown_actions() {
        for input in [
            r#"{"action":"check","url":"https://example.com"}"#,
            r#"{"action":"info","version":"99.0.0"}"#,
            r#"{"action":"install"}"#,
            r#"{"action":"download","handle":"id","path":"C:\\secret"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(input).is_err(), "{input}");
        }
    }

    #[test]
    fn package_save_never_overwrites_and_leaves_no_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("update.zip");
        save_package(&path, b"first").unwrap();
        assert!(save_package(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn release_assets_must_belong_to_the_exact_repository_and_tag() {
        let mut data = release("v0.0.2");
        let name = "LovelyHawk-0.0.2-windows-x64.zip";
        data.assets = vec![
            Asset {
                name: name.into(),
                size: 3,
                browser_download_url: format!("{DOWNLOAD_ROOT}v0.0.2/{name}"),
            },
            Asset {
                name: format!("{name}.sha256"),
                size: 99,
                browser_download_url: format!("{DOWNLOAD_ROOT}v0.0.2/{name}.sha256"),
            },
        ];
        data.assets[0].browser_download_url = "https://evil.invalid/package.zip".into();
        assert!(select_release(data, "0.0.1").unwrap().1.is_none());
    }

    /// Opt-in network verification; never replaces an installed executable.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[tokio::test]
    #[ignore = "downloads the current public GitHub release into a temporary directory"]
    async fn public_release_download_is_verified_and_saved() {
        let client = client().unwrap();
        let (_, selected) = discover_release(&client, "0.0.0").await.unwrap();
        let selected = selected.expect("a Windows release with checksum");
        let progress = Mutex::new(Progress::default());
        let bytes = download_package(&client, &selected, &progress)
            .await
            .unwrap();
        assert_eq!(progress.lock().received, selected.size);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(&selected.name);
        save_package(&path, &bytes).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().len(), selected.size);
        println!(
            "Verified public release {} ({} bytes)",
            selected.version, selected.size
        );
    }
}
