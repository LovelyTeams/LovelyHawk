//! Debug builds only: load the pages from a local Vite server, so an edit to
//! the UI shows in the running window without rebuilding the executable.
//!
//! Nothing here exists in a release build. The pages normally come from the
//! assets embedded at `https://tauri.localhost`; with `LOVELYHAWK_DEV_SERVER`
//! set, the same pages come from one loopback origin instead. That origin gets
//! a copy of the two capability files and nothing more — the same commands,
//! for the same window labels — so the host's per-window checks are the ones
//! the embedded build runs.

use serde_json::{Value, json};
use tauri::{Manager, Runtime, Url};

pub const DEV_SERVER_VARIABLE: &str = "LOVELYHAWK_DEV_SERVER";

const CAPABILITIES: [&str; 2] = [
    include_str!("../capabilities/main-window.json"),
    include_str!("../capabilities/child-windows.json"),
];

/// The development origin from the environment, if one is set and acceptable.
pub fn from_env() -> Option<Url> {
    let value = std::env::var(DEV_SERVER_VARIABLE).ok()?;
    let origin = parse(&value);
    match &origin {
        Some(origin) => tracing::info!(%origin, "loading the pages from a development server"),
        None => tracing::warn!(
            "ignoring {DEV_SERVER_VARIABLE}: expected http://127.0.0.1:<port>/ or http://localhost:<port>/"
        ),
    }
    origin
}

/// Only a bare loopback http origin with an explicit port: no path, query,
/// fragment or credentials, so the variable cannot point the windows anywhere
/// but a server on this machine.
pub fn parse(value: &str) -> Option<Url> {
    let url: Url = value.parse().ok()?;
    let acceptable = url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    acceptable.then_some(url)
}

/// Grants the development origin what the embedded pages already have.
pub fn grant<R: Runtime, M: Manager<R>>(
    manager: &M,
    origin: &Url,
) -> Result<(), Box<dyn std::error::Error>> {
    for source in CAPABILITIES {
        manager.add_capability(remote_copy(source, origin)?)?;
    }
    Ok(())
}

/// The capability file, renamed and moved from the local origin to `origin`.
fn remote_copy(source: &str, origin: &Url) -> Result<String, Box<dyn std::error::Error>> {
    let mut capability: Value = serde_json::from_str(source)?;
    let fields = capability
        .as_object_mut()
        .ok_or("capability file is not an object")?;
    let identifier = fields
        .get("identifier")
        .and_then(Value::as_str)
        .ok_or("capability file has no identifier")?;
    let identifier = format!("{identifier}-dev-server");
    fields.insert("identifier".into(), json!(identifier));
    fields.insert("local".into(), json!(false));
    fields.insert("remote".into(), json!({ "urls": [format!("{origin}*")] }));
    Ok(capability.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bare_loopback_origin_is_accepted() {
        for value in [
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5173/",
            "http://localhost:5173/",
        ] {
            assert!(parse(value).is_some(), "{value}");
        }
        for value in [
            "https://127.0.0.1:5173/",
            "http://127.0.0.1/",
            "http://192.168.1.10:5173/",
            "http://example.com:5173/",
            "http://127.0.0.1.example.com:5173/",
            "http://user@127.0.0.1:5173/",
            "http://127.0.0.1:5173/index.html",
            "http://127.0.0.1:5173/?x=1",
            "http://127.0.0.1:5173/#x",
            "file:///C:/ui/index.html",
            "",
        ] {
            assert!(parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn the_copy_moves_the_same_permissions_to_the_development_origin() {
        let origin = parse("http://127.0.0.1:5173/").unwrap();
        for source in CAPABILITIES {
            let original: Value = serde_json::from_str(source).unwrap();
            let copy: Value = serde_json::from_str(&remote_copy(source, &origin).unwrap()).unwrap();
            assert_eq!(
                copy["identifier"],
                json!(format!(
                    "{}-dev-server",
                    original["identifier"].as_str().unwrap()
                ))
            );
            assert_eq!(copy["local"], json!(false));
            assert_eq!(
                copy["remote"],
                json!({ "urls": ["http://127.0.0.1:5173/*"] })
            );
            assert_eq!(copy["windows"], original["windows"]);
            assert_eq!(copy["permissions"], original["permissions"]);
            // And it still parses as a capability Tauri accepts.
            assert!(
                remote_copy(source, &origin)
                    .unwrap()
                    .parse::<tauri::utils::acl::capability::CapabilityFile>()
                    .is_ok()
            );
        }
    }
}
