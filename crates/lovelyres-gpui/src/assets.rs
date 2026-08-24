use std::borrow::Cow;

use std::sync::Arc;

use gpui::{AssetSource, Image, ImageFormat, Result, SharedString};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets"]
struct LovelyResAssets;

/// Serves application assets first, then gpui-component's embedded icon set.
pub struct Assets;

/// Returns the bundled brand mark as image bytes so the title bar can decode it synchronously.
///
/// GPUI's resource-backed `img("logo.png")` loader is asynchronous. At title-bar size that left
/// a permanently empty slot on the Windows backend in the current pinned GPUI release. Supplying
/// an `Image` makes decoding use GPUI's image cache directly and keeps the application offline.
pub fn embedded_brand_logo() -> Arc<Image> {
    Arc::new(Image::from_bytes(
        ImageFormat::Png,
        include_bytes!("../assets/logo.png").to_vec(),
    ))
}

pub fn embedded_fonts() -> Vec<Cow<'static, [u8]>> {
    [
        "fonts/Inter-Regular.ttf",
        "fonts/Inter-SemiBold.ttf",
        "fonts/CascadiaMono.ttf",
    ]
    .into_iter()
    .map(|path| {
        LovelyResAssets::get(path)
            .unwrap_or_else(|| panic!("embedded font is missing: {path}"))
            .data
    })
    .collect()
}

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(asset) = LovelyResAssets::get(path) {
            return Ok(Some(asset.data));
        }
        gpui::AssetSource::load(&gpui_component_assets::Assets, path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut assets: Vec<SharedString> = LovelyResAssets::iter()
            .filter(|name| name.starts_with(path))
            .map(|name| name.into_owned().into())
            .collect();
        assets.extend(gpui::AssetSource::list(
            &gpui_component_assets::Assets,
            path,
        )?);
        assets.sort_unstable();
        assets.dedup();
        Ok(assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_asset_loader_resolves_local_bundle_and_rejects_remote_urls() {
        for local in [
            "logo.png",
            "fonts/Inter-Regular.ttf",
            "fonts/Inter-SemiBold.ttf",
            "fonts/CascadiaMono.ttf",
            "security_reference.json",
        ] {
            assert!(
                Assets.load(local).unwrap().is_some(),
                "missing embedded asset {local}"
            );
        }
        for remote in [
            ["https", "://cdn.example.invalid/app.js"].concat(),
            ["https", "://fonts.example.invalid/font.woff2"].concat(),
            ["http", "://example.invalid/logo.png"].concat(),
        ] {
            assert!(
                !matches!(Assets.load(&remote), Ok(Some(_))),
                "resolved {remote}"
            );
        }
        assert!(Assets.list("").unwrap().iter().all(|path| {
            let path = path.to_ascii_lowercase();
            !path.starts_with("http://") && !path.starts_with("https://")
        }));
    }

    #[test]
    fn brand_logo_is_a_real_embedded_png() {
        let logo = embedded_brand_logo();
        assert_eq!(logo.format(), ImageFormat::Png);
        assert!(logo.bytes().starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(logo.bytes().len() > 100_000);
    }
}
