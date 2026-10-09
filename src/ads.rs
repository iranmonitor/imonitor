//! Optional sponsored PNG placements. Remote work never blocks panel rendering.
use crate::app_types::UiLanguage;
use crate::util::html_escape;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const API: &str = "https://iranmonitor.net/api/imonitor/ads";
const REFRESH_AFTER: Duration = Duration::from_secs(900);
const EXPIRE_AFTER: Duration = Duration::from_secs(86_400);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Creative {
    pub image_url: String,
    pub click_url: String,
    #[serde(default)]
    pub alt: String,
}

#[derive(Default)]
struct CachedPlacement {
    creative: Option<Creative>,
    updated: Option<Instant>,
    creative_at: Option<Instant>,
    refreshing: bool,
}

type PlacementCache = Mutex<BTreeMap<String, CachedPlacement>>;
static CACHE: OnceLock<PlacementCache> = OnceLock::new();

fn https_host(value: &str) -> Option<&str> {
    if value.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return None;
    }
    let authority = value.strip_prefix("https://")?.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') || authority.contains(':') {
        return None;
    }
    Some(authority)
}

fn valid_creative(creative: &Creative) -> bool {
    let Some(image_host) = https_host(&creative.image_url) else { return false };
    let image_path = creative.image_url.split(['?', '#']).next().unwrap_or("");
    matches!(image_host, "iranmonitor.net" | "www.iranmonitor.net" | "irnmo.ir")
        && image_path.to_ascii_lowercase().ends_with(".png")
        && https_host(&creative.click_url).is_some()
        && creative.image_url.len() <= 2048
        && creative.click_url.len() <= 2048
        && creative.alt.len() <= 300
}

fn download_creative(placement: &str, language: &str) -> Result<Option<Creative>, ()> {
    let url = format!("{API}?placement={placement}&lang={language}");
    let output = Command::new("curl")
        .args(["--silent", "--show-error", "--fail", "--proto", "=https",
            "--connect-timeout", "2", "--max-time", "5", "--max-filesize", "65536", &url])
        .output().map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() > 65_536 { return Err(()); }
    if output.stdout.is_empty() { return Ok(None); }
    let creative: Creative = serde_json::from_slice(&output.stdout).map_err(|_| ())?;
    if !valid_creative(&creative) { return Err(()); }
    Ok(Some(creative))
}

/// A missing or unavailable API produces an empty placement. Cached content is
/// served immediately while a single worker refreshes each of the four keys.
pub fn payload(placement: &str, lang: UiLanguage) -> Value {
    if !matches!(placement, "admin" | "public") { return json!({"creative": null}); }
    let key = format!("{placement}:{}", lang.as_str());
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let Ok(mut entries) = cache.lock() else { return json!({"creative": null}); };
    let entry = entries.entry(key.clone()).or_default();
    let age = entry.updated.map(|at| at.elapsed());
    let current = if entry.creative_at.is_some_and(|at| at.elapsed() < EXPIRE_AFTER) {
        entry.creative.clone()
    } else { None };
    if !entry.refreshing && age.is_none_or(|age| age >= REFRESH_AFTER) {
        entry.refreshing = true;
        let placement = placement.to_string();
        let language = lang.as_str().to_string();
        std::thread::spawn(move || {
            let creative = download_creative(&placement, &language);
            if let Some(cache) = CACHE.get() {
                if let Ok(mut entries) = cache.lock() {
                    if let Some(entry) = entries.get_mut(&key) {
                        if let Ok(creative) = creative {
                            entry.creative = creative;
                            entry.creative_at = Some(Instant::now());
                        }
                        entry.updated = Some(Instant::now());
                        entry.refreshing = false;
                    }
                }
            }
        });
    }
    json!({"placement": placement, "creative": current})
}

pub fn render_slot(placement: &str, lang: UiLanguage) -> String {
    if !matches!(placement, "admin" | "public") { return String::new(); }
    let label = if lang.is_rtl() { "تبلیغ" } else { "Sponsored" };
    format!(r#"<aside class="ad-slot" data-ad-placement="{placement}" data-ad-lang="{lang}" aria-label="{label}" hidden>
<span class="ad-label">{label}</span><a class="ad-link" target="_blank" rel="sponsored noopener noreferrer"><img class="ad-image" alt="{label}" loading="lazy" decoding="async" referrerpolicy="no-referrer"></a></aside>
<script>{script}</script>"#,
        placement=placement, lang=lang.as_str(), label=html_escape(label),
        script=include_str!("ui/ads.js"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn creative(image: &str, click: &str) -> Creative {
        Creative { image_url: image.into(), click_url: click.into(), alt: "Sponsor".into() }
    }
    #[test]
    fn accepts_only_official_png_creatives_and_https_links() {
        assert!(valid_creative(&creative("https://iranmonitor.net/api/ads/image.png", "https://example.org/")));
        for image in ["https://iranmonitor.net.evil.test/a.png", "https://evil.test/a.png", "https://iranmonitor.net@evil.test/a.png", "http://iranmonitor.net/a.png", "https://iranmonitor.net/a.svg", "https://iranmonitor.net\\@evil.test/a.png"] {
            assert!(!valid_creative(&creative(image, "https://example.org/")), "{image}");
        }
        assert!(!valid_creative(&creative("https://iranmonitor.net/a.png", "javascript:alert(1)")));
    }
    #[test]
    fn invalid_placement_is_inert_and_slots_are_distinct() {
        assert_eq!(payload("anything", UiLanguage::En)["creative"], Value::Null);
        assert!(render_slot("admin", UiLanguage::En).contains("data-ad-placement=\"admin\""));
        assert!(render_slot("public", UiLanguage::Fa).contains("data-ad-placement=\"public\""));
        assert!(render_slot("anything", UiLanguage::En).is_empty());
    }
}
