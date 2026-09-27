//! UI preferences in `%APPDATA%\Stemma\ui.json`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// `system`, `en` or `zh-CN`.
    pub language: String,
    pub close_to_tray: bool,
    /// Show only the tray icon when started at logon.
    pub start_minimized: bool,
    pub window: Option<Geometry>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            language: "system".to_owned(),
            close_to_tray: true,
            start_minimized: false,
            window: None,
        }
    }
}

/// Size in logical (96-DPI) pixels, position in desktop pixels, so a window
/// keeps its apparent size when it reopens on a monitor with another scale.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: f64,
    pub height: f64,
    pub maximized: bool,
}

fn path() -> Option<PathBuf> {
    Some(
        PathBuf::from(std::env::var_os("APPDATA")?)
            .join("Stemma")
            .join("ui.json"),
    )
}

pub fn load() -> Prefs {
    path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn save(prefs: &Prefs) -> Result<(), String> {
    let path = path().ok_or("APPDATA is not set")?;
    let dir = path.parent().expect("has a parent");
    std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    let temporary = path.with_extension("json.new");
    let text = serde_json::to_string_pretty(prefs).expect("preferences serialize");
    std::fs::write(&temporary, text).map_err(|err| err.to_string())?;
    std::fs::rename(&temporary, &path).map_err(|err| err.to_string())
}

/// The language the UI shows: `en` or `zh-CN`.
pub fn resolved_language(language: &str) -> &'static str {
    match language {
        "en" => "en",
        "zh-CN" => "zh-CN",
        _ => match sys_locale::get_locale() {
            Some(locale) if locale.to_ascii_lowercase().starts_with("zh") => "zh-CN",
            _ => "en",
        },
    }
}
