//! Persistent user settings and the cached winning strategy.

use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Turn the bypass on as soon as the app starts.
    pub enable_on_start: bool,
    /// Closing the window hides it to the tray instead of quitting.
    pub minimize_to_tray: bool,
    /// Periodically re-check access and re-select on degradation.
    pub watchdog: bool,
    /// Include the user's own sites in the strategy test suite.
    pub test_user_sites: bool,
    /// Last strategy that passed, tried first next time.
    pub last_strategy: Option<String>,
    /// Engine bundle the cached strategy was validated with.
    pub last_engine: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable_on_start: true,
            minimize_to_tray: true,
            watchdog: true,
            test_user_sites: true,
            last_strategy: None,
            last_engine: None,
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string(self).map_err(std::io::Error::other)?;
        fs::write(path, text)
    }

    /// The cached strategy, only if it was validated with this engine bundle.
    pub fn cached_for(&self, engine_id: &str) -> Option<&str> {
        (self.last_engine.as_deref() == Some(engine_id))
            .then_some(self.last_strategy.as_deref())
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_unknown_or_broken_files_fall_back_to_defaults() {
        let path =
            std::env::temp_dir().join(format!("zapreta-settings-{}.toml", std::process::id()));
        let settings = Settings {
            watchdog: false,
            last_strategy: Some("zapreta-split-1".into()),
            last_engine: Some("e1".into()),
            ..Settings::default()
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        assert_eq!(settings.cached_for("e1"), Some("zapreta-split-1"));
        assert_eq!(settings.cached_for("e2"), None);
        fs::write(&path, "not = [valid").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        fs::write(&path, "watchdog = false\n").unwrap();
        assert!(!Settings::load(&path).watchdog);
        let _ = fs::remove_file(&path);
    }
}
