use serde::{Deserialize, Serialize};

/// Operating mode.
///
/// `Observe` is the default and is a hard guarantee: the engine never asks the
/// host to change, delay or answer a response. It only produces events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Observe,
    Protect,
}

/// How client IP addresses appear in events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpLogging {
    #[default]
    Raw,
    /// Keyed hash: stable per deployment, not reversible without the secret.
    Hashed,
    Omit,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tarpit {
    pub enabled: bool,
    pub min_ms: u32,
    pub max_ms: u32,
}

impl Default for Tarpit {
    fn default() -> Self {
        Tarpit {
            enabled: false,
            min_ms: 800,
            max_ms: 2500,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    pub suspicious: u32,
    pub flagged: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            suspicious: 30,
            flagged: 70,
        }
    }
}

/// Engine configuration. Unknown fields are rejected so typos surface
/// immediately instead of silently falling back to defaults.
///
/// Deliberately not `Debug`: it holds the deployment secret.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub secret: String,
    pub mode: Mode,
    /// Protect mode: embed per-session bait comments in HTML documents.
    pub html_decoys: bool,
    /// Protect mode: add a decoy field to JSON object responses (opt-in).
    pub json_decoys: bool,
    /// Protect mode: answer probes for `.env`, `.git/config`, `.aws/credentials`
    /// with fake files containing honeytokens.
    pub bait_files: bool,
    /// Protect mode: answer the derived decoy routes.
    pub decoy_routes: bool,
    pub tarpit: Tarpit,
    pub thresholds: Thresholds,
    pub ip_logging: IpLogging,
    /// Path prefixes the engine skips entirely (health checks, static assets).
    pub ignore_paths: Vec<String>,
    /// Real application paths decoy routes must never collide with.
    pub reserved_paths: Vec<String>,
    /// Real application field / parameter names decoys must never reuse.
    pub reserved_names: Vec<String>,
    pub max_sessions: usize,
    pub session_ttl_secs: u64,
    pub max_events_per_minute: u32,
    pub enumeration_threshold: u32,
    pub auth_failure_threshold: u32,
    pub behavior_window_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            secret: String::new(),
            mode: Mode::Observe,
            html_decoys: true,
            json_decoys: false,
            bait_files: true,
            decoy_routes: true,
            tarpit: Tarpit::default(),
            thresholds: Thresholds::default(),
            ip_logging: IpLogging::Raw,
            ignore_paths: Vec::new(),
            reserved_paths: Vec::new(),
            reserved_names: Vec::new(),
            max_sessions: 50_000,
            session_ttl_secs: 6 * 60 * 60,
            max_events_per_minute: 600,
            enumeration_threshold: 20,
            auth_failure_threshold: 10,
            behavior_window_secs: 60,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigError {
    pub code: &'static str,
    pub message: String,
}

impl ConfigError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        ConfigError {
            code,
            message: message.into(),
        }
    }
}

pub const MIN_SECRET_LEN: usize = 32;

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.secret.trim().is_empty() {
            return Err(ConfigError::new(
                "secret_missing",
                "No Kagami secret configured. Set KAGAMI_SECRET (generate one with `npx @agenticslabs/kagami secret` or `openssl rand -hex 32`).",
            ));
        }
        if self.secret.chars().count() < MIN_SECRET_LEN {
            return Err(ConfigError::new(
                "secret_too_short",
                format!(
                    "The Kagami secret must be at least {MIN_SECRET_LEN} characters. Generate one with `npx @agenticslabs/kagami secret` or `openssl rand -hex 32`."
                ),
            ));
        }
        if self.thresholds.suspicious == 0 || self.thresholds.suspicious >= self.thresholds.flagged
        {
            return Err(ConfigError::new(
                "invalid_thresholds",
                "thresholds.suspicious must be greater than 0 and lower than thresholds.flagged.",
            ));
        }
        if self.tarpit.min_ms > self.tarpit.max_ms || self.tarpit.max_ms > 30_000 {
            return Err(ConfigError::new(
                "invalid_tarpit",
                "tarpit.min_ms must be <= tarpit.max_ms, and tarpit.max_ms must be <= 30000.",
            ));
        }
        if self.max_sessions < 100 {
            return Err(ConfigError::new(
                "invalid_max_sessions",
                "max_sessions must be at least 100.",
            ));
        }
        if self.behavior_window_secs == 0
            || self.enumeration_threshold == 0
            || self.auth_failure_threshold == 0
        {
            return Err(ConfigError::new(
                "invalid_behavior",
                "behavior_window_secs, enumeration_threshold and auth_failure_threshold must be greater than 0.",
            ));
        }
        Ok(())
    }
}
