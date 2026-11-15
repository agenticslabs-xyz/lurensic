use serde::{Deserialize, Serialize};

/// Operating mode.
///
/// `Observe` is the default. In this mode the engine never asks the host to
/// change, delay or answer a response. It only produces events.
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
    /// Keyed hash that is stable per deployment and cannot be reversed without the secret.
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

/// What starts containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Trigger {
    /// Only tripwires that honest visitors never touch: a planted credential,
    /// a decoy field or parameter, a decoy route, or a tampered sealed value.
    #[default]
    Tripwire,
    /// Tripwires, and any session that reaches the flagged state through
    /// accumulated signals. Wider, with a higher false positive risk.
    Flagged,
}

/// What a contained machine receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContainAction {
    /// Replayed public responses, never the live application. The agent keeps
    /// working against a copy and does not learn that it was cut off.
    #[default]
    Shadow,
    /// A plain `403 Forbidden`.
    Block,
}

/// Containment cuts a machine off from the live application once it has
/// shown itself to be an attacker. Off by default. Enforced in protect mode
/// only; in observe mode it runs as a dry run that only emits events.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Containment {
    pub enabled: bool,
    pub trigger: Trigger,
    pub action: ContainAction,
    /// How long a machine stays contained after its last trigger.
    pub ttl_secs: u64,
    /// Addresses and CIDR ranges that are never contained, such as your own
    /// offices, monitoring and authorised testers.
    pub allow: Vec<String>,
    /// Maximum number of contained machines held in memory.
    pub max_entries: usize,
    /// Memory budget for the public responses the shadow replays.
    pub shadow_cache_bytes: usize,
}

impl Default for Containment {
    fn default() -> Self {
        Containment {
            enabled: false,
            trigger: Trigger::Tripwire,
            action: ContainAction::Shadow,
            ttl_secs: 24 * 60 * 60,
            allow: Vec::new(),
            max_entries: 10_000,
            shadow_cache_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Engine configuration. Unknown fields are rejected so typos surface
/// immediately instead of silently falling back to defaults.
///
/// Deliberately not `Debug`, because it holds the deployment secret.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub secret: String,
    pub mode: Mode,
    /// In protect mode, embed a bait comment in the home page and a keyed
    /// subset of other HTML documents.
    pub html_decoys: bool,
    /// In protect mode, add a decoy field to JSON object responses (opt-in).
    pub json_decoys: bool,
    /// In protect mode, add the decoy field as a hidden input to POST forms in
    /// HTML documents (opt-in, because the app then receives one extra field).
    pub form_decoys: bool,
    /// In protect mode, answer probes for `.env`, `.git/config`, `.aws/credentials`
    /// with fake files containing honeytokens.
    pub bait_files: bool,
    /// In protect mode, answer the derived decoy routes.
    pub decoy_routes: bool,
    pub tarpit: Tarpit,
    pub containment: Containment,
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
            form_decoys: false,
            bait_files: true,
            decoy_routes: true,
            tarpit: Tarpit::default(),
            containment: Containment::default(),
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
        let c = &self.containment;
        if !(60..=30 * 24 * 60 * 60).contains(&c.ttl_secs) {
            return Err(ConfigError::new(
                "invalid_containment",
                "containment.ttl_secs must be between 60 (one minute) and 2592000 (30 days).",
            ));
        }
        if c.max_entries < 10 || c.shadow_cache_bytes > 64 * 1024 * 1024 {
            return Err(ConfigError::new(
                "invalid_containment",
                "containment.max_entries must be at least 10 and containment.shadow_cache_bytes at most 67108864 (64 MiB).",
            ));
        }
        if let Some(bad) = c
            .allow
            .iter()
            .find(|r| crate::net::Cidr::parse(r).is_none())
        {
            return Err(ConfigError::new(
                "invalid_containment",
                format!(
                    "containment.allow holds `{}`, which is not an IP address or CIDR range.",
                    crate::normalize::sanitize(bad, 64)
                ),
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
