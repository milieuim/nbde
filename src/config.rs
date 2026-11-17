//! Agent configuration. The file holds no secrets: gate addresses and `thp`
//! pins come from the JWE itself.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use snafu::{ResultExt, Snafu, ensure};

/// systemd-cryptsetup volume names end up in an abstract socket address and
/// unit names; keep them to a conservative character set.
const MAX_VOLUME_NAME_LEN: usize = 64;

/// The keyfile path systemd-cryptsetup is pointed at (design §7.6).
pub const DEFAULT_SOCKET: &str = "/run/nbde/key.sock";

#[derive(Debug, Snafu)]
pub enum ConfigError {
    #[snafu(display("read config {}", path.display()))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("parse config {}", path.display()))]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[snafu(display("config declares no volume"))]
    NoVolume,

    #[snafu(display("invalid volume name `{name}`"))]
    VolumeName { name: String },

    #[snafu(display("duplicate volume name `{name}`"))]
    DuplicateVolume { name: String },

    #[snafu(display("`{field}` must be greater than zero"))]
    Zero { field: &'static str },

    #[snafu(display("`{field}` must not exceed deadline_secs"))]
    ExceedsDeadline { field: &'static str },

    #[snafu(display("socket path {} must be absolute with a parent directory", path.display()))]
    SocketPath { path: PathBuf },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_attempt_timeout")]
    attempt_timeout_secs: u64,
    #[serde(default = "default_retry_interval")]
    retry_interval_secs: u64,
    #[serde(default = "default_deadline")]
    deadline_secs: u64,
    #[serde(default = "default_socket")]
    socket: PathBuf,
    #[serde(default = "default_console")]
    console: bool,
    #[serde(rename = "volume")]
    volumes: Vec<Volume>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    pub name: String,
    pub jwe: PathBuf,
}

fn default_attempt_timeout() -> u64 {
    30
}

fn default_retry_interval() -> u64 {
    10
}

fn default_deadline() -> u64 {
    900
}

fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}

fn default_console() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).context(ReadSnafu { path })?;
        Self::parse(&text).map_err(|e| match e {
            ParseError::Toml(source) => ConfigError::Parse {
                path: path.to_owned(),
                source,
            },
            ParseError::Invalid(e) => e,
        })
    }

    fn parse(text: &str) -> Result<Self, ParseError> {
        let config: Self = toml::from_str(text).map_err(ParseError::Toml)?;
        config.validate().map_err(ParseError::Invalid)?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        ensure!(!self.volumes.is_empty(), NoVolumeSnafu);
        ensure!(
            self.socket.is_absolute()
                && self.socket.parent().is_some_and(|p| p != Path::new("/"))
                && self.socket.file_name().is_some(),
            SocketPathSnafu { path: &self.socket }
        );

        let mut seen = HashSet::new();
        for volume in &self.volumes {
            ensure!(
                valid_volume_name(&volume.name),
                VolumeNameSnafu { name: &volume.name }
            );
            ensure!(
                seen.insert(volume.name.as_str()),
                DuplicateVolumeSnafu { name: &volume.name }
            );
        }

        for (field, value) in [
            ("attempt_timeout_secs", self.attempt_timeout_secs),
            ("retry_interval_secs", self.retry_interval_secs),
            ("deadline_secs", self.deadline_secs),
        ] {
            ensure!(value > 0, ZeroSnafu { field });
        }
        for (field, value) in [
            ("attempt_timeout_secs", self.attempt_timeout_secs),
            ("retry_interval_secs", self.retry_interval_secs),
        ] {
            ensure!(value <= self.deadline_secs, ExceedsDeadlineSnafu { field });
        }
        Ok(())
    }

    pub fn attempt_timeout(&self) -> Duration {
        Duration::from_secs(self.attempt_timeout_secs)
    }

    pub fn retry_interval(&self) -> Duration {
        Duration::from_secs(self.retry_interval_secs)
    }

    pub fn deadline(&self) -> Duration {
        Duration::from_secs(self.deadline_secs)
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn console(&self) -> bool {
        self.console
    }

    pub fn volumes(&self) -> &[Volume] {
        &self.volumes
    }

    /// Looks up the volume a systemd-cryptsetup peer asked for.
    pub fn volume(&self, name: &str) -> Option<&Volume> {
        self.volumes.iter().find(|v| v.name == name)
    }
}

enum ParseError {
    Toml(toml::de::Error),
    Invalid(ConfigError),
}

fn valid_volume_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_VOLUME_NAME_LEN
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text).map_err(|e| match e {
            ParseError::Invalid(e) => e,
            ParseError::Toml(source) => ConfigError::Parse {
                path: PathBuf::from("<test>"),
                source,
            },
        })
    }

    const MINIMAL: &str = r#"
        [[volume]]
        name = "crypt-root"
        jwe = "/etc/nbde/crypt-root.jwe"
    "#;

    #[test]
    fn minimal_config_uses_defaults() {
        let config = parse(MINIMAL).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(config.attempt_timeout(), Duration::from_secs(30));
        assert_eq!(config.retry_interval(), Duration::from_secs(10));
        assert_eq!(config.deadline(), Duration::from_secs(900));
        assert_eq!(config.socket(), Path::new(DEFAULT_SOCKET));
        assert!(config.console());
        assert!(config.volume("crypt-root").is_some());
        assert!(config.volume("crypt-home").is_none());
    }

    #[test]
    fn load_reads_a_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| unreachable!("{e}"));
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, MINIMAL).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(Config::load(&path).is_ok());
    }

    #[test]
    fn missing_file_reports_read_error() {
        let result = Config::load(Path::new("/nonexistent/nbde/agent.toml"));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = format!("secret = \"x\"\n{MINIMAL}");
        assert!(matches!(parse(&text), Err(ConfigError::Parse { .. })));
        let text = MINIMAL.replace("jwe =", "pin = \"tpm2\"\njwe =");
        assert!(matches!(parse(&text), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn at_least_one_volume_is_required() {
        assert!(matches!(parse("volume = []"), Err(ConfigError::NoVolume)));
    }

    #[test]
    fn volume_names_are_validated() {
        for bad in ["", ".hidden", "a/b", "a b", &"x".repeat(65)] {
            let text = MINIMAL.replace("crypt-root", bad);
            assert!(
                matches!(parse(&text), Err(ConfigError::VolumeName { .. })),
                "accepted `{bad}`"
            );
        }
    }

    #[test]
    fn duplicate_volumes_are_rejected() {
        let text = format!("{MINIMAL}{MINIMAL}");
        assert!(matches!(
            parse(&text),
            Err(ConfigError::DuplicateVolume { .. })
        ));
    }

    #[test]
    fn timings_are_validated() {
        let zero = format!("retry_interval_secs = 0\n{MINIMAL}");
        assert!(matches!(parse(&zero), Err(ConfigError::Zero { .. })));
        let long = format!("deadline_secs = 20\n{MINIMAL}");
        assert!(matches!(
            parse(&long),
            Err(ConfigError::ExceedsDeadline {
                field: "attempt_timeout_secs"
            })
        ));
    }

    #[test]
    fn socket_path_is_validated() {
        for bad in ["key.sock", "/key.sock", "/"] {
            let text = format!("socket = \"{bad}\"\n{MINIMAL}");
            assert!(
                matches!(parse(&text), Err(ConfigError::SocketPath { .. })),
                "accepted `{bad}`"
            );
        }
        let text = format!("socket = \"/run/x/k.sock\"\nconsole = false\n{MINIMAL}");
        let config = parse(&text).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(config.socket(), Path::new("/run/x/k.sock"));
        assert!(!config.console());
    }
}
