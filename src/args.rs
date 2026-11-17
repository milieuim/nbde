//! Command line parsing. Only `std::env::args_os` is used; the agent has two
//! modes and no option parser library is warranted.

use std::ffi::OsString;
use std::path::PathBuf;

use snafu::Snafu;

pub const DEFAULT_CONFIG: &str = "/etc/nbde/agent.toml";

pub const USAGE: &str = "\
usage: nbde-agent [--config <path>]   run the socket-activated unlock agent
       nbde-agent check <jwe>         run one unlock attempt without revealing the secret
       nbde-agent --help | --version";

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    Daemon { config: PathBuf },
    Check { jwe: PathBuf },
    Help,
    Version,
}

#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum ArgsError {
    #[snafu(display("option `{option}` requires a value"))]
    MissingValue { option: String },

    #[snafu(display("unexpected argument `{argument}`"))]
    Unexpected { argument: String },
}

/// Parses the arguments that follow the program name.
pub fn parse<I>(args: I) -> Result<Mode, ArgsError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Mode::Daemon {
            config: PathBuf::from(DEFAULT_CONFIG),
        });
    };

    let mode = match first.to_str() {
        Some("--help" | "-h") => Mode::Help,
        Some("--version" | "-V") => Mode::Version,
        Some("--config") => Mode::Daemon {
            config: required(&mut args, "--config")?,
        },
        Some("check") => Mode::Check {
            jwe: required(&mut args, "check")?,
        },
        _ => return unexpected(first),
    };

    match args.next() {
        Some(extra) => unexpected(extra),
        None => Ok(mode),
    }
}

fn required(args: &mut impl Iterator<Item = OsString>, option: &str) -> Result<PathBuf, ArgsError> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| ArgsError::MissingValue {
            option: option.to_owned(),
        })
}

fn unexpected<T>(argument: OsString) -> Result<T, ArgsError> {
    Err(ArgsError::Unexpected {
        argument: argument.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Mode, ArgsError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_selects_daemon_with_default_config() {
        assert_eq!(
            run(&[]),
            Ok(Mode::Daemon {
                config: PathBuf::from(DEFAULT_CONFIG)
            })
        );
    }

    #[test]
    fn config_option_selects_daemon_with_given_path() {
        assert_eq!(
            run(&["--config", "/tmp/a.toml"]),
            Ok(Mode::Daemon {
                config: PathBuf::from("/tmp/a.toml")
            })
        );
    }

    #[test]
    fn check_takes_a_jwe_path() {
        assert_eq!(
            run(&["check", "root.jwe"]),
            Ok(Mode::Check {
                jwe: PathBuf::from("root.jwe")
            })
        );
    }

    #[test]
    fn help_and_version_are_recognised() {
        assert_eq!(run(&["-h"]), Ok(Mode::Help));
        assert_eq!(run(&["--version"]), Ok(Mode::Version));
    }

    #[test]
    fn missing_values_are_rejected() {
        assert!(matches!(
            run(&["--config"]),
            Err(ArgsError::MissingValue { .. })
        ));
        assert!(matches!(
            run(&["check"]),
            Err(ArgsError::MissingValue { .. })
        ));
    }

    #[test]
    fn unknown_and_trailing_arguments_are_rejected() {
        assert!(matches!(
            run(&["decrypt"]),
            Err(ArgsError::Unexpected { .. })
        ));
        assert!(matches!(
            run(&["check", "a.jwe", "b.jwe"]),
            Err(ArgsError::Unexpected { .. })
        ));
    }
}
