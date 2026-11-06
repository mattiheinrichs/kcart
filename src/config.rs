//! The TOML config file and the CLI flags that override it.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::abi;
use crate::hosts::HostPattern;

/// `HOSTS_MAX` in the BPF program.
pub const HOSTS_MAX: usize = 1024;
/// `FLOWS_DEFAULT_MAX` in the BPF program.
pub const FLOWS_DEFAULT_MAX: u32 = 262_144;
pub const EVENTS_PER_SEC_DEFAULT: u32 = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Try native XDP, fall back to skb mode
    #[default]
    Auto,
    /// Driver (native) XDP only
    Native,
    /// Generic XDP in the network stack
    Skb,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Config with every field optional: the shape of the file and of the CLI flags.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialConfig {
    pub interface: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub hosts: Option<Vec<String>>,
    pub mode: Option<Mode>,
    pub flows_max: Option<u32>,
    pub events_per_sec: Option<u32>,
    pub allow_legacy_ping: Option<bool>,
    pub rst: Option<bool>,
    pub log_format: Option<LogFormat>,
}

/// Validated config with defaults filled in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Config {
    pub interface: String,
    pub ports: Vec<u16>,
    pub hosts: Vec<HostPattern>,
    pub mode: Mode,
    pub flows_max: u32,
    pub events_per_sec: u32,
    pub allow_legacy_ping: bool,
    pub rst: bool,
    pub log_format: LogFormat,
}

impl PartialConfig {
    pub fn load(path: &Path) -> Result<PartialConfig> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing config file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<PartialConfig> {
        Ok(toml::from_str(text)?)
    }

    /// Fields set in `overrides` win.
    pub fn merge(self, overrides: PartialConfig) -> PartialConfig {
        PartialConfig {
            interface: overrides.interface.or(self.interface),
            ports: overrides.ports.or(self.ports),
            hosts: overrides.hosts.or(self.hosts),
            mode: overrides.mode.or(self.mode),
            flows_max: overrides.flows_max.or(self.flows_max),
            events_per_sec: overrides.events_per_sec.or(self.events_per_sec),
            allow_legacy_ping: overrides.allow_legacy_ping.or(self.allow_legacy_ping),
            rst: overrides.rst.or(self.rst),
            log_format: overrides.log_format.or(self.log_format),
        }
    }

    pub fn resolve(self) -> Result<Config> {
        let interface = match self.interface {
            Some(name) if !name.is_empty() && !name.contains('\0') => name,
            Some(_) => bail!("interface name is invalid"),
            None => bail!("no interface given (set interface in the config file or pass --iface)"),
        };

        let mut ports = self.ports.unwrap_or_default();
        if ports.contains(&0) {
            bail!("port 0 is not a valid TCP port");
        }
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() {
            bail!("no ports given (set ports in the config file or pass --port)");
        }

        let mut hosts = self
            .hosts
            .unwrap_or_default()
            .iter()
            .map(|host| HostPattern::parse(host).with_context(|| format!("host {host:?}")))
            .collect::<Result<Vec<_>>>()?;
        hosts.sort();
        hosts.dedup();
        if hosts.len() > HOSTS_MAX {
            bail!(
                "{} hosts given, the map holds at most {HOSTS_MAX}",
                hosts.len()
            );
        }

        let flows_max = self.flows_max.unwrap_or(FLOWS_DEFAULT_MAX);
        if flows_max == 0 {
            bail!("flows_max must be at least 1");
        }

        Ok(Config {
            interface,
            ports,
            hosts,
            mode: self.mode.unwrap_or_default(),
            flows_max,
            events_per_sec: self.events_per_sec.unwrap_or(EVENTS_PER_SEC_DEFAULT),
            allow_legacy_ping: self.allow_legacy_ping.unwrap_or(false),
            rst: self.rst.unwrap_or(false),
            log_format: self.log_format.unwrap_or_default(),
        })
    }
}

impl Config {
    /// Things that are valid but probably not what the operator wants.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.hosts.is_empty() {
            warnings.push(
                "no hosts configured, every handshake on the protected ports will be dropped"
                    .to_string(),
            );
        }
        if self.events_per_sec == 0 {
            warnings.push("events_per_sec is 0, drops will not be reported".to_string());
        }
        warnings
    }

    pub fn bpf_config(&self) -> abi::Config {
        let mut flags = 0;
        if self.allow_legacy_ping {
            flags |= abi::F_ALLOW_LEGACY_PING;
        }
        if self.rst {
            flags |= abi::F_RST;
        }
        abi::Config {
            flags,
            events_per_sec: self.events_per_sec,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
interface = "eth0"
ports = [25565, 25566, 25565]
hosts = ["Play.Example.com", "*.example.com"]
mode = "skb"
flows_max = 1000
events_per_sec = 5
allow_legacy_ping = true
rst = true
log_format = "json"
"#;

    #[test]
    fn parses_and_resolves_full_file() {
        let config = PartialConfig::parse(FULL).unwrap().resolve().unwrap();
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.ports, vec![25565, 25566]);
        assert_eq!(
            config.hosts,
            vec![
                HostPattern::Exact("play.example.com".into()),
                HostPattern::Wildcard("example.com".into())
            ]
        );
        assert_eq!(config.mode, Mode::Skb);
        assert_eq!(config.flows_max, 1000);
        assert_eq!(config.events_per_sec, 5);
        assert!(config.allow_legacy_ping);
        assert!(config.rst);
        assert_eq!(config.log_format, LogFormat::Json);
        assert_eq!(
            config.bpf_config(),
            abi::Config {
                flags: abi::F_ALLOW_LEGACY_PING | abi::F_RST,
                events_per_sec: 5
            }
        );
    }

    #[test]
    fn defaults() {
        let config = PartialConfig::parse("interface = \"eth0\"\nports = [25565]\n")
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(config.mode, Mode::Auto);
        assert_eq!(config.flows_max, FLOWS_DEFAULT_MAX);
        assert_eq!(config.events_per_sec, EVENTS_PER_SEC_DEFAULT);
        assert!(!config.allow_legacy_ping);
        assert!(!config.rst);
        assert_eq!(config.log_format, LogFormat::Text);
        assert!(config.hosts.is_empty());
        assert_eq!(config.warnings().len(), 1);
        assert_eq!(config.bpf_config().flags, 0);
    }

    #[test]
    fn overrides_win() {
        let file = PartialConfig::parse(FULL).unwrap();
        let overrides = PartialConfig {
            interface: Some("kc0".into()),
            ports: Some(vec![1]),
            hosts: Some(vec![]),
            ..PartialConfig::default()
        };
        let config = file.merge(overrides).resolve().unwrap();
        assert_eq!(config.interface, "kc0");
        assert_eq!(config.ports, vec![1]);
        assert!(config.hosts.is_empty());
        assert_eq!(config.mode, Mode::Skb);
    }

    #[test]
    fn rejects_invalid() {
        assert!(PartialConfig::parse("bogus = 1").is_err());
        assert!(PartialConfig::parse("ports = [25565]")
            .unwrap()
            .resolve()
            .is_err());
        assert!(PartialConfig::parse("interface = \"eth0\"")
            .unwrap()
            .resolve()
            .is_err());
        assert!(PartialConfig::parse("interface = \"eth0\"\nports = [0]")
            .unwrap()
            .resolve()
            .is_err());
        assert!(
            PartialConfig::parse("interface = \"eth0\"\nports = [1]\nflows_max = 0")
                .unwrap()
                .resolve()
                .is_err()
        );
        let err = PartialConfig::parse("interface = \"eth0\"\nports = [1]\nhosts = [\"a b\"]")
            .unwrap()
            .resolve()
            .unwrap_err();
        assert!(format!("{err:#}").contains("host \"a b\""));
    }

    #[test]
    fn serializes_effective_config() {
        let config = PartialConfig::parse(FULL).unwrap().resolve().unwrap();
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("hosts = [\"play.example.com\", \"*.example.com\"]"));
        assert!(text.contains("mode = \"skb\""));
    }
}
