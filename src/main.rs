mod hosts_cmd;
mod logger;
mod pins;
mod run;
mod stats;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use kcart::config::PartialConfig;

#[derive(Parser)]
#[command(name = "kcart", version, about = "XDP filter for Minecraft servers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load the filter, attach it and print drop events until SIGINT or SIGTERM
    Run(run::RunArgs),
    /// Show the counters of the running filter
    Stats(stats::StatsArgs),
    /// List or change the allowed hosts of the running filter
    Hosts(hosts_cmd::HostsArgs),
    /// Validate a config file and print the effective config
    CheckConfig {
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Run(args) => run::run(args),
        Command::Stats(args) => stats::stats(&args),
        Command::Hosts(args) => hosts_cmd::hosts(&args),
        Command::CheckConfig { config } => check_config(&config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("kcart: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn check_config(path: &Path) -> Result<()> {
    let config = PartialConfig::load(path)?.resolve()?;
    for warning in config.warnings() {
        eprintln!("warning: {warning}");
    }
    print!("{}", toml::to_string(&config)?);
    Ok(())
}
