use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use aya::maps::MapError;
use clap::{Args, Subcommand};
use kcart::abi::{HOST_EXACT, HOST_WILDCARD};
use kcart::hosts::HostPattern;

use crate::pins;

#[derive(Args)]
pub struct HostsArgs {
    #[command(subcommand)]
    command: HostsCommand,
    #[arg(long, global = true, default_value = pins::DEFAULT_PIN_DIR, value_name = "DIR")]
    pin_dir: PathBuf,
}

#[derive(Subcommand)]
enum HostsCommand {
    /// Print the allowed hosts
    List,
    /// Allow a host until the next restart or config reload
    Add { host: String },
    /// Remove a host until the next restart or config reload
    Remove { host: String },
}

pub fn hosts(args: &HostsArgs) -> Result<()> {
    let mut map = pins::hosts(&args.pin_dir)?;
    match &args.command {
        HostsCommand::List => {
            let mut rows = Vec::new();
            for entry in map.iter() {
                let (key, value) = entry.context("reading the hosts map")?;
                match HostPattern::from_key(key.prefix_len(), &key.data()) {
                    Ok(pattern) => rows.push((pattern, value)),
                    Err(err) => eprintln!("warning: skipping undecodable entry: {err}"),
                }
            }
            rows.sort();
            for (pattern, value) in rows {
                let kind = match value {
                    HOST_EXACT => "exact",
                    HOST_WILDCARD => "wildcard",
                    _ => "unknown",
                };
                println!("{kind:<9} {pattern}");
            }
        }
        HostsCommand::Add { host } => {
            let pattern = parse(host)?;
            map.insert(&pins::trie_key(&pattern.key()), &pattern.kind(), 0)
                .with_context(|| format!("adding {pattern} to the hosts map"))?;
            println!("added {pattern}");
        }
        HostsCommand::Remove { host } => {
            let pattern = parse(host)?;
            match map.remove(&pins::trie_key(&pattern.key())) {
                Ok(()) => println!("removed {pattern}"),
                Err(MapError::SyscallError(err))
                    if err.io_error.raw_os_error() == Some(libc::ENOENT) =>
                {
                    bail!("{pattern} is not in the hosts map")
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("removing {pattern} from the hosts map"))
                }
            }
        }
    }
    Ok(())
}

fn parse(host: &str) -> Result<HostPattern> {
    HostPattern::parse(host).with_context(|| format!("host {host:?}"))
}
