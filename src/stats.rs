use std::io::{self, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use kcart::abi::Reason;

use crate::pins::{self, StatsMap};

#[derive(Args)]
pub struct StatsArgs {
    #[arg(long, default_value = pins::DEFAULT_PIN_DIR, value_name = "DIR")]
    pin_dir: PathBuf,
    /// Print the table again every N seconds
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
    watch: Option<u64>,
}

pub fn stats(args: &StatsArgs) -> Result<()> {
    loop {
        // Reopened every round so a restarted kcart is picked up.
        let counts = read_counts(&pins::stats(&args.pin_dir)?)?;
        print_table(&counts)?;
        match args.watch {
            Some(seconds) => {
                println!();
                thread::sleep(Duration::from_secs(seconds));
            }
            None => return Ok(()),
        }
    }
}

fn read_counts(map: &StatsMap) -> Result<[u64; Reason::COUNT]> {
    let mut counts = [0u64; Reason::COUNT];
    for (slot, reason) in counts.iter_mut().zip(Reason::ALL) {
        let per_cpu = map
            .get(&reason.index(), 0)
            .with_context(|| format!("reading counter {reason}"))?;
        *slot = per_cpu.iter().sum();
    }
    Ok(counts)
}

fn print_table(counts: &[u64; Reason::COUNT]) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{:<8} {:<18} {:>14}", "VERDICT", "REASON", "COUNT")?;
    let mut passed = 0u64;
    let mut dropped = 0u64;
    for (reason, count) in Reason::ALL.into_iter().zip(counts) {
        writeln!(
            out,
            "{:<8} {:<18} {:>14}",
            reason.verdict(),
            reason.name(),
            count
        )?;
        if reason.is_drop() {
            dropped += count;
        } else {
            passed += count;
        }
    }
    writeln!(out, "{:<27} {:>14}", "total passed", passed)?;
    writeln!(out, "{:<27} {:>14}", "total dropped", dropped)?;
    Ok(())
}
