use std::collections::HashSet;
use std::ffi::CString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, Map, MapData, RingBuf};
use aya::programs::xdp::XdpLinkId;
use aya::programs::{ProgramError, Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use clap::Args;
use kcart::abi;
use kcart::config::{Config, LogFormat, Mode, PartialConfig};
use kcart::events::DropEvent;
use kcart::hosts::HostPattern;
use log::{error, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{signal, SignalKind};

use crate::logger;
use crate::pins::{self, HostsMap, PinDir};

#[derive(Args)]
pub struct RunArgs {
    /// TOML config file, re-read on SIGHUP
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Interface to attach to
    #[arg(long, value_name = "IFACE")]
    iface: Option<String>,
    /// Protected TCP port, repeatable; replaces the ports from the config file
    #[arg(long = "port", value_name = "P")]
    ports: Vec<u16>,
    /// Allowed host, repeatable; replaces the hosts from the config file
    #[arg(long = "host", value_name = "H")]
    hosts: Vec<String>,
    /// XDP attach mode
    #[arg(long, value_enum)]
    mode: Option<Mode>,
    /// Size of the table of connections that passed the handshake
    #[arg(long, value_name = "N")]
    flows: Option<u32>,
    /// Cap on drop events per second and CPU, 0 disables events
    #[arg(long, value_name = "N")]
    events_per_sec: Option<u32>,
    /// Let pre-1.7 server list pings through
    #[arg(long)]
    allow_legacy_ping: bool,
    /// Answer dropped handshakes with a TCP RST so the server closes the socket
    #[arg(long)]
    rst: bool,
    /// Format of the drop event lines on stdout
    #[arg(long, value_enum)]
    log_format: Option<LogFormat>,
    /// Where the maps are pinned for the stats and hosts commands
    #[arg(long, default_value = pins::DEFAULT_PIN_DIR, value_name = "DIR")]
    pin_dir: PathBuf,
}

impl RunArgs {
    fn overrides(&self) -> PartialConfig {
        PartialConfig {
            interface: self.iface.clone(),
            ports: non_empty(&self.ports),
            hosts: non_empty(&self.hosts),
            mode: self.mode,
            flows_max: self.flows,
            events_per_sec: self.events_per_sec,
            allow_legacy_ping: self.allow_legacy_ping.then_some(true),
            rst: self.rst.then_some(true),
            log_format: self.log_format,
        }
    }
}

fn non_empty<T: Clone>(values: &[T]) -> Option<Vec<T>> {
    (!values.is_empty()).then(|| values.to_vec())
}

fn load_config(path: Option<&Path>, overrides: &PartialConfig) -> Result<Config> {
    let file = match path {
        Some(path) => PartialConfig::load(path)?,
        None => PartialConfig::default(),
    };
    file.merge(overrides.clone()).resolve()
}

pub fn run(args: RunArgs) -> Result<()> {
    let overrides = args.overrides();
    let config = load_config(args.config.as_deref(), &overrides)?;
    logger::init(config.log_format)?;
    for warning in config.warnings() {
        warn!("{warning}");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    runtime.block_on(run_filter(
        args.config.as_deref(),
        &overrides,
        &args.pin_dir,
        config,
    ))
}

struct Maps {
    config: Array<MapData, abi::Config>,
    ports: Array<MapData, u8>,
    hosts: HostsMap,
}

fn take_map(bpf: &mut Ebpf, name: &str) -> Result<Map> {
    bpf.take_map(name)
        .with_context(|| format!("map {name} missing from the BPF object"))
}

fn take_maps(bpf: &mut Ebpf) -> Result<Maps> {
    Ok(Maps {
        config: Array::try_from(take_map(bpf, "config")?).context("config map")?,
        ports: Array::try_from(take_map(bpf, "ports")?).context("ports map")?,
        hosts: HostsMap::try_from(take_map(bpf, "hosts")?).context("hosts map")?,
    })
}

async fn run_filter(
    config_path: Option<&Path>,
    overrides: &PartialConfig,
    pin_dir: &Path,
    mut config: Config,
) -> Result<()> {
    let mut bpf = EbpfLoader::new()
        .map_max_entries("flows", config.flows_max)
        .load(kcart::BPF_OBJECT)
        .context("loading the BPF object")?;
    let pin_dir = PinDir::create(pin_dir)?;
    pin_dir.pin_maps(&bpf)?;

    let mut maps = take_maps(&mut bpf)?;
    apply(&mut maps, None, &config)?;
    let events = RingBuf::try_from(take_map(&mut bpf, "events")?).context("events map")?;
    // SAFETY: the ring buffer owns its descriptor and lives inside the AsyncFd.
    let mut events = unsafe { AsyncFd::register(events) }
        .map_err(|err| anyhow!("registering the ring buffer with tokio: {err}"))?;

    let program: &mut Xdp = bpf
        .program_mut(kcart::PROGRAM_NAME)
        .with_context(|| {
            format!(
                "program {} missing from the BPF object",
                kcart::PROGRAM_NAME
            )
        })?
        .try_into()
        .context("kcart_xdp is not an XDP program")?;
    program
        .load()
        .context("loading kcart_xdp into the kernel")?;

    let iface = CString::new(config.interface.as_str()).context("interface name")?;
    let (link, mode) = attach(program, &iface, config.mode)?;
    info!(
        "attached to {} in {mode} mode, ports {}, {} hosts, allow_legacy_ping={}, rst={}, pins under {}",
        config.interface,
        ports_list(&config.ports),
        config.hosts.len(),
        config.allow_legacy_ping,
        config.rst,
        pin_dir.path().display()
    );

    let result = event_loop(&mut events, &mut maps, &mut config, config_path, overrides).await;
    let detached = program.detach(link).context("detaching kcart_xdp");
    result.and(detached)
}

fn attach(program: &mut Xdp, iface: &CString, mode: Mode) -> Result<(XdpLinkId, &'static str)> {
    let native = || format!("attaching to {} in native mode", iface.to_string_lossy());
    let skb = || format!("attaching to {} in skb mode", iface.to_string_lossy());
    match mode {
        Mode::Native => Ok((
            program
                .attach(iface, XdpMode::Driver)
                .with_context(native)?,
            "native",
        )),
        Mode::Skb => Ok((
            program.attach(iface, XdpMode::Skb).with_context(skb)?,
            "skb",
        )),
        Mode::Auto => match program.attach(iface, XdpMode::Driver) {
            Ok(link) => Ok((link, "native")),
            Err(err @ ProgramError::UnknownInterface { .. }) => Err(err).with_context(native),
            Err(err) => {
                warn!("native XDP not available ({err}), falling back to skb mode");
                Ok((
                    program.attach(iface, XdpMode::Skb).with_context(skb)?,
                    "skb",
                ))
            }
        },
    }
}

async fn event_loop(
    events: &mut AsyncFd<RingBuf<MapData>>,
    maps: &mut Maps,
    config: &mut Config,
    config_path: Option<&Path>,
    overrides: &PartialConfig,
) -> Result<()> {
    let mut hangup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let clock = Clock::new()?;
    loop {
        tokio::select! {
            ready = events.readable_mut() => {
                let mut guard = ready.context("waiting for ring buffer events")?;
                // Clear first: the kernel only wakes the reader when it has
                // caught up, so a wakeup between draining and clearing would
                // be lost otherwise.
                guard.clear_ready();
                drain(guard.get_inner_mut(), config.log_format, &clock)?;
            }
            _ = hangup.recv() => reload(config_path, overrides, maps, config),
            _ = interrupt.recv() => {
                info!("got SIGINT, shutting down");
                return Ok(());
            }
            _ = terminate.recv() => {
                info!("got SIGTERM, shutting down");
                return Ok(());
            }
        }
    }
}

fn drain(ring: &mut RingBuf<MapData>, format: LogFormat, clock: &Clock) -> Result<()> {
    let mut out = io::stdout().lock();
    while let Some(item) = ring.next() {
        match DropEvent::parse(&item) {
            Ok(event) => {
                let line = match format {
                    LogFormat::Text => event.text_line(),
                    LogFormat::Json => event.json_line(clock.wall_ms(event.ts_ns)),
                };
                writeln!(out, "{line}").context("writing an event to stdout")?;
            }
            Err(err) => warn!("skipping unreadable event: {err}"),
        }
    }
    Ok(())
}

fn reload(
    config_path: Option<&Path>,
    overrides: &PartialConfig,
    maps: &mut Maps,
    current: &mut Config,
) {
    let Some(path) = config_path else {
        warn!("got SIGHUP but no config file was given, nothing to reload");
        return;
    };
    let next = match load_config(Some(path), overrides) {
        Ok(next) => next,
        Err(err) => {
            error!("reload failed, keeping the running config: {err:#}");
            return;
        }
    };
    if let Err(err) = apply(maps, Some(current), &next) {
        error!("reload failed while updating the maps: {err:#}");
        return;
    }
    for warning in next.warnings() {
        warn!("{warning}");
    }
    for (changed, field) in [
        (next.interface != current.interface, "interface"),
        (next.mode != current.mode, "mode"),
        (next.flows_max != current.flows_max, "flows_max"),
        (next.log_format != current.log_format, "log_format"),
    ] {
        if changed {
            warn!(
                "{field} changed in {}, this needs a restart",
                path.display()
            );
        }
    }
    info!(
        "config reloaded from {}, ports {}, {} hosts",
        path.display(),
        ports_list(&next.ports),
        next.hosts.len()
    );
    *current = next;
}

/// Brings the maps in line with `next`. `previous` is what the maps hold now,
/// `None` right after loading.
fn apply(maps: &mut Maps, previous: Option<&Config>, next: &Config) -> Result<()> {
    let previous_ports = previous
        .map(|config| config.ports.as_slice())
        .unwrap_or(&[]);
    sync_ports(&mut maps.ports, previous_ports, &next.ports)?;
    let (added, removed) = sync_hosts(&mut maps.hosts, &next.hosts)?;
    if previous.is_some() {
        info!("hosts synced: {added} added, {removed} removed");
    }
    maps.config
        .set(0, &next.bpf_config(), 0)
        .context("writing the config map")
}

fn sync_ports(map: &mut Array<MapData, u8>, previous: &[u16], next: &[u16]) -> Result<()> {
    for port in next {
        map.set(u32::from(*port), &1, 0)
            .with_context(|| format!("protecting port {port}"))?;
    }
    for port in previous.iter().filter(|port| !next.contains(port)) {
        map.set(u32::from(*port), &0, 0)
            .with_context(|| format!("unprotecting port {port}"))?;
    }
    Ok(())
}

/// Adds missing patterns, removes everything else. Returns (added, removed).
fn sync_hosts(map: &mut HostsMap, wanted: &[HostPattern]) -> Result<(usize, usize)> {
    let wanted: HashSet<&HostPattern> = wanted.iter().collect();
    let mut present = HashSet::new();
    let mut removed = 0;
    // Keys are collected first: deleting while iterating confuses get_next_key.
    let keys = map
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .context("reading the hosts map")?;
    for key in keys {
        match HostPattern::from_key(key.prefix_len(), &key.data()) {
            Ok(pattern) if wanted.contains(&pattern) => {
                present.insert(pattern);
            }
            decoded => {
                if let Err(err) = decoded {
                    warn!("removing undecodable hosts entry: {err}");
                }
                map.remove(&key).context("removing a hosts entry")?;
                removed += 1;
            }
        }
    }
    let mut added = 0;
    for pattern in wanted {
        if present.contains(pattern) {
            continue;
        }
        map.insert(&pins::trie_key(&pattern.key()), &pattern.kind(), 0)
            .with_context(|| format!("adding host {pattern}"))?;
        added += 1;
    }
    Ok((added, removed))
}

fn ports_list(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Converts the monotonic timestamps of events into wall clock time.
struct Clock {
    offset_ns: i128,
}

impl Clock {
    fn new() -> Result<Clock> {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime only writes into the timespec passed to it.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
            return Err(io::Error::last_os_error()).context("reading CLOCK_MONOTONIC");
        }
        let monotonic_ns = i128::from(now.tv_sec) * 1_000_000_000 + i128::from(now.tv_nsec);
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the unix epoch")?
            .as_nanos() as i128;
        Ok(Clock {
            offset_ns: wall_ns - monotonic_ns,
        })
    }

    fn wall_ms(&self, ts_ns: u64) -> u64 {
        let wall_ns = (self.offset_ns + i128::from(ts_ns)).max(0);
        (wall_ns / 1_000_000) as u64
    }
}
