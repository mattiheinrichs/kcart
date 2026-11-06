use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use aya::maps::lpm_trie::Key;
use aya::maps::{LpmTrie, Map, MapData, PerCpuArray};
use aya::Ebpf;
use kcart::abi::{HostKey, HOST_KEY_LEN};
use log::error;

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/kcart";
pub const PINNED_MAPS: [&str; 4] = ["config", "ports", "hosts", "stats"];

pub type HostsMap = LpmTrie<MapData, [u8; HOST_KEY_LEN], u8>;
pub type StatsMap = PerCpuArray<MapData, u64>;

pub fn trie_key(key: &HostKey) -> Key<[u8; HOST_KEY_LEN]> {
    Key::new(key.prefixlen, key.data)
}

fn open(pin_dir: &Path, name: &str) -> Result<Map> {
    let path = pin_dir.join(name);
    let data = MapData::from_pin(&path)
        .with_context(|| format!("opening pinned map {} (is kcart running?)", path.display()))?;
    Map::from_map_data(data).with_context(|| format!("unsupported map type at {}", path.display()))
}

pub fn hosts(pin_dir: &Path) -> Result<HostsMap> {
    HostsMap::try_from(open(pin_dir, "hosts")?).context("hosts map has an unexpected layout")
}

pub fn stats(pin_dir: &Path) -> Result<StatsMap> {
    StatsMap::try_from(open(pin_dir, "stats")?).context("stats map has an unexpected layout")
}

/// The pin directory of a running instance; the pins go away with it.
pub struct PinDir {
    path: PathBuf,
    created: bool,
}

impl PinDir {
    pub fn create(path: &Path) -> Result<PinDir> {
        let created = !path.exists();
        fs::create_dir_all(path)
            .with_context(|| format!("creating pin directory {}", path.display()))?;
        for name in PINNED_MAPS {
            let pin = path.join(name);
            if pin.exists() {
                bail!(
                    "{} exists: another kcart instance seems to be running, if it is not, remove the stale pins by hand",
                    pin.display()
                );
            }
        }
        Ok(PinDir {
            path: path.to_path_buf(),
            created,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pin_maps(&self, bpf: &Ebpf) -> Result<()> {
        for name in PINNED_MAPS {
            let map = bpf
                .map(name)
                .with_context(|| format!("map {name} missing from the BPF object"))?;
            map.pin(self.path.join(name))
                .with_context(|| format!("pinning map {name} under {}", self.path.display()))?;
        }
        Ok(())
    }
}

impl Drop for PinDir {
    fn drop(&mut self) {
        for name in PINNED_MAPS {
            let pin = self.path.join(name);
            match fs::remove_file(&pin) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => error!("removing pin {}: {err}", pin.display()),
            }
        }
        if self.created {
            if let Err(err) = fs::remove_dir(&self.path) {
                error!("removing pin directory {}: {err}", self.path.display());
            }
        }
    }
}
