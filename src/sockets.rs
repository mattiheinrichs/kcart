//! Listening TCP sockets of this network namespace, read from /proc/net/tcp.

use std::collections::BTreeSet;
use std::fs;
use std::io;

use anyhow::{Context, Result};

const TABLES: [&str; 2] = ["/proc/net/tcp", "/proc/net/tcp6"];
/// `st` column value of a socket in `TCP_LISTEN`.
const LISTEN: &str = "0A";

/// The subset of `ports` that has a listening socket, sorted.
pub fn listening(ports: &[u16]) -> Result<Vec<u16>> {
    let mut found = BTreeSet::new();
    for path in TABLES {
        let table = match fs::read_to_string(path) {
            Ok(table) => table,
            // tcp6 is missing on kernels booted with ipv6.disable=1.
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("reading {path}")),
        };
        found.extend(listen_ports(&table).filter(|port| ports.contains(port)));
    }
    Ok(found.into_iter().collect())
}

/// Local ports of the LISTEN sockets in one /proc/net/tcp style table.
pub fn listen_ports(table: &str) -> impl Iterator<Item = u16> + '_ {
    table.lines().skip(1).filter_map(listen_port)
}

/// Columns are `sl local_address rem_address st ...`, local_address is
/// `0100007F:63DD` (or 32 hex digits for IPv6) with the port in hex.
fn listen_port(line: &str) -> Option<u16> {
    let mut columns = line.split_whitespace();
    let local = columns.nth(1)?;
    let state = columns.nth(1)?;
    if state != LISTEN {
        return None;
    }
    let (_, port) = local.rsplit_once(':')?;
    u16::from_str_radix(port, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:63DD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:63DD 0100007F:C3A4 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:63DE 00000000:0000 06 00000000:00000000 03:00000A5B 00000000     0        0 0 3 0000000000000000
";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:63DD 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12348 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:63DF 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12349 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn finds_listeners_only() {
        assert_eq!(listen_ports(TCP).collect::<Vec<_>>(), vec![25565, 22]);
        assert_eq!(listen_ports(TCP6).collect::<Vec<_>>(), vec![25565, 25567]);
    }

    #[test]
    fn ignores_header_and_garbage() {
        assert_eq!(listen_ports("").count(), 0);
        assert_eq!(listen_ports("header only\n").count(), 0);
        assert_eq!(
            listen_ports("header\n 0: nonsense\n 1: 0100007F 0 0A\n").count(),
            0
        );
        assert_eq!(
            listen_ports("header\n 0: 0100007F:ZZZZ 00000000:0000 0A\n").count(),
            0
        );
    }
}
