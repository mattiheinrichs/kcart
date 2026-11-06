//! Mirror of `bpf/kcart.h`. Every struct here must match the C layout byte
//! for byte; the tests compare the constants against the header.

use std::fmt;

use aya::Pod;

/// `KCART_MAX_HOST`: longest hostname the filter accepts.
pub const MAX_HOST: usize = 255;
/// `KCART_HOST_KEY_LEN`: size of the hostname buffers and the trie key data.
pub const HOST_KEY_LEN: usize = 256;

const _: () = assert!(
    MAX_HOST < HOST_KEY_LEN,
    "an exact entry needs room for its terminator"
);

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// `kcart_config.flags` bit: let legacy (pre 1.7) server list pings through.
pub const F_ALLOW_LEGACY_PING: u32 = 1 << 0;
/// `kcart_config.flags` bit: answer dropped handshakes with a TCP RST.
pub const F_RST: u32 = 1 << 1;
/// `kcart_config.flags` bit: ask the kernel's socket table before touching
/// flow state, so spoofed packets can neither create nor delete entries.
pub const F_SOCKET_CHECK: u32 = 1 << 2;

/// Value of an exact hosts trie entry.
pub const HOST_EXACT: u8 = 1;
/// Value of a suffix wildcard hosts trie entry.
pub const HOST_WILDCARD: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub flags: u32,
    pub events_per_sec: u32,
}

unsafe impl Pod for Config {}

/// Key of the hosts LPM trie, see [`crate::hosts`] for the encoding.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostKey {
    pub prefixlen: u32,
    pub data: [u8; HOST_KEY_LEN],
}

unsafe impl Pod for HostKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowKey {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub family: u8,
    pub pad: [u8; 3],
}

unsafe impl Pod for FlowKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    pub seen_ns: u64,
}

unsafe impl Pod for Flow {}

/// One drop event as written to the ring buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub ts_ns: u64,
    pub saddr: [u32; 4],
    pub protocol_version: i32,
    pub sport: u16,
    pub dport: u16,
    pub family: u8,
    pub reason: u8,
    pub host_len: u8,
    pub pad: u8,
    /// Reversed and lowercased like the trie key, only `host_len` bytes are valid.
    pub host: [u8; HOST_KEY_LEN],
}

unsafe impl Pod for Event {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rate {
    pub last_ns: u64,
    pub tokens: u32,
    pub pad: u32,
}

unsafe impl Pod for Rate {}

/// `enum kcart_reason`, also the index into the stats array.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    PassNoPayload = 0,
    PassKnownFlow = 1,
    PassHandshakeOk = 2,
    PassLegacyPing = 3,
    DropHostNotAllowed = 4,
    DropHostTooLong = 5,
    DropMalformed = 6,
    DropTruncated = 7,
    DropLegacyPing = 8,
    PassNoSocket = 9,
    DropExtHeaders = 10,
}

impl Reason {
    /// `KCART_REASON_MAX`, the number of stats slots.
    pub const COUNT: usize = 11;

    pub const ALL: [Reason; Self::COUNT] = [
        Reason::PassNoPayload,
        Reason::PassKnownFlow,
        Reason::PassHandshakeOk,
        Reason::PassLegacyPing,
        Reason::DropHostNotAllowed,
        Reason::DropHostTooLong,
        Reason::DropMalformed,
        Reason::DropTruncated,
        Reason::DropLegacyPing,
        Reason::PassNoSocket,
        Reason::DropExtHeaders,
    ];

    pub fn from_u8(value: u8) -> Option<Reason> {
        Self::ALL.get(usize::from(value)).copied()
    }

    pub fn index(self) -> u32 {
        self as u32
    }

    pub fn is_drop(self) -> bool {
        matches!(
            self,
            Reason::DropHostNotAllowed
                | Reason::DropHostTooLong
                | Reason::DropMalformed
                | Reason::DropTruncated
                | Reason::DropLegacyPing
                | Reason::DropExtHeaders
        )
    }

    pub fn verdict(self) -> &'static str {
        if self.is_drop() {
            "drop"
        } else {
            "pass"
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Reason::PassNoPayload => "no_payload",
            Reason::PassKnownFlow => "known_flow",
            Reason::PassHandshakeOk => "handshake_ok",
            Reason::PassLegacyPing => "legacy_ping",
            Reason::DropHostNotAllowed => "host_not_allowed",
            Reason::DropHostTooLong => "host_too_long",
            Reason::DropMalformed => "malformed",
            Reason::DropTruncated => "truncated",
            Reason::DropLegacyPing => "legacy_ping",
            Reason::PassNoSocket => "no_socket",
            Reason::DropExtHeaders => "ext_headers",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.verdict(), self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    const HEADER: &str = include_str!("../bpf/kcart.h");

    fn header_define(name: &str) -> usize {
        let prefix = format!("#define {name} ");
        let line = HEADER
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{name} not found in bpf/kcart.h"));
        line[prefix.len()..]
            .split_whitespace()
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{name} is not a plain number in bpf/kcart.h"))
    }

    #[test]
    fn max_host_matches_header() {
        assert_eq!(MAX_HOST, header_define("KCART_MAX_HOST"));
        assert_eq!(HOST_KEY_LEN, header_define("KCART_HOST_KEY_LEN"));
        assert_eq!(AF_INET, header_define("KCART_AF_INET") as u8);
        assert_eq!(AF_INET6, header_define("KCART_AF_INET6") as u8);
        assert_eq!(HOST_EXACT, header_define("KCART_HOST_EXACT") as u8);
        assert_eq!(HOST_WILDCARD, header_define("KCART_HOST_WILDCARD") as u8);
        assert!(HEADER.contains("#define KCART_F_ALLOW_LEGACY_PING (1u << 0)"));
        assert!(HEADER.contains("#define KCART_F_RST (1u << 1)"));
        assert!(HEADER.contains("#define KCART_F_SOCKET_CHECK (1u << 2)"));
    }

    #[test]
    fn reason_count_matches_header() {
        let body = HEADER
            .split("enum kcart_reason {")
            .nth(1)
            .and_then(|rest| rest.split("};").next())
            .expect("enum kcart_reason in bpf/kcart.h");
        let names: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim().strip_suffix(','))
            .map(|name| name.split('=').next().unwrap_or(name).trim())
            .collect();
        assert_eq!(names.last(), Some(&"KCART_REASON_MAX"));
        assert_eq!(names.len() - 1, Reason::COUNT);
        for (i, reason) in Reason::ALL.iter().enumerate() {
            assert_eq!(reason.index() as usize, i);
            assert_eq!(Reason::from_u8(i as u8), Some(*reason));
        }
        assert_eq!(Reason::from_u8(Reason::COUNT as u8), None);
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(size_of::<Config>(), 8);
        assert_eq!(size_of::<HostKey>(), 4 + HOST_KEY_LEN);
        assert_eq!(size_of::<FlowKey>(), 40);
        assert_eq!(size_of::<Flow>(), 8);
        assert_eq!(size_of::<Rate>(), 16);
        assert_eq!(size_of::<Event>(), (36 + HOST_KEY_LEN).next_multiple_of(8));
    }
}
