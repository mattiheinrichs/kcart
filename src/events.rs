//! Decoding of drop events from the ring buffer.

use std::error::Error;
use std::fmt;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;

use crate::abi::{Event, Reason, AF_INET, AF_INET6, HOST_KEY_LEN};
use crate::hosts::unreverse;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropEvent {
    /// `CLOCK_MONOTONIC` nanoseconds at the time of the drop.
    pub ts_ns: u64,
    pub reason: Reason,
    pub src: SocketAddr,
    pub dport: u16,
    pub host: String,
    pub protocol_version: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventError {
    TooShort { len: usize, expected: usize },
    UnknownReason(u8),
    UnknownFamily(u8),
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventError::TooShort { len, expected } => {
                write!(f, "event record is {len} bytes, expected {expected}")
            }
            EventError::UnknownReason(reason) => write!(f, "unknown reason {reason}"),
            EventError::UnknownFamily(family) => write!(f, "unknown address family {family}"),
        }
    }
}

impl Error for EventError {}

impl DropEvent {
    pub fn parse(bytes: &[u8]) -> Result<DropEvent, EventError> {
        let expected = size_of::<Event>();
        if bytes.len() < expected {
            return Err(EventError::TooShort {
                len: bytes.len(),
                expected,
            });
        }
        // SAFETY: the length is checked above and Event is plain old data,
        // so any byte pattern is a valid value.
        let raw: Event = unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) };
        Self::from_raw(&raw)
    }

    pub fn from_raw(raw: &Event) -> Result<DropEvent, EventError> {
        let ip = match raw.family {
            AF_INET => IpAddr::V4(Ipv4Addr::from(u32::from_be(raw.saddr[0]))),
            AF_INET6 => {
                let mut bytes = [0u8; 16];
                for (i, word) in raw.saddr.iter().enumerate() {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            other => return Err(EventError::UnknownFamily(other)),
        };
        let reason = Reason::from_u8(raw.reason).ok_or(EventError::UnknownReason(raw.reason))?;
        let host_len = usize::from(raw.host_len).min(HOST_KEY_LEN);
        Ok(DropEvent {
            ts_ns: raw.ts_ns,
            reason,
            src: SocketAddr::new(ip, u16::from_be(raw.sport)),
            dport: u16::from_be(raw.dport),
            host: unreverse(&raw.host[..host_len]),
            protocol_version: raw.protocol_version,
        })
    }

    pub fn text_line(&self) -> String {
        format!(
            "drop reason={} src={} dport={} host={:?} proto={}",
            self.reason.name(),
            self.src,
            self.dport,
            self.host,
            self.protocol_version
        )
    }

    /// `wall_ms` is the drop time as unix milliseconds, computed by the caller
    /// since only it knows the offset between the monotonic and wall clocks.
    pub fn json_line(&self, wall_ms: u64) -> String {
        serde_json::json!({
            "event": "drop",
            "ts_ms": wall_ms,
            "reason": self.reason.name(),
            "src": self.src.ip().to_string(),
            "sport": self.src.port(),
            "dport": self.dport,
            "host": self.host,
            "proto": self.protocol_version,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;
    use std::slice;

    fn raw(family: u8, saddr: [u32; 4], host: &[u8]) -> Event {
        let mut event = Event {
            ts_ns: 42,
            saddr,
            protocol_version: 767,
            sport: 51234u16.to_be(),
            dport: 25565u16.to_be(),
            family,
            reason: Reason::DropHostNotAllowed as u8,
            host_len: host.len() as u8,
            pad: 0,
            host: [0; HOST_KEY_LEN],
        };
        event.host[..host.len()].copy_from_slice(host);
        event
    }

    fn bytes(event: &Event) -> &[u8] {
        // SAFETY: Event is plain old data, viewing it as bytes is sound.
        unsafe { slice::from_raw_parts((event as *const Event).cast(), size_of::<Event>()) }
    }

    #[test]
    fn ipv4_event() {
        let event = raw(
            AF_INET,
            [u32::from(Ipv4Addr::new(1, 2, 3, 4)).to_be(), 0, 0, 0],
            b"4.3.2.1",
        );
        let parsed = DropEvent::parse(bytes(&event)).unwrap();
        assert_eq!(parsed.src, "1.2.3.4:51234".parse().unwrap());
        assert_eq!(parsed.dport, 25565);
        assert_eq!(parsed.host, "1.2.3.4");
        assert_eq!(
            parsed.text_line(),
            "drop reason=host_not_allowed src=1.2.3.4:51234 dport=25565 host=\"1.2.3.4\" proto=767"
        );
        assert_eq!(
            parsed.json_line(1700000000123),
            "{\"dport\":25565,\"event\":\"drop\",\"host\":\"1.2.3.4\",\"proto\":767,\"reason\":\"host_not_allowed\",\"sport\":51234,\"src\":\"1.2.3.4\",\"ts_ms\":1700000000123}"
        );
    }

    #[test]
    fn ipv6_event() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let octets = ip.octets();
        let mut saddr = [0u32; 4];
        for (word, chunk) in saddr.iter_mut().zip(octets.chunks_exact(4)) {
            *word = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let parsed = DropEvent::from_raw(&raw(AF_INET6, saddr, b"moc.elpmaxe")).unwrap();
        assert_eq!(parsed.src, SocketAddr::new(IpAddr::V6(ip), 51234));
        assert_eq!(parsed.host, "example.com");
        assert!(parsed.text_line().contains("src=[2001:db8::1]:51234"));
    }

    #[test]
    fn host_is_escaped_in_text() {
        let parsed = DropEvent::from_raw(&raw(AF_INET, [0; 4], b"\"a\n")).unwrap();
        assert!(parsed.text_line().ends_with("host=\"\\na\\\"\" proto=767"));
    }

    #[test]
    fn rejects_bad_records() {
        let event = raw(AF_INET, [0; 4], b"");
        let short = &bytes(&event)[..size_of::<Event>() - 1];
        assert!(matches!(
            DropEvent::parse(short),
            Err(EventError::TooShort { .. })
        ));

        let mut bad_family = event;
        bad_family.family = 7;
        assert_eq!(
            DropEvent::from_raw(&bad_family),
            Err(EventError::UnknownFamily(7))
        );

        let mut bad_reason = event;
        bad_reason.reason = 200;
        assert_eq!(
            DropEvent::from_raw(&bad_reason),
            Err(EventError::UnknownReason(200))
        );
    }
}
