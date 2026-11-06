//! Hostname normalization and the LPM trie key encoding.
//!
//! The kernel reverses the server address from the handshake, folds every
//! byte with `| 0x20` and looks it up with a full length prefix. An exact
//! entry is the reversed name followed by a NUL, a wildcard is the reversed
//! base followed by a dot, so `*.example.com` matches every subdomain but not
//! the apex. Stored entries go through the same fold, which is why only
//! characters that survive it are accepted.

use std::error::Error;
use std::fmt;

use serde::{Serialize, Serializer};

use crate::abi::{HostKey, HOST_EXACT, HOST_KEY_LEN, HOST_WILDCARD, MAX_HOST};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostPattern {
    Exact(String),
    /// The base without the leading `*.`.
    Wildcard(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostError {
    Empty,
    TooLong(usize),
    ForbiddenChar(char),
    TrailingDot,
    BadWildcard,
    BadKey(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostError::Empty => write!(f, "hostname is empty"),
            HostError::TooLong(len) => {
                write!(f, "hostname is {len} bytes, the limit is {MAX_HOST}")
            }
            HostError::ForbiddenChar(c) => write!(
                f,
                "hostname contains {c:?}, allowed are ASCII letters, digits, '-', '.', '_' and ':'"
            ),
            HostError::TrailingDot => write!(f, "hostname ends with a dot"),
            HostError::BadWildcard => {
                write!(f, "'*' is only allowed as a leading \"*.\" label")
            }
            HostError::BadKey(why) => write!(f, "invalid trie key: {why}"),
        }
    }
}

impl Error for HostError {}

fn allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':')
}

/// The kernel's case fold. Besides lowercasing letters it turns '_' into 0x7f.
fn fold(byte: u8) -> u8 {
    byte | 0x20
}

fn unfold(byte: u8) -> u8 {
    if byte == 0x7f {
        b'_'
    } else {
        byte
    }
}

impl HostPattern {
    /// Normalizes user input: ASCII lowercase, one trailing dot stripped.
    pub fn parse(input: &str) -> Result<HostPattern, HostError> {
        let name = input.to_ascii_lowercase();
        let name = name.strip_suffix('.').unwrap_or(&name);
        if name.is_empty() {
            return Err(HostError::Empty);
        }
        let (pattern, stored_len) = match name.strip_prefix("*.") {
            Some(base) => (HostPattern::Wildcard(base.to_string()), base.len() + 1),
            None => (HostPattern::Exact(name.to_string()), name.len()),
        };
        if pattern.base().is_empty() || pattern.base().contains('*') {
            return Err(HostError::BadWildcard);
        }
        if let Some(c) = pattern.base().chars().find(|c| !allowed(*c)) {
            return Err(HostError::ForbiddenChar(c));
        }
        if pattern.base().ends_with('.') {
            return Err(HostError::TrailingDot);
        }
        if stored_len > MAX_HOST {
            return Err(HostError::TooLong(stored_len));
        }
        Ok(pattern)
    }

    /// Decodes a key read back from the trie.
    pub fn from_key(prefixlen: u32, data: &[u8]) -> Result<HostPattern, HostError> {
        if !prefixlen.is_multiple_of(8) {
            return Err(HostError::BadKey(format!(
                "prefixlen {prefixlen} is not a byte multiple"
            )));
        }
        let len = (prefixlen / 8) as usize;
        if len < 2 || len > data.len() {
            return Err(HostError::BadKey(format!(
                "prefixlen {prefixlen} out of range"
            )));
        }
        let base: Vec<u8> = data[..len - 1].iter().rev().map(|b| unfold(*b)).collect();
        let base = String::from_utf8_lossy(&base).into_owned();
        match data[len - 1] {
            0 => Ok(HostPattern::Exact(base)),
            b'.' => Ok(HostPattern::Wildcard(base)),
            other => Err(HostError::BadKey(format!("terminator byte {other:#04x}"))),
        }
    }

    pub fn key(&self) -> HostKey {
        let mut data = [0u8; HOST_KEY_LEN];
        let base = self.base().as_bytes();
        for (dst, src) in data.iter_mut().zip(base.iter().rev()) {
            *dst = fold(*src);
        }
        data[base.len()] = match self {
            HostPattern::Exact(_) => 0,
            HostPattern::Wildcard(_) => b'.',
        };
        HostKey {
            prefixlen: ((base.len() + 1) * 8) as u32,
            data,
        }
    }

    /// The trie value, `HOST_EXACT` or `HOST_WILDCARD`.
    pub fn kind(&self) -> u8 {
        match self {
            HostPattern::Exact(_) => HOST_EXACT,
            HostPattern::Wildcard(_) => HOST_WILDCARD,
        }
    }

    fn base(&self) -> &str {
        match self {
            HostPattern::Exact(name) | HostPattern::Wildcard(name) => name,
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(name) => f.write_str(name),
            HostPattern::Wildcard(base) => write!(f, "*.{base}"),
        }
    }
}

impl Serialize for HostPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Turns the reversed bytes the kernel reports back into a readable name.
pub fn unreverse(reversed: &[u8]) -> String {
    let bytes: Vec<u8> = reversed.iter().rev().copied().collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_bytes(pattern: &HostPattern) -> (u32, Vec<u8>) {
        let key = pattern.key();
        let len = (key.prefixlen / 8) as usize;
        (key.prefixlen, key.data[..len].to_vec())
    }

    #[test]
    fn exact_key_is_reversed_with_nul() {
        let pattern = HostPattern::parse("Example.COM").unwrap();
        assert_eq!(pattern, HostPattern::Exact("example.com".into()));
        assert_eq!(key_bytes(&pattern), (12 * 8, b"moc.elpmaxe\0".to_vec()));
        assert_eq!(pattern.kind(), HOST_EXACT);
        assert_eq!(pattern.to_string(), "example.com");
    }

    #[test]
    fn wildcard_key_is_reversed_with_dot() {
        let pattern = HostPattern::parse("*.example.com.").unwrap();
        assert_eq!(pattern, HostPattern::Wildcard("example.com".into()));
        assert_eq!(key_bytes(&pattern), (12 * 8, b"moc.elpmaxe.".to_vec()));
        assert_eq!(pattern.kind(), HOST_WILDCARD);
        assert_eq!(pattern.to_string(), "*.example.com");
    }

    #[test]
    fn key_tail_is_zeroed() {
        let key = HostPattern::parse("a").unwrap().key();
        assert_eq!(&key.data[..2], b"a\0");
        assert!(key.data[2..].iter().all(|b| *b == 0));
    }

    #[test]
    fn roundtrip_through_key() {
        for input in [
            "example.com",
            "*.example.com",
            "mc.play.example.net",
            "xn--bcher-kva.de",
        ] {
            let pattern = HostPattern::parse(input).unwrap();
            let key = pattern.key();
            assert_eq!(
                HostPattern::from_key(key.prefixlen, &key.data).unwrap(),
                pattern
            );
        }
    }

    #[test]
    fn key_uses_the_kernel_fold() {
        let pattern = HostPattern::parse("Play_Host.Example:25565").unwrap();
        assert_eq!(
            pattern,
            HostPattern::Exact("play_host.example:25565".into())
        );
        let (_, bytes) = key_bytes(&pattern);
        assert_eq!(bytes, b"56552:elpmaxe.tsoh\x7fyalp\0".to_vec());
        let key = pattern.key();
        assert_eq!(
            HostPattern::from_key(key.prefixlen, &key.data).unwrap(),
            pattern
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(HostPattern::parse(""), Err(HostError::Empty));
        assert_eq!(HostPattern::parse("."), Err(HostError::Empty));
        assert_eq!(
            HostPattern::parse("example.com.."),
            Err(HostError::TrailingDot)
        );
        assert_eq!(
            HostPattern::parse("a b.com"),
            Err(HostError::ForbiddenChar(' '))
        );
        assert_eq!(
            HostPattern::parse("a\tb"),
            Err(HostError::ForbiddenChar('\t'))
        );
        assert_eq!(
            HostPattern::parse("a\0b"),
            Err(HostError::ForbiddenChar('\0'))
        );
        assert_eq!(
            HostPattern::parse("a/b"),
            Err(HostError::ForbiddenChar('/'))
        );
        assert_eq!(
            HostPattern::parse("[::1]"),
            Err(HostError::ForbiddenChar('['))
        );
        assert_eq!(
            HostPattern::parse("bücher.de"),
            Err(HostError::ForbiddenChar('ü'))
        );
        assert_eq!(
            HostPattern::parse("*.a b"),
            Err(HostError::ForbiddenChar(' '))
        );
        assert_eq!(HostPattern::parse("*"), Err(HostError::BadWildcard));
        assert_eq!(HostPattern::parse("*."), Err(HostError::BadWildcard));
        assert_eq!(
            HostPattern::parse("*example.com"),
            Err(HostError::BadWildcard)
        );
        assert_eq!(
            HostPattern::parse("mc.*.example.com"),
            Err(HostError::BadWildcard)
        );
        assert_eq!(
            HostPattern::parse("*.*.example.com"),
            Err(HostError::BadWildcard)
        );
    }

    #[test]
    fn length_limit_follows_max_host() {
        let longest = "a".repeat(MAX_HOST);
        assert!(HostPattern::parse(&longest).is_ok());
        assert_eq!(
            HostPattern::parse(&format!("{longest}b")),
            Err(HostError::TooLong(MAX_HOST + 1))
        );
        let base = "a".repeat(MAX_HOST - 1);
        assert!(HostPattern::parse(&format!("*.{base}")).is_ok());
        assert_eq!(
            HostPattern::parse(&format!("*.{base}b")),
            Err(HostError::TooLong(MAX_HOST + 1))
        );
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(HostPattern::from_key(7, b"a\0").is_err());
        assert!(HostPattern::from_key(8, b"a\0").is_err());
        assert!(HostPattern::from_key(24, b"a\0").is_err());
        assert!(HostPattern::from_key(16, b"ab").is_err());
    }

    #[test]
    fn unreverse_restores_order() {
        assert_eq!(unreverse(b"moc.elpmaxe"), "example.com");
        assert_eq!(unreverse(b""), "");
    }
}
