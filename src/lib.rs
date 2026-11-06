//! Userspace side of kcart, an XDP filter that drops Minecraft handshakes
//! whose server address is not on the allow list.
//!
//! The kernel program lives in `bpf/kcart.bpf.c`, is compiled by `build.rs`
//! and embedded as [`BPF_OBJECT`]. [`abi`] mirrors the shared header,
//! [`hosts`] turns hostnames into trie keys, [`events`] decodes drop
//! events from the ring buffer and [`sockets`] finds the server's listeners
//! for the socket check.

pub mod abi;
pub mod config;
pub mod events;
pub mod hosts;
pub mod sockets;

/// The compiled XDP object, ready for `aya::EbpfLoader`.
pub const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kcart.bpf.o"));

/// Name of the XDP program function inside [`BPF_OBJECT`].
pub const PROGRAM_NAME: &str = "kcart_xdp";
