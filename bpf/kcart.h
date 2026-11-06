/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared ABI between the kcart XDP program and the userspace loader.
 * Every struct here is mirrored in src/abi.rs; keep the two in sync.
 */
#ifndef KCART_H
#define KCART_H

#ifdef __bpf__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
#endif

/*
 * Longest hostname the filter accepts, the protocol maximum by default.
 * Override with -DKCART_MAX_HOST=64 for a cheaper verifier run on kernels
 * that reject the default.
 */
#ifndef KCART_MAX_HOST
#define KCART_MAX_HOST 255
#endif
/*
 * Size of the hostname buffers and the LPM trie key data. Fixed at 256 so
 * indices can be masked instead of bounds checked, which keeps the verifier
 * happy regardless of register spills.
 */
#define KCART_HOST_KEY_LEN 256
#define KCART_HOST_IDX_MASK (KCART_HOST_KEY_LEN - 1)

#define KCART_AF_INET 2
#define KCART_AF_INET6 10

/* Verdict reasons. Also the index into the per-CPU stats array. */
enum kcart_reason {
	KCART_PASS_NO_PAYLOAD = 0,
	KCART_PASS_KNOWN_FLOW,
	KCART_PASS_HANDSHAKE_OK,
	KCART_PASS_LEGACY_PING,
	KCART_DROP_HOST_NOT_ALLOWED,
	KCART_DROP_HOST_TOO_LONG,
	KCART_DROP_MALFORMED,
	KCART_DROP_TRUNCATED,
	KCART_DROP_LEGACY_PING,
	/* Valid handshake, but the kernel has no socket for the tuple. */
	KCART_PASS_NO_SOCKET,
	/* IPv6 extension header chain too long to parse, any port. */
	KCART_DROP_EXT_HEADERS,
	KCART_REASON_MAX,
};

/* kcart_config.flags */
#define KCART_F_ALLOW_LEGACY_PING (1u << 0)
/*
 * Turn a dropped packet into a TCP RST and hand it to the local stack, so
 * the kernel closes the already accepted socket instead of letting the
 * server wait for its handshake timeout.
 */
#define KCART_F_RST (1u << 1)
/*
 * Consult the kernel's socket table before creating or deleting flow
 * state. Spoofed packets can then neither poison the flow map nor knock
 * out a player's entry. Needs the server in the same network namespace as
 * the interface.
 */
#define KCART_F_SOCKET_CHECK (1u << 2)

struct kcart_config {
	__u32 flags;
	/* Upper bound on drop events emitted per second and CPU, 0 disables events. */
	__u32 events_per_sec;
};

/*
 * Key of the allowed hosts LPM trie. data holds the hostname reversed and
 * lowercased. An exact entry ends with a NUL byte ("moc.elpmaxe\0"), a
 * suffix wildcard ends with the dot ("moc.elpmaxe." for *.example.com).
 */
struct kcart_host_key {
	__u32 prefixlen;
	__u8 data[KCART_HOST_KEY_LEN];
};

#define KCART_HOST_EXACT 1
#define KCART_HOST_WILDCARD 2

struct kcart_flow_key {
	__u32 saddr[4];
	__u32 daddr[4];
	__u16 sport;
	__u16 dport;
	__u8 family;
	__u8 pad[3];
};

struct kcart_flow {
	__u64 seen_ns;
};

/* One drop event in the ring buffer. */
struct kcart_event {
	__u64 ts_ns;
	__u32 saddr[4];
	__s32 protocol_version;
	__u16 sport;
	__u16 dport;
	__u8 family;
	__u8 reason;
	__u8 host_len;
	__u8 pad;
	/* Reversed, lowercased, NUL cut, same bytes as the trie lookup key. */
	__u8 host[KCART_HOST_KEY_LEN];
};

struct kcart_rate {
	__u64 last_ns;
	__u32 tokens;
	__u32 pad;
};

#endif
