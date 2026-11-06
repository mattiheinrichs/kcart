// SPDX-License-Identifier: GPL-2.0
/*
 * kcart: drop Minecraft connections whose handshake does not carry an
 * allowed hostname. Runs as XDP on the public interface.
 *
 * The program sees single frames, not streams. The Minecraft handshake is
 * the first data segment a client sends and always fits into one segment,
 * so the first payload-carrying packet of every unknown flow is inspected.
 * Flows with a valid handshake are remembered in an LRU map and all later
 * packets pass with a single lookup.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "kcart.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_HOPOPTS 0
#define IPPROTO_TCP 6
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60
#define IPPROTO_MH 135

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

#define ETH_HLEN 14
#define VLAN_HLEN 4
#define IPV6_HLEN 40
#define TCP_MIN_HLEN 20

/*
 * RFC 8200 allows each extension header once, destination options twice:
 * eight is more than any legitimate chain. Eight headers of at most 2048
 * bytes fit under the mask.
 */
#define IPV6_EXT_MAX 8
#define IPV6_EXT_MASK 0x7fff

enum l3_status {
	L3_TCP,
	L3_NOT_OURS,
	L3_DROP,
};

#define FLOWS_DEFAULT_MAX 262144
#define HOSTS_MAX 1024
#define EVENTS_RINGBUF_BYTES (1 << 20)

/*
 * Own header layouts instead of the uapi ones: those use endian dependent
 * bitfields and pull in asm/ headers that are not on clang's bpf include path.
 */
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

struct vlanhdr {
	__be16 tci;
	__be16 encapsulated_proto;
};

struct iphdr {
	__u8 version_ihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__be32 version_class_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct ipv6_opthdr {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct ipv6_fraghdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_res;
	__u8 flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kcart_config);
} config SEC(".maps");

/* Indexed by TCP destination port, non-zero means the port is protected. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, HOSTS_MAX);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct kcart_host_key);
	__type(value, __u8);
} hosts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOWS_DEFAULT_MAX);
	__type(key, struct kcart_flow_key);
	__type(value, struct kcart_flow);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, KCART_REASON_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EVENTS_RINGBUF_BYTES);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kcart_rate);
} event_rate SEC(".maps");

/*
 * Per-CPU working memory for the handshake parser. The trie key alone is
 * 260 bytes, together with a copy of the hostname it would not fit the
 * 512 byte BPF stack.
 */
struct kcart_scratch {
	struct kcart_host_key key;
	__u8 raw[KCART_HOST_KEY_LEN];
	__u32 slot;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kcart_scratch);
} scratch SEC(".maps");

/*
 * Round trips a value through map memory. The compiler cannot forward the
 * store past the volatile access, so the verifier sees a fresh scalar with
 * nothing but the mask as its bound. Every data dependent loop below leaves
 * one verifier state per possible exit; without this the next loop would be
 * verified once per such state and the program would exceed the
 * instruction budget.
 */
static __always_inline __u32 launder(struct kcart_scratch *sc, __u32 value,
				     __u32 mask)
{
	*(volatile __u32 *)&sc->slot = value;
	return *(volatile __u32 *)&sc->slot & mask;
}

static __always_inline int verdict(__u32 reason, int action)
{
	__u64 *counter = bpf_map_lookup_elem(&stats, &reason);

	if (counter)
		(*counter)++;
	return action;
}

/*
 * Reads a Minecraft VarInt. Returns 0 on success, -1 when the packet ends
 * early and -2 when the encoding is longer than five bytes.
 */
static __always_inline int read_varint(const __u8 **cur, const __u8 *end,
				       __s32 *out, __u32 *consumed)
{
	const __u8 *p = *cur;
	__u32 value = 0;

#pragma unroll
	for (int i = 0; i < 5; i++) {
		if (p + 1 > end)
			return -1;
		__u8 b = *p++;

		value |= (__u32)(b & 0x7f) << (7 * i);
		if (!(b & 0x80)) {
			*cur = p;
			*out = (__s32)value;
			*consumed += i + 1;
			return 0;
		}
	}
	return -2;
}

static __always_inline __u8 varint_error(int err)
{
	return err == -1 ? KCART_DROP_TRUNCATED : KCART_DROP_MALFORMED;
}

/*
 * Copies hlen bytes of the hostname into sc->raw. Chunked so the verifier
 * only has to follow a handful of iterations over packet memory. Indices
 * are masked with KCART_HOST_IDX_MASK right at their use: the masks never
 * change a value in range, but they give the verifier a bound even when
 * the compiler reloads a value from a stack spill made before the check.
 */
static __always_inline __u8 copy_host(const __u8 *host, const __u8 *end,
				      __u32 hlen, struct kcart_scratch *sc)
{
	for (__u32 k = 0; k < KCART_MAX_HOST / 16 + 1; k++) {
		__u32 off = k * 16;

		if (off + 16 > hlen)
			break;
		if (host + off + 16 > end)
			return KCART_DROP_TRUNCATED;
		__builtin_memcpy(sc->raw + off, host + off, 16);
	}

	__u32 base = hlen & ~15u;

	for (__u32 t = 0; t < 16; t++) {
		__u32 off = (base + t) & KCART_HOST_IDX_MASK;

		if (off >= hlen)
			break;
		if (host + off + 1 > end)
			return KCART_DROP_TRUNCATED;
		sc->raw[off] = host[off];
	}
	return 0;
}

/*
 * Builds the trie key from sc->raw: cut at the first NUL (Forge and
 * BungeeCord append "\0..." to the hostname), strip one trailing dot,
 * reverse and fold case. Returns the effective hostname length, or 0 when
 * the name contains a control character.
 */
static __always_inline __u32 build_host_key(struct kcart_scratch *sc, __u32 hlen)
{
	__u32 eff = hlen;

	for (__u32 i = 0; i < KCART_MAX_HOST; i++) {
		if (i >= hlen)
			break;
		if (sc->raw[i] == 0) {
			eff = i;
			break;
		}
	}

	eff = launder(sc, eff, KCART_HOST_IDX_MASK);
	if (eff > 0 && sc->raw[(eff - 1) & KCART_HOST_IDX_MASK] == '.')
		eff--;
	eff = launder(sc, eff, KCART_HOST_IDX_MASK);

	sc->key.prefixlen = KCART_HOST_KEY_LEN * 8;
	__u32 control = 0;

	for (__u32 i = 0; i < KCART_MAX_HOST; i++) {
		if (i >= eff)
			break;
		__u32 j = (eff - 1 - i) & KCART_HOST_IDX_MASK;
		__u32 c = sc->raw[j];

		/*
		 * Both branch free: the fold ORs in the case bit, userspace stores
		 * keys the same way. Control characters would fold onto printable
		 * ones (0x0e onto '.'), so they are flagged and rejected below.
		 */
		control |= ((c >> 5) - 1) >> 31;
		sc->key.data[i] = c | 0x20;
	}
	eff = launder(sc, eff, KCART_HOST_IDX_MASK);
	/* The scratch memory is reused, the terminator must be written each time. */
	sc->key.data[eff] = 0;
	return control ? 0 : eff;
}

/*
 * Parses the handshake at cur and fills sc->key with the reversed, lowercased
 * hostname. Returns 0 when the structure is sound, otherwise a reason.
 */
static __always_inline __u8 parse_handshake(const __u8 *cur, const __u8 *end,
					    struct kcart_scratch *sc,
					    __s32 *protocol_version,
					    __u8 *host_len)
{
	const __u8 *payload = cur;
	__s32 packet_len, packet_id, hlen_signed, next_state;
	__u32 prefix = 0;
	__u32 consumed = 0;
	int err;

	if (cur + 1 > end)
		return KCART_DROP_TRUNCATED;
	if (*cur == 0xFE)
		return KCART_PASS_LEGACY_PING;

	err = read_varint(&cur, end, &packet_len, &prefix);
	if (err)
		return varint_error(err);
	if (packet_len <= 0)
		return KCART_DROP_MALFORMED;

	err = read_varint(&cur, end, &packet_id, &consumed);
	if (err)
		return varint_error(err);
	if (packet_id != 0)
		return KCART_DROP_MALFORMED;

	err = read_varint(&cur, end, protocol_version, &consumed);
	if (err)
		return varint_error(err);

	err = read_varint(&cur, end, &hlen_signed, &consumed);
	if (err)
		return varint_error(err);
	if (hlen_signed < 0)
		return KCART_DROP_MALFORMED;
	if (hlen_signed > KCART_MAX_HOST)
		return KCART_DROP_HOST_TOO_LONG;

	__u32 hlen = hlen_signed & KCART_HOST_IDX_MASK;
	const __u8 *host = cur;

	prefix += consumed;
	if (host + hlen > end)
		return KCART_DROP_TRUNCATED;
	cur = host + hlen;
	consumed += hlen;

	/* server port, not verified */
	if (cur + 2 > end)
		return KCART_DROP_TRUNCATED;
	cur += 2;
	consumed += 2;

	err = read_varint(&cur, end, &next_state, &consumed);
	if (err)
		return varint_error(err);
	if (next_state < 1 || next_state > 3)
		return KCART_DROP_MALFORMED;
	if (consumed != (__u32)packet_len)
		return KCART_DROP_MALFORMED;

	/*
	 * Four VarInts of one to five bytes each leave hundreds of verifier
	 * states with different pointer offsets and value widths. Rebuild the
	 * values the loops depend on from laundered scalars so they collapse
	 * into one state before the loops.
	 */
	host = payload + launder(sc, prefix, 0x1f);
	hlen = launder(sc, hlen, KCART_HOST_IDX_MASK);
	*protocol_version = launder(sc, *protocol_version, 0xffffffff);

	__u8 reason = copy_host(host, end, hlen, sc);

	if (reason)
		return reason;
	*host_len = build_host_key(sc, hlen);
	if (!*host_len)
		return KCART_DROP_MALFORMED;
	return 0;
}

static __always_inline void emit_event(const struct kcart_config *cfg,
				       const struct kcart_flow_key *flow,
				       __u8 reason, __s32 protocol_version,
				       const struct kcart_host_key *key,
				       __u8 host_len)
{
	__u32 zero = 0;

	if (!cfg->events_per_sec)
		return;

	struct kcart_rate *rate = bpf_map_lookup_elem(&event_rate, &zero);

	if (!rate)
		return;

	__u64 now = bpf_ktime_get_ns();

	if (now - rate->last_ns >= 1000000000ULL) {
		rate->last_ns = now;
		rate->tokens = cfg->events_per_sec;
	}
	if (!rate->tokens)
		return;
	rate->tokens--;

	struct kcart_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);

	if (!ev)
		return;
	ev->ts_ns = now;
	__builtin_memcpy(ev->saddr, flow->saddr, sizeof(ev->saddr));
	ev->protocol_version = protocol_version;
	ev->sport = flow->sport;
	ev->dport = flow->dport;
	ev->family = flow->family;
	ev->reason = reason;
	ev->host_len = host_len;
	ev->pad = 0;
	__builtin_memcpy(ev->host, key->data, sizeof(ev->host));
	bpf_ringbuf_submit(ev, 0);
}

/*
 * Finds the TCP header behind an IPv4 header. l4_len receives the length IP
 * claims for it, l4_off the offset of the TCP header from l3.
 */
static __always_inline enum l3_status parse_ipv4(void *l3, void *data_end,
						 struct kcart_flow_key *flow,
						 struct tcphdr **tcp,
						 __u32 *l4_len, __u32 *l4_off)
{
	struct iphdr *ip = l3;

	if ((void *)(ip + 1) > data_end)
		return L3_NOT_OURS;
	if (ip->protocol != IPPROTO_TCP)
		return L3_NOT_OURS;
	if (ip->frag_off & bpf_htons(0x1fff))
		return L3_NOT_OURS;

	__u32 ihl = (ip->version_ihl & 0x0f) * 4;
	__u32 tot_len = bpf_ntohs(ip->tot_len);

	if (ihl < sizeof(*ip) || tot_len < ihl)
		return L3_NOT_OURS;

	flow->family = KCART_AF_INET;
	flow->saddr[0] = ip->saddr;
	flow->daddr[0] = ip->daddr;
	*l4_len = tot_len - ihl;
	*l4_off = ihl;
	*tcp = l3 + ihl;
	return L3_TCP;
}

static __always_inline int ipv6_is_ext(__u8 nexthdr)
{
	return nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
	       nexthdr == IPPROTO_DSTOPTS || nexthdr == IPPROTO_MH ||
	       nexthdr == IPPROTO_FRAGMENT || nexthdr == IPPROTO_AH;
}

static __always_inline enum l3_status parse_ipv6(void *l3, void *data_end,
						 struct kcart_flow_key *flow,
						 struct tcphdr **tcp,
						 __u32 *l4_len, __u32 *l4_off)
{
	struct ipv6hdr *ip6 = l3;

	if ((void *)(ip6 + 1) > data_end)
		return L3_NOT_OURS;

	__u8 nexthdr = ip6->nexthdr;
	__u32 ext_len = 0;
	void *cur = ip6 + 1;

	/*
	 * Extension headers must be walked, otherwise a hop-by-hop option in
	 * front of the TCP header would bypass the filter. Laundering the
	 * offset after each header keeps the verifier from exploring every
	 * header combination separately through the rest of the program.
	 */
	if (nexthdr != IPPROTO_TCP) {
		__u32 zero = 0;
		struct kcart_scratch *sc = bpf_map_lookup_elem(&scratch, &zero);

		if (!sc)
			return L3_NOT_OURS;
		for (int i = 0; i < IPV6_EXT_MAX; i++) {
			if (!ipv6_is_ext(nexthdr))
				break;
			if (nexthdr == IPPROTO_FRAGMENT) {
				struct ipv6_fraghdr *frag = cur;

				if ((void *)(frag + 1) > data_end)
					return L3_NOT_OURS;
				if (frag->frag_off & bpf_htons(0xfff8))
					return L3_NOT_OURS;
				nexthdr = frag->nexthdr;
				ext_len += sizeof(*frag);
			} else {
				struct ipv6_opthdr *opt = cur;

				if ((void *)(opt + 1) > data_end)
					return L3_NOT_OURS;
				/* AH counts its length in 32 bit words, the others in 64 bit. */
				if (nexthdr == IPPROTO_AH)
					ext_len += ((__u32)opt->hdrlen + 2) * 4;
				else
					ext_len += ((__u32)opt->hdrlen + 1) * 8;
				nexthdr = opt->nexthdr;
			}
			ext_len = launder(sc, ext_len, IPV6_EXT_MASK);
			cur = (void *)(ip6 + 1) + ext_len;
		}
		/* A chain this long cannot be parsed, so it cannot be let through. */
		if (ipv6_is_ext(nexthdr))
			return L3_DROP;
		if (nexthdr != IPPROTO_TCP)
			return L3_NOT_OURS;
	}

	__u32 payload_len = bpf_ntohs(ip6->payload_len);

	if (payload_len < ext_len)
		return L3_NOT_OURS;

	flow->family = KCART_AF_INET6;
	__builtin_memcpy(flow->saddr, ip6->saddr, 16);
	__builtin_memcpy(flow->daddr, ip6->daddr, 16);
	*l4_len = payload_len - ext_len;
	*l4_off = IPV6_HLEN + ext_len;
	*tcp = cur;
	return L3_TCP;
}

/*
 * Asks the kernel whether a connection exists for the flow: established, or
 * still a request socket when the handshake data rides on the final ACK.
 * The lookup falls back to the listener for unknown tuples, hence the state
 * check.
 */
static __always_inline int socket_alive(struct xdp_md *ctx,
					const struct kcart_flow_key *flow)
{
	struct bpf_sock_tuple tuple = {};
	__u32 size;

	if (flow->family == KCART_AF_INET) {
		tuple.ipv4.saddr = flow->saddr[0];
		tuple.ipv4.daddr = flow->daddr[0];
		tuple.ipv4.sport = flow->sport;
		tuple.ipv4.dport = flow->dport;
		size = sizeof(tuple.ipv4);
	} else {
		__builtin_memcpy(tuple.ipv6.saddr, flow->saddr, 16);
		__builtin_memcpy(tuple.ipv6.daddr, flow->daddr, 16);
		tuple.ipv6.sport = flow->sport;
		tuple.ipv6.dport = flow->dport;
		size = sizeof(tuple.ipv6);
	}

	struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tuple, size,
						 BPF_F_CURRENT_NETNS, 0);

	if (!sk)
		return 0;

	__u32 state = sk->state;

	bpf_sk_release(sk);
	return state == BPF_TCP_ESTABLISHED || state == BPF_TCP_SYN_RECV ||
	       state == BPF_TCP_NEW_SYN_RECV;
}

static __always_inline __u32 csum_fold(__u64 sum)
{
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

/* RFC 1624 incremental update of a 16 bit field. */
static __always_inline void csum_replace16(__sum16 *check, __be16 old, __be16 new)
{
	__u64 sum = (__u16)~*check;

	sum += (__u16)~old;
	sum += new;
	*check = ~csum_fold(sum);
}

static __always_inline __u64 csum_words(const __be16 *words, __u32 count)
{
	__u64 sum = 0;

	for (__u32 i = 0; i < count; i++)
		sum += words[i];
	return sum;
}

/*
 * Rewrites the packet in place into a TCP RST from the client and shortens
 * it to the headers, so XDP_PASS makes the kernel reset the accepted socket.
 * The sequence number is the one the socket expects next, which is what the
 * stack requires to accept a reset. TCP options are dropped.
 */
static __always_inline int reset_to_stack(struct xdp_md *ctx, __u8 family,
					  __u32 l3_off, __u32 l4_off_total)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *l3 = data + l3_off;
	struct tcphdr *tcp = data + l4_off_total;
	__u64 sum;

	/*
	 * Pin both pointers to their registers, otherwise clang derives the
	 * bounds checks from data plus offset and the verifier does not carry
	 * the result over to the pointers used for the writes.
	 */
	asm volatile("" : "+r"(l3));
	asm volatile("" : "+r"(tcp));
	if ((void *)(tcp + 1) > data_end)
		return XDP_DROP;
	if (family == KCART_AF_INET) {
		if (l3 + sizeof(struct iphdr) > data_end)
			return XDP_DROP;
	} else if (l3 + sizeof(struct ipv6hdr) > data_end) {
		return XDP_DROP;
	}

	tcp->doff_res = (TCP_MIN_HLEN / 4) << 4;
	tcp->flags = TCP_RST | TCP_ACK;
	tcp->window = 0;
	tcp->urg_ptr = 0;
	tcp->check = 0;

	if (family == KCART_AF_INET) {
		struct iphdr *ip = l3;
		__be16 old_len = ip->tot_len;
		__be16 new_len = bpf_htons((ip->version_ihl & 0x0f) * 4 + TCP_MIN_HLEN);

		ip->tot_len = new_len;
		csum_replace16(&ip->check, old_len, new_len);
		sum = csum_words((const __be16 *)&ip->saddr, 4);
	} else {
		struct ipv6hdr *ip6 = l3;
		__u32 ext_len = l4_off_total - IPV6_HLEN;

		ip6->payload_len = bpf_htons(ext_len + TCP_MIN_HLEN);
		sum = csum_words((const __be16 *)ip6->saddr, 16);
	}
	sum += bpf_htons(IPPROTO_TCP) + bpf_htons(TCP_MIN_HLEN);
	sum += csum_words((const __be16 *)tcp, TCP_MIN_HLEN / 2);
	tcp->check = ~csum_fold(sum);

	__u32 frame_len = ctx->data_end - ctx->data;
	__u32 keep = l4_off_total + TCP_MIN_HLEN;

	if (frame_len > keep && bpf_xdp_adjust_tail(ctx, (int)keep - (int)frame_len))
		return XDP_DROP;
	return XDP_PASS;
}

/*
 * A SYN reuses the tuple of a finished connection, so the old flow state
 * goes. With the socket check a SYN against a live connection is a spoof
 * and leaves the state alone; the kernel answers it with a challenge ACK.
 * Called only on paths that return right after, the socket lookup is
 * expensive to verify and must not run into the handshake parser.
 */
static __always_inline void forget_on_syn(struct xdp_md *ctx,
					  const struct kcart_flow_key *flow)
{
	__u32 zero = 0;
	struct kcart_config *cfg = bpf_map_lookup_elem(&config, &zero);

	if (cfg && (cfg->flags & KCART_F_SOCKET_CHECK) && socket_alive(ctx, flow))
		return;
	bpf_map_delete_elem(&flows, flow);
}

SEC("xdp")
int kcart_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__be16 proto = eth->h_proto;
	void *l3 = eth + 1;
	__u32 l3_off = ETH_HLEN;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlanhdr *vlan = l3;

		if ((void *)(vlan + 1) > data_end)
			return XDP_PASS;
		proto = vlan->encapsulated_proto;
		l3 = vlan + 1;
		l3_off += VLAN_HLEN;
	}

	struct kcart_flow_key flow = {};
	struct tcphdr *tcp = NULL;
	__u32 l4_len = 0, l4_off = 0;
	enum l3_status status;

	if (proto == bpf_htons(ETH_P_IP))
		status = parse_ipv4(l3, data_end, &flow, &tcp, &l4_len, &l4_off);
	else if (proto == bpf_htons(ETH_P_IPV6))
		status = parse_ipv6(l3, data_end, &flow, &tcp, &l4_len, &l4_off);
	else
		return XDP_PASS;
	if (status == L3_DROP)
		return verdict(KCART_DROP_EXT_HEADERS, XDP_DROP);
	if (status != L3_TCP || !tcp || (void *)(tcp + 1) > data_end)
		return XDP_PASS;

	__u32 port = bpf_ntohs(tcp->dest);
	__u8 *protected = bpf_map_lookup_elem(&ports, &port);

	if (!protected || !*protected)
		return XDP_PASS;

	/* Header length or claimed IP length out of range: the stack drops it anyway. */
	__u32 doff = (tcp->doff_res >> 4) * 4;

	if (doff < sizeof(*tcp) || l4_len < doff)
		return XDP_PASS;

	__u32 payload_len = l4_len - doff;
	const __u8 *payload = (void *)tcp + doff;

	if ((void *)payload > data_end)
		return XDP_PASS;

	flow.sport = tcp->source;
	flow.dport = tcp->dest;

	__u8 flags = tcp->flags;
	int closing = flags & (TCP_FIN | TCP_RST);

	/*
	 * FIN and RST never delete flow state: they are easy to spoof and the
	 * next SYN or the LRU cleans up anyway.
	 */
	if (payload_len == 0) {
		if (flags & TCP_SYN)
			forget_on_syn(ctx, &flow);
		return verdict(KCART_PASS_NO_PAYLOAD, XDP_PASS);
	}

	/* A SYN with data skips the lookup: whatever state exists is stale. */
	if (!(flags & TCP_SYN) && bpf_map_lookup_elem(&flows, &flow))
		return verdict(KCART_PASS_KNOWN_FLOW, XDP_PASS);

	/* First payload of an unknown flow: this has to be the handshake. */
	__u32 zero = 0;
	struct kcart_config *cfg = bpf_map_lookup_elem(&config, &zero);

	if (!cfg)
		return XDP_PASS;

	struct kcart_scratch *sc = bpf_map_lookup_elem(&scratch, &zero);

	if (!sc)
		return XDP_PASS;

	__s32 protocol_version = 0;
	__u8 host_len = 0;
	__u8 reason = parse_handshake(payload, data_end, sc, &protocol_version,
				      &host_len);

	if (reason == KCART_PASS_LEGACY_PING) {
		if (cfg->flags & KCART_F_ALLOW_LEGACY_PING)
			return verdict(KCART_PASS_LEGACY_PING, XDP_PASS);
		reason = KCART_DROP_LEGACY_PING;
	} else if (reason == 0) {
		if (bpf_map_lookup_elem(&hosts, &sc->key)) {
			if (closing)
				return verdict(KCART_PASS_HANDSHAKE_OK, XDP_PASS);
			/* Without a connection behind it the packet is spoofed or stale. */
			if ((cfg->flags & KCART_F_SOCKET_CHECK) && !socket_alive(ctx, &flow))
				return verdict(KCART_PASS_NO_SOCKET, XDP_PASS);

			struct kcart_flow state = {
				.seen_ns = bpf_ktime_get_ns(),
			};

			bpf_map_update_elem(&flows, &flow, &state, BPF_ANY);
			return verdict(KCART_PASS_HANDSHAKE_OK, XDP_PASS);
		}
		reason = KCART_DROP_HOST_NOT_ALLOWED;
	}

	/*
	 * The parser leaves one verifier state per hostname length and reason.
	 * Laundering both lets the verifier check the drop path once instead of
	 * once per state.
	 */
	reason = launder(sc, reason, 0xf);
	host_len = launder(sc, host_len, KCART_HOST_IDX_MASK);
	emit_event(cfg, &flow, reason, protocol_version, &sc->key, host_len);
	if (flags & TCP_SYN)
		forget_on_syn(ctx, &flow);
	if (!(cfg->flags & KCART_F_RST))
		return verdict(reason, XDP_DROP);

	/*
	 * The packet pointers carry a different proven range on every parser
	 * exit, which also keeps the states apart. Rebuilding them from the
	 * laundered offsets gives every state the same pointers again.
	 */
	__u32 l4_at = launder(sc, l3_off + l4_off, 0x7fff);

	l3_off = launder(sc, l3_off, 0x3f);
	return verdict(reason, reset_to_stack(ctx, flow.family, l3_off, l4_at));
}

char LICENSE[] SEC("license") = "GPL";
