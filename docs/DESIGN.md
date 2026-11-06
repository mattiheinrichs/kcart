# Design

kcart is an XDP program plus a small loader. The XDP program runs on the
network interface before the kernel's TCP stack sees a packet.

## Packet flow

XDP sees frames, not TCP streams. The Minecraft handshake (packet id 0x00
in the handshaking state) is the first data a client sends after the TCP
three way handshake, it is at most a few hundred bytes, and every real
client sends it in a single segment. So the first payload carrying packet
of a flow is the handshake, and that one packet is all kcart looks at.

For every received frame:

1. Parse Ethernet (with up to two 802.1Q tags), IPv4 or IPv6 (including
   extension headers), TCP. Anything that is not TCP to a protected port
   passes untouched. This path costs a few comparisons and one array lookup.
2. A SYN deletes any flow state for the 4-tuple, because a client may reuse
   a port after TIME_WAIT. Packets without payload pass. FIN and RST never
   touch flow state.
3. A packet with payload is looked up in the flow map. A hit means the
   handshake was already verified: pass. This is the hot path for player
   traffic, one LRU hash lookup per packet.
4. No hit: the payload must be a handshake. The parser reads the VarInt
   framed fields, bounds checks every byte against the end of the frame and
   builds a lookup key from the hostname. On a match the flow is stored and
   the packet passes. Everything else is dropped: unknown hostname, hostname
   over the limit, broken VarInts, wrong packet id or next state, a handshake
   that does not fit the segment, legacy (pre 1.7) pings, and arbitrary
   garbage like HTTP probes.

Payload length is taken from the IP header, not from the frame length, so
Ethernet padding on small frames does not look like data. IPv6 extension
header chains are walked up to eight headers, including AH; a longer chain
cannot be parsed and is dropped on every port, since the kernel would still
deliver it.

## Spoofing

Everything above works on single frames with nothing but their own content
as evidence, and TCP header flags are trivial to spoof. Two attacks follow
from a naive design: a spoofed SYN on a player's 4-tuple would delete the
flow entry and the player's next packet would be treated as a failed
handshake, and spoofed packets with a valid handshake would create flow
entries for connections that do not exist until the LRU evicts real
players. Finding a player's source port is a matter of 65535 packets.

With the socket check on, kcart asks the kernel through
`bpf_skc_lookup_tcp` before it touches flow state. A SYN only deletes when
no established or half open socket exists for the tuple (a TIME_WAIT socket
counts as gone, so port reuse keeps working), and a valid handshake only
creates an entry when such a socket exists. The hot path is unchanged. The
lookup only sees the interface's network namespace, which is why the loader
checks for a listener on the protected ports in `/proc/net/tcp` and warns
when the server is not visible; in that case kcart falls back to the naive
behaviour. `bpf_tcp_sock`, which would allow checking sequence numbers and
bytes received, is not available to XDP programs.

## Hostname matching

Hostnames are matched with one lookup in an LPM trie keyed on the reversed
hostname. An exact entry for `play.example.com` is stored as
`moc.elpmaxe.yalp\0`, a wildcard `*.example.com` as `moc.elpmaxe.`. The
longest prefix match then covers exact names, suffix wildcards and look
alikes (`notexample.com` reversed does not start with `moc.elpmaxe.`) in a
single trie walk. A wildcard does not match the apex domain.

Before the lookup the hostname is cut at the first NUL byte, because Forge
appends `\0FML3\0` and BungeeCord's IP forwarding appends
`\0<ip>\0<uuid>\0<properties>`. One trailing dot is stripped. Case is folded
by OR-ing every byte with 0x20, which the loader applies to stored entries
the same way. That fold is branch free and maps ASCII letters to lowercase;
it also maps a few punctuation characters onto others (`[` and `{`, `_` and
DEL), which cannot occur in a hostname, and would map control characters
onto printable ones, so names containing bytes below 0x20 are rejected.

## Verifier notes

The parser contains several loops over the hostname. The BPF verifier
simulates every iteration and every branch, and a loop whose exit depends on
packet data leaves one verifier state per possible exit. The next loop is
then verified once per such state, so two loops over a 255 byte string are
quadratic and four VarInts of one to five bytes each multiply that by
hundreds. A straightforward implementation needs far more than the one
million instruction budget.

kcart keeps the verifier cost well under the budget with two techniques:

- Indices are masked (`& 0xff`) right where they are used, with buffers
  sized to 256 bytes. The mask never changes a value that is in range, but
  it gives the verifier a bound even when the compiler reloads a value from
  a stack spill it made before the bounds check.
- Values that loops depend on are written to per-CPU map memory and read
  back through a volatile pointer (`launder()` in the source). The compiler
  cannot forward the store, so the verifier sees a fresh scalar with only the
  mask as its bound, and all the states the previous loop left behind merge
  into one. The same trick bounds the IPv6 extension header walk.

The per-CPU scratch map also holds the 260 byte trie key and the hostname
copy, which do not fit the 512 byte BPF stack next to everything else.

The socket lookup and the reset path are placed on paths that return
immediately and are fed laundered offsets, otherwise their verification
would be repeated for every state the parser leaves behind. With both, the
program needs about 360k instructions.

The same pointer arithmetic is why the loader needs CAP_PERFMON besides
CAP_BPF and CAP_NET_ADMIN: without it the verifier runs in its unprivileged
mode and rejects the program with "pointer arithmetic with it prohibited for
!root".

## Reset mode

By the time the handshake arrives the kernel has already accepted the
connection. Dropping the packet leaves that socket open until the server's
handshake timeout fires, thirty seconds in vanilla; a scanner opening a
thousand connections per second keeps thirty thousand idle Netty channels
on the server. With `--rst` kcart rewrites the packet in place instead: TCP
options and payload are cut off with `bpf_xdp_adjust_tail`, the flags become
RST+ACK, IP length and both checksums are fixed, and the packet goes to the
local stack. Its sequence number is the one the socket expects next, which
Linux requires to accept a reset, so the socket is closed at once. The
client gets nothing and times out on its own.

Reset mode relies on the kernel validating the checksum kcart wrote. A
driver that reports `CHECKSUM_COMPLETE` from hardware for a packet that XDP
then modified may make the stack discard the reset as corrupt; if
`nstat -az TcpInCsumErrors` climbs with reset mode on, turn it off.
virtio_net was tested and works.

A handshake split over several segments is dropped. No real client does
that, and accepting it would mean reassembling streams in XDP.

## Performance

Measured with BPF_PROG_TEST_RUN on a single vCPU (virtio, kernel 6.1),
average per packet:

| path | ns |
|---|---|
| TCP to another port | 20 |
| pure ACK on a protected port | 28 |
| data packet of a known flow | 60 |
| handshake, allowed, exact or wildcard | 144 |
| handshake, denied (bare IP) | 173 |
| handshake, denied, 255 character hostname | 642 |
| garbage payload (HTTP probe) | 114 |

`make bench-bpf` reproduces the table.
