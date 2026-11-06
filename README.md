# kcart

XDP filter for Minecraft servers. It reads the server address from the
handshake packet and drops every connection that does not use one of your
domains. Scanners and most attack tools connect to the raw IP, so they never
get past the network card.

## How it works

The handshake is the first packet a Minecraft client sends once the TCP
connection is up, and it always fits in one segment. kcart parses that one
packet, looks the hostname up in an allowlist and remembers the connection
if it passed. Everything else on a protected port is dropped: unknown
hostnames, raw IPs, legacy pings, HTTP probes, garbage. Later packets of a
known connection cost one hash lookup.

A dropped packet can be turned into a TCP RST for the local stack (`--rst`).
The kernel has already accepted the connection at that point. Without the
reset it sits in the server until the handshake timeout, with it the socket
is closed right away.

Flow state is only created or removed when the kernel confirms the
connection exists (`socket_check`), so spoofed packets can neither fill the
flow table nor knock a player out of it. This needs the server in the same
network namespace as the interface; kcart detects that at startup and warns
if the server is not visible.

Numbers from a single vCPU: about 60 ns per player packet, about 170 ns per
rejected handshake. [docs/DESIGN.md](docs/DESIGN.md) has the details,
including what it took to get the parser past the BPF verifier.

## Requirements

Linux 5.10 or newer. Native XDP support in the NIC driver is nice to have
(virtio_net, ixgbe, i40e, mlx5 all have it), otherwise kcart falls back to
generic XDP. The process needs root or CAP_BPF, CAP_NET_ADMIN and
CAP_PERFMON.

kcart runs on the machine that owns the public IP: the game server, or the
proxy (Velocity, BungeeCord) in front of it.

## Build

```
apt install clang llvm libbpf-dev    # Debian, Ubuntu
cargo build --release
```

`build.rs` compiles `bpf/kcart.bpf.c` with clang and embeds it. The result
is the single binary `target/release/kcart`.

## Usage

```
kcart run --iface eth0 --host play.example.com --host '*.example.com' --rst
```

This protects port 25565 on eth0. `--port` adds other ports, `--mode skb`
forces generic XDP. Dropped handshakes are printed one per line, rate
limited in the kernel (`--events-per-sec`, default 100):

```
drop reason=host_not_allowed src=203.0.113.7:51234 dport=25565 host="203.0.113.1" proto=767
```

`kcart stats` shows the counters, `kcart hosts list|add|remove` changes the
allowlist of the running instance, `kcart check-config` validates a config
file. With `--config`, SIGHUP re-reads the file. `--host` and `--port` on
the command line replace the lists from the file.

For a quick test without a domain, allow `<your ip>.nip.io` and put that
name in the server list.

Matching is case insensitive and ignores a trailing dot. `*.example.com`
matches subdomains, not `example.com` itself. The Forge suffix (`\0FML3\0`)
and BungeeCord IP forwarding data after the hostname are ignored. Allowed
characters are letters, digits, `-`, `.`, `_` and `:`, use punycode for
anything else. Keep in mind that connecting by IP stops working for
everyone, the server list ping included.

`--allow-legacy-ping` lets pre 1.7 server list pings through. They carry no
hostname, so with it on, scanners get the server status again.

### Running as a service

```
cp target/release/kcart /usr/local/bin/
mkdir /etc/kcart && cp packaging/kcart.example.toml /etc/kcart/kcart.toml
cp packaging/kcart.service /etc/systemd/system/
systemctl enable --now kcart
```

## Tests

`make test-bpf` (root) runs the XDP program against crafted frames through
`BPF_PROG_TEST_RUN`, `make bench-bpf` prints ns per packet, `cargo test`
covers the loader, `sudo scripts/integration.sh` makes real TCP connections
through a veth pair and injects spoofed packets against them.

## Limitations

Whoever knows your domain gets through. This is not DDoS protection, and
SYN floods are still the kernel's business. Bedrock (UDP) is not covered.
If `nstat -az TcpInCsumErrors` climbs with `--rst` on, the driver does not
like modified packets; turn the reset off.

kcart only sees what arrives on the interface as plain TCP. Traffic inside
GRE, IPIP or IPsec tunnels that the host terminates is decapsulated after
XDP and bypasses it. In front of a BungeeCord or Velocity backend, kcart
checks the hostname but not the forwarding secret; the backend still has to
reject direct connections itself. If the server runs in a container with its
own network namespace, the socket check is off and spoofed packets can
disturb flow state; run the container with host networking to get it back.

Tested on Debian 12, kernel 6.1, virtio_net.

Written together with AI. Everything here was measured and tested before it
went in.

## License

Loader MIT, `bpf/` GPL-2.0.
