#!/usr/bin/env python3
"""Functional test of bpf/kcart.bpf.o through BPF_PROG_TEST_RUN.

Needs root, bpftool and a mounted bpffs. Builds synthetic frames, loads the
object with pinned maps, fills the port and host maps and checks the XDP
verdict for every case. No Minecraft server or network interface involved.

    python3 tests/prog_run.py path/to/kcart.bpf.o [--bench]
"""
import os
import struct
import subprocess
import sys
import tempfile

XDP_DROP = 1
XDP_PASS = 2
PIN = "/sys/fs/bpf/kcart-test"
HOST_KEY_LEN = 256
MAX_HOST = 255

REASONS = [
    "pass_no_payload", "pass_known_flow", "pass_handshake_ok", "pass_legacy_ping",
    "drop_host_not_allowed", "drop_host_too_long", "drop_malformed",
    "drop_truncated", "drop_legacy_ping",
]


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def handshake(host, protocol=767, port=25565, state=2, packet_id=0, host_len=None):
    host = host if isinstance(host, bytes) else host.encode()
    body = varint(packet_id) + varint(protocol) + varint(len(host) if host_len is None else host_len)
    body += host + struct.pack("!H", port) + varint(state)
    return varint(len(body)) + body


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_header(sport, dport, flags, options=b"", seq=1000):
    doff = 5 + len(options) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, doff << 4, flags, 65535, 0, 0) + options


# Every case gets its own source port, otherwise the flow state of one case
# would leak into the next.
SPORT = 40000


def ipv4_frame(payload, sport=None, dport=25565, flags=0x18, vlan=False, pad=0, options=b""):
    tcp = tcp_header(sport or SPORT, dport, flags, options)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0,
                     bytes([10, 0, 0, 2]), bytes([10, 0, 0, 1]))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = b"\x02" * 6 + b"\x04" * 6
    if vlan:
        eth += struct.pack("!HHH", 0x8100, 100, 0x0800)
    else:
        eth += struct.pack("!H", 0x0800)
    return eth + ip + tcp + payload + b"\0" * pad


def ipv6_frame(payload, sport=None, dport=25565, flags=0x18, hopbyhop=False):
    tcp = tcp_header(sport or SPORT, dport, flags)
    ext = b""
    nexthdr = 6
    if hopbyhop:
        ext = bytes([6, 0]) + b"\0" * 6
        nexthdr = 0
    ip = struct.pack("!IHBB16s16s", 0x60000000, len(ext) + len(tcp) + len(payload), nexthdr, 64,
                     bytes.fromhex("20010db8000000000000000000000002"),
                     bytes.fromhex("20010db8000000000000000000000001"))
    eth = b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", 0x86DD)
    return eth + ip + ext + tcp + payload


def bpftool(*args, check=True):
    return subprocess.run(["bpftool", *args], check=check, capture_output=True, text=True)


def hexbytes(data):
    return [f"{b:02x}" for b in data]


def host_key(host):
    """Mirror of the userspace encoding: reversed, case folded with | 0x20."""
    wildcard = host.startswith("*.")
    if wildcard:
        host = host[2:]
    data = bytes(b | 0x20 for b in host.encode()[::-1])
    data += b"." if wildcard else b"\0"
    return struct.pack("<I", len(data) * 8) + data.ljust(HOST_KEY_LEN, b"\0")


def setup(obj):
    subprocess.run(["rm", "-rf", PIN], check=True)
    os.makedirs(PIN)
    bpftool("prog", "load", obj, f"{PIN}/prog", "type", "xdp", "pinmaps", PIN)
    bpftool("map", "update", "pinned", f"{PIN}/ports", "key", "hex", *hexbytes(struct.pack("<I", 25565)), "value", "hex", "01")
    bpftool("map", "update", "pinned", f"{PIN}/config", "key", "hex", *hexbytes(struct.pack("<I", 0)),
            "value", "hex", *hexbytes(struct.pack("<II", 0, 100)))
    for host, kind in (("play.example.com", 1), ("*.wild.example.org", 2)):
        bpftool("map", "update", "pinned", f"{PIN}/hosts", "key", "hex", *hexbytes(host_key(host)),
                "value", "hex", f"{kind:02x}")


def run(frame, want_output=False):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(frame)
        path = f.name
    out_path = path + ".out"
    try:
        out = bpftool("prog", "run", "pinned", f"{PIN}/prog", "data_in", path, "data_out", out_path,
                      "repeat", "1").stdout
        with open(out_path, "rb") as f:
            output = f.read()
    finally:
        os.unlink(path)
        os.unlink(out_path)
    verdict = int(out.split("Return value:")[1].split(",")[0])
    return (verdict, output) if want_output else verdict


def set_flags(flags):
    bpftool("map", "update", "pinned", f"{PIN}/config", "key", "hex", *hexbytes(struct.pack("<I", 0)),
            "value", "hex", *hexbytes(struct.pack("<II", flags, 100)))


def tcp_checksum_ok(frame):
    """Validates IPv4 header and TCP checksums of an Ethernet frame."""
    l3 = 14
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x8100:
        l3 = 18
        ethertype = struct.unpack("!H", frame[16:18])[0]
    if ethertype == 0x0800:
        ihl = (frame[l3] & 0x0F) * 4
        ip = frame[l3:l3 + ihl]
        if checksum(ip) != 0:
            return False
        total = struct.unpack("!H", ip[2:4])[0]
        segment = frame[l3 + ihl:l3 + total]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(segment))
    else:
        plen = struct.unpack("!H", frame[l3 + 4:l3 + 6])[0]
        segment = frame[l3 + 40:l3 + 40 + plen]
        pseudo = frame[l3 + 8:l3 + 40] + struct.pack("!IBBBB", len(segment), 0, 0, 0, 6)
    return checksum(pseudo + segment) == 0


def l4_offset(frame):
    l3 = 14
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x8100:
        l3 = 18
        ethertype = struct.unpack("!H", frame[16:18])[0]
    return l3 + ((frame[l3] & 0x0F) * 4 if ethertype == 0x0800 else 40)


def check_rst(name, frame):
    verdict, out = run(frame, want_output=True)
    if len(out) < 54:
        print(f"FAIL rst: {name}: verdict {verdict}, output {len(out)} bytes: {out.hex()}")
        return False
    l4 = l4_offset(out)
    flags = out[l4 + 13]
    doff = out[l4 + 12] >> 4
    problems = []
    if verdict != XDP_PASS:
        problems.append(f"verdict {verdict}")
    if flags != 0x14:
        problems.append(f"flags {flags:#x}")
    if doff != 5:
        problems.append(f"doff {doff}")
    if len(out) != l4 + 20:
        problems.append(f"length {len(out)} expected {l4 + 20}")
    if out[l4 + 4:l4 + 8] != frame[l4 + 4:l4 + 8]:
        problems.append("sequence number changed")
    if not tcp_checksum_ok(out):
        problems.append("bad checksum")
    print(f"{'ok' if not problems else 'FAIL':4} rst: {name}: {', '.join(problems) or 'valid reset'}")
    return not problems


def bench(frame, repeat=500000):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(frame)
        path = f.name
    try:
        out = bpftool("prog", "run", "pinned", f"{PIN}/prog", "data_in", path, "repeat", str(repeat)).stdout
    finally:
        os.unlink(path)
    return int(out.split("duration (average):")[1].split("ns")[0])


BENCHES = [
    ("other port, untouched", ipv4_frame(b"\x05\x00abcd", sport=60000, dport=25566)),
    ("pure ack", ipv4_frame(b"", sport=60001, flags=0x10)),
    ("known flow data", ipv4_frame(b"\x05\x00abcd", sport=60002)),
    # FIN keeps the flow out of the map, so every repetition takes the parse path
    ("handshake allowed, parsed", ipv4_frame(handshake("play.example.com"), sport=60003, flags=0x19)),
    ("handshake wildcard, parsed", ipv4_frame(handshake("eu.wild.example.org"), sport=60004, flags=0x19)),
    ("handshake denied (bare ip)", ipv4_frame(handshake("46.224.145.178"), sport=60005)),
    ("handshake denied, 255 chars", ipv4_frame(handshake("a" * 255), sport=60006)),
    ("garbage payload", ipv4_frame(b"GET / HTTP/1.0\r\n\r\n", sport=60007)),
]


def stats():
    out = bpftool("map", "dump", "pinned", f"{PIN}/stats", "-j").stdout
    import json
    counts = {}
    for entry in json.loads(out):
        idx = int.from_bytes(bytes(int(b, 16) for b in entry["key"]), "little")
        total = 0
        for cpu in entry["values"]:
            total += int.from_bytes(bytes(int(b, 16) for b in cpu["value"]), "little")
        counts[REASONS[idx]] = total
    return counts


CASES = []


def case(name, frames, expect):
    global SPORT
    CASES.append((name, frames, expect))
    SPORT += 1


ok = handshake("play.example.com")
case("handshake with allowed host", [ipv4_frame(ok)], [XDP_PASS])
case("allowed host, upper case", [ipv4_frame(handshake("Play.Example.COM"))], [XDP_PASS])
case("allowed host, trailing dot", [ipv4_frame(handshake("play.example.com."))], [XDP_PASS])
case("allowed host, forge suffix", [ipv4_frame(handshake("play.example.com\0FML3\0"))], [XDP_PASS])
case("allowed host, bungee forwarding", [ipv4_frame(handshake("play.example.com\x0010.0.0.2\x00uuid\x00[]"))], [XDP_PASS])
case("wildcard subdomain", [ipv4_frame(handshake("eu.wild.example.org"))], [XDP_PASS])
case("wildcard deeper subdomain", [ipv4_frame(handshake("a.b.wild.example.org"))], [XDP_PASS])
case("wildcard does not match apex", [ipv4_frame(handshake("wild.example.org"))], [XDP_DROP])
case("wildcard does not match similar suffix", [ipv4_frame(handshake("notwild.example.org"))], [XDP_DROP])
case("bare ip as host", [ipv4_frame(handshake("46.224.145.178"))], [XDP_DROP])
case("other domain", [ipv4_frame(handshake("example.com"))], [XDP_DROP])
case("prefix of allowed host", [ipv4_frame(handshake("play.example.co"))], [XDP_DROP])
case("allowed host plus suffix", [ipv4_frame(handshake("play.example.comx"))], [XDP_DROP])
case("allowed host as subdomain", [ipv4_frame(handshake("x.play.example.com"))], [XDP_DROP])
case("empty host", [ipv4_frame(handshake(""))], [XDP_DROP])
case("host too long", [ipv4_frame(handshake("a" * 256))], [XDP_DROP])
case("host exactly max, not allowed", [ipv4_frame(handshake("a" * 255))], [XDP_DROP])
case("status request (state 1)", [ipv4_frame(handshake("play.example.com", state=1))], [XDP_PASS])
case("transfer (state 3)", [ipv4_frame(handshake("play.example.com", state=3))], [XDP_PASS])
case("bad next state", [ipv4_frame(handshake("play.example.com", state=4))], [XDP_DROP])
case("wrong packet id", [ipv4_frame(handshake("play.example.com", packet_id=1))], [XDP_DROP])
case("length field lies", [ipv4_frame(handshake("play.example.com", host_len=5))], [XDP_DROP])
case("truncated handshake", [ipv4_frame(ok[:10])], [XDP_DROP])
case("legacy ping", [ipv4_frame(b"\xfe\x01")], [XDP_DROP])
case("http probe", [ipv4_frame(b"GET / HTTP/1.0\r\n\r\n")], [XDP_DROP])
case("random bytes", [ipv4_frame(bytes(range(1, 60)))], [XDP_DROP])
case("pure ack", [ipv4_frame(b"", flags=0x10)], [XDP_PASS])
case("pure ack with ethernet padding", [ipv4_frame(b"", flags=0x10, pad=6)], [XDP_PASS])
case("syn", [ipv4_frame(b"", flags=0x02)], [XDP_PASS])
case("other port", [ipv4_frame(handshake("1.2.3.4"), dport=25566)], [XDP_PASS])
case("vlan tagged allowed", [ipv4_frame(ok, vlan=True)], [XDP_PASS])
case("vlan tagged denied", [ipv4_frame(handshake("1.2.3.4"), vlan=True)], [XDP_DROP])
case("ipv6 allowed", [ipv6_frame(ok)], [XDP_PASS])
case("ipv6 denied", [ipv6_frame(handshake("1.2.3.4"))], [XDP_DROP])
case("ipv6 hop-by-hop denied", [ipv6_frame(handshake("1.2.3.4"), hopbyhop=True)], [XDP_DROP])
case("ipv6 hop-by-hop allowed", [ipv6_frame(ok, hopbyhop=True)], [XDP_PASS])
case("flow: handshake then data passes",
     [ipv4_frame(ok, sport=50001), ipv4_frame(b"\x05\x00abcd", sport=50001)], [XDP_PASS, XDP_PASS])
case("flow: data without handshake drops",
     [ipv4_frame(b"\x05\x00abcd", sport=50002), ipv4_frame(b"\x05\x00abcd", sport=50002)], [XDP_DROP, XDP_DROP])
case("flow: fin with data passes and forgets flow",
     [ipv4_frame(ok, sport=50003), ipv4_frame(b"\x05\x00abcd", sport=50003, flags=0x19),
      ipv4_frame(b"\x05\x00abcd", sport=50003)], [XDP_PASS, XDP_PASS, XDP_DROP])
case("flow: syn resets state for reused tuple",
     [ipv4_frame(ok, sport=50004), ipv4_frame(b"", sport=50004, flags=0x02),
      ipv4_frame(b"\x05\x00abcd", sport=50004)], [XDP_PASS, XDP_PASS, XDP_DROP])
case("flow: syn with data (tfo) is inspected",
     [ipv4_frame(handshake("1.2.3.4"), sport=50005, flags=0x02)], [XDP_DROP])
case("flow: denied handshake leaves no state",
     [ipv4_frame(handshake("1.2.3.4"), sport=50006), ipv4_frame(ok, sport=50006),
      ipv4_frame(b"\x05\x00abcd", sport=50006)], [XDP_DROP, XDP_PASS, XDP_PASS])
case("ipv6 flow: handshake then data",
     [ipv6_frame(ok, sport=50007), ipv6_frame(b"\x05\x00abcd", sport=50007)], [XDP_PASS, XDP_PASS])


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    setup(sys.argv[1])
    if "--bench" in sys.argv:
        # the known flow bench needs its handshake first
        run(ipv4_frame(handshake("play.example.com"), sport=60002))
        for name, frame in BENCHES:
            print(f"{name:32} {bench(frame):5d} ns/packet")
        subprocess.run(["rm", "-rf", PIN], check=True)
        return
    failed = 0
    for name, frames, expect in CASES:
        got = [run(f) for f in frames]
        status = "ok" if got == expect else "FAIL"
        if got != expect:
            failed += 1
        print(f"{status:4} {name}: {got} expected {expect}")
    print()
    for reason, count in stats().items():
        print(f"{reason:24} {count}")

    set_flags(2)
    rst_cases = [
        ("ipv4 denied handshake", ipv4_frame(handshake("1.2.3.4"), sport=61000)),
        ("ipv4 with tcp options", ipv4_frame(handshake("1.2.3.4"), sport=61001, options=b"\x01" * 8)),
        ("ipv4 garbage", ipv4_frame(b"GET / HTTP/1.0\r\n", sport=61002)),
        ("ipv6 denied handshake", ipv6_frame(handshake("1.2.3.4"), sport=61003)),
        ("vlan denied handshake", ipv4_frame(handshake("1.2.3.4"), sport=61004, vlan=True)),
    ]
    total = len(CASES) + len(rst_cases) + 1
    for name, frame in rst_cases:
        if not check_rst(name, frame):
            failed += 1
    got = run(ipv4_frame(handshake("play.example.com"), sport=61005), want_output=True)
    if got[0] == XDP_PASS and got[1] == ipv4_frame(handshake("play.example.com"), sport=61005):
        print("ok   rst: allowed handshake untouched")
    else:
        print("FAIL rst: allowed handshake untouched")
        failed += 1

    subprocess.run(["rm", "-rf", PIN], check=True)
    print(f"\n{total - failed}/{total} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
