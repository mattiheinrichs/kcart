#!/usr/bin/env python3
"""Checks that spoofed packets cannot break an established connection.

Opens a connection with a valid handshake, then injects raw frames that
reuse the connection's 4-tuple: a SYN, a FIN and a valid handshake with a
bogus sequence number. Afterwards the connection must still work. Runs
inside the client namespace, needs root for the raw socket.

    spoof.py <iface> <server ip> <hostname>
"""
import random
import socket
import struct
import sys
import time

from mc_client import handshake


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, random.getrandbits(32), 0, 5 << 4, flags, 65535, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp + payload


def main():
    iface, server_ip, host = sys.argv[1:4]
    conn = socket.create_connection((server_ip, 25565), timeout=4)
    conn.sendall(handshake(host))
    conn.recv(1024)
    sport = conn.getsockname()[1]
    src_ip = conn.getsockname()[0]

    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw.bind((iface, 0))
    src_mac = raw.getsockname()[4]
    dst_mac = bytes.fromhex(open(f"/sys/class/net/{iface}/address").read().strip().replace(":", ""))
    # the peer's MAC is not known here, but a veth delivers regardless of it
    for name, flags, payload in [
        ("syn", 0x02, b""),
        ("fin", 0x11, b""),
        ("handshake with bogus seq", 0x18, handshake(host)),
        ("garbage with bogus seq", 0x18, b"GET / HTTP/1.0\r\n"),
    ]:
        raw.send(frame(src_mac, dst_mac, src_ip, server_ip, sport, 25565, flags, payload))
        time.sleep(0.2)
        conn.sendall(b"\x02\x00\x01")
        try:
            data = conn.recv(1024)
        except (socket.timeout, ConnectionResetError):
            data = b""
        if data.startswith(b"ECHO:"):
            print(f"ok   spoofed {name}: connection still works")
        else:
            print(f"FAIL spoofed {name}: connection broken")
            sys.exit(1)
    conn.close()


if __name__ == "__main__":
    main()
