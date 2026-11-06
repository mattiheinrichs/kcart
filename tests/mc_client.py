#!/usr/bin/env python3
"""Sends a Minecraft handshake plus status request and reports what comes back."""
import socket, struct, sys, time

def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)

def handshake(host, state=1):
    h = host.encode()
    body = varint(0) + varint(767) + varint(len(h)) + h + struct.pack("!H", 25565) + varint(state)
    return varint(len(body)) + body

ip, host = sys.argv[1], sys.argv[2]
t0 = time.time()
s = socket.create_connection((ip, 25565), timeout=4)
s.sendall(handshake(host) + b"\x01\x00")
try:
    data = s.recv(1024)
    print(f"host={host!r}: reply {len(data)} bytes in {time.time()-t0:.2f}s: {data[:40]!r}")
except socket.timeout:
    print(f"host={host!r}: no reply within 4s (dropped)")
except ConnectionResetError:
    print(f"host={host!r}: connection reset in {time.time()-t0:.2f}s")
s.close()
