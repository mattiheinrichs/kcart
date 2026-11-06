#!/usr/bin/env python3
"""Minimal stand in for a Minecraft server: logs what arrives on 25565 and echoes it back."""
import socket, sys, threading, time

def handle(conn, addr):
    conn.settimeout(5)
    try:
        data = conn.recv(1024)
        print(f"{time.strftime('%H:%M:%S')} {addr[0]}:{addr[1]} got {len(data)} bytes: {data[:60]!r}", flush=True)
        if data:
            conn.sendall(b"ECHO:" + data)
    except Exception as e:
        print(f"{time.strftime('%H:%M:%S')} {addr[0]}:{addr[1]} {e}", flush=True)
    finally:
        conn.close()

s = socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 25565))
s.listen(128)
print("listening", flush=True)
while True:
    c, a = s.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()
