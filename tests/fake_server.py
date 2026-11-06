#!/usr/bin/env python3
"""Stand in for a Minecraft server: logs every message on 25565 and echoes it back."""
import socket
import sys
import threading
import time


def log(addr, text):
    print(f"{time.strftime('%H:%M:%S')} {addr[0]}:{addr[1]} {text}", flush=True)


def handle(conn, addr):
    conn.settimeout(10)
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                log(addr, "closed")
                return
            log(addr, f"got {len(data)} bytes: {data[:60]!r}")
            conn.sendall(b"ECHO:" + data)
    except Exception as e:
        log(addr, str(e))
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
