#!/usr/bin/env python3
# 参数化 SOCKS5 探针：probe.py <engine_port> <host_or_ip> <port> [domain]
import socket
import struct
import sys

engine_port = int(sys.argv[1])
target = sys.argv[2]
target_port = int(sys.argv[3])
use_domain = len(sys.argv) > 4 and sys.argv[4] == "domain"

c = socket.create_connection(("127.0.0.1", engine_port), timeout=10)
c.settimeout(10)
c.sendall(b"\x05\x01\x00")
print("greeting:", c.recv(2))
if use_domain:
    h = target.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", target_port)
else:
    req = b"\x05\x01\x00\x01" + socket.inet_aton(target) + struct.pack(">H", target_port)
c.sendall(req)
print("connect:", c.recv(16))
c.sendall(b"probe-payload")
print("echo:", c.recv(64))
c.close()
