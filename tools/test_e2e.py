#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端测试：echo <- socks5 server <- engine <- client

覆盖路径：
  1) 本地 SOCKS5 入口 + IP 目标（ATYP=1）
  2) 本地 SOCKS5 入口 + 域名透传（ATYP=3，等价远程解析）

用法：python test_e2e.py [pyengine/oddly_proxy.py | engine/OddlyProxy.exe]
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
ENGINE_PORT = 37771
SOCKS_PORT = 17771
ECHO_PORT = 27771


def wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def socks5_request(engine_port, host_bytes, port, host_repr, expect_ok=True):
    """对 engine 端口发一次完整 SOCKS5 CONNECT 并回显测试。"""
    c = socket.create_connection(("127.0.0.1", engine_port), timeout=10)
    c.settimeout(10)
    c.sendall(b"\x05\x01\x00")                      # greeting
    assert c.recv(2) == b"\x05\x00", "engine must select no-auth"
    if host_bytes is None:                          # 域名
        h = host_repr.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port)
    else:
        req = b"\x05\x01\x00\x01" + host_bytes + struct.pack(">H", port)
    c.sendall(req)
    rep = c.recv(4)
    ok = (len(rep) == 4 and rep[1] == 0)
    if atyp_bytes := rep[3:4]:
        n = {b"\x01": 6, b"\x04": 18}.get(atyp_bytes)
        if n is None:
            nl = c.recv(1)[0]
            c.recv(nl + 2)
        else:
            c.recv(n)
    assert ok == expect_ok, "CONNECT reply unexpected: %r" % rep
    payload = b"hello-oddlyproxy-1234"
    c.sendall(payload)
    echo = c.recv(len(b"[echo] ") + len(payload))
    assert echo == b"[echo] " + payload, "echo mismatch: %r" % echo
    c.close()
    print("[PASS] %s -> echoed via socks5 chain" % host_repr)


def main():
    engine_cmd = sys.argv[1:] if len(sys.argv) > 1 else \
        [PY, os.path.join(HERE, "..", "pyengine", "oddly_proxy.py")]

    procs = []
    try:
        procs.append(subprocess.Popen(
            [PY, os.path.join(HERE, "echo_server.py"), str(ECHO_PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
        procs.append(subprocess.Popen(
            [PY, os.path.join(HERE, "socks5_test_server.py"), str(SOCKS_PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
        if engine_cmd[0].endswith(".py") and engine_cmd[0] != PY:
            engine_cmd = [PY] + engine_cmd
        engine_args = engine_cmd + ["local", str(ENGINE_PORT),
                                    "127.0.0.1", str(SOCKS_PORT)]
        procs.append(subprocess.Popen(
            engine_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT))

        for port in (ECHO_PORT, SOCKS_PORT, ENGINE_PORT):
            assert wait_port(port), "port %d did not come up" % port
        time.sleep(0.3)

        socks5_request(ENGINE_PORT, socket.inet_aton("127.0.0.1"), ECHO_PORT,
                       "127.0.0.1:%d" % ECHO_PORT)
        socks5_request(ENGINE_PORT, None, ECHO_PORT, "localhost")
        print("\n=== E2E TEST: ALL PASSED ===")
        return 0
    finally:
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass
        for p in procs:
            out = p.stdout.read() if p.stdout else b""
            if out:
                print("---- child %d ----" % p.pid)
                print(out.decode(errors="replace"))


if __name__ == "__main__":
    sys.exit(main())
