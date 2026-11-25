#!/usr/bin/env python3
# 测试用最小 SOCKS5 服务端（no-auth + CONNECT），扮演"代理服务器"
import socket
import struct
import sys
import threading


def handle(conn):
    try:
        ver, nmethods = recvn(conn, 2)
        if ver != 5:
            return
        recvn(conn, nmethods)
        conn.sendall(b"\x05\x00")
        ver, cmd, _rsv, atyp = recvn(conn, 4)
        if cmd != 1:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        if atyp == 1:
            rest = recvn(conn, 6)
            host = socket.inet_ntop(socket.AF_INET, rest[:4])
            port = struct.unpack(">H", rest[4:])[0]
        elif atyp == 3:
            n = recvn(conn, 1)[0]
            rest = recvn(conn, n + 2)
            host = rest[:n].decode(errors="replace")
            port = struct.unpack(">H", rest[n:])[0]
        elif atyp == 4:
            rest = recvn(conn, 18)
            host = socket.inet_ntop(socket.AF_INET6, rest[:16])
            port = struct.unpack(">H", rest[16:])[0]
        else:
            return
        print("[socks5] CONNECT %s:%d (atyp=%d)" % (host, port, atyp), flush=True)
        try:
            upstream = socket.create_connection((host, port), timeout=10)
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        except OSError as exc:
            print("[socks5] dial failed: %s" % exc, flush=True)
            conn.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
            return
        pipe(conn, upstream)
        upstream.close()
    except Exception as exc:
        print("[socks5] error: %s" % exc, flush=True)
    finally:
        conn.close()


def recvn(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def pipe(a, b):
    """双向中继（select 同时等两侧）。"""
    import select as _sel
    pair = [a, b]
    while True:
        readable, _, _ = _sel.select(pair, [], [], 30)
        if not readable:
            break
        for s in readable:
            try:
                data = s.recv(65536)
            except OSError:
                return
            if not data:
                return
            other = b if s is a else a
            try:
                other.sendall(data)
            except OSError:
                return


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
    bind_ip = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    srv.bind((bind_ip, port))
    srv.listen(16)
    print("[socks5] listening on %s:%d" % (bind_ip, port), flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
