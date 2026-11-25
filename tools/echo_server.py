#!/usr/bin/env python3
# 测试目标服务：收到什么就回什么（模拟任意 TCP 服务）
import socket
import sys


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    bind_ip = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    srv.bind((bind_ip, port))
    srv.listen(16)
    print("[echo] listening on %s:%d" % (bind_ip, port), flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(b"[echo] " + data)
        except OSError:
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    main()
