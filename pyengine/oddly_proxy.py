#!/usr/bin/env python3
"""
OddlyProxifier Python reference engine.

Modes:
  local  <listenPort> <proxyHost> <proxyPort> [user pass]
      Local SOCKS5 entry (no driver).
  driver <listenPort> <proxyHost> <proxyPort> [targetPort]
      Driver mode (ABI v2): OddlyDrv redirects outgoing TCP connections here;
      the original destination is read from the accepted socket.
  stats
      Print the driver's counters.

A small reference implementation. The full engine is cmd/oddlyproxifier.
"""
import argparse, ctypes, select, socket, struct, sys, threading, os

# Driver ABI v2: see driver/oddly_ioctl.h.
ABI_VERSION             = 2
IOCTL_ODDLY_GET_VERSION = 0x00226400
IOCTL_ODDLY_SET_POLICY  = 0x0022E404
IOCTL_ODDLY_GET_STATS   = 0x00226408
FLAG_ENABLED            = 0x1
CTX_MAGIC               = 0x3243444F
SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT = 0x980000DD
DEVICE = "\\\\.\\OddlyDrv"

if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                         ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    ws2_32 = ctypes.WinDLL("ws2_32", use_last_error=True)
    ws2_32.WSAIoctl.argtypes = [ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

def driver_open():
    GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3
    h = kernel32.CreateFileW(DEVICE, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
    if h is None or h == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "cannot open the OddlyDrv device")
    buf = ctypes.create_string_buffer(4)
    ret = ctypes.c_ulong(0)
    if not kernel32.DeviceIoControl(h, IOCTL_ODDLY_GET_VERSION, None, 0, buf, 4, ctypes.byref(ret), None):
        raise OSError(ctypes.get_last_error(), "GET_VERSION failed")
    version = struct.unpack("<I", buf.raw)[0]
    if version != ABI_VERSION:
        raise OSError(0, "driver ABI version %d, this engine needs %d" % (version, ABI_VERSION))
    return h

def driver_set_policy(handle, port, enable, target_port=0, exclude_pids=()):
    """ODDLY_POLICY header (160 bytes), no network or application entries:
    IPv4 connections of every application are redirected."""
    pids = list(exclude_pids)[:32]
    blob = struct.pack("<IIIIHHIII32I", 160, ABI_VERSION, FLAG_ENABLED if enable else 0,
                       os.getpid(), port, target_port, len(pids), 0, 0,
                       *(pids + [0] * (32 - len(pids))))
    ret = ctypes.c_ulong(0)
    if not kernel32.DeviceIoControl(handle, IOCTL_ODDLY_SET_POLICY, blob, len(blob), None, 0,
                                    ctypes.byref(ret), None):
        raise OSError(ctypes.get_last_error(), "SET_POLICY failed")

def driver_get_stats(handle):
    buf = ctypes.create_string_buffer(40)
    ret = ctypes.c_ulong(0)
    if not kernel32.DeviceIoControl(handle, IOCTL_ODDLY_GET_STATS, None, 0, buf, 40,
                                    ctypes.byref(ret), None):
        raise OSError(ctypes.get_last_error(), "GET_STATS failed")
    names = ("classified", "redirected", "bypassed", "quic_blocked", "errors")
    return dict(zip(names, struct.unpack("<5Q", buf.raw)))

def query_orig_dest(sock):
    """Original destination and process of a redirected connection, read from
    the 48-byte ODDLY_REDIRECT_CTX the driver attached to it."""
    buf = ctypes.create_string_buffer(48)
    got = ctypes.c_ulong(0)
    if ws2_32.WSAIoctl(sock.fileno(), SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, None, 0,
                       buf, 48, ctypes.byref(got), None, None) != 0 or got.value < 48:
        return None
    magic, pid, family = struct.unpack_from("<IIH", buf.raw)
    port = struct.unpack_from(">H", buf.raw, 10)[0]
    if magic != CTX_MAGIC:
        return None
    if family == 6:
        host = socket.inet_ntop(socket.AF_INET6, buf.raw[12:28])
    else:
        host = socket.inet_ntop(socket.AF_INET, buf.raw[12:16])
    return host, port, pid

def socks5_serve(conn):
    conn.settimeout(10)
    ver, nmethods = _recvn(conn, 2)
    if ver != 5:
        raise RuntimeError("not SOCKS5")
    _recvn(conn, nmethods)
    conn.sendall(b"\x05\x00")
    ver, cmd, _rsv, atyp = _recvn(conn, 4)
    if cmd != 1:
        conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        raise RuntimeError("only CONNECT")
    if atyp == 1:
        addr = _recvn(conn, 6)
        host = socket.inet_ntop(socket.AF_INET, addr[:4])
        port = struct.unpack(">H", addr[4:])[0]
    elif atyp == 3:
        n = _recvn(conn, 1)[0]
        rest = _recvn(conn, n + 2)
        host = rest[:n].decode(errors="replace")
        port = struct.unpack(">H", rest[n:])[0]
    elif atyp == 4:
        addr = _recvn(conn, 18)
        host = socket.inet_ntop(socket.AF_INET6, addr[:16])
        port = struct.unpack(">H", addr[16:])[0]
    else:
        raise RuntimeError("bad ATYP")
    conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
    return host, port

def _recvn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data

def relay(a, b):
    pair = [a, b]
    try:
        while True:
            readable, _, _ = select.select(pair, [], [], 30)
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
    except OSError:
        pass

def handle_conn(conn, cfg):
    try:
        if cfg["mode"] == "driver":
            rctx = query_orig_dest(conn)
            if rctx:
                target_host, target_port, pid = rctx
                print(f"[>] pid {pid} -> {target_host}:{target_port}", flush=True)
            else:
                print("[!] no redirect context, closing", flush=True)
                conn.close()
                return
        else:
            target_host, target_port = socks5_serve(conn)
            print(f"[>] client request: {target_host}:{target_port}", flush=True)
        up = socks5_connect_upstream(target_host, target_port,
                                     cfg["proxy_host"], cfg["proxy_port"],
                                     cfg.get("user"), cfg.get("password"))
        relay(conn, up)
        up.close()
    except Exception as exc:
        print(f"[!] {exc}", flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass

def socks5_connect_upstream(target_host, target_port, proxy_host, proxy_port, user=None, password=None):
    up = socket.create_connection((proxy_host, proxy_port), timeout=10)
    up.settimeout(10)
    if user is not None:
        up.sendall(b"\x05\x02\x00\x02")
    else:
        up.sendall(b"\x05\x01\x00")
    resp = _recvn(up, 2)
    if resp[0] != 5:
        raise RuntimeError("bad SOCKS version")
    if resp[1] == 0x02:
        u = (user or "").encode()
        p = (password or "").encode()
        up.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        auth = _recvn(up, 2)
        if auth[1] != 0:
            up.close()
            raise RuntimeError("auth rejected")
    elif resp[1] != 0x00:
        up.close()
        raise RuntimeError("no acceptable auth")
    try:
        addr = socket.inet_pton(socket.AF_INET, target_host)
        req = b"\x05\x01\x00\x01" + addr + struct.pack(">H", target_port)
    except OSError:
        try:
            addr = socket.inet_pton(socket.AF_INET6, target_host)
            req = b"\x05\x01\x00\x04" + addr + struct.pack(">H", target_port)
        except OSError:
            h = target_host.encode()
            req = b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", target_port)
    up.sendall(req)
    rep = _recvn(up, 4)
    if rep[1] != 0:
        up.close()
        raise RuntimeError("proxy CONNECT failed, code=%d" % rep[1])
    atyp = rep[3]
    if atyp == 1:
        _recvn(up, 6)
    elif atyp == 3:
        n = _recvn(up, 1)[0]
        _recvn(up, n + 2)
    elif atyp == 4:
        _recvn(up, 18)
    return up

def main():
    ap = argparse.ArgumentParser(description="OddlyProxifier Python engine")
    ap.add_argument("mode", choices=["local", "driver", "stats"])
    ap.add_argument("listen_port", nargs="?", type=int)
    ap.add_argument("proxy_host", nargs="?")
    ap.add_argument("proxy_port", nargs="?", type=int)
    ap.add_argument("target_port", nargs="?", type=int, default=0)
    args = ap.parse_args()

    if args.mode == "stats":
        h = driver_open()
        for name, value in driver_get_stats(h).items():
            print(f"{name} = {value}")
        return

    cfg = {"mode": args.mode, "proxy_host": args.proxy_host, "proxy_port": args.proxy_port}

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # The driver sends a bound socket to its own local address, so the redirect
    # listener accepts on every address; the SOCKS5 entry is local only.
    bind_host = "0.0.0.0" if args.mode == "driver" else "127.0.0.1"
    listener.bind((bind_host, args.listen_port))
    listener.listen(64)
    print(f"[+] OddlyProxy listening on {bind_host}:{args.listen_port}", flush=True)

    if args.mode == "driver":
        try:
            h = driver_open()
            driver_set_policy(h, args.listen_port, True, args.target_port)
            print(f"[+] policy installed (target port {args.target_port or 'any'})", flush=True)
            import atexit
            atexit.register(lambda: (driver_set_policy(h, 0, False), kernel32.CloseHandle(h)))
        except OSError as exc:
            sys.exit(f"[!] driver unavailable: {exc}")

    try:
        while True:
            conn, _addr = listener.accept()
            cfg_conn = dict(cfg)
            cfg_conn["conn"] = conn
            threading.Thread(target=handle_conn, args=(conn, cfg_conn), daemon=True).start()
    except KeyboardInterrupt:
        print("\nbye")

if __name__ == "__main__":
    main()
