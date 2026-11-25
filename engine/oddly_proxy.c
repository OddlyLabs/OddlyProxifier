/*
    oddly_proxy.c - minimal C engine for OddlyDrv.sys (driver ABI v2).

    A small reference client of the driver interface in driver/oddly_ioctl.h.
    It forwards every connection through one SOCKS5 proxy, with no rules,
    chains or UI. The full engine is the Go program in cmd/oddlyproxifier.

    Modes:
      driver <listenPort> <proxyHost> <proxyPort> [targetPort] [user pass]
        Asks the driver to redirect outgoing TCP connections (all ports, or
        only targetPort) to this process, and reads each original
        destination from the accepted socket. Needs administrator rights.
      local  <listenPort> <proxyHost> <proxyPort> [user pass]
        Local SOCKS5 entry on 127.0.0.1, no driver.

    Build: build.bat   (cl /O2 /W3 oddly_proxy.c ws2_32.lib)

    License: MIT
*/

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../driver/oddly_ioctl.h"

#pragma comment(lib, "ws2_32.lib")

#ifndef SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT
#define SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT 0x980000DDu
#endif

#define MODE_LOCAL  0
#define MODE_DRIVER 1

typedef struct _CONN_CTX {
    SOCKET client;
    int    mode;
} CONN_CTX;

static HANDLE g_Driver = INVALID_HANDLE_VALUE;
static char   g_ProxyHost[128];
static char   g_ProxyPort[8];
static char   g_ProxyUser[256];
static char   g_ProxyPass[256];

/* ------------------------------------------------------------ helpers */

/* Reads exactly `need` bytes; 0 on success, -1 on error or end of stream. */
static int
recvn(SOCKET s, unsigned char *buf, int need)
{
    int got = 0, r;
    while (got < need) {
        r = recv(s, (char *)buf + got, need - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

static int
sendn(SOCKET s, const unsigned char *buf, int len)
{
    int sent = 0, r;
    while (sent < len) {
        r = send(s, (const char *)buf + sent, len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

static void
set_timeout(SOCKET s, int ms)
{
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof(t));
}

/* --------------------------------------------------- SOCKS5 client */

/* Connects to the proxy and asks it for targetHost:targetPort. */
static SOCKET
oddly_socks5_connect(const char *targetHost, int targetPort)
{
    struct addrinfo hints, *res = NULL, *ai;
    SOCKET up = INVALID_SOCKET;
    unsigned char buf[600];
    struct in_addr a4;
    struct in6_addr a6;
    int hostLen = (int)strlen(targetHost);
    int off = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_ProxyHost, g_ProxyPort, &hints, &res) != 0) return INVALID_SOCKET;
    for (ai = res; ai; ai = ai->ai_next) {
        up = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (up == INVALID_SOCKET) continue;
        set_timeout(up, 15000);
        if (connect(up, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        closesocket(up);
        up = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (up == INVALID_SOCKET) return INVALID_SOCKET;

    /* greeting */
    buf[0] = 5;
    if (g_ProxyUser[0]) { buf[1] = 2; buf[2] = 0; buf[3] = 2; off = 4; }
    else                { buf[1] = 1; buf[2] = 0; off = 3; }
    if (sendn(up, buf, off) != 0 || recvn(up, buf, 2) != 0 || buf[0] != 5) goto fail;
    if (buf[1] == 2) {
        int ul = (int)strlen(g_ProxyUser), pl = (int)strlen(g_ProxyPass);
        if (!g_ProxyUser[0] || ul > 255 || pl > 255) goto fail;
        off = 0;
        buf[off++] = 1;
        buf[off++] = (unsigned char)ul; memcpy(buf + off, g_ProxyUser, ul); off += ul;
        buf[off++] = (unsigned char)pl; memcpy(buf + off, g_ProxyPass, pl); off += pl;
        if (sendn(up, buf, off) != 0 || recvn(up, buf, 2) != 0 || buf[1] != 0) goto fail;
    } else if (buf[1] != 0) {
        goto fail;
    }

    /* request */
    off = 0;
    buf[off++] = 5; buf[off++] = 1; buf[off++] = 0;
    if (inet_pton(AF_INET, targetHost, &a4) == 1) {
        buf[off++] = 1; memcpy(buf + off, &a4, 4); off += 4;
    } else if (inet_pton(AF_INET6, targetHost, &a6) == 1) {
        buf[off++] = 4; memcpy(buf + off, &a6, 16); off += 16;
    } else {
        if (hostLen < 1 || hostLen > 255) goto fail;
        buf[off++] = 3; buf[off++] = (unsigned char)hostLen;
        memcpy(buf + off, targetHost, hostLen); off += hostLen;
    }
    buf[off++] = (unsigned char)(targetPort >> 8);
    buf[off++] = (unsigned char)(targetPort & 0xff);
    if (sendn(up, buf, off) != 0) goto fail;

    /* reply */
    if (recvn(up, buf, 4) != 0 || buf[0] != 5 || buf[1] != 0) goto fail;
    switch (buf[3]) {
    case 1: if (recvn(up, buf, 6) != 0) goto fail; break;
    case 3: if (recvn(up, buf, 1) != 0) goto fail;
            if (recvn(up, buf + 1, buf[0] + 2) != 0) goto fail;
            break;
    case 4: if (recvn(up, buf, 18) != 0) goto fail; break;
    default: goto fail;
    }
    set_timeout(up, 0);
    return up;
fail:
    closesocket(up);
    return INVALID_SOCKET;
}

/* ---------------------------------------------------- SOCKS5 server */

static void
socks5_reply(SOCKET c, unsigned char code)
{
    unsigned char r[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    r[1] = code;
    sendn(c, r, sizeof(r));
}

/* Reads the client's request. The reply is sent by the caller. */
static int
oddly_socks5_serve(SOCKET c, char *outHost, int outHostMax, int *outPort)
{
    unsigned char buf[600];
    char host[256];
    int n, i, ok = 0;

    set_timeout(c, 15000);
    if (recvn(c, buf, 2) != 0 || buf[0] != 5) return -1;
    n = buf[1];
    if (n < 1 || recvn(c, buf, n) != 0) return -1;
    for (i = 0; i < n; i++) if (buf[i] == 0) ok = 1;
    buf[0] = 5; buf[1] = ok ? 0 : 0xff;
    if (sendn(c, buf, 2) != 0 || !ok) return -1;

    if (recvn(c, buf, 4) != 0 || buf[0] != 5) return -1;
    if (buf[1] != 1) { socks5_reply(c, 7); return -1; }   /* CONNECT only */
    switch (buf[3]) {
    case 1:
        if (recvn(c, buf, 6) != 0) return -1;
        sprintf(host, "%u.%u.%u.%u", buf[0], buf[1], buf[2], buf[3]);
        *outPort = (buf[4] << 8) | buf[5];
        break;
    case 3:
        if (recvn(c, buf, 1) != 0) return -1;
        n = buf[0];
        if (n < 1 || recvn(c, buf, n + 2) != 0) return -1;
        memcpy(host, buf, n); host[n] = 0;
        *outPort = (buf[n] << 8) | buf[n + 1];
        break;
    case 4:
        if (recvn(c, buf, 18) != 0) return -1;
        if (!inet_ntop(AF_INET6, buf, host, sizeof(host))) return -1;
        *outPort = (buf[16] << 8) | buf[17];
        break;
    default:
        socks5_reply(c, 8);
        return -1;
    }
    strncpy(outHost, host, outHostMax - 1);
    outHost[outHostMax - 1] = 0;
    return 0;
}

/* --------------------------------------------------------- redirect */

/* Original destination and owning process of a redirected connection. */
static int
query_orig_dest(SOCKET s, char *host, int hostMax, int *port, unsigned long *pid)
{
    ODDLY_REDIRECT_CTX ctx;
    DWORD got = 0;

    if (WSAIoctl(s, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, NULL, 0,
                 &ctx, sizeof(ctx), &got, NULL, NULL) != 0)
        return 0;
    if (got < sizeof(ctx) || ctx.Magic != ODDLY_CTX_MAGIC) return 0;
    if (!inet_ntop(ctx.Family == 6 ? AF_INET6 : AF_INET, ctx.Addr, host, hostMax))
        return 0;
    *port = ntohs(ctx.Port);
    *pid = ctx.Pid;
    return 1;
}

/* -------------------------------------------------------------- relay */

static void
oddly_relay(SOCKET a, SOCKET b)
{
    static const struct timeval idle = { 300, 0 };
    char *data = (char *)malloc(65536);
    int openA = 1, openB = 1;   /* a->b and b->a still flowing */

    if (!data) return;
    while (openA || openB) {
        fd_set r;
        struct timeval tv = idle;
        int i;
        FD_ZERO(&r);
        if (openA) FD_SET(a, &r);
        if (openB) FD_SET(b, &r);
        if (select(0, &r, NULL, NULL, &tv) <= 0) break;
        for (i = 0; i < 2; i++) {
            SOCKET from = i ? b : a, to = i ? a : b;
            int got;
            if (!(i ? openB : openA) || !FD_ISSET(from, &r)) continue;
            got = recv(from, data, 65536, 0);
            if (got < 0) goto done;
            if (got == 0) {                 /* half close */
                shutdown(to, SD_SEND);
                if (i) openB = 0; else openA = 0;
                continue;
            }
            if (sendn(to, (const unsigned char *)data, got) != 0) goto done;
        }
    }
done:
    free(data);
}

/* ---------------------------------------------------- driver control */

static BOOL
oddly_driver_set_policy(USHORT port, USHORT targetPort, BOOL enable)
{
    ODDLY_POLICY p;
    DWORD ret = 0;

    memset(&p, 0, sizeof(p));
    p.Size       = sizeof(p);
    p.Version    = ODDLY_ABI_VERSION;
    p.Flags      = enable ? ODDLY_FLAG_ENABLED : 0;   /* IPv4, all applications */
    p.EnginePid  = GetCurrentProcessId();
    p.Port       = port;
    p.TargetPort = targetPort;
    return DeviceIoControl(g_Driver, IOCTL_ODDLY_SET_POLICY,
                           &p, sizeof(p), NULL, 0, &ret, NULL);
}

static BOOL
oddly_driver_attach(USHORT port, USHORT targetPort)
{
    unsigned int version = 0;
    DWORD ret = 0;

    g_Driver = CreateFileA(ODDLY_DEVICE_WIN32, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_Driver == INVALID_HANDLE_VALUE) {
        printf("[!] cannot open %s (error %lu): is the driver started, and is this an elevated prompt?\n",
               ODDLY_DEVICE_WIN32, GetLastError());
        return FALSE;
    }
    if (!DeviceIoControl(g_Driver, IOCTL_ODDLY_GET_VERSION, NULL, 0,
                         &version, sizeof(version), &ret, NULL) ||
        version != ODDLY_ABI_VERSION) {
        printf("[!] driver ABI version %u, this engine needs %u\n", version, ODDLY_ABI_VERSION);
        goto fail;
    }
    if (!oddly_driver_set_policy(port, targetPort, TRUE)) {
        printf("[!] the driver refused the policy (error %lu)\n", GetLastError());
        goto fail;
    }
    if (targetPort)
        printf("[+] redirecting TCP port %u to port %u\n", targetPort, port);
    else
        printf("[+] redirecting all TCP connections to port %u\n", port);
    return TRUE;
fail:
    CloseHandle(g_Driver);
    g_Driver = INVALID_HANDLE_VALUE;
    return FALSE;
}

/* The driver also drops the policy by itself when the handle closes. */
static BOOL WINAPI
oddly_console_ctrl(DWORD type)
{
    UNREFERENCED_PARAMETER(type);
    if (g_Driver != INVALID_HANDLE_VALUE) {
        oddly_driver_set_policy(0, 0, FALSE);
        CloseHandle(g_Driver);
    }
    ExitProcess(0);
}

/* ----------------------------------------------------------- per-conn */

static DWORD WINAPI
oddly_conn_thread(LPVOID arg)
{
    CONN_CTX *cx = (CONN_CTX *)arg;
    SOCKET c = cx->client, up;
    int mode = cx->mode;
    char targetHost[256];
    int targetPort = 0;
    unsigned long pid = 0;

    free(cx);

    if (mode == MODE_DRIVER) {
        if (!query_orig_dest(c, targetHost, sizeof(targetHost), &targetPort, &pid)) {
            /* Somebody connected to the listener directly. */
            closesocket(c);
            return 0;
        }
        printf("[>] pid %lu -> %s:%d\n", pid, targetHost, targetPort);
    } else {
        if (oddly_socks5_serve(c, targetHost, sizeof(targetHost), &targetPort) != 0) {
            closesocket(c);
            return 0;
        }
        printf("[>] request %s:%d\n", targetHost, targetPort);
    }

    up = oddly_socks5_connect(targetHost, targetPort);
    if (up == INVALID_SOCKET) {
        printf("[!] proxy could not connect to %s:%d\n", targetHost, targetPort);
        if (mode == MODE_LOCAL) socks5_reply(c, 5);
        closesocket(c);
        return 0;
    }
    if (mode == MODE_LOCAL) socks5_reply(c, 0);
    set_timeout(c, 0);
    oddly_relay(c, up);
    closesocket(c);
    closesocket(up);
    return 0;
}

/* ---------------------------------------------------------------- main */

static int
usage(void)
{
    printf("usage:\n"
           "  OddlyProxy driver <listenPort> <proxyHost> <proxyPort> [targetPort] [user pass]\n"
           "  OddlyProxy local  <listenPort> <proxyHost> <proxyPort> [user pass]\n");
    return 2;
}

static int
parse_port(const char *s, int allowZero)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*end || v > 65535 || v < (allowZero ? 0 : 1)) return -1;
    return (int)v;
}

int
main(int argc, char **argv)
{
    WSADATA wsa;
    SOCKET ls;
    struct sockaddr_in la;
    int mode, listenPort, proxyPort, targetPort = 0, next = 5;
    BOOL on = TRUE;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 5) return usage();
    if (strcmp(argv[1], "driver") == 0) mode = MODE_DRIVER;
    else if (strcmp(argv[1], "local") == 0) mode = MODE_LOCAL;
    else return usage();

    listenPort = parse_port(argv[2], 0);
    proxyPort  = parse_port(argv[4], 0);
    if (listenPort < 0 || proxyPort < 0 || strlen(argv[3]) >= sizeof(g_ProxyHost)) return usage();
    strcpy(g_ProxyHost, argv[3]);
    sprintf(g_ProxyPort, "%d", proxyPort);

    if (mode == MODE_DRIVER && (argc == 6 || argc == 8)) {
        targetPort = parse_port(argv[next++], 1);
        if (targetPort < 0) return usage();
    }
    if (argc == next + 2) {
        if (strlen(argv[next]) > 255 || strlen(argv[next + 1]) > 255) return usage();
        strcpy(g_ProxyUser, argv[next]);
        strcpy(g_ProxyPass, argv[next + 1]);
    } else if (argc != next) {
        return usage();
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[!] WSAStartup failed\n");
        return 1;
    }
    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { printf("[!] socket failed (%d)\n", WSAGetLastError()); return 1; }
    setsockopt(ls, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof(on));
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_port = htons((unsigned short)listenPort);
    /* The driver sends a bound socket to its own local address, so the
       redirect listener has to accept on every address. */
    la.sin_addr.s_addr = htonl(mode == MODE_DRIVER ? INADDR_ANY : INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&la, sizeof(la)) != 0 || listen(ls, SOMAXCONN) != 0) {
        printf("[!] cannot listen on port %d (%d)\n", listenPort, WSAGetLastError());
        return 1;
    }

    if (mode == MODE_DRIVER) {
        SetConsoleCtrlHandler(oddly_console_ctrl, TRUE);
        if (!oddly_driver_attach((USHORT)listenPort, (USHORT)targetPort)) return 1;
    }
    printf("[+] %s mode on port %d, proxy %s:%s%s\n", mode == MODE_DRIVER ? "driver" : "local",
           listenPort, g_ProxyHost, g_ProxyPort, g_ProxyUser[0] ? " (with password)" : "");

    for (;;) {
        CONN_CTX *cx;
        HANDLE th;
        SOCKET c = accept(ls, NULL, NULL);
        if (c == INVALID_SOCKET) {
            if (WSAGetLastError() == WSAEINTR) break;
            continue;
        }
        cx = (CONN_CTX *)malloc(sizeof(*cx));
        if (!cx) { closesocket(c); continue; }
        cx->client = c;
        cx->mode = mode;
        th = CreateThread(NULL, 0, oddly_conn_thread, cx, 0, NULL);
        if (!th) { closesocket(c); free(cx); continue; }
        CloseHandle(th);
    }
    return 0;
}
