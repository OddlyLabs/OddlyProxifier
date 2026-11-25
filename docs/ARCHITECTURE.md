# OddlyProxifier architecture

## Overview

```
 application ── connect(dst) ──► OS network stack
                                      │  platform backend redirects the connection
                                      ▼
                      ┌──────────────────────────────────┐
                      │ engine (one Go binary)           │
 SOCKS/HTTP clients ─►│  transparent listener  + inbound │
                      │  origin + process lookup         │
                      │  hostname: sniff / fake-IP DNS   │
                      │  rules ─► direct | block | proxy │──► proxy 1 ─► proxy 2 ─► target
                      │  API + embedded web interface    │──► target (direct)
                      └──────────────────────────────────┘
```

One process does everything except the kernel-level redirection. The engine never
needs cgo; the platform-specific part is behind one interface.

| Package | Role |
|---|---|
| `internal/config` | Profile (JSON): proxies, chains, rules, DNS, options; defaults and validation |
| `internal/rules` | Compiled rule set: application globs, host wildcards / CIDR / ranges, ports; first match wins |
| `internal/profiles` | Named profiles kept in `profiles/` beside the profile file; what a switch replaces and what it keeps |
| `internal/ppx` | Import of Proxifier `.ppx` profiles, with remarks for what could not be carried over |
| `internal/proxy` | Dialers for SOCKS5, SOCKS4/4a, HTTP CONNECT, HTTPS; chains (`chain`, `failover`, `balance`); SOCKS5 UDP ASSOCIATE client |
| `internal/proxytest` | The proxy and chain test behind `check` and `POST /api/check` |
| `internal/netx` | Small connection helpers shared by the engine |
| `internal/intercept` | `Backend` interface and the Windows, Linux and macOS implementations |
| `internal/procinfo` | Which process owns a connection |
| `internal/sniff` | Hostname from TLS SNI or HTTP Host without consuming the stream |
| `internal/dnsx` | Fake-IP DNS server |
| `internal/engine` | Sessions, routing, relaying, UDP relay, traffic statistics, log buffer and log file |
| `internal/api` | HTTP API and the embedded web interface |
| `internal/service` | Running with the system: Windows service (SCM), systemd unit, launchd daemon |
| `internal/tray` | Windows notification-area icon (plain Win32, no cgo) |
| `cmd/oddlyproxifier` | Command line; the tray client that talks to a running engine over the API |
| `tools/release` | Builds and packs every platform |

## Life of a connection

1. The backend redirects an outgoing TCP connection to the transparent listener
   (or a client connects to the mixed SOCKS5 / SOCKS4 / HTTP inbound port).
2. `Backend.Origin` returns the original destination and, on Windows, the PID.
   On other systems `procinfo.Find` looks the process up from the socket pair.
3. If the destination is a fake-IP address, the name it stands for is restored.
   Otherwise, when a name could change the route, the engine peeks at the first
   bytes (300 ms at most, never on server-first ports such as 21, 22, 25) for a TLS
   SNI or HTTP Host.
4. The rule set picks an action. For `proxy` and `chain` the engine builds the
   route; a proxy that failed is skipped for 30 seconds; an error reported by the
   target itself (`proxy.ErrTarget`) ends failover.
5. The engine's own sockets are exempt from interception (PID on Windows,
   `SO_MARK` on Linux, the root user on macOS), and connections to configured proxy
   servers are never redirected.
6. Both directions are relayed, with half-close, until either side ends.

## UDP

UDP is relayed only for SOCKS5 clients of the inbound port (`UDP ASSOCIATE`,
`options.udp`); the interception backends redirect TCP only.

- An association owns one UDP socket towards the client and one flow per
  destination (1024 at most). Each flow is routed by the same rules as a TCP
  connection and shows up in the connection list with network `udp`.
- A flow goes out directly or through exactly one SOCKS5 proxy, over that
  proxy's own UDP association. HTTP, HTTPS and SOCKS4 proxies and chains of
  several proxies cannot carry UDP: the flow fails and its datagrams are
  dropped. It is never sent directly instead, because that would leak traffic
  a rule meant for a proxy.
- While a flow is being set up, up to 32 datagrams wait. A failed attempt is
  retried after 5 seconds; a proxy's refusal to relay UDP is remembered for 30
  seconds, until the destination falls silent or the profile is saved again.
- The association ends with its TCP control connection.

## Statistics and logs

- Every finished or running session is accounted to three tables: application,
  route (proxy, chain, `(direct)`, `(blocked)`, `(failed)`) and rule. A table
  keeps 400 keys; the rest is folded into `(other)`.
- A sampler records the bytes of each second; the history covers 300 seconds
  and feeds the rate chart of the interface.
- The log is a ring buffer in memory. With `options.log_file` it is also
  appended to a file, from `options.log_level` upward; beyond 5 MB the file is
  renamed to `<file>.1` and started again.

## Profiles

The engine runs with one profile file. `internal/profiles` keeps named copies in
the directory `profiles/` beside it. Activating or importing a profile replaces
proxies, chains, rules, the default action and name resolution, and keeps what
belongs to the computer: listen addresses and ports, the API token, the log
file. An export leaves proxy passwords out unless asked for them.

`internal/ppx` reads a Proxifier profile: SOCKS4, SOCKS5 and HTTPS proxies,
chains, rules with applications, targets and ports, the default rule and the
name-resolution exclusion list. Proxy types the engine does not have, chains
and rules that depend on them, and passwords Proxifier stored encrypted are
left out, each with a remark the interface shows after the import.

## Running with the system

`oddlyproxifier service install` registers the program to start at boot with a
fixed profile path: a Windows service `OddlyProxifier` (the binary itself
speaks the service control protocol), the systemd unit
`/etc/systemd/system/oddlyproxifier.service`, or a launchd daemon in
`/Library/LaunchDaemons/`.

On Windows the engine shows a notification-area icon when it was started by
double-click (`-tray`). A service has no desktop, so `oddlyproxifier tray` is a
separate small client: it reads the API address and token from the profile,
polls `/api/status`, and offers the interface, the interception switch and
exit. `tray -autostart on` adds it to the user's `Run` registry key.

## Interception backends

```go
type Backend interface {
    Name() string
    Listen(port int, ipv6 bool) ([]net.Listener, error)
    Apply(Policy) error      // install or update redirection
    Stop() error             // remove it
    Reset() error            // remove what a crashed engine left behind
    Origin(c net.Conn) (Origin, error)
    DialControl() func(network, address string, c syscall.RawConn) error
    Info() map[string]any
}
```

`Policy` carries the listener port, IPv6 and QUIC flags, networks to bypass or
force, application patterns and the "applications only" switch.

### Windows: OddlyDrv.sys

A WFP callout driver. It only rewrites destinations; it never touches payload.

- `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, TCP: redirect to the engine.
- `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, UDP port 443: block (QUIC fallback) for
  traffic that would be redirected.
- Provider, sublayer, callouts and filters are added in one transaction of a
  dynamic session, so they disappear when the driver unloads.

Decision for each connection (`OddlyDecide`), in order:

1. No PID, PID 0 or 4, the engine's PID, an excluded PID: pass.
2. IPv6 without the IPv6 flag, or a destination port other than the debug target port: pass.
3. Loopback, unspecified, multicast and IPv4-mapped destinations: pass.
4. First matching network entry: `force` redirects, `bypass` passes.
5. Application on the exclude list: pass. In "applications only" mode an
   application that is not on the include list: pass.
6. Otherwise redirect.

The image name comes from the `ALE_APP_ID` field, with the process path from the
metadata as a fallback, lower-cased, base name only.

Redirect (`OddlyRedirect`): acquire the classify handle from the classify
context and the writable layer data; allocate a 48-byte context with the original
destination and the PID; rewrite the remote address to 127.0.0.1 / ::1 (or, for a
socket bound to an address, to that address) and the engine's port; set
`localRedirectHandle`, `localRedirectTargetPID` and the context; set the action to
PERMIT before `FwpsApplyModifiedLayerData0`. Connections the driver already
redirected are recognised with `FwpsQueryConnectionRedirectState0`.

The engine reads the context from the accepted socket with
`WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT)`.

#### Driver interface (ABI v2)

Defined in `driver/oddly_ioctl.h`; `internal/intercept/intercept_windows.go` keeps
the same numbers. Change both together and bump `ODDLY_ABI_VERSION`.

Device `\\.\OddlyDrv`, service `OddlyDrv`. Only SYSTEM and administrators may open it.

| IOCTL | Code | Input | Output |
|---|---|---|---|
| `GET_VERSION` | `0x00226400` | | `UINT32` ABI version |
| `SET_POLICY` | `0x0022E404` | policy blob | |
| `GET_STATS` | `0x00226408` | | `ODDLY_STATS`, 40 bytes |

Policy blob: `ODDLY_POLICY` header (160 bytes: size, version, flags, engine PID,
port, target port, counts, 32 excluded PIDs), then `NetCount` × `ODDLY_NET`
(20 bytes; `force` entries first) and `AppCount` × `ODDLY_APP` (132 bytes: kind and
a lower-case UTF-16 glob of up to 63 characters). Limits: 256 networks, 128
applications.

Flags: `0x1` enabled, `0x2` applications only, `0x4` IPv6, `0x8` block QUIC.

Statistics: classified, redirected, bypassed, QUIC blocked, errors. "Bypassed"
also counts the second classification of each redirected connection.

Redirect context (48 bytes): magic `0x3243444F`, PID, family (4 or 6), port in
network order, 16 address bytes, 16 reserved bytes, IPv6 scope id.

Ownership: the first handle that sets a policy owns it; another handle gets
`STATUS_SHARING_VIOLATION`. When the owner's handle closes, for any reason
including a crash, the driver drops the policy and connections go direct again.
The driver cannot stop while a handle is open.

`engine/oddly_proxy.c` and `pyengine/oddly_proxy.py` are minimal clients of this
interface: one SOCKS5 proxy, every application, no rules.

### Linux: netfilter

- `table ip|ip6 oddlyproxifier`, chain in `nat OUTPUT`: return for packets marked
  `0x4f44` (the engine), optional redirect of fake-IP networks, optional redirect
  of UDP/53 to the fake DNS server, return for bypassed networks, `redirect` of
  TCP to the transparent port. A filter chain rejects UDP/443 when QUIC blocking
  is on. Without `nft` the same rules are written with `iptables-restore`.
- Original destination: `getsockopt(SO_ORIGINAL_DST)`.
- Process: `NETLINK_SOCK_DIAG` gives the socket's inode and uid; `/proc/<pid>/fd`
  gives the process. netfilter cannot match by program, so every TCP connection
  enters the engine and the rules decide there.
- A guard child process waits on a pipe from the engine and removes the rules
  when the engine dies without cleaning up.

### macOS: pf (experimental, untested on a real machine)

Rules in the anchor `com.apple/250.OddlyProxifier`: `route-to lo0` for outgoing
TCP, `rdr` on `lo0` to the transparent port; the original destination comes from
`DIOCNATLOOK` on `/dev/pf`. The engine is exempted with `user != root`, so
connections of other root-owned processes are not intercepted either.

## Hostnames

Transparent connections arrive with an IP address. Two mechanisms recover the name:

- **Sniffing** (`dns.sniff`): TLS ClientHello SNI or HTTP `Host`. Cheap, but only
  for those two protocols.
- **Fake-IP DNS** (`dns.fake`): the engine answers DNS queries with addresses from
  `198.18.0.0/15` and remembers the name for each. A connection to such an address
  is always redirected and carries the name to the proxy, so the proxy resolves it.
  Linux redirects DNS queries automatically; on Windows the system DNS has to point
  at the fake server.

With `dns.mode` `local` the engine resolves names itself and hands the proxy an IP.
Names matching `dns.local_names` are always resolved locally, whatever the mode:
for internal names a proxy cannot know.

## API and web interface

`internal/api` serves the embedded page and a JSON API on `options.api`
(default `127.0.0.1:9090`).

- Every `/api/` request needs `Authorization: Bearer <api_token>`; the page gets
  the token from the URL fragment, which is never sent to a server.
- Requests whose `Host` is not a local name are refused (DNS rebinding).
- The page is served with `Content-Security-Policy: default-src 'self'; img-src
  'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'` and
  `X-Frame-Options: DENY`. No script comes from anywhere but the binary.

| Endpoint | |
|---|---|
| `GET /api/status` | version, backend, listeners, interception state, counters |
| `GET`, `PUT /api/profile` | read or replace the profile (validated, saved, applied) |
| `GET /api/profiles` | saved profiles and the active one (409 when the engine has no profile file) |
| `PUT /api/profiles/{name}` | save the current profile under a name |
| `POST /api/profiles/{name}/activate`, `DELETE /api/profiles/{name}` | switch to a saved profile; delete one |
| `GET /api/export[?passwords=1]` | the profile as a file, without passwords by default |
| `POST /api/import[?name=]` | body: an exported JSON profile or a Proxifier `.ppx`; answers the profile and remarks, 422 for a file that is neither |
| `POST /api/intercept` | `{"enabled": bool}`: the quick switch |
| `GET`, `DELETE /api/traffic` | rate history and usage tables; reset |
| `GET /api/connections`, `DELETE /api/connections[/id]` | live and recent connections; close |
| `GET /api/logs?after=n` | log lines |
| `POST /api/check` | test a proxy or chain |
| `POST /api/match` | which rule a connection would hit |
| `GET /api/driver`, `POST /api/driver/<op>` | Windows driver state and control |

## Safety properties

- Interception is removed when the engine stops; on Windows also when it crashes
  (handle close), on Linux and macOS by the guard process. `oddlyproxifier cleanup`
  removes anything still left.
- The engine's own traffic and traffic to the configured proxy servers is never
  redirected, so a chain cannot loop into itself.
- A connection addressed to the transparent port itself is dropped.
- Without administrator or root rights the engine still runs, with the inbound
  proxy port only.

## Verification status

| Area | How it was checked |
|---|---|
| Rules, proxies, chains, sniffing, fake DNS, API, UDP relay, statistics, profile store, `.ppx` import, service definitions | unit tests (`go test ./...`), all platforms compile and vet |
| Web interface | headless Chrome against a running engine: traffic chart and tables, quick switch, settings, save / switch / delete / export / import of profiles, in both languages and colour schemes |
| Windows driver v2 | VMware guest, Windows 11, test-signed: per-application and all-application modes, 60 parallel connections, block rule, SNI / Host rules, QUIC block, engine kill, driver stop |
| Windows service and tray client | same guest: `service install`, start at boot, redirection through the service, stop (connections go direct), uninstall; `tray` against the service from a non-elevated session: interception off and on, close, `-autostart on` / `off` |
| Linux transparent mode | network namespace under WSL2 (`tools/linux_test.sh`): proxied and direct applications, process names, guard cleanup after `kill -9`, clean stop |
| Windows driver, IPv6 and fake DNS | same guest. IPv6: `curl.exe` to a ULA address of the guest is redirected; with a proxy rule the SOCKS5 proxy receives the IPv6 target (ATYP 4), with a direct rule and `handle_direct` the request passes through the engine and succeeds. Fake DNS: adapter DNS set to `127.0.0.1` by hand; names resolve into `198.18.0.0/15`, `curl.exe` reaches `example.com` through the proxy by name (ATYP 3), another program reaches it directly through the engine |
| systemd | WSL2 (Ubuntu, systemd as PID 1), interception off in the profile: `service install` writes and enables the unit, start, proxy inbound serves a request, restart after `SIGKILL`, stop, uninstall removes the unit |
| Not verified | macOS backend; QUIC fallback in a real browser; launchd install; tray double-click and elevation prompt; WSL2 mirrored networking does not work (no original destination) |
