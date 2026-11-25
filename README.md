# OddlyProxifier

让本身不支持代理设置的网络程序，通过 SOCKS 或 HTTPS 代理服务器（以及代理链）联网的跨平台客户端。
功能定位对标 Proxifier：按「应用程序 / 目标主机 / 端口」写规则，命中的连接被透明地送进代理，程序本身无需任何改动。

A cross-platform client that makes applications without proxy settings connect through SOCKS or HTTPS
proxy servers and proxy chains, selected by per-application rules.

## 功能

- **代理协议**：SOCKS5（含用户名/密码）、SOCKS4、SOCKS4a、HTTP CONNECT（含 Basic 认证）、HTTPS（TLS 上的 CONNECT）。
- **代理链**：`chain`（逐跳串联）、`failover`（第一个可用的代理）、`balance`（轮询并带故障切换）。失败的代理暂停 30 秒。
- **规则**：应用程序（文件名或完整路径通配）、目标（域名通配、CIDR、IP 区间）、端口；动作为直连 / 阻止 / 代理 / 代理链；自上而下第一条命中的规则生效。
- **透明拦截**：系统级重定向出站 TCP 连接，并识别发起连接的进程；界面顶部有一键开关。
- **域名处理**：从 TLS SNI 与 HTTP Host 取回域名；可选的 Fake-IP DNS，让域名交给代理端解析；可以列出始终在本机解析的名字（内网域名等）。
- **代理入口**：本机 SOCKS5 / SOCKS4 / HTTP 混合端口，供能设置代理的程序直接使用（不需要管理员权限）。
- **UDP 转发**：代理入口支持 SOCKS5 UDP ASSOCIATE，按规则直连或经一个 SOCKS5 代理转发（限制见「已知限制」）。
- **管理界面**：内嵌网页（中 / 英文、浅色 / 深色），可编辑代理、代理链和规则，查看实时连接、日志，测试代理。
- **流量统计**：最近 5 分钟的收发速率曲线，以及按应用程序、出口、规则汇总的连接数与流量。
- **多份配置**：按名字保存、切换、删除配置；导出（可选是否带密码）与导入；可以导入 Proxifier 的 `.ppx` 配置。
- **日志文件**：日志可同时写入文件，超过 5 MB 自动轮转。
- **随系统运行**：注册为 Windows 服务 / systemd 单元 / launchd 守护进程；Windows 上有通知区域图标，可设为登录时自动显示。
- **单个可执行文件**，无运行时依赖。

## 平台支持

| 平台 | 透明拦截方式 | 状态 |
|---|---|---|
| Windows 10/11 x64 | WFP 内核驱动 `OddlyDrv.sys` | 已在 Windows 11 虚拟机中实测 |
| Linux | nftables（回退到 iptables）`REDIRECT` | 已在 Linux 网络命名空间中实测 |
| macOS | pf `rdr` + `route-to` | 实验性：可以编译，**未经实机测试** |

不使用透明拦截时（`-no-intercept`），三个平台上的代理入口和管理界面都可以用普通权限运行。

## 快速开始

需要 Go 1.26 或更新版本。

```powershell
go build -trimpath -ldflags "-s -w" -o build/oddlyproxifier.exe ./cmd/oddlyproxifier
```

```powershell
build\oddlyproxifier.exe -open
```

启动后终端会打印管理界面地址（默认 `http://127.0.0.1:9090/#token=…`）。在界面里添加代理服务器，再添加规则即可。

- 透明拦截需要管理员（Windows）或 root（Linux / macOS）权限。没有权限时引擎照常启动，只提供代理入口。
- 配置保存在用户配置目录下的 `OddlyProxifier/profile.json`（Windows 为 `%AppData%`），可用 `-profile 文件` 指定别处。
- 默认配置：局域网与本机直连，其余直连，代理入口 `127.0.0.1:1080`。

### 命令行

```
oddlyproxifier [run] [flags]     启动引擎与管理界面
    -profile 文件   -api 地址   -log debug|info|warn|error|off   -no-intercept   -open
    -tray on|off|auto    Windows 通知区域图标（auto：双击启动时显示）
oddlyproxifier check             测试配置里的代理与代理链
oddlyproxifier match -app 程序 -host 主机 -port 端口    查看一条连接会命中哪条规则
oddlyproxifier service status|install|start|stop|uninstall    随系统运行（install 可带 -profile、-api）
oddlyproxifier tray [-api 地址] [-profile 文件] [-autostart on|off]    Windows：为已在运行的引擎显示通知区域图标
oddlyproxifier driver status|install|start|stop|uninstall    Windows 驱动管理
oddlyproxifier cleanup           清除引擎异常退出后遗留的重定向规则
oddlyproxifier version
```

### 交叉编译与打包

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o build/linux/oddlyproxifier ./cmd/oddlyproxifier
```

macOS 用 `GOOS=darwin`、`GOARCH=arm64` 或 `amd64`。不需要 cgo。

一次构建并打包全部平台（windows/amd64，linux 与 darwin 的 amd64、arm64）：

```powershell
go run ./tools/release
```

压缩包写入 `dist/`（`-out 目录` 可改，`-only linux/arm64,windows/amd64` 只做其中几个），并生成 `SHA256SUMS`。
每个包里有程序、README、LICENSE 和架构文档；Windows 包在 `driver/OddlyDrv.sys` 已经构建时一并带上驱动。

## 配置文件

配置是一个 JSON 文件，管理界面读写的就是它；也可以手写，缺省的字段取默认值。

```json
{
  "version": 1,
  "proxies": [
    {"id": "office", "name": "Office SOCKS5", "type": "socks5", "host": "10.0.0.8", "port": 1080,
     "username": "user", "password": "secret"},
    {"id": "exit", "name": "Exit HTTPS", "type": "https", "host": "proxy.example.com", "port": 443}
  ],
  "chains": [
    {"id": "two-hop", "name": "Office then exit", "type": "chain", "proxies": ["office", "exit"]}
  ],
  "rules": [
    {"id": "lan", "name": "LAN", "enabled": true,
     "hosts": ["localhost", "10.0.0.0/8", "192.168.0.0/16"], "action": {"type": "direct"}},
    {"id": "git", "name": "Git over the chain", "enabled": true,
     "apps": ["git.exe", "ssh.exe"], "ports": "22,443", "action": {"type": "chain", "target": "two-hop"}},
    {"id": "ads", "name": "Ads", "enabled": true,
     "hosts": ["*.ads.example"], "action": {"type": "block"}}
  ],
  "default": {"type": "proxy", "target": "office"},
  "dns": {"mode": "auto", "sniff": true, "local_names": ["*.corp.example", "printer"],
          "fake": {"enabled": false, "listen": "127.0.0.1:53", "range": "198.18.0.0/15", "upstream": ""}},
  "options": {
    "intercept": true, "ipv6": true, "block_quic": true, "handle_direct": false,
    "transparent_port": 37080, "target_port": 0,
    "inbound": "127.0.0.1:1080", "udp": true, "api": "127.0.0.1:9090",
    "connect_timeout": 15, "idle_timeout": 0,
    "log_file": "", "log_level": "info"
  }
}
```

| 字段 | 说明 |
|---|---|
| `proxies[].type` | `socks5`、`socks4`、`socks4a`、`http`、`https`；`https` 另有 `tls_server_name`、`tls_insecure` |
| `chains[].type` | `chain`、`failover`、`balance` |
| `rules[].apps` | 如 `chrome.exe`、`*\Steam\*`；留空表示任意程序 |
| `rules[].hosts` | 如 `*.example.com`、`10.0.0.0/8`、`1.1.1.1-1.1.1.9`；留空表示任意目标 |
| `rules[].ports` | 如 `80,443,8000-9000`；留空表示任意端口 |
| `default` | 没有规则命中时的动作 |
| `dns.mode` | `auto` / `remote`：已知域名时交给代理解析；`local`：本机解析后把 IP 交给代理 |
| `dns.sniff` | 从 TLS SNI / HTTP Host 取回域名，使按域名的规则对透明连接生效 |
| `dns.local_names` | 始终在本机解析的名字（通配写法同 `hosts`），用于代理端不认识的内网域名 |
| `options.udp` | 代理入口是否接受 SOCKS5 UDP ASSOCIATE |
| `options.log_file`、`log_level` | 日志同时写入这个文件（空为不写）及写入的最低级别；文件超过 5 MB 时改名为 `<文件>.1` 后重新开始 |
| `options.block_quic` | 拒绝被拦截流量的 UDP/443，让浏览器从 QUIC 退回 TCP |
| `options.handle_direct` | 只可能直连的连接也经过引擎（便于在界面里观察全部连接） |
| `options.target_port` | 调试用：只拦截这个目标端口，`0` 为全部 |

`api_token` 不写时自动生成并保存。管理接口只监听本机，所有 `/api/` 请求都要带这个令牌。

### 多份配置与导入

在「设置 → 配置」里可以把当前配置另存为一个名字，之后在几份配置之间切换。保存的配置放在配置文件旁边的 `profiles/` 目录。
切换或导入只替换代理、代理链、规则和域名解析；属于这台电脑的内容（端口、访问令牌、日志文件）保持不变。

- **导出**：得到一个 JSON 文件，默认不含代理密码，勾选后以明文写入。
- **导入**：接受本程序导出的 JSON，也接受 Proxifier 的 `.ppx`。`.ppx` 中本程序不支持的内容会被跳过并逐条列出：
  不支持的代理类型（如 SSH）、引用了这些代理的代理链与规则；Proxifier 加密保存的密码无法读取，需要重新填写。

## 各平台说明

### Windows

透明拦截依赖内核驱动 `OddlyDrv.sys`。把它放在 `oddlyproxifier.exe` 同目录（或其下的 `driver\`），以管理员身份启动引擎，
引擎会自行注册并启动驱动服务；也可以用 `oddlyproxifier driver install|start|stop|uninstall` 手动管理。

构建与签名驱动（需要 Visual Studio 2022 Build Tools 与 WDK 10.0.26100）：

```bat
cd driver
build.bat
sign.bat <证书.pfx> <密码>
```

**驱动签名是使用上的硬性条件**：仓库不附带已签名的驱动。自己用测试证书签名的驱动，只能在信任该证书并开启测试签名的机器上加载：

```bat
:: 管理员，执行后重启一次
bcdedit /set testsigning on
```

正式发布需要 EV 代码签名证书并经微软签署（attestation signing）。请先在虚拟机里试用自行构建的驱动。

驱动的行为：只改写出站 TCP 连接的目的地址，不读取也不修改数据；引擎进程自身、发往代理服务器的连接、回环与组播地址不被重定向；
引擎退出或崩溃（句柄关闭）时驱动立即丢弃策略，连接恢复直连；设备只允许 SYSTEM 与管理员打开。

Fake-IP DNS 在 Windows 上不会自动接管系统 DNS：启用后需要把网卡的 DNS 服务器手动指向 `dns.fake.listen` 的地址。

**作为服务运行**（管理员）：

```powershell
oddlyproxifier service install
```

```powershell
oddlyproxifier service start
```

服务名为 `OddlyProxifier`，随系统启动，以 SYSTEM 身份运行，使用安装时 `-profile` 指定的配置文件（默认是你自己的那一份，安装时会打印路径）。

**通知区域图标**：双击启动 `oddlyproxifier.exe` 时自动出现（`-tray on|off` 可强制）；菜单里可以打开管理界面、开关拦截、退出。
引擎以服务运行时，用 `oddlyproxifier tray` 单独显示图标，`oddlyproxifier tray -autostart on` 让它在登录时自动出现
（写入当前用户的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，`-autostart off` 取消）。

### Linux

以 root 运行。引擎在 `nat OUTPUT` 安装 `REDIRECT` 规则（优先 nftables，没有 `nft` 时用 iptables），
用 `SO_MARK` 排除自身流量，用 `SO_ORIGINAL_DST` 取回原始目的地，通过 netlink 与 `/proc` 识别进程。
一个守护子进程在引擎被强杀时清除规则；仍有遗留时执行 `oddlyproxifier cleanup`。

- 内核无法按程序名筛选，所以全部出站 TCP 都先进入引擎，再由规则决定直连还是走代理。
- 启用 Fake-IP DNS 时，发往非回环地址的 UDP/53 会被重定向到假 DNS 服务。
- **WSL2 镜像网络模式（`networkingMode=mirrored`）下不可用**：系统不保留被重定向连接的原始目的地，引擎会给出一次警告并拒绝这些连接。请改用 NAT 网络模式，或只使用代理入口。
- `sudo oddlyproxifier service install` 写入 systemd 单元 `/etc/systemd/system/oddlyproxifier.service` 并设为开机启动；`service start|stop|status|uninstall` 管理它。

### macOS（实验性）

以 root 运行，使用 pf 锚点 `com.apple/250.OddlyProxifier` 与 `DIOCNATLOOK`。引擎自身靠 `user != root` 排除，因此其它 root 进程的连接也不会被拦截。这部分代码能通过编译和静态检查，但没有在真机上运行过，请当作未验证的实现对待。

`sudo oddlyproxifier service install` 在 `/Library/LaunchDaemons/` 写入 launchd 守护进程的 plist（同样未经实机测试）。

## 测试

```powershell
go test ./...
```

- `tools/linux_test.sh`：在独立的网络命名空间里验证 Linux 透明拦截（root）。
- `tools/testproxy`：用于手动试验的 SOCKS5 / SOCKS4 / HTTP / HTTPS 测试代理与回显服务。
- `tools/trayprobe.ps1`：检查 Windows 通知区域图标是否已经注册。
- `tools/test_e2e.py`：C / Python 参考引擎的本地端到端测试。

## 目录

| 路径 | 内容 |
|---|---|
| `cmd/oddlyproxifier/` | 主程序入口与命令行 |
| `internal/config`、`rules`、`proxy` | 配置、规则匹配、代理协议与代理链 |
| `internal/profiles`、`ppx` | 按名字保存的配置、Proxifier `.ppx` 导入 |
| `internal/intercept`、`procinfo` | 各平台的拦截后端与进程识别 |
| `internal/engine`、`sniff`、`dnsx` | 会话处理、UDP 转发、流量统计、日志、域名嗅探、Fake-IP DNS |
| `internal/api`、`proxytest` | HTTP API 与内嵌管理界面、代理测试 |
| `internal/service`、`tray` | 系统服务（SCM / systemd / launchd）、Windows 通知区域图标 |
| `tools/release` | 全平台构建与打包 |
| `driver/` | WFP 驱动 `OddlyDrv.sys`，接口定义见 `driver/oddly_ioctl.h` |
| `engine/`、`pyengine/` | 驱动接口的最小 C / Python 参考实现（单一 SOCKS5 代理，无规则） |
| `docs/ARCHITECTURE.md` | 架构与驱动接口说明 |

## 已知限制

- 透明拦截只处理 TCP；可选地阻断 UDP/443 以迫使 QUIC 回退到 TCP。
- UDP 只在代理入口上经 SOCKS5 UDP ASSOCIATE 转发：直连，或经**一个** SOCKS5 代理。HTTP / HTTPS / SOCKS4 代理和多跳代理链不能承载 UDP，
  命中它们的 UDP 流量会被丢弃，**不会**改为直连绕过代理。
- 域名嗅探只认 TLS SNI 与 HTTP Host；加密的 SNI（ECH）或其它协议只能按 IP 匹配，除非启用 Fake-IP DNS。
- Windows 驱动的 IPv6 重定向、Fake-IP DNS 在 Windows 上的使用、浏览器里真实的 QUIC 回退尚未实测。
- macOS 后端未经实机测试。
- 没有原生图形界面，管理界面是本机网页；通知区域图标只有 Windows 有；没有安装程序。
- Windows 服务（安装、随系统启动、接管、停止、卸载）与 `tray` 命令（开关接管、关闭图标、登录自启动）已在 Windows 11 虚拟机中实测。
  尚未实测：systemd 与 launchd 的安装、通知区域图标的鼠标双击与提权提示。
- 卸载服务不会卸载驱动；需要时另行执行 `oddlyproxifier driver stop` 与 `driver uninstall`。
- 导入 `.ppx` 时列出的说明只有英文。

## License

MIT
