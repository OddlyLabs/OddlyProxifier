'use strict';

/* OddlyProxifier control panel. Plain DOM code: no build step, no dependencies. */

/* ------------------------------------------------------------------- text */

const T = {
  'lamps.label': ['Engine state', '引擎状态'],
  'lamp.intercept': ['Interception', '透明接管'],
  'lamp.inbound': ['Local proxy', '本地代理端口'],
  'lamp.fake': ['Fake DNS', 'Fake DNS'],
  'state.on': ['on', '已开启'],
  'state.off': ['off', '已关闭'],
  'state.idle': ['standby', '待命'],
  'state.error': ['problem', '异常'],
  'tot.sent': ['Sent', '已发送'],
  'tot.recv': ['Received', '已接收'],
  'nav.label': ['Sections', '功能分区'],
  'nav.connections': ['Connections', '连接'],
  'nav.traffic': ['Traffic', '流量'],
  'nav.rules': ['Rules', '规则'],
  'quick.pause': ['Pause interception', '暂停接管'],
  'quick.resume': ['Resume interception', '恢复接管'],
  'quick.on': ['Interception is on', '透明接管已开启'],
  'quick.off': ['Interception is paused. Applications connect directly.', '透明接管已暂停，应用程序将直接连接。'],
  'tr.title': ['Traffic', '流量'],
  'tr.reset': ['Reset statistics', '清零统计'],
  'tr.reset.title': ['Reset the traffic statistics?', '清零流量统计？'],
  'tr.reset.text': ['The chart and the tables start again from zero. Connections are not touched.', '曲线和表格将从零开始统计，现有连接不受影响。'],
  'tr.reset.done': ['Statistics reset', '统计已清零'],
  'tr.chart': ['Transfer rate over the last 5 minutes', '最近 5 分钟的传输速率'],
  'tr.down': ['Receiving', '接收'],
  'tr.up': ['Sending', '发送'],
  'tr.peak': ['Peak', '峰值'],
  'tr.ago': ['5 minutes ago', '5 分钟前'],
  'tr.now': ['now', '现在'],
  'tr.plot': ['Rate chart. Use the left and right arrow keys to read values.', '速率曲线，可用左右方向键逐秒查看数值。'],
  'tr.svg': ['Receiving {down}, sending {up}; peak {peak} in the last 5 minutes', '当前接收 {down}，发送 {up}；最近 5 分钟峰值 {peak}'],
  'tr.usage': ['Where the traffic went', '流量去向'],
  'tr.apps': ['Applications', '按应用程序'],
  'tr.routes': ['Routes', '按线路'],
  'tr.rules': ['Rules', '按规则'],
  'tr.conns': ['Connections', '连接数'],
  'tr.empty': ['No connections have been counted yet.', '还没有统计到连接。'],
  'use.unknown': ['Unknown application', '未知程序'],
  'use.other': ['Everything else', '其他'],
  'nav.proxies': ['Proxies', '代理'],
  'nav.log': ['Log', '日志'],
  'nav.settings': ['Settings', '设置'],

  'conn.title': ['Connections', '连接'],
  'conn.filter': ['Filter connections', '筛选连接'],
  'conn.filter.ph': ['Filter by application, host or rule', '按程序、主机或规则筛选'],
  'conn.closeAll': ['Close all', '全部断开'],
  'conn.active': ['Open now', '进行中'],
  'conn.recent': ['Finished', '已结束'],
  'conn.close': ['Close', '断开'],
  'conn.closeLabel': ['Close the connection to {target}', '断开到 {target} 的连接'],
  'conn.connecting': ['connecting…', '连接中…'],
  'conn.unknownApp': ['Unknown application', '未知程序'],
  'conn.empty.active': ['No open connections right now. Connections that a rule proxies or blocks appear here.',
    '当前没有进行中的连接。命中代理或阻止规则的连接会显示在这里。'],
  'conn.empty.start': ['Nothing to show yet. Add a proxy server, then a rule that sends an application or a host through it.',
    '还没有可显示的内容。请先添加代理服务器，再添加一条让某个程序或主机走该代理的规则。'],
  'conn.empty.recent': ['No finished connections yet.', '还没有已结束的连接。'],
  'conn.empty.filter': ['No connection matches the filter.', '没有符合筛选条件的连接。'],
  'conn.closeAll.title': ['Close all connections?', '断开全部连接？'],
  'conn.closeAll.text': ['{n} open connections will be cut off. Applications usually reconnect on their own.',
    '将断开 {n} 个进行中的连接，应用程序通常会自动重连。'],
  'conn.lasted': ['lasted {d}', '持续 {d}'],
  'col.app': ['Application', '应用程序'],
  'col.dest': ['Destination', '目标'],
  'col.route': ['Route', '线路'],
  'col.sent': ['Sent', '发送'],
  'col.recv': ['Received', '接收'],
  'col.age': ['Open for', '已持续'],
  'col.actions': ['Actions', '操作'],
  'col.ended': ['Ended', '结束时间'],
  'col.result': ['Result', '结果'],
  'in.socks5': ['SOCKS5 client', 'SOCKS5 接入'],
  'in.socks4': ['SOCKS4 client', 'SOCKS4 接入'],
  'in.http': ['HTTP client', 'HTTP 接入'],
  'res.closed': ['Closed', '已关闭'],
  'res.failed': ['Failed', '失败'],
  'res.blocked': ['Blocked', '已阻止'],
  'res.noroute': ['no route', '未连通'],

  'rules.title': ['Rules', '规则'],
  'rules.add': ['Add rule', '添加规则'],
  'rules.lede': ['Rules are checked from top to bottom. The first one that matches decides where the connection goes.',
    '规则自上而下逐条匹配，第一条命中的规则决定连接的去向。'],
  'rule.any': ['Any connection', '任意连接'],
  'rule.w.apps': ['Applications', '程序'],
  'rule.w.hosts': ['Hosts', '主机'],
  'rule.w.ports': ['Ports', '端口'],
  'rule.off': ['Off', '已停用'],
  'rule.enable': ['Use rule “{name}”', '启用规则“{name}”'],
  'rule.default': ['Everything else', '其余所有连接'],
  'rule.default.h': ['Applies when no rule above matches.', '以上规则都未命中时生效。'],
  'rule.default.short': ['Default', '默认去向'],
  'rule.sys.proxy': ['Proxy server itself', '代理服务器自身'],
  'rule.sys.local': ['Local proxy program', '本机代理程序'],
  'rule.new': ['Add a rule', '添加规则'],
  'rule.edit': ['Edit rule', '编辑规则'],
  'rule.apps': ['Applications', '应用程序'],
  'rule.apps.h': ['One per line. A program name such as chrome.exe, or a path with wildcards such as *\\Steam\\*. Empty means any application.',
    '每行一个。可以填程序名（如 chrome.exe），也可以填带通配符的路径（如 *\\Steam\\*）。留空表示任意程序。'],
  'rule.hosts': ['Destination hosts', '目标主机'],
  'rule.hosts.h': ['One per line. *.example.com, 10.0.0.0/8, 192.168.1.1-192.168.1.50. Empty means any host.',
    '每行一个。例如 *.example.com、10.0.0.0/8、192.168.1.1-192.168.1.50。留空表示任意主机。'],
  'rule.ports': ['Destination ports', '目标端口'],
  'rule.ports.h': ['For example 80, 443, 8000-9000. Empty means any port.', '例如 80, 443, 8000-9000。留空表示任意端口。'],
  'rule.action': ['Send the connection', '连接去向'],
  'rule.save': ['Save rule', '保存规则'],
  'rule.del.title': ['Delete rule “{name}”?', '删除规则“{name}”？'],
  'rule.del.text': ['Connections it matched fall through to the rules below it.', '原本命中它的连接将交给后面的规则处理。'],
  'act.direct': ['Direct', '直连'],
  'act.block': ['Blocked', '阻止'],
  'act.missing': ['Missing proxy', '代理不存在'],
  'act.opt.direct': ['Directly, without a proxy', '直连（不经过代理）'],
  'act.opt.block': ['Nowhere: block it', '阻止连接'],
  'act.opt.proxy': ['Through a proxy', '通过代理'],
  'act.opt.chain': ['Through a chain or group', '通过代理链或代理组'],
  'route.or': ['or', '或'],
  'route.through': ['Through {list}', '经由 {list}'],
  'route.then': [', then ', '，再到 '],
  'tester.title': ['Try a connection', '试一试'],
  'tester.hint': ['See which rule a connection would hit, without making it.', '不发起真实连接，查看它会命中哪条规则。'],
  'tester.app': ['Application', '应用程序'],
  'tester.host': ['Host or IP address', '主机名或 IP 地址'],
  'tester.run': ['Find matching rule', '查找命中的规则'],
  'tester.match': ['Matches “{rule}”', '命中规则“{rule}”'],
  'tester.default': ['No rule matches, so the default applies.', '没有规则命中，按默认去向处理。'],
  'tester.need': ['Enter an application or a host first.', '请先填写应用程序或主机。'],

  'px.title': ['Proxy servers', '代理服务器'],
  'px.target': ['Check against', '检测目标'],
  'px.checkAll': ['Check all', '全部检测'],
  'px.add': ['Add proxy', '添加代理'],
  'px.addr': ['Address', '地址'],
  'px.auth': ['Sign-in', '认证'],
  'px.check': ['Last check', '检测结果'],
  'px.none': ['None', '无'],
  'px.never': ['Not checked', '未检测'],
  'px.checking': ['Checking…', '检测中…'],
  'px.ok': ['{ms} ms', '{ms} 毫秒'],
  'px.okNote': ['Works. Reached {target} in {ms} ms.', '可用，{ms} 毫秒连通 {target}。'],
  'px.test': ['Check', '检测'],
  'px.empty': ['No proxy servers yet. Add one to start routing connections through it.',
    '还没有代理服务器。添加一个之后，就可以让连接经由它转发。'],
  'px.new': ['Add a proxy server', '添加代理服务器'],
  'px.edit': ['Edit proxy server', '编辑代理服务器'],
  'px.host': ['Server address', '服务器地址'],
  'px.user': ['User name', '用户名'],
  'px.pass': ['Password', '密码'],
  'px.sni': ['Certificate name', '证书域名'],
  'px.sni.h': ['Only if it differs from the server address.', '仅当与服务器地址不同时填写。'],
  'px.insecure': ['Accept any certificate', '接受任意证书'],
  'px.insecure.h': ['Lets anyone on the path read the traffic. For testing only.', '链路上的任何人都可能窃听流量，仅用于测试。'],
  'px.save': ['Save proxy', '保存代理'],
  'px.del.title': ['Delete proxy “{name}”?', '删除代理“{name}”？'],
  'px.del.text': ['Connections that are open through it stay open until they end.', '正在经由它的连接会保持到自然结束。'],
  'inuse.title': ['“{name}” is still in use', '“{name}”仍在使用中'],
  'inuse.text': ['Used by: {list}. Point those somewhere else first.', '以下项目正在使用它：{list}。请先为它们改用其他去向。'],
  'f.name': ['Name', '名称'],
  'f.type': ['Type', '类型'],
  'f.port': ['Port', '端口'],

  'ch.title': ['Chains and groups', '代理链与代理组'],
  'ch.add': ['Add chain or group', '添加代理链或代理组'],
  'ch.lede': ['A chain passes a connection through several proxies in a row. A failover group uses the first proxy that answers. A load-balancing group takes turns.',
    '代理链让连接依次经过多个代理；故障转移组使用第一个可用的代理；负载均衡组让各个代理轮流承担新连接。'],
  'ch.empty': ['No chains or groups yet.', '还没有代理链或代理组。'],
  'ch.empty.noproxy': ['Add a proxy server first; chains and groups are built from them.', '请先添加代理服务器，代理链和代理组由它们组成。'],
  'ch.new': ['Add a chain or group', '添加代理链或代理组'],
  'ch.edit': ['Edit chain or group', '编辑代理链或代理组'],
  'ch.kind': ['How the proxies are used', '代理的使用方式'],
  'ch.t.chain': ['Chain', '代理链'],
  'ch.t.chain.h': ['Through every proxy, in this order.', '按顺序依次经过每个代理。'],
  'ch.t.failover': ['Failover', '故障转移'],
  'ch.t.failover.h': ['The first proxy that answers; the next one if it does not.', '使用第一个可用的代理，不可用时换下一个。'],
  'ch.t.balance': ['Load balancing', '负载均衡'],
  'ch.t.balance.h': ['Each new connection takes the next proxy in turn.', '新连接轮流使用各个代理。'],
  'ch.members': ['Proxies', '代理列表'],
  'ch.pick': ['Proxy to add', '要加入的代理'],
  'ch.pick.add': ['Add to list', '加入列表'],
  'ch.remove': ['Remove', '移除'],
  'ch.needs': ['Add at least one proxy.', '请至少加入一个代理。'],
  'ch.save': ['Save', '保存'],
  'ch.del.title': ['Delete “{name}”?', '删除“{name}”？'],
  'ch.del.text': ['The proxy servers in it are kept.', '其中的代理服务器会保留。'],
  'ch.group.ok': ['{ok} of {n} answer', '{n} 个中有 {ok} 个可用'],

  'log.title': ['Log', '日志'],
  'log.show': ['Show', '显示'],
  'log.all': ['Everything', '全部'],
  'log.warn': ['Warnings and errors', '警告和错误'],
  'log.error': ['Errors only', '仅错误'],
  'log.clear': ['Clear view', '清空显示'],
  'log.empty': ['Nothing logged yet.', '暂无日志。'],
  'lvl.debug': ['debug', '调试'],
  'lvl.info': ['info', '信息'],
  'lvl.warn': ['warning', '警告'],
  'lvl.error': ['error', '错误'],

  'set.title': ['Settings', '设置'],
  'set.intercept': ['Interception', '透明接管'],
  'set.intercept.on': ['Capture connections of applications that have no proxy setting', '接管没有代理设置的应用程序的连接'],
  'set.intercept.on.h': ['Needs administrator or root rights. Only traffic that a rule sends to a proxy or blocks is touched.',
    '需要管理员或 root 权限。只有被规则送往代理或阻止的流量会受影响。'],
  'set.ipv6': ['Capture IPv6 connections too', '同时接管 IPv6 连接'],
  'set.quic': ['Block QUIC (UDP port 443)', '阻止 QUIC（UDP 443 端口）'],
  'set.quic.h': ['Browsers then fall back to TCP, which can be proxied.', '浏览器会回退到可以代理的 TCP。'],
  'set.direct': ['Show direct connections as well', '同时显示直连的连接'],
  'set.direct.h': ['Every connection passes through the engine and appears in the list. Slightly slower.',
    '所有连接都经过引擎并出现在列表中，速度略有下降。'],
  'set.tport': ['Capture port', '接管端口'],
  'set.tport.h': ['Local port captured connections arrive on.', '被接管的连接到达的本机端口。'],
  'set.target': ['Only this destination port', '仅接管此目标端口'],
  'set.target.h': ['For troubleshooting. 0 captures all ports.', '用于排查问题，0 表示全部端口。'],
  'drv.title': ['Windows driver', 'Windows 驱动'],
  'drv.hint': ['Capturing on Windows is done by the OddlyDrv kernel driver. It must be signed, or Windows must be in test-signing mode.',
    'Windows 上的接管由 OddlyDrv 内核驱动完成。驱动需要有效签名，或系统处于测试签名模式。'],
  'drv.install': ['Install and start', '安装并启动'],
  'drv.start': ['Start', '启动'],
  'drv.stop': ['Stop', '停止'],
  'drv.uninstall': ['Uninstall', '卸载'],
  'drv.state': ['State', '状态'],
  'drv.s.missing': ['Not installed', '未安装'],
  'drv.s.running': ['Running', '运行中'],
  'drv.s.stopped': ['Installed, not running', '已安装，未运行'],
  'drv.file': ['Driver file', '驱动文件'],
  'drv.file.none': ['OddlyDrv.sys was not found next to the program', '未在程序目录找到 OddlyDrv.sys'],
  'drv.path': ['Installed at', '安装位置'],
  'drv.admin': ['Rights', '权限'],
  'drv.admin.yes': ['Administrator', '管理员'],
  'drv.admin.no': ['Not an administrator. Restart the engine as administrator to manage the driver.',
    '非管理员。请以管理员身份重新启动引擎后再管理驱动。'],
  'drv.done': ['Driver state updated', '驱动状态已更新'],
  'drv.un.title': ['Uninstall the driver?', '卸载驱动？'],
  'drv.un.text': ['Interception stops until the driver is installed again.', '卸载后透明接管将停止，直到重新安装驱动。'],
  'set.inbound': ['Local proxy listener', '本地代理端口'],
  'set.inbound.addr': ['Listen address', '监听地址'],
  'set.inbound.h': ['Applications that do have a proxy setting can point at this address (SOCKS5, SOCKS4 or HTTP). They follow the same rules. Leave empty to turn it off.',
    '自带代理设置的程序可以直接指向此地址（支持 SOCKS5、SOCKS4 和 HTTP），同样按规则处理。留空则关闭。'],
  'set.udp': ['Relay UDP for SOCKS5 clients', '为 SOCKS5 客户端转发 UDP'],
  'set.udp.h': ['UDP goes out directly or through a single SOCKS5 proxy. Other proxy types and chains of several proxies cannot carry it; such traffic is dropped, never sent around the proxy.',
    'UDP 只能直连或经由单个 SOCKS5 代理转发。其他类型的代理和多级代理链无法承载 UDP，这类流量会被丢弃，不会绕过代理直连。'],
  'set.localnames': ['Names always looked up on this computer', '始终在本机解析的域名'],
  'set.localnames.h': ['One per line, such as *.corp.example or printer. For names the proxy cannot know.', '每行一个，例如 *.corp.example 或 printer。用于代理无法解析的内部域名。'],
  'set.log': ['Log file', '日志文件'],
  'set.log.file': ['File', '文件路径'],
  'set.log.file.h': ['The log is also written to this file, which is rotated when it grows large. Leave empty to keep the log in memory only.',
    '日志会同时写入此文件，文件过大时自动轮转。留空则只保留在内存中。'],
  'set.log.level': ['Detail', '详细程度'],
  'set.log.debug': ['Everything, for troubleshooting', '全部（排查问题用）'],
  'set.log.info': ['Normal', '常规'],
  'set.dns': ['Name resolution', '域名解析'],
  'set.dns.mode': ['Who looks up host names for proxied connections', '走代理的连接由谁解析域名'],
  'set.dns.remote': ['The proxy server', '代理服务器'],
  'set.dns.remote.h': ['The host name is sent to the proxy whenever it is known. Recommended.', '只要知道域名，就把域名交给代理解析。推荐。'],
  'set.dns.local': ['This computer', '本机'],
  'set.dns.local.h': ['The proxy only ever sees IP addresses.', '代理只会收到 IP 地址。'],
  'set.sniff': ['Read the host name from the connection itself', '从连接内容中识别域名'],
  'set.sniff.h': ['Uses the TLS server name or the HTTP Host header, so that host rules work for captured connections.',
    '读取 TLS 的服务器名称或 HTTP 的 Host 头，让按主机名写的规则对被接管的连接生效。'],
  'set.fake': ['Run a fake DNS server', '启用 Fake DNS 服务器'],
  'set.fake.h': ['Answers lookups with placeholder addresses and remembers the names, so the proxy can do the real lookup. Point the system DNS at it where capture does not do so automatically.',
    '用占位地址应答查询并记住对应域名，真正的解析交给代理完成。在接管不会自动转发 DNS 的系统上，需要把系统 DNS 指向它。'],
  'set.fake.listen': ['Fake DNS address', 'Fake DNS 监听地址'],
  'set.fake.range': ['Placeholder range', '占位地址段'],
  'set.fake.up': ['Real DNS server', '上游 DNS 服务器'],
  'set.time': ['Timeouts', '超时'],
  'set.time.connect': ['Connecting, seconds', '连接超时（秒）'],
  'set.time.idle': ['Idle, seconds', '空闲超时（秒）'],
  'set.time.idle.h': ['0 never closes idle connections.', '0 表示不关闭空闲连接。'],
  'set.save': ['Save settings', '保存设置'],
  'set.revert': ['Discard changes', '放弃更改'],
  'set.saved': ['Settings saved', '设置已保存'],
  'prof.title': ['Profiles', '配置方案'],
  'prof.lede': ['A profile holds proxies, chains, rules and name resolution. Switching profiles keeps what belongs to this computer: ports, the access token and the log file. Profiles exported from Proxifier (.ppx) can be imported.',
    '配置方案包含代理、代理链、规则和域名解析设置。切换方案时，属于本机的设置（端口、访问令牌、日志文件）保持不变。可以导入 Proxifier 导出的配置（.ppx）。'],
  'prof.save': ['Save as…', '另存为…'],
  'prof.import': ['Import…', '导入…'],
  'prof.export': ['Export…', '导出…'],
  'prof.contents': ['Contents', '内容'],
  'prof.saved': ['Saved', '保存时间'],
  'prof.counts': ['{proxies} proxies, {chains} chains, {rules} rules', '{proxies} 个代理，{chains} 个代理链，{rules} 条规则'],
  'prof.inuse': ['in use', '使用中'],
  'prof.activate': ['Switch to', '切换'],
  'prof.empty': ['No saved profiles yet. “Save as…” keeps the current proxies and rules under a name, so you can switch back to them later.',
    '还没有保存的配置方案。用“另存为…”把当前的代理和规则存成一个方案，之后可以随时切换回来。'],
  'prof.dir': ['Stored in {dir}', '保存位置：{dir}'],
  'prof.nostore': ['This engine was started without a profile file, so profiles cannot be saved by name.',
    '引擎启动时没有指定配置文件，因此无法按名称保存配置方案。'],
  'prof.name': ['Profile name', '方案名称'],
  'prof.name.h': ['Up to 64 characters, without < > : " / \\ | ? *. A profile of the same name is replaced.',
    '最多 64 个字符，不能包含 < > : " / \\ | ? *。同名方案会被覆盖。'],
  'prof.save.title': ['Save the current profile', '保存当前配置'],
  'prof.save.ok': ['Save profile', '保存方案'],
  'prof.saved.as': ['Saved as “{name}”', '已保存为“{name}”'],
  'prof.act.title': ['Switch to “{name}”?', '切换到“{name}”？'],
  'prof.act.text': ['Proxies, chains, rules and name resolution are replaced. Changes that were not saved under a name are lost. Open connections keep their route.',
    '代理、代理链、规则和域名解析设置将被替换，未另存的修改会丢失。已建立的连接保持原有线路。'],
  'prof.activated': ['Now using “{name}”', '已切换到“{name}”'],
  'prof.del.title': ['Delete profile “{name}”?', '删除方案“{name}”？'],
  'prof.del.text': ['Only the saved copy is deleted. What the engine uses right now stays as it is.', '只删除保存的副本，引擎当前使用的配置不受影响。'],
  'prof.import.title': ['Import {name}', '导入 {name}'],
  'prof.import.text': ['Proxies, chains, rules and name resolution are replaced with the contents of the file.', '代理、代理链、规则和域名解析设置将被文件内容替换。'],
  'prof.import.name.h': ['Also saves the result under this name. Leave empty to import without saving a copy.', '同时以此名称保存一份。留空则只导入，不保存副本。'],
  'prof.import.ok': ['Import', '导入'],
  'prof.imported': ['Profile imported', '配置已导入'],
  'prof.notes.title': ['Imported, with remarks', '已导入，有以下说明'],
  'prof.toobig': ['That file is too large to be a profile.', '文件过大，不是有效的配置文件。'],
  'prof.export.title': ['Export the profile', '导出配置'],
  'prof.export.text': ['The file holds proxies, chains, rules and name resolution, and can be imported on another computer.', '文件包含代理、代理链、规则和域名解析设置，可以在另一台电脑上导入。'],
  'prof.export.pw': ['Include proxy passwords', '包含代理密码'],
  'prof.export.pw.h': ['They are stored in the file as plain text.', '密码会以明文写入文件。'],
  'prof.export.ok': ['Export', '导出'],
  'about.title': ['About this engine', '关于引擎'],
  'about.version': ['Version', '版本'],
  'about.platform': ['Platform', '平台'],
  'about.backend': ['Capture method', '接管方式'],
  'about.rights': ['Rights', '权限'],
  'about.rights.yes': ['Administrator or root', '管理员 / root'],
  'about.rights.no': ['Standard user: interception is unavailable', '普通用户：无法透明接管'],
  'about.pid': ['Process ID', '进程 ID'],
  'about.uptime': ['Running for', '已运行'],
  'about.profile': ['Profile file', '配置文件路径'],
  'about.conns': ['Connections so far', '累计连接'],
  'about.conns.v': ['{total} in total: {proxied} proxied, {direct} direct, {blocked} blocked, {failed} failed',
    '共 {total} 个：代理 {proxied}，直连 {direct}，阻止 {blocked}，失败 {failed}'],
  'about.driver': ['Driver counters', '驱动计数'],
  'about.driver.v': ['{classified} seen, {redirected} captured, {bypassed} left alone, {quic_blocked} QUIC blocked, {errors} errors',
    '检查 {classified}，接管 {redirected}，放行 {bypassed}，阻止 QUIC {quic_blocked}，错误 {errors}'],

  'tok.title': ['Access token needed', '需要访问令牌'],
  'tok.text': ['Open the address the engine printed when it started, or paste the token from it here. The token is also stored as api_token in the profile file.',
    '请打开引擎启动时打印的地址，或把其中的令牌粘贴到这里。令牌也保存在配置文件的 api_token 字段中。'],
  'tok.label': ['Access token', '访问令牌'],
  'tok.save': ['Connect', '连接'],
  'err.conn': ['Cannot reach the engine. Retrying.', '无法连接引擎，正在重试。'],
  'err.token': ['The access token is missing or wrong.', '访问令牌缺失或不正确。'],
  'notice.settings': ['Open settings', '打开设置'],
  'b.up': ['Move up', '上移'],
  'b.down': ['Move down', '下移'],
  'b.edit': ['Edit', '编辑'],
  'b.delete': ['Delete', '删除'],
  'b.change': ['Change', '更改'],
  'b.cancel': ['Cancel', '取消'],
  'b.ok': ['OK', '知道了'],
};

const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage unavailable */ } },
};

let lang = store.get('oddly.lang') || (/^zh/i.test(navigator.language || '') ? 'zh' : 'en');

function t(key, vars) {
  const entry = T[key];
  let s = entry ? entry[lang === 'zh' ? 1 : 0] : key;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  return s;
}

/* ---------------------------------------------------------------- helpers */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// h builds an element. Text always goes in as text nodes: host names and
// application names come from the network and must never be parsed as HTML.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v == null) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (typeof v === 'boolean') {
        if (k in el) el[k] = v;
        else if (v) el.setAttribute(k, '');
      } else el.setAttribute(k, v);
    }
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid);
  }
  return el;
}

function setText(el, s) {
  if (el.textContent !== s) el.textContent = s;
}

const p2 = (n) => String(n).padStart(2, '0');

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return (n >= 100 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
}

function fmtDur(ms) {
  let s = Math.max(0, Math.floor(ms / 1000));
  const hh = Math.floor(s / 3600);
  s -= hh * 3600;
  const mm = Math.floor(s / 60);
  s -= mm * 60;
  return hh ? hh + ':' + p2(mm) + ':' + p2(s) : mm + ':' + p2(s);
}

function fmtClock(ms) {
  const d = new Date(ms);
  return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds());
}

function joinHostPort(host, port) {
  return (host.includes(':') ? '[' + host + ']' : host) + ':' + port;
}

function splitList(v) {
  return v.split(/[\n;,]+/).map((s) => s.trim()).filter(Boolean);
}

function quietBtn(label, fn, danger) {
  return h('button', { type: 'button', class: 'btn btn--quiet' + (danger ? ' btn--danger' : ''), onclick: fn }, label);
}

function iconBtn(glyph, label, fn, disabled) {
  return h('button', {
    type: 'button', class: 'btn btn--quiet btn--icon', 'aria-label': label, title: label,
    disabled: !!disabled, onclick: fn,
  }, glyph);
}

function toast(msg, kind) {
  const el = h('div', { class: 'toast', 'data-kind': kind || null }, msg);
  $('#toasts').append(el);
  setTimeout(() => el.remove(), kind === 'error' ? 6500 : 2600);
}

function setFacts(dl, rows) {
  rows = rows.filter(Boolean);
  const sig = JSON.stringify(rows);
  if (dl.dataset.sig === sig) return;
  dl.dataset.sig = sig;
  dl.replaceChildren(...rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]).flat());
}

/* ------------------------------------------------------------------ state */

const VIEWS = ['connections', 'traffic', 'rules', 'proxies', 'log', 'settings'];
const TYPE_LABEL = { socks5: 'SOCKS5', socks4: 'SOCKS4', socks4a: 'SOCKS4a', http: 'HTTP', https: 'HTTPS' };
const SYSTEM_RULES = {
  'Default': 'rule.default.short',
  '(proxy server)': 'rule.sys.proxy',
  '(local proxy program)': 'rule.sys.local',
};

const S = {
  token: '',
  profile: null,
  status: null,
  active: [],
  recent: [],
  logs: [],
  logSeq: 0,
  logCleared: 0,
  view: 'connections',
  tab: 'active',
  filter: '',
  checks: new Map(), // "proxy:<id>" | "chain:<id>" -> result
  driver: null,
  traffic: null,
  usage: 'apps',
  saved: null, // the list of saved profiles
  savedOff: false, // the engine has no profile file to save next to
  offline: false,
  settingsDirty: false,
};

function ruleLabel(name) {
  return SYSTEM_RULES[name] ? t(SYSTEM_RULES[name]) : name;
}

/* -------------------------------------------------------------------- API */

class ApiError extends Error {
  constructor(msg, status) {
    super(msg);
    this.status = status;
  }
}

// api talks to the engine. With raw set, the body goes out as it is.
async function api(method, path, body, raw) {
  let res;
  try {
    const headers = { Authorization: 'Bearer ' + S.token };
    if (body !== undefined) headers['Content-Type'] = raw ? 'application/octet-stream' : 'application/json';
    res = await fetch('/api/' + path, {
      method, headers, body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
    });
  } catch (e) {
    throw new ApiError(t('err.conn'), 0);
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* no JSON body */ }
  if (res.status === 401) {
    askToken();
    throw new ApiError(t('err.token'), 401);
  }
  if (!res.ok) throw new ApiError((data && data.error) || res.statusText || 'HTTP ' + res.status, res.status);
  return data;
}

function initToken() {
  const m = /(?:^#|[&?])token=([^&]+)/.exec(location.hash);
  if (m) {
    S.token = decodeURIComponent(m[1]);
    store.set('oddly.token', S.token);
    // Keep the token out of the address bar and the history.
    history.replaceState(null, '', location.pathname + location.search + '#/connections');
  } else {
    S.token = store.get('oddly.token') || '';
  }
}

function askToken() {
  const dlg = $('#dlg-token');
  if (dlg.open) return;
  dlg.querySelector('form').reset();
  dlg.showModal();
}

/* ------------------------------------------------------------ route strip */

// strip draws one routing decision as a line with stations.
function strip(kind, opt) {
  const { stops = [], label = '', cap = '' } = opt || {};
  const el = h('span', { class: 'route', 'data-kind': kind, role: 'img' });
  if (cap) el.append(h('span', { class: 'route__cap' }, cap));
  stops.forEach((name, i) => {
    if (kind === 'group' && i > 0) el.append(h('span', { class: 'route__or' }, t('route.or')));
    el.append(h('span', { class: 'route__stop' + (i === stops.length - 1 ? ' route__stop--last' : '') }, name));
  });
  // The arrowhead stays on the line of the last station when the strip wraps.
  const end = h('span', { class: 'route__end' });
  if (stops.length) el.lastElementChild.append(end); else el.append(end);
  if (label) el.append(h('span', { class: 'route__label' }, label));

  let spoken = label;
  if (stops.length) {
    const list = stops.join(kind === 'group' ? ' ' + t('route.or') + ' ' : t('route.then'));
    spoken = (cap ? cap + ': ' : '') + t('route.through', { list });
  }
  el.setAttribute('aria-label', spoken);
  return el;
}

function proxyName(id) {
  const x = S.profile.proxies.find((x) => x.id === id);
  return x ? x.name : '?';
}

function chainStrip(c, named) {
  const stops = c.proxies.map(proxyName);
  if (c.type === 'chain') return strip('chain', { stops, cap: named ? c.name : '' });
  const kind = t('ch.t.' + c.type);
  return strip('group', { stops, cap: named ? c.name + ' (' + kind + ')' : '' });
}

function actionStrip(a) {
  const p = S.profile;
  if (a.type === 'direct') return strip('direct', { label: t('act.direct') });
  if (a.type === 'block') return strip('block', { label: t('act.block') });
  if (a.type === 'proxy') {
    const x = p.proxies.find((x) => x.id === a.target);
    return x ? strip('proxy', { stops: [x.name] }) : strip('missing', { label: t('act.missing') });
  }
  if (a.type === 'chain') {
    const c = p.chains.find((c) => c.id === a.target);
    return c ? chainStrip(c, true) : strip('missing', { label: t('act.missing') });
  }
  return strip('missing', { label: String(a.type) });
}

function connStrip(c) {
  if (c.action === 'block') return strip('block', { label: t('act.block') });
  if (c.action === 'direct') return strip('direct', { label: t('act.direct') });
  const stops = c.via ? c.via.split(' → ') : [];
  if (!stops.length) {
    return strip(c.action === 'chain' ? 'chain' : 'proxy',
      { label: c.state === 'connecting' ? t('conn.connecting') : t('res.noroute') });
  }
  return strip(stops.length > 1 ? 'chain' : 'proxy', { stops });
}

/* ------------------------------------------------------- header and notice */

function partState(p) {
  if (!p) return 'off';
  if (p.error) return 'error';
  if (!p.enabled) return 'off';
  return p.active ? 'on' : 'idle';
}

function renderLamps() {
  const s = S.status;
  for (const k of ['intercept', 'inbound', 'fake_dns']) {
    const el = $('#lamp-' + k);
    const p = s && s[k];
    const st = S.offline ? 'off' : partState(p);
    el.dataset.state = st;
    setText(el.querySelector('.lamp__state'), t('state.' + st));
    el.title = p ? (p.error || p.detail || '') : '';
  }
}

function renderQuick() {
  const b = $('#quick-intercept');
  const p = S.status && S.status.intercept;
  b.hidden = !p || S.offline;
  if (p) setText(b, t(p.enabled ? 'quick.pause' : 'quick.resume'));
}

async function toggleIntercept() {
  const b = $('#quick-intercept');
  const on = !(S.status && S.status.intercept && S.status.intercept.enabled);
  b.disabled = true;
  try {
    S.status = await api('POST', 'intercept', { enabled: on });
    if (S.profile) S.profile.options.intercept = on;
    if (S.settingsDirty) $('#s-intercept').checked = on;
    else fillSettings();
    const p = S.status.intercept || {};
    if (p.error) toast(p.error, 'error');
    else toast(t(on ? 'quick.on' : 'quick.off'));
  } catch (e) {
    toast(e.message, 'error');
  }
  b.disabled = false;
  renderLive();
}

function renderTotals() {
  const st = S.status && S.status.stats;
  setText($('#tot-up'), fmtBytes(st ? st.up : 0));
  setText($('#tot-down'), fmtBytes(st ? st.down : 0));
  setText($('#nav-active'), String(st ? st.active : 0));
}

function renderNotice() {
  const el = $('#notice');
  const s = S.status;
  let kind = '';
  let parts = [];
  if (S.offline) {
    kind = 'error';
    parts = [['', t('err.conn')]];
  } else if (s) {
    for (const [name, p] of [['lamp.intercept', s.intercept], ['lamp.inbound', s.inbound], ['lamp.fake', s.fake_dns]]) {
      if (p && p.error) parts.push([t(name), p.error]);
    }
    if (parts.length) kind = 'error';
  }
  const sig = JSON.stringify([kind, parts, S.view, lang]);
  if (el.dataset.sig === sig) return;
  el.dataset.sig = sig;
  el.hidden = !parts.length;
  el.dataset.kind = kind;
  el.replaceChildren(...parts.map(([name, msg]) => h('span', null, name ? h('strong', null, name + ': ') : null, msg)));
  if (parts.length && !S.offline && S.view !== 'settings') {
    el.append(h('a', { href: '#/settings' }, t('notice.settings')));
  }
}

/* ------------------------------------------------------------ connections */

function connMatch(c, q) {
  if (!q) return true;
  return [c.app, c.app_path, c.host, c.ip, c.port, c.pid, ruleLabel(c.rule), c.via]
    .some((v) => v != null && String(v).toLowerCase().includes(q));
}

// syncRows updates a table body in place, so that focus, selection and
// scroll position survive the once-a-second refresh.
function syncRows(tbody, items, create, update) {
  const have = new Map();
  for (const tr of Array.from(tbody.children)) have.set(tr.dataset.key, tr);
  let prev = null;
  for (const it of items) {
    const key = String(it.id);
    let tr = have.get(key);
    if (tr) have.delete(key);
    else {
      tr = create(it);
      tr.dataset.key = key;
    }
    update(tr, it);
    const want = prev ? prev.nextSibling : tbody.firstChild;
    if (want !== tr) tbody.insertBefore(tr, want);
    prev = tr;
  }
  for (const tr of have.values()) tr.remove();
}

function setCell(td, sig, build) {
  if (td.dataset.sig === sig) return;
  td.dataset.sig = sig;
  td.replaceChildren(...[build()].flat().filter(Boolean));
}

function targetOf(c) {
  return joinHostPort(c.host || c.ip || '?', c.port);
}

function fillShared(tr, c) {
  const td = tr.children;
  setCell(td[0], [c.app, c.app_path, c.pid, c.inbound, c.network].join('|'), () => {
    const tag = c.inbound && c.inbound !== 'transparent' ? h('span', { class: 'tag' }, t('in.' + c.inbound)) : null;
    const udp = c.network === 'udp' ? h('span', { class: 'tag' }, 'UDP') : null;
    const sub = c.pid || tag || udp
      ? h('span', { class: 'sub' }, c.pid ? 'PID ' + c.pid + ' ' : null, tag, tag && udp ? ' ' : null, udp) : null;
    return [h('span', { class: 'app', title: c.app_path || null }, c.app || t('conn.unknownApp')), sub];
  });
  setCell(td[1], [c.host, c.ip, c.port].join('|'), () => [
    h('span', { class: 'addr' }, targetOf(c)),
    c.host && c.ip ? h('span', { class: 'sub addr' }, c.ip) : null,
  ]);
  setCell(td[2], [c.rule, c.action, c.via, c.state].join('|'), () => [
    h('span', { class: 'rulename' }, ruleLabel(c.rule)),
    connStrip(c),
  ]);
  setText(td[3], fmtBytes(c.up));
  setText(td[4], fmtBytes(c.down));
  tr.dataset.state = c.state;
}

function activeRow(c) {
  return h('tr', null,
    h('td'), h('td'), h('td'), h('td', { class: 'num opt' }), h('td', { class: 'num opt' }), h('td', { class: 'num' }),
    h('td', { class: 'acts' }, h('button', {
      type: 'button', class: 'btn btn--quiet btn--danger',
      onclick: () => api('DELETE', 'connections/' + c.id).then(pollNow, (e) => toast(e.message, 'error')),
    }, t('conn.close'))));
}

function updateActiveRow(tr, c) {
  fillShared(tr, c);
  setText(tr.children[5], fmtDur(Date.now() - c.start));
  tr.children[6].firstChild.setAttribute('aria-label', t('conn.closeLabel', { target: targetOf(c) }));
}

function recentRow() {
  return h('tr', null,
    h('td'), h('td'), h('td'), h('td', { class: 'num opt' }), h('td', { class: 'num opt' }), h('td', { class: 'num' }), h('td'));
}

function updateRecentRow(tr, c) {
  fillShared(tr, c);
  const end = c.end || c.start;
  setCell(tr.children[5], end + '|' + c.start, () => [
    fmtClock(end),
    h('span', { class: 'sub' }, t('conn.lasted', { d: fmtDur(end - c.start) })),
  ]);
  setCell(tr.children[6], c.state + '|' + (c.error || ''), () =>
    h('span', { class: 'result', 'data-state': c.state },
      t('res.' + (c.state === 'failed' || c.state === 'blocked' ? c.state : 'closed')),
      c.state === 'failed' && c.error ? ': ' + c.error : null));
}

function renderConnections() {
  const q = S.filter;
  const act = S.active.filter((c) => connMatch(c, q)).sort((a, b) => b.id - a.id);
  const rec = S.recent.filter((c) => connMatch(c, q)).sort((a, b) => (b.end || 0) - (a.end || 0) || b.id - a.id);
  setText($('#count-active'), String(S.active.length));
  setText($('#count-recent'), String(S.recent.length));
  syncRows($('#tbl-active tbody'), act, activeRow, updateActiveRow);
  syncRows($('#tbl-recent tbody'), rec, recentRow, updateRecentRow);

  const noProxies = S.profile && !S.profile.proxies.length;
  const emptyText = (total, key) => (total && q ? t('conn.empty.filter') : t(key));
  $('#tbl-active').hidden = !act.length;
  $('#empty-active').hidden = !!act.length;
  setText($('#empty-active'), emptyText(S.active.length, noProxies ? 'conn.empty.start' : 'conn.empty.active'));
  $('#tbl-recent').hidden = !rec.length;
  $('#empty-recent').hidden = !!rec.length;
  setText($('#empty-recent'), emptyText(S.recent.length, 'conn.empty.recent'));
  $('#conn-close-all').disabled = !S.active.length;
}

function selectTab(name, focus) {
  S.tab = name;
  for (const n of ['active', 'recent']) {
    const on = n === name;
    const tab = $('#tab-' + n);
    const panel = $('#panel-' + n);
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
    panel.hidden = !on;
    if (on) panel.tabIndex = 0;
    else panel.removeAttribute('tabindex');
    if (on && focus) tab.focus();
  }
  $('#conn-close-all').hidden = name !== 'active';
}

/* ---------------------------------------------------------------- traffic */

// The chart is drawn in a 600 by 160 box that the SVG stretches; one slot per
// second, the newest at the right edge.
const CH = { w: 600, base: 159, top: 10, slots: 300 };
const USAGE_NAMES = {
  '(unknown)': 'use.unknown', '(direct)': 'act.direct', '(blocked)': 'res.blocked',
  '(failed)': 'res.failed', '(other)': 'use.other',
};
let chartAt = -1; // the slot under the crosshair, -1 for none

function fmtRate(n) {
  return fmtBytes(Math.round(n)) + '/s';
}

// niceTop is the scale's upper end: the next round step above v.
function niceTop(v) {
  for (let unit = 1024; ; unit *= 1024) {
    for (const m of [1, 2, 5, 10, 20, 50, 100, 200, 500]) {
      if (unit * m >= v) return unit * m;
    }
  }
}

function chartPoints() {
  const pts = (S.traffic && S.traffic.points) || [];
  return pts.length > CH.slots ? pts.slice(-CH.slots) : pts;
}

function chartX(slot) {
  return slot * CH.w / (CH.slots - 1);
}

function chartPath(pts, key, top) {
  const off = CH.slots - pts.length;
  let d = '';
  pts.forEach((p, i) => {
    const y = CH.base - Math.min(1, p[key] / top) * (CH.base - CH.top);
    d += (i ? 'L' : 'M') + chartX(off + i).toFixed(1) + ' ' + y.toFixed(1);
  });
  return d;
}

function renderChart() {
  const pts = chartPoints();
  let peak = 0;
  for (const p of pts) peak = Math.max(peak, p.up, p.down);
  const top = niceTop(peak);
  const down = chartPath(pts, 'down', top);
  $('#tr-line-down').setAttribute('d', down);
  $('#tr-line-up').setAttribute('d', chartPath(pts, 'up', top));
  $('#tr-area').setAttribute('d', pts.length > 1
    ? down + 'L' + CH.w + ' ' + CH.base + 'L' + chartX(CH.slots - pts.length).toFixed(1) + ' ' + CH.base + 'Z' : '');
  setText($('#tr-tick-top'), fmtRate(top));
  setText($('#tr-tick-mid'), fmtRate(top / 2));
  const last = pts.length ? pts[pts.length - 1] : { up: 0, down: 0 };
  const now = { down: fmtRate(last.down), up: fmtRate(last.up), peak: fmtRate(peak) };
  setText($('#tr-now-down'), now.down);
  setText($('#tr-now-up'), now.up);
  setText($('#tr-peak'), now.peak);
  $('#tr-svg').setAttribute('aria-label', t('tr.svg', now));
  paintCrosshair();
}

function paintCrosshair() {
  const pts = chartPoints();
  const cross = $('#tr-cross');
  const tip = $('#tr-tip');
  const p = chartAt < 0 ? null : pts[chartAt - (CH.slots - pts.length)];
  if (!p) {
    cross.setAttribute('data-off', '');
    tip.hidden = true;
    return;
  }
  const x = chartX(chartAt);
  cross.removeAttribute('data-off');
  cross.setAttribute('x1', x);
  cross.setAttribute('x2', x);
  const row = (kind, label, v) => h('div', null,
    h('span', { class: 'legend__key legend__key--' + kind, 'aria-hidden': 'true' }), label, h('b', null, fmtRate(v)));
  tip.replaceChildren(h('time', null, fmtClock(p.t * 1000)), row('down', t('tr.down'), p.down), row('up', t('tr.up'), p.up));
  // The note sits on the side of the crosshair that has room for it.
  const left = chartAt < CH.slots / 2;
  tip.style.insetInlineStart = left ? 'calc(' + (x / CH.w * 100) + '% + .6rem)' : 'auto';
  tip.style.insetInlineEnd = left ? 'auto' : 'calc(' + (100 - x / CH.w * 100) + '% + .6rem)';
  tip.hidden = false;
}

function chartHover(e) {
  const r = $('#tr-plot').getBoundingClientRect();
  if (!r.width) return;
  const f = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
  chartAt = Math.round(f * (CH.slots - 1));
  paintCrosshair();
}

function chartKey(e) {
  const first = CH.slots - chartPoints().length;
  if (first >= CH.slots) return;
  let at = chartAt < first ? CH.slots - 1 : chartAt;
  if (e.key === 'ArrowLeft') at = Math.max(first, chartAt < first ? at : at - 1);
  else if (e.key === 'ArrowRight') at = Math.min(CH.slots - 1, chartAt < first ? at : at + 1);
  else if (e.key === 'Home') at = first;
  else if (e.key === 'End') at = CH.slots - 1;
  else if (e.key === 'Escape') at = -1;
  else return;
  e.preventDefault();
  chartAt = at;
  paintCrosshair();
}

function usageName(kind, name) {
  if (USAGE_NAMES[name]) return t(USAGE_NAMES[name]);
  return kind === 'rules' ? ruleLabel(name) : name;
}

function renderUsage() {
  const kind = S.usage;
  const rows = ((S.traffic && S.traffic[kind]) || []).map((r) => ({ ...r, id: r.name }));
  syncRows($('#tbl-usage tbody'), rows,
    () => h('tr', null, h('td'), h('td', { class: 'num' }), h('td', { class: 'num opt' }), h('td', { class: 'num' }), h('td', { class: 'num' })),
    (tr, r) => {
      const td = tr.children;
      setCell(td[0], kind + '|' + r.name, () => (kind === 'routes' && !USAGE_NAMES[r.name]
        ? strip(r.name.includes(' → ') ? 'chain' : 'proxy', { stops: r.name.split(' → ') })
        : h('span', { class: 'app' }, usageName(kind, r.name))));
      setText(td[1], String(r.conns));
      setText(td[2], String(r.active));
      setText(td[3], fmtBytes(r.up));
      setText(td[4], fmtBytes(r.down));
    });
  const empty = $('#empty-usage');
  empty.hidden = rows.length > 0;
  setText(empty, t('tr.empty'));
}

function renderTraffic() {
  renderChart();
  renderUsage();
}

function selectUsage(kind, focus) {
  S.usage = kind;
  for (const b of $$('#tr-tabs [role="tab"]')) {
    const on = b.dataset.usage === kind;
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
    if (on) {
      $('#panel-usage').setAttribute('aria-labelledby', b.id);
      if (focus) b.focus();
    }
  }
  $('#tbl-usage tbody').replaceChildren(); // the same name means something else in another table
  renderUsage();
}

async function resetTraffic() {
  if (!await ask({ title: t('tr.reset.title'), text: t('tr.reset.text'), ok: t('tr.reset') })) return;
  try {
    await api('DELETE', 'traffic');
    S.traffic = null;
    chartAt = -1;
    toast(t('tr.reset.done'));
    pollNow();
  } catch (e) {
    toast(e.message, 'error');
  }
}

/* ------------------------------------------------------------------ rules */

function renderRules() {
  const p = S.profile;
  if (!p) return;
  $('#rule-list').replaceChildren(...p.rules.map((r, i) => ruleItem(r, i, p.rules.length)));
  $('#rule-default').replaceChildren(
    h('span', { class: 'rule__on' }),
    h('div', { class: 'rule__body' },
      h('div', { class: 'rule__name' }, t('rule.default')),
      h('div', { class: 'rule__when' }, t('rule.default.h'))),
    h('div', { class: 'rule__route' }, actionStrip(p.default)),
    h('div', { class: 'rule__acts' }, quietBtn(t('b.change'), () => editRule(-1))));
}

function ruleItem(r, i, n) {
  const when = [];
  if (r.apps && r.apps.length) when.push([t('rule.w.apps'), r.apps.join('; ')]);
  if (r.hosts && r.hosts.length) when.push([t('rule.w.hosts'), r.hosts.join(', ')]);
  if (r.ports) when.push([t('rule.w.ports'), r.ports]);
  return h('li', { class: 'rule', 'data-off': r.enabled ? null : '' },
    h('label', { class: 'rule__on' }, h('input', {
      type: 'checkbox', checked: !!r.enabled, 'aria-label': t('rule.enable', { name: r.name }),
      onchange: (e) => change((p) => { p.rules[i].enabled = e.target.checked; }),
    })),
    h('div', { class: 'rule__body' },
      h('div', { class: 'rule__name' }, r.name, r.enabled ? null : [' ', h('span', { class: 'tag' }, t('rule.off'))]),
      when.length
        ? h('dl', { class: 'rule__when' }, when.map(([k, v]) => h('div', null, h('dt', null, k), h('dd', null, v))))
        : h('div', { class: 'rule__when' }, t('rule.any'))),
    h('div', { class: 'rule__route' }, actionStrip(r.action)),
    h('div', { class: 'rule__acts' },
      iconBtn('↑', t('b.up'), () => moveRule(i, -1), i === 0),
      iconBtn('↓', t('b.down'), () => moveRule(i, 1), i === n - 1),
      quietBtn(t('b.edit'), () => editRule(i)),
      quietBtn(t('b.delete'), () => deleteRule(i), true)));
}

async function moveRule(i, d) {
  const j = i + d;
  await change((p) => {
    const [r] = p.rules.splice(i, 1);
    p.rules.splice(j, 0, r);
  });
  // The list was rebuilt: put the focus back on the rule that moved.
  const btns = $$('#rule-list > li:nth-child(' + (j + 1) + ') .btn--icon');
  const btn = btns[d < 0 ? 0 : 1];
  if (btn) (btn.disabled ? btns[d < 0 ? 1 : 0] : btn).focus();
}

async function deleteRule(i) {
  const r = S.profile.rules[i];
  const ok = await ask({ title: t('rule.del.title', { name: r.name }), text: t('rule.del.text'), ok: t('b.delete') });
  if (ok) change((p) => { p.rules.splice(i, 1); });
}

let ruleCtx = null; // { i }: index, -1 for the default, null for a new rule

function fillActionSelect(sel, cur) {
  const p = S.profile;
  sel.replaceChildren(
    h('option', { value: 'direct' }, t('act.opt.direct')),
    h('option', { value: 'block' }, t('act.opt.block')),
    p.proxies.length
      ? h('optgroup', { label: t('act.opt.proxy') }, p.proxies.map((x) => h('option', { value: 'proxy:' + x.id }, x.name)))
      : null,
    p.chains.length
      ? h('optgroup', { label: t('act.opt.chain') },
        p.chains.map((c) => h('option', { value: 'chain:' + c.id }, c.name + ' (' + t('ch.t.' + c.type) + ')')))
      : null);
  sel.value = cur.type === 'proxy' || cur.type === 'chain' ? cur.type + ':' + cur.target : cur.type;
  if (sel.selectedIndex < 0) sel.value = 'direct';
}

function parseAction(v) {
  const i = v.indexOf(':');
  return i < 0 ? { type: v } : { type: v.slice(0, i), target: v.slice(i + 1) };
}

function editRule(i) {
  const dlg = $('#dlg-rule');
  const f = dlg.querySelector('form');
  f.reset();
  showErr(f, '');
  const p = S.profile;
  const isDefault = i === -1;
  const isNew = i === null;
  let r;
  if (isDefault) r = { action: p.default };
  else if (isNew) {
    r = { name: '', apps: [], hosts: [], ports: '', action: p.proxies.length ? { type: 'proxy', target: p.proxies[0].id } : { type: 'direct' } };
  } else r = p.rules[i];
  ruleCtx = { i };
  setText($('#dlg-rule-title'), isDefault ? t('rule.default') : isNew ? t('rule.new') : t('rule.edit'));
  const only = f.querySelector('[data-rule-only]');
  only.hidden = isDefault;
  for (const el of $$('input, textarea', only)) el.disabled = isDefault;
  fillActionSelect(f.elements.action, r.action);
  if (!isDefault) {
    f.elements.name.value = r.name;
    f.elements.apps.value = (r.apps || []).join('\n');
    f.elements.hosts.value = (r.hosts || []).join('\n');
    f.elements.ports.value = r.ports || '';
  }
  openModal(dlg);
}

async function saveRule(f) {
  const { i } = ruleCtx;
  const action = parseAction(f.elements.action.value);
  await saveProfile((p) => {
    if (i === -1) {
      p.default = action;
      return;
    }
    const old = i === null ? null : p.rules[i];
    const r = {
      id: old ? old.id : '',
      name: f.elements.name.value.trim(),
      enabled: old ? old.enabled : true,
      apps: splitList(f.elements.apps.value),
      hosts: splitList(f.elements.hosts.value),
      ports: f.elements.ports.value.replace(/;/g, ',').replace(/\s+/g, ''),
      action,
    };
    if (old) p.rules[i] = r;
    else p.rules.push(r);
  });
}

async function runTester(e) {
  e.preventDefault();
  const out = $('#tester-out');
  const app = $('#tester-app').value.trim();
  const host = $('#tester-host').value.trim();
  const port = Number($('#tester-port').value) || 0;
  if (!app && !host) {
    out.replaceChildren(t('tester.need'));
    return;
  }
  try {
    const r = await api('POST', 'match', { app, host, port });
    out.replaceChildren(
      h('span', null, r.rule === 'Default' ? t('tester.default') : t('tester.match', { rule: r.rule })),
      actionStrip(r.action));
  } catch (err) {
    out.replaceChildren(h('span', { class: 'result', 'data-state': 'failed' }, err.message));
  }
}

/* ---------------------------------------------------------------- proxies */

function checkTarget() {
  return $('#check-target').value.trim() || 'www.gstatic.com:80';
}

function paintCheck(el, r) {
  el.removeAttribute('data-ok');
  el.classList.toggle('sub', !r || !!r.pending);
  if (!r) setText(el, t('px.never'));
  else if (r.pending) setText(el, t('px.checking'));
  else {
    el.dataset.ok = r.ok ? 'true' : 'false';
    setText(el, r.text || (r.ok ? t('px.ok', { ms: r.ms }) : r.error || t('res.failed')));
  }
}

function checkCell(key) {
  const el = h('span', { class: 'check-res', 'data-check': key });
  paintCheck(el, S.checks.get(key));
  return el;
}

function repaintChecks() {
  for (const el of $$('[data-check]')) paintCheck(el, S.checks.get(el.dataset.check));
}

async function runCheck(kind, id) {
  const key = kind + ':' + id;
  S.checks.set(key, { pending: true });
  repaintChecks();
  let r;
  try {
    r = await api('POST', 'check', { kind, id, target: checkTarget() });
  } catch (e) {
    r = { ok: false, error: e.message };
  }
  S.checks.set(key, r);
  repaintChecks();
  return r;
}

async function checkChain(c) {
  if (c.type === 'chain') return runCheck('chain', c.id);
  // Members of a group are alternatives: check each on its own.
  const key = 'chain:' + c.id;
  S.checks.set(key, { pending: true });
  repaintChecks();
  const res = await Promise.all(c.proxies.map((id) => runCheck('proxy', id)));
  const ok = res.filter((r) => r.ok).length;
  S.checks.set(key, { ok: ok > 0, text: t('ch.group.ok', { ok, n: res.length }) });
  repaintChecks();
}

function renderProxies() {
  const p = S.profile;
  if (!p) return;
  $('#tbl-proxies tbody').replaceChildren(...p.proxies.map((x, i) => h('tr', null,
    h('td', null, h('span', { class: 'app' }, x.name)),
    h('td', null, TYPE_LABEL[x.type] || x.type),
    h('td', null, h('span', { class: 'addr' }, joinHostPort(x.host, x.port))),
    h('td', { class: 'opt' }, x.username || h('span', { class: 'sub' }, t('px.none'))),
    h('td', null, checkCell('proxy:' + x.id)),
    h('td', { class: 'acts' },
      quietBtn(t('px.test'), () => runCheck('proxy', x.id)),
      quietBtn(t('b.edit'), () => editProxy(i)),
      quietBtn(t('b.delete'), () => deleteProxy(i), true)))));
  $('#tbl-proxies').hidden = !p.proxies.length;
  $('#empty-proxies').hidden = !!p.proxies.length;
  setText($('#empty-proxies'), t('px.empty'));
  $('#px-check-all').disabled = !p.proxies.length;
}

function usersOf(kind, id) {
  const p = S.profile;
  const users = [];
  if (kind === 'proxy') for (const c of p.chains) if (c.proxies.includes(id)) users.push(c.name);
  for (const r of p.rules) if (r.action.type === kind && r.action.target === id) users.push(r.name);
  if (p.default.type === kind && p.default.target === id) users.push(t('rule.default'));
  return users;
}

async function deleteProxy(i) {
  const x = S.profile.proxies[i];
  const users = usersOf('proxy', x.id);
  if (users.length) {
    await ask({ title: t('inuse.title', { name: x.name }), text: t('inuse.text', { list: users.join(', ') }), cancel: t('b.ok') });
    return;
  }
  const ok = await ask({ title: t('px.del.title', { name: x.name }), text: t('px.del.text'), ok: t('b.delete') });
  if (ok) change((p) => { p.proxies.splice(i, 1); });
}

let proxyCtx = null; // { i }: index, null for a new proxy

function syncProxyFields(f) {
  const type = f.elements.type.value;
  for (const el of $$('[data-only]', f)) {
    const on = el.dataset.only.split(' ').includes(type);
    el.hidden = !on;
    for (const c of $$('input', el)) c.disabled = !on;
  }
}

function setCheckNote(text, ok) {
  const el = $('#dlg-proxy-check');
  el.textContent = text;
  if (ok == null) el.removeAttribute('data-ok');
  else el.dataset.ok = ok ? 'true' : 'false';
}

function editProxy(i) {
  const dlg = $('#dlg-proxy');
  const f = dlg.querySelector('form');
  f.reset();
  showErr(f, '');
  setCheckNote('');
  const x = i === null ? { name: '', type: 'socks5', host: '', port: 1080 } : S.profile.proxies[i];
  proxyCtx = { i };
  setText($('#dlg-proxy-title'), i === null ? t('px.new') : t('px.edit'));
  for (const k of ['name', 'type', 'host', 'port', 'username', 'password', 'tls_server_name']) {
    f.elements[k].value = x[k] == null ? '' : x[k];
  }
  f.elements.tls_insecure.checked = !!x.tls_insecure;
  syncProxyFields(f);
  openModal(dlg);
}

function readProxy(f, old) {
  const type = f.elements.type.value;
  const x = {
    id: old ? old.id : '',
    name: f.elements.name.value.trim(),
    type,
    host: f.elements.host.value.trim().replace(/^\[|\]$/g, ''),
    port: Number(f.elements.port.value),
  };
  if (f.elements.username.value) x.username = f.elements.username.value;
  if (type !== 'socks4' && type !== 'socks4a' && f.elements.password.value) x.password = f.elements.password.value;
  if (type === 'https') {
    const sni = f.elements.tls_server_name.value.trim();
    if (sni) x.tls_server_name = sni;
    if (f.elements.tls_insecure.checked) x.tls_insecure = true;
  }
  return x;
}

async function saveProxy(f) {
  const { i } = proxyCtx;
  await saveProfile((p) => {
    if (i === null) p.proxies.push(readProxy(f, null));
    else {
      const x = readProxy(f, p.proxies[i]);
      S.checks.delete('proxy:' + x.id);
      p.proxies[i] = x;
    }
  });
}

async function testProxyForm() {
  const f = $('#dlg-proxy form');
  if (!f.reportValidity()) return;
  setCheckNote(t('px.checking'));
  try {
    const r = await api('POST', 'check', { proxy: readProxy(f, null), target: checkTarget() });
    setCheckNote(r.ok ? t('px.okNote', { ms: r.ms, target: r.target }) : r.error, r.ok);
  } catch (e) {
    setCheckNote(e.message, false);
  }
}

/* ----------------------------------------------------------------- chains */

function renderChains() {
  const p = S.profile;
  if (!p) return;
  const ul = $('#chain-list');
  ul.replaceChildren(...p.chains.map((c, i) => h('li', { class: 'chain' },
    h('div', null,
      h('div', { class: 'chain__name' }, c.name),
      h('span', { class: 'sub' }, t('ch.t.' + c.type))),
    h('div', { class: 'chain__route' }, chainStrip(c, false)),
    h('div', { class: 'chain__check' }, checkCell('chain:' + c.id)),
    h('div', { class: 'chain__acts' },
      quietBtn(t('px.test'), () => checkChain(c)),
      quietBtn(t('b.edit'), () => editChain(i)),
      quietBtn(t('b.delete'), () => deleteChain(i), true)))));
  if (!p.chains.length) ul.append(h('li', { class: 'empty' }, t(p.proxies.length ? 'ch.empty' : 'ch.empty.noproxy')));
  $('#ch-add').disabled = !p.proxies.length;
}

async function deleteChain(i) {
  const c = S.profile.chains[i];
  const users = usersOf('chain', c.id);
  if (users.length) {
    await ask({ title: t('inuse.title', { name: c.name }), text: t('inuse.text', { list: users.join(', ') }), cancel: t('b.ok') });
    return;
  }
  const ok = await ask({ title: t('ch.del.title', { name: c.name }), text: t('ch.del.text'), ok: t('b.delete') });
  if (ok) change((p) => { p.chains.splice(i, 1); });
}

let chainCtx = null; // { i, members }

function renderMembers() {
  const ms = chainCtx.members;
  const ol = $('#ch-members');
  ol.dataset.empty = t('ch.needs');
  ol.replaceChildren(...ms.map((id, k) => h('li', null,
    h('span', null, proxyName(id)),
    iconBtn('↑', t('b.up'), () => moveMember(k, -1), k === 0),
    iconBtn('↓', t('b.down'), () => moveMember(k, 1), k === ms.length - 1),
    quietBtn(t('ch.remove'), () => { ms.splice(k, 1); renderMembers(); }, true))));
  const pick = $('#ch-pick');
  for (const o of pick.options) o.disabled = ms.includes(o.value);
  const free = Array.from(pick.options).find((o) => !o.disabled);
  if (free && (pick.selectedIndex < 0 || pick.options[pick.selectedIndex].disabled)) pick.value = free.value;
  $('#ch-pick-add').disabled = !free;
  pick.disabled = !free;
}

function moveMember(k, d) {
  const ms = chainCtx.members;
  const [id] = ms.splice(k, 1);
  ms.splice(k + d, 0, id);
  renderMembers();
  const btns = $$('#ch-members > li:nth-child(' + (k + d + 1) + ') .btn--icon');
  const btn = btns[d < 0 ? 0 : 1];
  if (btn) (btn.disabled ? btns[d < 0 ? 1 : 0] : btn).focus();
}

function editChain(i) {
  const dlg = $('#dlg-chain');
  const f = dlg.querySelector('form');
  f.reset();
  showErr(f, '');
  const c = i === null ? { name: '', type: 'chain', proxies: [] } : S.profile.chains[i];
  chainCtx = { i, members: c.proxies.slice() };
  setText($('#dlg-chain-title'), i === null ? t('ch.new') : t('ch.edit'));
  f.elements.name.value = c.name;
  f.elements.type.value = c.type;
  $('#ch-pick').replaceChildren(...S.profile.proxies.map((x) => h('option', { value: x.id }, x.name)));
  renderMembers();
  openModal(dlg);
}

async function saveChain(f) {
  const { i, members } = chainCtx;
  if (!members.length) throw new Error(t('ch.needs'));
  await saveProfile((p) => {
    const c = {
      id: i === null ? '' : p.chains[i].id,
      name: f.elements.name.value.trim(),
      type: f.elements.type.value,
      proxies: members.slice(),
    };
    if (i === null) p.chains.push(c);
    else {
      S.checks.delete('chain:' + c.id);
      p.chains[i] = c;
    }
  });
}

/* -------------------------------------------------------------------- log */

let logPainted = 0; // highest sequence number already in the list

function addLogs(list) {
  if (!list || !list.length) return;
  for (const e of list) {
    S.logs.push(e);
    if (e.seq > S.logSeq) S.logSeq = e.seq;
  }
  if (S.logs.length > 2000) S.logs.splice(0, S.logs.length - 2000);
}

function levelPass(level, min) {
  if (min === 'error') return level === 'error';
  if (min === 'warn') return level === 'error' || level === 'warn';
  return true;
}

function renderLog(full) {
  const ol = $('#log-list');
  const stick = full || ol.scrollHeight - ol.scrollTop - ol.clientHeight < 32;
  if (full) {
    ol.replaceChildren();
    logPainted = S.logCleared;
  }
  const min = $('#log-level').value;
  const frag = document.createDocumentFragment();
  for (const e of S.logs) {
    if (e.seq <= logPainted) continue;
    logPainted = e.seq;
    if (!levelPass(e.level, min)) continue;
    frag.append(h('li', { 'data-level': e.level },
      h('time', null, fmtClock(e.time)),
      h('span', { class: 'lvl' }, t('lvl.' + e.level)),
      h('span', { class: 'msg' }, e.msg)));
  }
  ol.append(frag);
  while (ol.children.length > 2000) ol.firstChild.remove();
  if (stick) ol.scrollTop = ol.scrollHeight;
  const empty = $('#empty-log');
  empty.hidden = ol.children.length > 0;
  setText(empty, t('log.empty'));
}

/* --------------------------------------------------------------- settings */

function syncFakeFields() {
  const on = $('#s-fake').checked;
  $('#fake-fields').hidden = !on;
  for (const el of $$('#fake-fields input')) el.disabled = !on;
}

function fillSettings() {
  const p = S.profile;
  if (!p) return;
  const o = p.options;
  const d = p.dns;
  $('#s-intercept').checked = o.intercept;
  $('#s-ipv6').checked = o.ipv6;
  $('#s-quic').checked = o.block_quic;
  $('#s-direct').checked = o.handle_direct;
  $('#s-tport').value = o.transparent_port;
  $('#s-target').value = o.target_port;
  $('#s-inbound').value = o.inbound;
  $('#s-udp').checked = !!o.udp;
  $('#s-local-names').value = (d.local_names || []).join('\n');
  $('#s-logfile').value = o.log_file || '';
  $('#s-loglevel').value = o.log_level || 'info';
  for (const r of $$('input[name="dns-mode"]')) r.checked = r.value === (d.mode === 'local' ? 'local' : 'auto');
  $('#s-sniff').checked = d.sniff;
  $('#s-fake').checked = d.fake.enabled;
  $('#s-fake-listen').value = d.fake.listen;
  $('#s-fake-range').value = d.fake.range;
  $('#s-fake-up').value = d.fake.upstream;
  $('#s-connect').value = o.connect_timeout;
  $('#s-idle').value = o.idle_timeout;
  syncFakeFields();
  S.settingsDirty = false;
  $('#settings-error').hidden = true;
}

async function saveSettings(e) {
  e.preventDefault();
  const err = $('#settings-error');
  err.hidden = true;
  try {
    await saveProfile((p) => {
      const o = p.options;
      const d = p.dns;
      o.intercept = $('#s-intercept').checked;
      o.ipv6 = $('#s-ipv6').checked;
      o.block_quic = $('#s-quic').checked;
      o.handle_direct = $('#s-direct').checked;
      o.transparent_port = Number($('#s-tport').value);
      o.target_port = Number($('#s-target').value);
      o.inbound = $('#s-inbound').value.trim();
      o.udp = $('#s-udp').checked;
      d.local_names = splitList($('#s-local-names').value);
      o.log_file = $('#s-logfile').value.trim();
      o.log_level = $('#s-loglevel').value;
      d.mode = $('input[name="dns-mode"]:checked').value;
      d.sniff = $('#s-sniff').checked;
      d.fake.enabled = $('#s-fake').checked;
      if (d.fake.enabled) {
        d.fake.listen = $('#s-fake-listen').value.trim();
        d.fake.range = $('#s-fake-range').value.trim();
        d.fake.upstream = $('#s-fake-up').value.trim();
      }
      o.connect_timeout = Number($('#s-connect').value);
      o.idle_timeout = Number($('#s-idle').value);
    });
    fillSettings();
    toast(t('set.saved'));
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
}

async function loadDriver() {
  try {
    S.driver = await api('GET', 'driver');
  } catch (e) {
    return;
  }
  renderDriver();
}

function renderDriver() {
  const d = S.driver;
  const box = $('#driver-box');
  box.hidden = !(d && d.supported);
  if (box.hidden) return;
  const state = d.error ? d.error : !d.installed ? t('drv.s.missing') : d.running ? t('drv.s.running') : t('drv.s.stopped');
  setFacts($('#driver-facts'), [
    [t('drv.state'), state],
    [t('drv.file'), d.file || t('drv.file.none')],
    d.path ? [t('drv.path'), d.path] : null,
    [t('drv.admin'), d.elevated ? t('drv.admin.yes') : t('drv.admin.no')],
  ]);
  for (const b of $$('[data-drv]')) {
    const op = b.dataset.drv;
    b.disabled = !d.elevated
      || (op === 'install' && (!d.file || d.running))
      || (op === 'start' && (!d.installed || d.running))
      || (op === 'stop' && !d.running)
      || (op === 'uninstall' && !d.installed);
  }
}

async function driverOp(op) {
  const err = $('#driver-error');
  err.hidden = true;
  if (op === 'uninstall' && !await ask({ title: t('drv.un.title'), text: t('drv.un.text'), ok: t('drv.uninstall') })) return;
  for (const b of $$('[data-drv]')) b.disabled = true;
  try {
    S.driver = await api('POST', 'driver/' + op);
    toast(t('drv.done'));
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
    try { S.driver = await api('GET', 'driver'); } catch (e2) { /* keep the old state */ }
  }
  renderDriver();
  pollNow();
}

function renderAbout() {
  const s = S.status;
  if (!s) return;
  const bi = s.backend_info || {};
  setFacts($('#about-facts'), [
    [t('about.version'), s.version],
    [t('about.platform'), s.os + '/' + s.arch],
    [t('about.backend'), s.backend + (bi.impl ? ' (' + bi.impl + ')' : '')],
    [t('about.rights'), t(s.elevated ? 'about.rights.yes' : 'about.rights.no')],
    [t('about.pid'), String(s.pid)],
    [t('about.uptime'), fmtDur(s.uptime * 1000)],
    [t('about.profile'), s.profile_path || '-'],
    [t('about.conns'), t('about.conns.v', s.stats)],
    bi.classified != null ? [t('about.driver'), t('about.driver.v', bi)] : null,
  ]);
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// fileName turns a profile name into something every system accepts.
function fileName(s) {
  return String(s || '').replace(/[<>:"/\\|?*\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').replace(/^[ .]+|[ .]+$/g, '').slice(0, 64);
}

async function exportProfile(f) {
  const p = await api('GET', 'export' + (f.elements.passwords.checked ? '?passwords=1' : ''));
  download((fileName(S.profile && S.profile.name) || 'oddlyproxifier-profile') + '.json', JSON.stringify(p, null, 2) + '\n');
}

async function loadProfiles() {
  try {
    S.saved = await api('GET', 'profiles');
    S.savedOff = false;
  } catch (e) {
    if (e.status !== 409) return;
    S.saved = null;
    S.savedOff = true;
  }
  renderProfiles();
}

function renderProfiles() {
  $('#prof-store').hidden = S.savedOff;
  $('#prof-none').hidden = !S.savedOff;
  $('#prof-save').disabled = S.savedOff;
  const sv = S.saved;
  if (!sv) return;
  const rows = (sv.list || []).map((p) => ({ ...p, id: p.name }));
  syncRows($('#tbl-profiles tbody'), rows,
    (p) => h('tr', null, h('td'), h('td', { class: 'opt' }), h('td', { class: 'opt' }),
      h('td', { class: 'acts' },
        quietBtn(t('prof.activate'), () => activateProfile(p.name)),
        quietBtn(t('b.delete'), () => deleteSavedProfile(p.name), true))),
    (tr, p) => {
      const td = tr.children;
      const used = sv.active === p.name;
      setCell(td[0], p.name + '|' + used, () => [
        h('span', { class: 'app' }, p.name), used ? h('span', { class: 'sub' }, h('span', { class: 'tag' }, t('prof.inuse'))) : null,
      ]);
      setText(td[1], t('prof.counts', p));
      setText(td[2], new Date(p.modified * 1000).toLocaleString(lang === 'zh' ? 'zh-CN' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' }));
    });
  const empty = $('#empty-profiles');
  empty.hidden = rows.length > 0;
  setText(empty, t('prof.empty'));
  setText($('#prof-dir'), sv.dir ? t('prof.dir', { dir: sv.dir }) : '');
}

// adoptProfile takes over a profile the engine has just switched to.
function adoptProfile(p) {
  S.profile = p;
  S.checks.clear();
  S.settingsDirty = false;
  renderProfile();
  loadProfiles();
  pollNow();
}

let nameCtx = null; // { save(name) }: what the naming dialog does

function askName({ title, text, hint, ok, value, required, save }) {
  const dlg = $('#dlg-name');
  const f = dlg.querySelector('form');
  f.reset();
  showErr(f, '');
  setText($('#dlg-name-title'), title);
  setText($('#dlg-name-text'), text || '');
  setText($('#dlg-name-h'), hint);
  setText($('#dlg-name-ok'), ok);
  f.elements.name.value = value || '';
  f.elements.name.required = !!required;
  f.elements.name.closest('.field').hidden = S.savedOff;
  f.elements.name.disabled = S.savedOff;
  nameCtx = { save };
  openModal(dlg);
}

function saveProfileAs() {
  askName({
    title: t('prof.save.title'), hint: t('prof.name.h'), ok: t('prof.save.ok'), required: true,
    value: (S.saved && S.saved.active) || (S.profile && S.profile.name) || '',
    save: async (name) => {
      S.saved = await api('PUT', 'profiles/' + encodeURIComponent(name));
      if (S.profile) S.profile.name = name;
      renderProfiles();
      toast(t('prof.saved.as', { name }));
    },
  });
}

async function activateProfile(name) {
  if (!await ask({ title: t('prof.act.title', { name }), text: t('prof.act.text'), ok: t('prof.activate') })) return;
  try {
    adoptProfile(await api('POST', 'profiles/' + encodeURIComponent(name) + '/activate'));
    toast(t('prof.activated', { name }));
  } catch (e) {
    toast(e.message, 'error');
    loadProfiles();
  }
}

async function deleteSavedProfile(name) {
  if (!await ask({ title: t('prof.del.title', { name }), text: t('prof.del.text'), ok: t('b.delete') })) return;
  try {
    S.saved = await api('DELETE', 'profiles/' + encodeURIComponent(name));
    renderProfiles();
  } catch (e) {
    toast(e.message, 'error');
    loadProfiles();
  }
}

function importProfile(file) {
  if (file.size > 4 * 1024 * 1024) {
    toast(t('prof.toobig'), 'error');
    return;
  }
  askName({
    title: t('prof.import.title', { name: file.name }), text: t('prof.import.text'),
    hint: t('prof.import.name.h') + ' ' + t('prof.name.h'), ok: t('prof.import.ok'),
    value: fileName(file.name.replace(/\.(json|ppx)$/i, '')),
    save: async (name) => {
      const r = await api('POST', 'import' + (name && !S.savedOff ? '?name=' + encodeURIComponent(name) : ''), file, true);
      adoptProfile(r.profile);
      const notes = r.notes || [];
      if (!notes.length) toast(t('prof.imported'));
      // The naming dialog closes first; then the remarks get a dialog of their own.
      else setTimeout(() => ask({ title: t('prof.notes.title'), text: notes.join('\n'), cancel: t('b.ok') }), 0);
    },
  });
}

/* ---------------------------------------------------------------- dialogs */

function openModal(dlg) {
  dlg.returnValue = '';
  dlg.showModal();
}

function showErr(form, msg) {
  const el = form.querySelector('.form-error');
  el.textContent = msg;
  el.hidden = !msg;
}

// submitDialog runs an editor dialog's save. The dialog only closes once the
// engine has accepted the change; its answer is the real validation.
async function submitDialog(e, save) {
  e.preventDefault();
  const f = e.target;
  const btns = $$('button[type="submit"]', f);
  showErr(f, '');
  for (const b of btns) b.disabled = true;
  try {
    await save(f);
    f.closest('dialog').close('save');
  } catch (err) {
    showErr(f, err.message);
  } finally {
    for (const b of btns) b.disabled = false;
  }
}

// ask shows a question. With no "ok" label it is a plain message.
function ask({ title, text, ok, cancel }) {
  const dlg = $('#dlg-confirm');
  setText($('#dlg-confirm-title'), title);
  setText($('#dlg-confirm-text'), text);
  const okBtn = $('#dlg-confirm-ok');
  okBtn.hidden = !ok;
  okBtn.textContent = ok || '';
  dlg.querySelector('button[value="cancel"]').textContent = cancel || t('b.cancel');
  return new Promise((resolve) => {
    dlg.addEventListener('close', () => {
      const v = dlg.returnValue;
      dlg.returnValue = '';
      resolve(v === 'ok');
    }, { once: true });
    openModal(dlg);
  });
}

/* ---------------------------------------------------------------- profile */

async function loadProfile() {
  S.profile = await api('GET', 'profile');
  renderProfile();
}

function renderProfile() {
  renderRules();
  renderProxies();
  renderChains();
  if (!S.settingsDirty) fillSettings();
}

// saveProfile sends a modified copy; the engine validates, applies and stores it.
async function saveProfile(mutate) {
  const p = structuredClone(S.profile);
  mutate(p);
  S.profile = await api('PUT', 'profile', p);
  renderProfile();
  pollNow();
}

// change is saveProfile for one-click edits: failures surface as a toast.
async function change(mutate) {
  try {
    await saveProfile(mutate);
  } catch (e) {
    toast(e.message, 'error');
    renderProfile();
  }
}

/* ---------------------------------------------------------------- polling */

let timer = 0;
let polling = false;

function setOffline(off) {
  S.offline = off;
}

async function poll() {
  if (polling) return;
  if ($('#dlg-token').open) {
    schedule();
    return;
  }
  polling = true;
  try {
    if (!S.profile) await loadProfile();
    const jobs = [api('GET', 'status').then((s) => { S.status = s; })];
    if (S.view === 'connections') {
      jobs.push(api('GET', 'connections').then((c) => {
        S.active = c.active || [];
        S.recent = c.recent || [];
      }));
    }
    if (S.view === 'log') jobs.push(api('GET', 'logs?after=' + S.logSeq).then(addLogs));
    if (S.view === 'traffic') jobs.push(api('GET', 'traffic').then((tr) => { S.traffic = tr; }));
    await Promise.all(jobs);
    setOffline(false);
  } catch (e) {
    if (e.status === 0) setOffline(true);
  } finally {
    polling = false;
  }
  renderLive();
  schedule();
}

function schedule() {
  clearTimeout(timer);
  if (!document.hidden) timer = setTimeout(poll, S.offline ? 3000 : 1000);
}

function pollNow() {
  clearTimeout(timer);
  poll();
}

function renderLive() {
  renderLamps();
  renderQuick();
  renderTotals();
  renderNotice();
  if (S.view === 'connections') renderConnections();
  if (S.view === 'traffic') renderTraffic();
  if (S.view === 'log') renderLog(false);
  if (S.view === 'settings') renderAbout();
}

/* ---------------------------------------------------------------- routing */

function route() {
  const m = /^#\/(\w+)/.exec(location.hash);
  const v = m && VIEWS.includes(m[1]) ? m[1] : 'connections';
  S.view = v;
  for (const name of VIEWS) $('#view-' + name).hidden = name !== v;
  for (const a of $$('.nav a')) {
    if (a.dataset.view === v) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  document.title = t('nav.' + v) + ' - OddlyProxifier';
  if (v === 'settings') {
    loadDriver();
    loadProfiles();
    if (!S.settingsDirty) fillSettings();
  }
  if (v === 'log') renderLog(true);
  renderLive();
  pollNow();
}

function applyText() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  for (const el of $$('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  for (const el of $$('[data-i18n-placeholder]')) el.placeholder = t(el.dataset.i18nPlaceholder);
  for (const el of $$('[data-i18n-label]')) el.setAttribute('aria-label', t(el.dataset.i18nLabel));
}

function setLang(v) {
  lang = v;
  store.set('oddly.lang', v);
  applyText();
  // Rows cache their text; rebuild them in the new language.
  $('#tbl-active tbody').replaceChildren();
  $('#tbl-recent tbody').replaceChildren();
  $('#tester-out').replaceChildren();
  $('#tbl-usage tbody').replaceChildren();
  $('#tbl-profiles tbody').replaceChildren();
  renderProfiles();
  renderProfile();
  renderDriver();
  route();
}

/* ------------------------------------------------------------------ wiring */

function wire() {
  window.addEventListener('hashchange', route);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return;
    const busy = S.settingsDirty || $$('dialog').some((d) => d.open);
    if (S.profile && !busy) loadProfile().catch(() => {});
    pollNow();
  });

  $('#lang').value = lang;
  $('#lang').addEventListener('change', (e) => setLang(e.target.value));

  // connections
  $('#conn-filter').addEventListener('input', (e) => {
    S.filter = e.target.value.trim().toLowerCase();
    renderConnections();
  });
  $('#conn-close-all').addEventListener('click', async () => {
    const ok = await ask({
      title: t('conn.closeAll.title'), text: t('conn.closeAll.text', { n: S.active.length }), ok: t('conn.closeAll'),
    });
    if (ok) api('DELETE', 'connections').then(pollNow, (e) => toast(e.message, 'error'));
  });
  $('#conn-tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (tab) selectTab(tab.id.slice(4), false);
  });
  $('#conn-tabs').addEventListener('keydown', (e) => {
    const order = ['active', 'recent'];
    let i = order.indexOf(S.tab);
    if (e.key === 'ArrowRight') i = (i + 1) % order.length;
    else if (e.key === 'ArrowLeft') i = (i + order.length - 1) % order.length;
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = order.length - 1;
    else return;
    e.preventDefault();
    selectTab(order[i], true);
  });

  // rules
  $('#rule-add').addEventListener('click', () => editRule(null));
  $('#dlg-rule form').addEventListener('submit', (e) => submitDialog(e, saveRule));
  $('#tester').addEventListener('submit', runTester);

  // proxies and chains
  const target = store.get('oddly.target');
  if (target) $('#check-target').value = target;
  $('#check-target').addEventListener('change', (e) => store.set('oddly.target', e.target.value.trim()));
  $('#px-add').addEventListener('click', () => editProxy(null));
  $('#px-check-all').addEventListener('click', () => {
    for (const x of S.profile.proxies) runCheck('proxy', x.id);
  });
  const pf = $('#dlg-proxy form');
  pf.addEventListener('submit', (e) => submitDialog(e, saveProxy));
  pf.elements.type.addEventListener('change', () => {
    syncProxyFields(pf);
    const usual = { socks5: 1080, socks4: 1080, socks4a: 1080, http: 8080, https: 443 };
    const port = Number(pf.elements.port.value);
    if (!port || Object.values(usual).includes(port)) pf.elements.port.value = usual[pf.elements.type.value];
  });
  $('#dlg-proxy-test').addEventListener('click', testProxyForm);
  $('#ch-add').addEventListener('click', () => editChain(null));
  $('#dlg-chain form').addEventListener('submit', (e) => submitDialog(e, saveChain));
  $('#ch-pick-add').addEventListener('click', () => {
    const id = $('#ch-pick').value;
    if (id && !chainCtx.members.includes(id)) chainCtx.members.push(id);
    renderMembers();
  });

  // log
  $('#log-level').addEventListener('change', () => renderLog(true));
  $('#log-clear').addEventListener('click', () => {
    S.logCleared = S.logSeq;
    renderLog(true);
  });

  // header and traffic
  $('#quick-intercept').addEventListener('click', toggleIntercept);
  $('#tr-reset').addEventListener('click', resetTraffic);
  const plot = $('#tr-plot');
  plot.addEventListener('pointermove', chartHover);
  plot.addEventListener('pointerdown', chartHover);
  plot.addEventListener('pointerleave', () => { chartAt = -1; paintCrosshair(); });
  plot.addEventListener('blur', () => { chartAt = -1; paintCrosshair(); });
  plot.addEventListener('keydown', chartKey);
  $('#tr-tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (tab) selectUsage(tab.dataset.usage, false);
  });
  $('#tr-tabs').addEventListener('keydown', (e) => {
    const order = ['apps', 'routes', 'rules'];
    let i = order.indexOf(S.usage);
    if (e.key === 'ArrowRight') i = (i + 1) % order.length;
    else if (e.key === 'ArrowLeft') i = (i + order.length - 1) % order.length;
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = order.length - 1;
    else return;
    e.preventDefault();
    selectUsage(order[i], true);
  });

  // settings
  const sf = $('#settings-form');
  sf.addEventListener('submit', saveSettings);
  sf.addEventListener('input', () => { S.settingsDirty = true; });
  $('#s-fake').addEventListener('change', syncFakeFields);
  $('#settings-reset').addEventListener('click', fillSettings);
  for (const b of $$('[data-drv]')) b.addEventListener('click', () => driverOp(b.dataset.drv));
  $('#prof-save').addEventListener('click', saveProfileAs);
  $('#prof-export').addEventListener('click', () => {
    const dlg = $('#dlg-export');
    dlg.querySelector('form').reset();
    showErr(dlg.querySelector('form'), '');
    openModal(dlg);
  });
  $('#dlg-export form').addEventListener('submit', (e) => submitDialog(e, exportProfile));
  $('#dlg-name form').addEventListener('submit', (e) => submitDialog(e, (f) => nameCtx.save(f.elements.name.value.trim())));
  $('#prof-import').addEventListener('click', () => $('#prof-file').click());
  $('#prof-file').addEventListener('change', (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (file) importProfile(file);
  });

  // dialogs
  for (const b of $$('dialog [data-close]')) b.addEventListener('click', () => b.closest('dialog').close('cancel'));
  $('#dlg-token form').addEventListener('submit', (e) => {
    e.preventDefault();
    const v = e.target.elements.token.value.trim();
    const m = /token=([^&\s]+)/.exec(v); // a pasted address works too
    S.token = m ? decodeURIComponent(m[1]) : v;
    store.set('oddly.token', S.token);
    $('#dlg-token').close();
    pollNow();
  });
}

initToken();
applyText();
wire();
selectTab('active', false);
if (!S.token) askToken();
route();
