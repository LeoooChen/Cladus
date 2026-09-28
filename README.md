# Cladus

[English](#english) | [简体中文](#简体中文)

## English

Windows per-process TCP/UDP proxying in Rust, without TUN or DLL injection.
Rules follow a process's descendants, including children that outlive their
launcher. WinDivert redirects traffic to a SOCKS5 server.

Windows 0.1.3 includes the service, desktop GUI, DNS forwarding, configuration import
and installer. See [verification status](docs/STATUS.md) for tested behavior
and remaining release checks. Linux/macOS backends are deferred; portable
logic remains separated in `cladus-core`.

## Install and use

Requires Windows 10 2004 (build 19041) or newer, x64. Run
`cladus-0.1.3-windows-x64-setup.exe` as administrator. Setup installs WebView2
if missing (Internet access needed), registers the Cladus Engine service and
starts it **idle**. Subsequent GUI launches do not need elevation for Windows
administrators using their normal UAC token. Standard users who are not members
of Administrators cannot control the engine.

1. Exit other traffic redirectors before starting Cladus to avoid overlapping
   interception. Also turn off the upstream
   client's TUN mode; keep its SOCKS5 listener running. Cladus supplies per-process
   routing itself. Mihomo TUN coexistence caused intercepted TCP connections to
   stall on the tested Windows host, even when the target IP was correct.
2. Open Cladus and set the SOCKS5 host/port in proxy groups. The default is
   `127.0.0.1:7890`; change it to your proxy. UDP needs UDP ASSOCIATE support.
3. Add a rule for the executable (e.g. `antigravity.exe`), select its group and
   TCP, UDP or both. Rules include descendants. The process tree also provides
   manual proxy assignments and exclusions.
4. Enable optional DNS forwarding in settings if needed. It is off by default.
   Language, close-to-tray, logon startup and minimized startup are configurable.

The small light to the right of each proxy address checks its SOCKS5 connection
and authentication automatically on opening the proxy tab and after saving.
Gray means checking, green means reachable, and red means failure (hover for the
reason; click to retry). Green does not guarantee Internet access. The separate
website button measures time to HTTP response headers, including TLS for HTTPS,
with target DNS resolved by the proxy and an overall 20-second timeout.

If the proxy light is green but Edge still cannot open Google, enable **DNS
Proxy**: ordinary browser connections otherwise use system DNS, which may return
incorrect destination addresses. Restart the affected browser to discard its
cached DNS and connections. The website latency test uses proxy-side DNS and
therefore does not by itself verify the browser's system DNS path.
TUN clients may also supply synthetic DNS addresses (for example `198.18.x.x`);
after switching from TUN to Cladus, restart affected browsers to discard those
cached addresses. Cladus's DNS redirection covers active Ethernet/Wi-Fi adapters,
not another client's TUN adapter.

Opening the GUI engages the engine. Closing the window hides it to the tray
by default; **Exit** stops proxying, restores DNS and leaves the service idle.
If shutdown cannot be confirmed, the GUI stays open and reports the error.
Existing proxied TCP connections cannot survive an engine stop. A crashed
service restarts, restores DNS and starts idle; a running GUI then reconnects
and engages it again.

## Configuration and recovery

| Location | Contents |
| --- | --- |
| `%ProgramData%\Cladus\config.json` | Engine settings, restricted to administrators and SYSTEM |
| `%ProgramData%\Cladus\config.json.bak` | Previous saved engine settings |
| `%ProgramData%\Cladus\logs` | Rotating engine logs |
| `%ProgramData%\Cladus\state\dns-journal.json` | DNS recovery journal while redirected or recovery is pending |
| `%APPDATA%\Cladus\ui.json` | Language and window preferences |
| `%LOCALAPPDATA%\Cladus` | WebView2 data |

Engine schema version 1 defaults omitted fields and rejects unknown fields
and invalid group references. The GUI applies changes through the service;
avoid editing its file while running.

- `proxy_groups`: SOCKS5 endpoints; optional `username` and `password` are
  currently configured through JSON rather than dedicated authentication fields.
- `rules`: ordered name wildcards, optional command-line/image-path conditions,
  `proxy_group_id`, `protocol` and `dst_filter`.
- `dst_filter`: `include_cidrs`, `exclude_cidrs`, `include_ports`, `exclude_ports`.
  Port ranges are strings such as `"8000-8100"`.
- `global_exclude_cidrs`: private IPv4 networks excluded by default. Loopback,
  link-local, multicast and broadcast destinations are always direct.
- `tcp_syn_parking`: bounded first-packet parking. Changing it requires an idle
  engine; exit the GUI before CLI `disengage`/`set-config`.
- `dns`: `enabled`, `upstream` (IP:port), `proxy_group_id`, `strict`.
- `log_level`: `trace`, `debug`, `info`, `warn`, `error`.

DNS forwarding changes **system-wide** resolver settings to a local forwarder
and sends upstream queries over SOCKS5 TCP. Failed proxy DNS queries normally
fall back to the original system resolvers; `strict: true` returns failure
instead. Interface changes are monitored and original settings journaled before
redirection. Applications using their own DoH/resolvers follow ordinary traffic
rules.

Upgrades preserve configuration. Uninstall restores DNS before removing the
service and program files, removes logs/cache, and retains engine configuration
and UI preferences. Failed recovery blocks uninstall and preserves the journal
and executable. Do not delete a real recovery journal to bypass an error.
For manual recovery, run in an administrator PowerShell:

```powershell
& "$env:ProgramFiles\Cladus\cladus-engine.exe" stop
& "$env:ProgramFiles\Cladus\cladus-engine.exe" restore-dns
```

Use the actual install path if customized. `restore-dns --data-dir <directory>`
supports custom data directories. Check engine logs if recovery reports an
error and retry uninstall after resolving it.

## Import compatible configuration

First setup starts with fresh Cladus settings; it does not detect or migrate
another product's installation. Optional explicit import remains available
for compatible v2 JSON files (administrator):

```powershell
& "$env:ProgramFiles\Cladus\cladus-engine.exe" import-config --from 'C:\path\config-v2.json'
```

Imports compatible v2 groups, rules, destination filters and DNS settings, leaves the
source untouched and saves the previous Cladus configuration as `.bak`.
Unsupported entries produce warnings; review the resulting settings. Source UI
preferences are not imported.

## Build

Install the toolchain in `rust-toolchain.toml`, MSVC C++ build tools and Node.js
24. From the repository root:

```powershell
.\scripts\package-windows.ps1
```

This installs locked npm packages, builds the frontend and release binaries,
collects dependency licenses and compiles Inno Setup. WinDivert and Inno Setup
downloads are hash-pinned; the Microsoft WebView2 bootstrapper is signature
verified. Outputs are in `target/installer`, including `SHA256SUMS`. Cladus's
binaries and installer are currently unsigned.

To run the console engine (administrator):

```powershell
.\scripts\bootstrap-windows.ps1
cargo build --release --locked -p cladus-engine
.\target\release\cladus-engine.exe console `
  --config .\examples\antigravity.json `
  --windivert-dir .\third_party\windivert
```

Stop any installed service first: only one engine can own interception. Ctrl+C
stops the console engine and restores DNS. Console configuration changes require
a restart. The example's SOCKS5 port is 7890.

## Verify

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
.\scripts\check-layering.ps1
Push-Location apps/cladus-gui
npm ci
npm run build
npx playwright install chromium
npm test -- --workers=2
npm audit
Pop-Location
.\scripts\test-windows.ps1 -Release -IPv6
.\scripts\test-service.ps1
.\scripts\test-dns.ps1 -ProxyPort 7897
.\scripts\package-windows.ps1
.\scripts\test-installer.ps1
```

Run system tests sequentially. Service/DNS/installer tests refuse to replace an
existing Cladus service. They elevate hidden helpers and save logs in `target`.
WinDivert tests use a local SOCKS5 test server and documentation addresses; omit
`-IPv6` without an IPv6 route. The DNS test requires a working local SOCKS5
server at the specified port and public DNS connectivity. It temporarily changes
system DNS and checks exact restoration. Frontend tests mock Tauri; they do not
exercise the native window or tray.

## Limits and license

Unsupported fragmented/IPsec traffic is not relayed. Interception is fail-open:
after the engine stops, new connections go direct. Cladus is an application
routing tool, not a fail-closed anonymity boundary.

Cladus is MIT licensed. WinDivert is dynamically loaded and has its own license.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the installed `licenses`
directory. The design and future scope are in [docs/DESIGN.md](docs/DESIGN.md).

## 简体中文

Cladus 是用 Rust 开发的 Windows 按进程 TCP/UDP 代理工具，无需 TUN 或 DLL 注入。规则会跟随目标进程的子进程，即使启动器已经退出也有效；程序通过 WinDivert 将流量转发到 SOCKS5 服务器。

Windows 0.1.3 包含系统服务、桌面界面、DNS 转发、配置导入和安装程序。已验证的功能及待完成的发布检查见[验证状态](docs/STATUS.md)。Linux/macOS 后端暂未实现；可移植逻辑放在 `cladus-core` 中。

### 安装与使用

需要 Windows 10 2004（内部版本 19041）或更新版本，x64。以管理员身份运行 `cladus-0.1.3-windows-x64-setup.exe`。安装程序会在缺少 WebView2 时安装它（需要联网），注册 Cladus Engine 服务并使其以**空闲**状态启动。此后，Windows 管理员使用普通 UAC 令牌即可启动界面，无需再次提权；非管理员标准用户无法控制引擎。

1. 启用 Cladus 前退出其他流量重定向工具，并关闭上游代理客户端的 TUN 模式，但保留其 SOCKS5 监听端口。Cladus 自行处理按进程路由。测试中，Mihomo TUN 与 Cladus 同时运行会使被拦截的 TCP 连接卡住。
2. 打开 Cladus，在代理组中设置 SOCKS5 地址和端口。默认值为 `127.0.0.1:7890`，请改成自己的代理地址。UDP 代理需要上游支持 UDP ASSOCIATE。
3. 为可执行文件（例如 `antigravity.exe`）添加规则，选择代理组以及 TCP、UDP 或两者。规则覆盖子进程；进程树还支持手动指定代理和排除进程。
4. 按需在设置中启用 DNS 代理，默认关闭。界面语言、关闭到托盘、登录时启动和最小化启动均可配置。

每个代理地址右侧的指示灯会在打开代理页和保存后自动检查 SOCKS5 连接及认证：灰色表示检查中，绿色表示可连接，红色表示失败（悬停查看原因，单击重试）。绿色不代表互联网一定可用。单独的网站测速按钮会等待 HTTP 响应头，HTTPS 测试包含 TLS 握手，目标域名由代理解析，整体超时为 20 秒。

若指示灯为绿色，但浏览器仍无法打开目标网站，请启用 **DNS 代理**：普通浏览器连接默认仍使用系统 DNS，可能得到错误的目标地址。更改 DNS 或从 TUN 切换到 Cladus 后，请重启受影响的浏览器，清除缓存的 DNS 与连接。TUN 客户端可能提供 `198.18.x.x` 等虚拟 DNS 地址。Cladus 的 DNS 重定向覆盖活动的以太网和 Wi-Fi 适配器，不覆盖其他客户端的 TUN 适配器。网站测速使用代理端 DNS，不能单独证明浏览器的系统 DNS 路径正常。

打开界面会使引擎开始工作。默认情况下，关闭窗口仅隐藏到托盘；选择**退出**会停止代理、恢复 DNS，并让服务保持空闲。若无法确认正常关闭，界面会留在屏幕上并报告错误。引擎停止后，已有的代理 TCP 连接会断开。服务崩溃后会自动重启、恢复 DNS 并保持空闲；正在运行的界面会重新连接并再次启用引擎。

### 配置与恢复

| 位置 | 内容 |
| --- | --- |
| `%ProgramData%\Cladus\config.json` | 引擎设置，仅管理员和 SYSTEM 可访问 |
| `%ProgramData%\Cladus\config.json.bak` | 上一次保存的引擎设置 |
| `%ProgramData%\Cladus\logs` | 轮转的引擎日志 |
| `%ProgramData%\Cladus\state\dns-journal.json` | DNS 重定向或待恢复时的恢复日志 |
| `%APPDATA%\Cladus\ui.json` | 语言和窗口首选项 |
| `%LOCALAPPDATA%\Cladus` | WebView2 数据 |

引擎配置版本为 1：省略的字段采用默认值，未知字段和无效的代理组引用会被拒绝。界面通过服务应用更改；运行时不要直接修改配置文件。主要字段如下：

- `proxy_groups`：SOCKS5 节点；可选的 `username` 和 `password` 目前需通过 JSON 配置。
- `rules`：按顺序匹配的进程名称通配符、可选命令行/映像路径条件、`proxy_group_id`、`protocol` 和 `dst_filter`。
- `dst_filter`：`include_cidrs`、`exclude_cidrs`、`include_ports`、`exclude_ports`；端口范围使用 `"8000-8100"` 等字符串。
- `global_exclude_cidrs`：默认直连的私有 IPv4 网段。环回、链路本地、多播和广播目标始终直连。
- `tcp_syn_parking`：有界的首包暂存；修改时引擎必须空闲，请先退出界面，再用 CLI 执行 `disengage`/`set-config`。
- `dns`：`enabled`、`upstream`（IP:端口）、`proxy_group_id`、`strict`。
- `log_level`：`trace`、`debug`、`info`、`warn`、`error`。

DNS 转发会把**系统级**解析器设置改为本地转发器，再通过 SOCKS5 TCP 发送上游查询。代理 DNS 查询失败时通常会回退到原系统解析器；设置 `strict: true` 则直接返回失败。程序监测网卡变化，并在重定向前记录原始设置。使用自身 DoH/解析器的应用仍遵循普通流量规则。

升级会保留配置。卸载会先恢复 DNS，再删除服务、程序文件、日志和缓存，但保留引擎配置及界面首选项。恢复失败时，卸载会中止并保留恢复日志及可执行文件；不要通过删除真实恢复日志来绕过错误。手动恢复请在管理员 PowerShell 中执行：

```powershell
& "$env:ProgramFiles\Cladus\cladus-engine.exe" stop
& "$env:ProgramFiles\Cladus\cladus-engine.exe" restore-dns
```

若自定义了安装目录，请替换实际路径。`restore-dns --data-dir <directory>` 支持自定义数据目录。恢复出错时先检查引擎日志，解决问题后再重试卸载。

### 导入兼容配置

首次安装使用全新的 Cladus 设置，不会检测或迁移其他产品。管理员可选择显式导入兼容的 v2 JSON 文件：

```powershell
& "$env:ProgramFiles\Cladus\cladus-engine.exe" import-config --from 'C:\path\config-v2.json'
```

导入会保留源文件，将此前的 Cladus 配置保存为 `.bak`，并导入兼容的代理组、规则、目标筛选和 DNS 设置。不支持的条目会产生警告，请检查导入结果。源界面的首选项不会导入。

### 构建与验证

安装 `rust-toolchain.toml` 指定的 Rust 工具链、MSVC C++ 构建工具和 Node.js 24。在仓库根目录运行：

```powershell
.\scripts\package-windows.ps1
```

脚本安装锁定版本的 npm 依赖，构建前端和 Release 二进制文件，收集依赖许可证，并用 Inno Setup 编译安装程序。WinDivert 和 Inno Setup 下载文件固定了哈希值；Microsoft WebView2 安装引导程序会验证签名。输出位于 `target/installer`，包含 `SHA256SUMS`。当前二进制文件和安装程序尚未进行代码签名。

管理员也可以构建并运行控制台引擎：

```powershell
.\scripts\bootstrap-windows.ps1
cargo build --release --locked -p cladus-engine
.\target\release\cladus-engine.exe console `
  --config .\examples\antigravity.json `
  --windivert-dir .\third_party\windivert
```

先停止已安装的服务，因为只能有一个引擎进行流量拦截。Ctrl+C 会停止控制台引擎并恢复 DNS。控制台配置变更需要重启，示例的 SOCKS5 端口是 7890。

主要验证命令与英文版 [Verify](#verify) 小节一致。系统测试应依次运行；服务、DNS 和安装程序测试会拒绝替换已有的 Cladus 服务。测试日志保存在 `target` 中。WinDivert 测试使用本地 SOCKS5 测试服务器；没有 IPv6 路由时不要传 `-IPv6`。DNS 测试需要指定端口上的可用本地 SOCKS5 服务器及公网 DNS 连接，并会临时修改系统 DNS、检查是否完整恢复。前端测试模拟 Tauri，不覆盖原生窗口和托盘。

### 限制与许可

分片流量和 IPsec 流量不会被转发。拦截采用故障开放策略：引擎停止后，新连接会直连；Cladus 不是故障封闭的匿名保护工具。

Cladus 使用 MIT 许可证。WinDivert 以动态方式加载，并受其自身许可证约束。详情见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和安装目录中的 `licenses`。设计与后续范围见 [docs/DESIGN.md](docs/DESIGN.md)。
