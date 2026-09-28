# Cladus · 设计方案

> 状态：**方案已确认（2026-09-26）**，按 §13 分阶段实施。
> Cladus 是 Windows 进程级流量代理 Clew 的 Rust 重写版，作为独立产品发布，不再沿用 Clew 的名称。
> 参考实现：`reference/clew-cpp`（LeoooChen/clew-proxy @ a895b9e，含 fork 的语言切换 / HiDPI / 安装器改动；不纳入本仓库版本控制）。
> 原则：稳定 > 简单 > 可维护 > 跨平台演进 > 与旧代码结构一致（最后一项不追求）。

## 已确认的决策

| 决策 | 结论 |
|---|---|
| 进程与权限架构 | 特权引擎服务 + 非特权 GUI |
| GUI | Tauri 2 + 复用 Vue 3 前端 |
| 托盘“退出” | 停止代理并恢复 DNS；服务回到空闲常驻 |
| 仓库 | 全新独立仓库 |
| 命名 | 一律使用 Cladus（见下表） |

**命名表**

| 对象 | 名称 |
|---|---|
| 产品 / 窗口标题 | Cladus |
| GUI 可执行文件 | `cladus.exe` |
| 引擎可执行文件 | `cladus-engine.exe` |
| Windows 服务 | `CladusEngine`（显示名 “Cladus Engine”） |
| 命名管道 | `\\.\pipe\CladusEngine` |
| ETW 会话 | `CladusProcessEtw` |
| 数据目录 | `%ProgramData%\Cladus`、`%APPDATA%\Cladus`、`%LOCALAPPDATA%\Cladus` |
| 自启注册表值 | `HKCU\...\Run\Cladus` |
| 安装程序 | `cladus-X.Y.Z-windows-x64-setup.exe`，AppId `{A931F2F9-36B8-4C52-9C9B-76AC7B86E1A3}` |
| Rust crate | `cladus-core`、`cladus-net`、`cladus-ipc`、`cladus-engine`、`cladus-platform-windows`；应用 `apps/cladus-engine`、`apps/cladus-gui` |
| 日志前缀 / 环境变量 | `CLADUS_LOG`、`CLADUS_DEV_URL` |

---

## 0. 结论摘要

| 议题 | 结论 |
|---|---|
| 进程模型 | `cladus-engine.exe` 作为 Windows 服务（LocalSystem）负责 WinDivert / ETW / DNS / 转发；`cladus.exe`（GUI）以普通用户权限运行，两者通过命名管道 IPC 通信。GUI 永不提权，开机自启不需要计划任务，也不会弹 UAC。 |
| 流量截获 | **继续使用 WinDivert 2.2.2**（双层：SOCKET 层做决策 + NETWORK 层反射），完整保留 SYN parking 设计。**不使用** LGPL 的 `windivert` / `windivert-sys` crate，改为自写约 200 行 FFI，运行时动态加载 `WinDivert.dll`，主项目保持 MIT。 |
| 进程追踪 | **继续使用 ETW Microsoft-Windows-Kernel-Process**（Start/Stop/Rundown + EventsLost 重同步），基于 `windows` crate 手写（移植已验证的 C++ 逻辑）。 |
| 核心并发 | 单线程“决策核心”actor 独占进程树和规则引擎（对应 C++ 的 strand），用**带优先级的通道**保证 CONNECT 决策优先于 ETW 突发；NETWORK 层 worker 只读原子量，从不阻塞在核心上；中继、UDP、DNS、IPC 运行在 tokio 上。 |
| GUI | Tauri 2 + 迁移现有 Vue 3 前端（已有中英文 i18n、Playwright 测试、HiDPI 行为）。没有内置 HTTP 服务器，也没有手写 WebView2 COM 宿主。 |
| 异步 / 日志 / 配置 | tokio · tracing（滚动文件、运行时调级）· serde_json（schema v3，可导入 Clew 的 `clew.json` v2） |
| IPC | 命名管道，长度前缀 JSON 帧，版本握手；管道 DACL + 服务端校验“调用者是本机 Administrators 组成员（无需提权）”。 |
| 数据目录 | 引擎配置 / 状态 / 日志放 `%ProgramData%\Cladus`（受保护 DACL）；UI 偏好放 `%APPDATA%\Cladus`；WebView2 缓存和 GUI 日志放 `%LOCALAPPDATA%\Cladus`。**安装目录只读，只放程序文件。** |
| 崩溃恢复 | WinDivert 句柄随进程退出由内核释放（fail-open）；DNS 采用**预写日志（journal）**，在服务启动、停止、SCM 自动重启、卸载时恢复；启动时清理残留 ETW 会话。 |
| 安装器 | Inno Setup（沿用 fork 已验证的流程、中文翻译、CI 安装 / 升级 / 卸载测试）；新 AppId；首次安装使用全新的 Cladus 配置，不检测或迁移其他产品。 |
| 许可证 | MIT。cargo-deny 白名单：MIT / Apache-2.0 / BSD / ISC / Zlib / Unicode；MPL-2.0 只允许作为未修改的传递依赖（Tauri 的 cssparser/selectors）；禁止 GPL / LGPL / AGPL 被编进二进制（WinDivert 以独立 DLL 动态加载，另行附带许可证）。设计与算法源自 Clew（MIT, © 2026 ymonster），在 `THIRD_PARTY_NOTICES.md` 中保留其许可声明与致谢。 |

---

## 1. 现有项目（Clew C++ 版）分析

### 1.1 进程与组件

单一进程 `clew.exe`，manifest 为 `requireAdministrator`：

```
main → app（组合根，约 30 个成员，析构时显式按序关闭）
  ├─ process_tree_manager（strand）── ETW consumer 线程
  │     flat_tree（LC-RS，PID→idx，(pid,psn) 身份）+ rule_engine_v3
  ├─ windivert_socket      TCP SOCKET 层（SNIFF，IOCP → strand）
  ├─ windivert_network     TCP NETWORK 层（2 个阻塞 worker，反射）
  ├─ syn_parker            SYN 停车池 + 注入 / 看门狗线程（1ms 高精度定时器）
  ├─ PortTracker           65536 槽位无锁状态字
  ├─ async_acceptor + relay 协程 + socks5 握手
  ├─ UDP：socket_udp / network_udp / session_table / Socks5UdpManager / UdpRelay
  ├─ DnsManager：dns_forwarder（127.0.0.2:53 → SOCKS5 UDP → 8.8.8.8）+ system_dns（SetInterfaceDnsSettings + dns_state.json）
  ├─ http_api_server（cpp-httplib，8 个 worker，:18080）+ 9 组 handler
  ├─ process_projection（原子快照 + 100ms 合并 + 可见性门控）
  └─ webview_app（无边框 WebView2 宿主、托盘、PostWebMessage 推送、DPI）
```

### 1.2 关键数据流

**TCP 截获（核心链路）**
1. 应用调用 `connect()` → 内核先产生 SOCKET 层 CONNECT 事件，再发出 SYN（CONNECT 领先 p50 约 17µs）。
2. NETWORK worker 看到尚无决策的初始 SYN 时，把包连同 `WINDIVERT_ADDRESS` 复制进停车池，槽位 CAS 为 `empty→pending`，不阻塞。
3. SOCKET 事件在 strand 上处理：先识别回声（自身重注入产生的 PID 4 幻影 CONNECT）；再判断是否为自身 PID（一律 direct）；未知 PID 当场同步解析整条祖先链（ETW 有 1–2s 延迟）；已知 PID 用 PSN 校验是否被回收；然后查规则和 CIDR 排除 → 发布 `proxied(group)` 或 `direct`。**每个 CONNECT 恰好发布一次。**
4. 若槽位处于 pending，由 CAS 胜者把池索引交给注入线程：direct 原样发出，proxied 则执行“交换源/目的地址、目的端口改为 acceptor 端口、Outbound=0”后作为入站重注入（streamdump 模式）。
5. 后续数据包按 `src_port` 查槽位做反射；acceptor 回包反向改写。
6. relay 按 `src_port` 从槽位取出原始目的地址 → 连接 SOCKS5 → CONNECT → 双向转发；关闭时用 `clear_if(port, connect_ts)` 清槽。
7. 看门狗：停车超过 20ms 仍无决策 → 原样放行，并把槽位钉为 `abandoned`，迟到的决策会被拒绝（避免在连接中途开始反射）。

**进程树**：ETW Start/Stop/Rundown（CAPTURE_STATE 取代快照）；父子关系按 (parent_pid, parent_psn) 链接，父进程未知时先作为孤儿挂起，5s 宽限后挂到根；丢事件时 1s 防抖后重新发起 rundown。

**规则**：进程名 glob（不区分大小写）→ 可选 cmdline（关键字 AND 模式 / glob 模式）→ 可选镜像路径前缀；按配置顺序首条命中；始终为树模式；手动 hijack 优先级最高并由子进程继承。

**UDP**：SOCKET 层 BIND/CONNECT 写入 UdpPortTracker；NETWORK 层逐包查策略表（排除 CIDR），命中则反射到 relay 端口并按 app 端口记录会话；每个 app 端口建一个 SOCKS5 UDP ASSOCIATE；回包通过 WinDivert 伪造入站包注入。

**DNS**：启用时枚举有 IPv4 网关的物理网卡，保存原配置到 `dns_state.json`，把 DNS 设为 127.0.0.2；关闭或退出时恢复；下次启动时发现状态文件就恢复。

**UI**：HTTP 负责 CRUD；推送走 `PostWebMessageAsJson`；窗口隐藏时后端完全停止构建快照。

### 1.3 fork 的改动（Cladus 必须具备，不能回退）

- 界面语言：跟随系统 / 简体中文 / English，持久化保存；切换时刷新 UI 并回到设置页，引擎不中断；Monaco 使用中文 nls；未保存的 JSON 编辑需要确认才丢弃；托盘菜单和原生错误框也本地化。
- HiDPI：PerMonitorV2 manifest；WebView 跟随显示器缩放，不做二次缩放；窗口宽高按 96-DPI 逻辑像素保存，位置按桌面像素保存（支持负坐标）；恢复时夹紧到工作区；处理 `WM_DPICHANGED` 建议矩形；最小尺寸随 DPI 缩放；进程图标 32px 源像素。
- 文件对话框为 Unicode，路径长度不受 MAX_PATH 限制。
- 安装器与发布：Inno Setup（固定 SHA-256）、中英文安装界面、按需安装运行库、卸载只删除属于本安装的自启项；CI 在中文路径下测试安装 / 升级 / 卸载并验证配置保留；打 tag 后先通过全部测试，再由独立的 release job 发布 EXE。

### 1.4 审阅中发现的问题（Cladus 修复，不照搬）

| # | 问题 | 位置 | Cladus 处理 |
|---|---|---|---|
| D1 | **TCP 决策不检查规则的 protocol**：只看 `is_proxied()`，“UDP only”规则同样会代理 TCP | `windivert_socket::decide` | 每个进程的 Assignment 携带协议集合，TCP / UDP 分别判断 |
| D2 | 规则状态以裸 PID 为键，PID 回收窗口内会误继承（文档已记为 known residual） | `rule_engine_v3` | 以 `ProcessKey(pid, instance)` 为键；继承在插入时从父节点 O(1) 取得 |
| D3 | DNS forwarder 的 `pending_` 被两个协程在多线程 io_context 上并发访问，存在**数据竞争** | `dns_forwarder` | 单任务所有权 |
| D4 | DNS 只按 tx_id 关联，不同客户端的相同 ID 会串线 | 同上 | 转发时重写 tx_id，映射表 (新ID → 客户端, 原ID) 并带超时 |
| D5 | UDP 会话每个端口只记一个目的地址；未 connect 的 socket 访问多个目的地时，回包源地址错误 | `udp_relay::inject_reply` | 用 SOCKS5 UDP 回包头里的源地址伪造回包源 |
| D6 | SOCKS5 只支持 IPv4、无认证，CONNECT 回复固定按 10 字节读取（BND 为域名或 IPv6 时解析错乱），没有超时 | `socks5_async` | 完整实现 RFC 1928 / 1929、IPv4 / IPv6 / 域名 BND，连接和握手都有超时 |
| D7 | relay 把 TCP:53 硬编码重定向到 8.8.8.8 | `relay.hpp` | 改为读取 DNS 配置，默认关闭 |
| D8 | acceptor 绑定 `0.0.0.0` 且不校验对端，局域网主机猜中端口就能滥用 | `acceptor` | 校验对端 IP 等于槽位记录的原始目的地址，否则立即关闭 |
| D9 | **IPv6 完全不处理**，被代理进程的 IPv6 连接直连泄漏 | NETWORK 层 | P2：先提供“被代理进程的 IPv6 连接被拒绝（促使快速回退到 IPv4）”，默认开启；随后实现 IPv6 反射 |
| D10 | DNS 只改 IPv4 DNS；网卡变化时不处理 | `system_dns` | 同时捕获并覆盖 v4 / v6；监听接口变化并增量写入 journal |
| D11 | 崩溃后要等再次启动才恢复 DNS | `DnsManager` | 服务开机自启时恢复；SCM 崩溃后自动重启；卸载时恢复 |
| D12 | 代理不可用时，全局 DNS 转发会让整机无法解析 | 同上 | 健康检查失败后回退到原 DNS（可选严格模式），UI 告警 |
| D13 | `dst_filter` 的 include_cidrs / include_ports / exclude_ports 只用于 UI 显示，决策只看 exclude_cidrs | `connection_service` vs `decide` | 决策与显示共用同一个过滤函数 |
| D14 | 配置、日志、状态文件都放在安装目录 | `exe_paths` | 按 §4 的目录方案存放 |
| D15 | 崩溃后 ETW 实时会话会残留到重启 | `etw_consumer` | 启动时清理；卸载时再清理 |

---

## 2. 保留什么、替换什么

| 保留（经测量验证的设计） | 替换 / 重做 |
|---|---|
| WinDivert 双层（SOCKET 决策 + NETWORK 反射）、streamdump 反射模式 | 单进程提权 → 引擎服务 + 非特权 GUI |
| **SYN parking 全部不变量**：四状态字 CAS、内核时间戳 TTL 10ms、同 ISN 视为重传、幻影 CONNECT 识别、CLOSE 语义、`clear_if`、池满时放行并钉住、终止开关、看门狗 20ms 和高精度定时器 | HTTP API + 手写 WebView2 宿主 → Tauri 命令 / 事件 + 命名管道 |
| 每个 CONNECT 恰好发布一次决策；不代理自身进程 | strand（FIFO）→ 带优先级的决策核心 actor；快照序列化移出核心线程 |
| ETW Kernel-Process + CAPTURE_STATE rundown + EventsLost 重同步 + TDH 字段计划 | `matched_pids` 集合 → 每个节点一个 Assignment（来源 / 组 / 协议 / 策略） |
| (pid, PSN) 身份；未知 PID 同步解析祖先链；已知 PID 做 PSN 校验 | 计划任务 `/RL HIGHEST` 自启 → HKCU Run 启动非特权 GUI |
| 懒加载 cmdline / 镜像路径并缓存 | VC++ redist 依赖 → 静态 CRT（`+crt-static`） |
| 可见性门控、推送合并（100ms） | 全量快照推送 → MVP 先全量，之后改增量（seq + upsert / remove） |
| 按实际截获结果做 e2e 判定（不信计数器） | 依赖外网代理的 e2e → CI 内置测试 SOCKS5 服务器 + TEST-NET 目的地址 |
| Inno Setup + 中英文安装界面 + CI 安装 / 升级 / 卸载测试 + tag 触发发布 | 配置散落在安装目录 → ProgramData / APPDATA 分离 |
| Vue 3 前端、i18n、Playwright（mock 后端） | 前端传输层改为 `@tauri-apps/api` |

---

## 3. 目标架构

```
┌──────────────── 用户会话（标准权限 asInvoker）────────────────┐
│ cladus.exe  — Tauri 2（WebView2 + Vue UI）                       │
│   托盘 / 窗口 / 自启(HKCU Run) / 语言 / 图标提取 / 文件对话框    │
│   %APPDATA%\Cladus\ui.json   %LOCALAPPDATA%\Cladus\{logs,WebView2}│
└───────────────┬─────────────────────────────────────────────────┘
                │  \\.\pipe\CladusEngine  (协议 v1, JSON 帧, 请求/响应 + 订阅推送)
┌───────────────┴──────── Session 0 · LocalSystem ────────────────┐
│ cladus-engine.exe — Windows 服务 CladusEngine（自动启动，默认空闲）│
│   决策核心 actor ◄── ETW 线程                                    │
│        ▲  ▲                                                      │
│        │  └── WinDivert SOCKET 线程(TCP/UDP) ── PortTracker ──┐  │
│        │                                   NETWORK workers ◄──┘  │
│        │                                   SYN 注入/看门狗线程    │
│   tokio: acceptor+relay │ UDP relay │ DNS forwarder │ IPC │ 配置  │
│   %ProgramData%\Cladus\{config.json, state\, logs\}（受保护 DACL）│
└─────────────────────────────────────────────────────────────────┘
```

**为什么选服务模型**：
1. GUI 不提权：手动启动和开机自启都不弹 UAC；文件对话框、资源管理器定位以用户身份运行。
2. 崩溃恢复有常驻的恢复者：服务开机自动启动，一启动就检查 DNS journal；崩溃后 SCM 自动重启。
3. 引擎与 UI 解耦：UI 崩溃不影响转发，重连即可恢复；为以后的 CLI / Linux daemon 打基础。
4. 代价：多一层 IPC、服务安装逻辑和管道访问控制，都是一次性工程量，模式成熟（Tailscale、Mullvad、WireGuard Windows 均采用）。

**引擎生命周期**：
- 服务开机启动但处于**空闲**：不加载 WinDivert，不开 ETW，只做 DNS journal 恢复检查。
- GUI 启动后发送 `Engage`，引擎开始工作；托盘点“退出” → `Disengage`（恢复 DNS、关闭 WinDivert），然后 GUI 退出。退出 Cladus 即停止代理。
- GUI 异常断开时引擎继续运行；GUI 重连后恢复显示。（以后可加“无 UI 常驻”选项。）
- 与 Clew 互斥：Engage 前检测 `Global\Clew_SingleInstance`，存在则拒绝并提示“请先退出 Clew”（两者同时反射会冲突）。

---

## 4. 权限模型与数据目录

| 内容 | 位置 | 所有者 / ACL | 说明 |
|---|---|---|---|
| 程序文件 | `%ProgramFiles%\Cladus\` | 安装器（管理员）；Users 只读 | 只含 exe、WinDivert.dll/.sys、licenses。自定义安装路径时由安装器设置受保护 DACL，防止标准用户替换服务 exe |
| 引擎配置 | `%ProgramData%\Cladus\config.json`（+ `.bak`） | **受保护 DACL**：SYSTEM、Administrators 完全控制，Users 无权限 | 服务读写；GUI 只经 IPC 访问。服务启动时校验目录所有者 / DACL，防止被预先植入 |
| 运行状态 | `%ProgramData%\Cladus\state\dns-journal.json` | 同上 | 预写日志：先写 journal 再改系统，校验恢复成功后才删除 |
| 引擎日志 | `%ProgramData%\Cladus\logs\engine.log*` | 同上（Users 可读） | 按大小滚动，保留 5 个；级别可运行时调整 |
| UI 偏好 | `%APPDATA%\Cladus\ui.json` | 当前用户 | 语言、主题、窗口几何、关闭到托盘、最小化启动 |
| GUI 日志 / WebView2 数据 | `%LOCALAPPDATA%\Cladus\{logs,WebView2}` | 当前用户 | 避免 Program Files 下 WebView2 报 0x800700aa |

**需要特权的操作全部在服务里执行**：WinDivert 驱动加载、ETW 内核 provider、`SetInterfaceDnsSettings`、读取其他会话进程的 cmdline。

**IPC 访问控制**：
- 管道 DACL：SYSTEM、Administrators、INTERACTIVE。
- 服务端逐连接校验：`ImpersonateNamedPipeClient` 取令牌 → 已提权管理员直接通过 → 受限令牌取 `TokenLinkedToken` 后 `CheckTokenMembership(Administrators)`。**即本机管理员组成员，无需提权**即可控制引擎，与原“必须 UAC 提权”安全边界等价，但不弹窗。
- 非管理员：拒绝连接（以后可扩展为只读）。
- GUI 用 `GetNamedPipeServerProcessId` 校验服务端就是 CladusEngine 服务进程，防止管道抢注。

**加固**：服务启动后立即 `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`，用完整路径加载 WinDivert.dll；服务 SID 类型 unrestricted；最小特权集合作为后续加固项。

**开机启动**：GUI 写 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Cladus = "<安装目录>\cladus.exe" --autostart`；按 UI 偏好决定是否只显示托盘。全程不提权。GUI 每次启动校验该值指向当前 exe，不一致就修正。

---

## 5. 目录结构与模块边界

```
Cladus/                          # 仓库根
├─ Cargo.toml                    # workspace；统一版本、lints、profile
├─ rust-toolchain.toml
├─ deny.toml / about.toml        # 许可证 / 漏洞策略；第三方声明生成
├─ crates/
│  ├─ cladus-core/               # 纯领域逻辑，不含 IO、平台代码和 tokio
│  │   ├─ model                  # ProcessKey, ProcessInfo, GroupId, RuleId, Verdict, FlowQuery …
│  │   ├─ config                 # schema v3、校验、Clew v2 导入
│  │   ├─ tree                   # 进程树（arena + 父子索引、孤儿、墓碑压缩）
│  │   ├─ rules                  # glob / cmdline / 路径匹配、Assignment 计算与继承、排除
│  │   ├─ policy                 # 目的过滤（CIDR v4/v6、端口），决策与显示共用
│  │   ├─ decision               # 决策核心状态机（同步可测）
│  │   └─ platform               # ★平台 trait（见 §6）
│  ├─ cladus-net/                # SOCKS5 TCP/UDP 客户端、TCP relay、UDP 会话、DNS forwarder（tokio）
│  ├─ cladus-ipc/                # IPC 协议类型、帧编解码、版本；传输按 cfg 切换 Named Pipe / UDS
│  ├─ cladus-engine/             # 组合根：actor 线程、生命周期、配置存储、DNS journal、统计；只依赖 trait
│  └─ cladus-platform-windows/   # 唯一可以 `use windows::…` 的地方
│      ├─ divert/                # FFI（运行时加载）、TCP/UDP SOCKET/NETWORK、PortTracker、SYN parker
│      ├─ etw.rs  process.rs  dns.rs  conntable.rs
│      ├─ service.rs             # 服务宿主、安装/卸载/恢复策略
│      └─ security.rs            # 管道 DACL、令牌校验、目录 DACL
├─ apps/
│  ├─ cladus-engine/             # bin：service | console | install | uninstall | start | stop | restore-dns | status
│  └─ cladus-gui/                # Tauri 2：src-tauri/ + frontend/（从 Clew 迁移的 Vue 3）
├─ installer/                    # cladus.iss、ChineseSimplified.isl
├─ scripts/                      # bootstrap（WinDivert 固定哈希）、package、test-installer、release.py、check-layering
├─ tests/e2e/                    # 需管理员权限的端到端测试（内置 SOCKS5 测试服务器）
├─ docs/                         # DESIGN.md、ARCHITECTURE.md、TROUBLESHOOTING
└─ reference/                    # 本地参考代码（git 忽略）
```

**依赖方向（CI 检查强制）**：
```
cladus-core ← cladus-net ← cladus-engine ← apps/cladus-engine
     ↑                          ↑                ↑
     └──── cladus-platform-windows ──────────────┘
cladus-ipc ← cladus-engine, apps/cladus-gui
```
- `cladus-core` 禁止依赖 tokio、windows 和任何 IO（可在 Linux CI 上跑单测）。
- `cladus-net` / `cladus-engine` 禁止依赖 `windows` crate。
- 平台代码只出现在 `cladus-platform-*` 和 GUI 的 `cfg(windows)` 模块里。

---

## 6. 平台抽象设计

### 6.1 核心 trait（`cladus-core::platform`）

```rust
/// 跨平台进程身份。instance：Windows=PSN，Linux=starttime，macOS=p_uniqueid
pub struct ProcessKey { pub pid: u32, pub instance: u64 }

pub enum ProcessEvent {
    Started(ProcessInfo),          // 实时启动或 rundown
    Exited(ProcessKey),
    ResyncRequested,               // 已发起 rundown（孤儿宽限起点）
    Lost { count: u32 },           // 事件丢失 → 引擎防抖后请求重同步
}

pub trait ProcessSource: Send + 'static {
    fn start(&mut self, sink: Box<dyn FnMut(ProcessEvent) + Send>) -> Result<()>;
    fn request_resync(&self);
    fn stop(&mut self);
}

pub trait ProcessInspector: Send + Sync + 'static {
    fn live_key(&self, pid: u32) -> Option<ProcessKey>;               // PID 回收校验
    fn lineage(&self, pid: u32, max_depth: usize) -> Vec<ProcessInfo>; // 同步解析祖先链
    fn image_path(&self, key: ProcessKey) -> Option<String>;
    fn cmdline(&self, key: ProcessKey) -> Option<String>;
}

/// 决策入口：两种后端模型都支持
pub trait DecisionOracle: Send + Sync + 'static {
    fn decide(&self, q: FlowQuery) -> Verdict;         // 逐流查询型（Windows WinDivert、macOS NE）
    fn subscribe_assignments(&self) -> AssignmentFeed; // 策略下推型（Linux eBPF map）
}

pub trait TrafficInterceptor: Send + 'static {
    fn start(&mut self, oracle: Arc<dyn DecisionOracle>, sinks: InterceptSinks) -> Result<()>;
    fn stop(&mut self);                                // 必须 fail-open
    fn stats(&self) -> InterceptStats;
}

pub trait SystemDns: Send + Sync + 'static {
    fn capture(&self) -> Result<DnsSnapshot>;          // 平台相关的不透明数据，可序列化进 journal
    fn apply(&self, snap: &DnsSnapshot, listen: &DnsListen) -> Result<()>;
    fn restore(&self, snap: &DnsSnapshot) -> Result<RestoreReport>;
}

pub trait ConnectionTable: Send + Sync { fn list(&self, filter: ConnFilter) -> Vec<ConnInfo>; }
```

服务宿主、IPC 传输、GUI 自启、图标提取不做运行时 trait，按 `cfg(target_os)` 静态选择实现，避免过度抽象。

### 6.2 各平台映射

| 能力 | Windows（阶段 1） | Linux（后续） | macOS（后续） |
|---|---|---|---|
| 进程事件 | ETW Kernel-Process | netlink proc connector 或 eBPF sched tracepoint | kqueue EVFILT_PROC / Endpoint Security（需 entitlement） |
| 进程身份 | PSN | /proc/pid/stat starttime | proc_pidinfo p_uniqueid |
| 截获 | WinDivert 反射（逐流查询） | cgroup v2 + eBPF `cgroup/connect4/6` 改写目的 + map（策略下推），或 nftables TPROXY | NETransparentProxyProvider（逐流查询；需签名、公证、系统扩展批准） |
| 系统 DNS | SetInterfaceDnsSettings + journal | systemd-resolved D-Bus（运行时设置，天然还原） | SCDynamicStore State: 键（运行时设置，天然还原） |
| 特权宿主 | Windows 服务 | systemd unit | launchd daemon + 系统扩展 |
| IPC | Named Pipe + DACL + 令牌校验 | Unix socket + SO_PEERCRED | Unix socket + getpeereid |
| GUI 自启 | HKCU Run | XDG autostart | LaunchAgent |

---

## 7. 引擎内部：线程模型与热路径

```
ETW 线程 ──(bounded, 溢出计数→resync)──┐
IPC 命令(tokio) ──(bounded)───────────┤
SOCKET 查询(TCP/UDP 线程) ─(最高优先)──┤──► 决策核心线程（select_biased!）
定时器(孤儿宽限/丢事件防抖/快照合并)────┘      │ 拥有：ProcessTree, RuleEngine, Policy
                                               ├─► reply（Verdict）
                                               ├─► ArcSwap<Snapshot>（仅有可见订阅者时，≤100ms 合并）
                                               └─► AssignmentFeed
```

- **决策路径**：TCP SOCKET 线程阻塞调用 `oracle.decide(q)`（跨线程一次往返，典型 < 100µs），拿到结果后**自己**写 PortTracker 并释放停车包。PortTracker 和 SYN parking 完全封装在 Windows 后端，核心不知道它们。
- **核心线程的承诺**：单次处理有上界；快照只做 `Arc` 克隆，序列化在 tokio 上执行。
- **NETWORK worker 的承诺**：只调用 `WinDivertRecv/Send` 和原子操作，永不等待核心、锁或 IO。PortTracker 辅助字段全部为原子类型（C++ 版的非原子并发读写在 Rust 中是未定义行为），语义不变：先 relaxed 写，再 release CAS。
- **Assignment 模型**：
  ```rust
  enum Source { Manual, ManualInherited, Rule(RuleId), RuleInherited(RuleId) }
  struct Assignment { source: Source, group: GroupId, protocols: ProtoSet, policy: PolicyId }
  ```
  优先级：手动（含继承）> 自动规则（按配置顺序，名称命中或父进程由同一规则命中）> 直连。排除（按 ProcessKey）作用于该进程及其子树。新进程插入时从父节点 O(1) 继承，规则变更时全量重算。
- **relay**：tokio；组配置从 `ArcSwap<Config>` 无锁读取；连接 / 握手超时；关闭时通过回调让后端执行 `clear_if`。

---

## 8. 技术选型

### 8.1 截获层

| 方案 | 收益 | 风险 / 成本 | 许可证 | 结论 |
|---|---|---|---|---|
| **WinDivert 2.2.2 + 自写 FFI（动态加载）** | 驱动已由作者签名；Clew 已验证；SOCKET 层有 PID | 上游 2022 年后无新版；部分安全软件会标记；所有出站 TCP 经过用户态（worker 必须 fail-open、永不阻塞） | LGPL-3.0 / GPL-2.0 双许可；独立 DLL 运行时加载，主程序 MIT 可行 | **采用** |
| `windivert` / `windivert-sys` crate | 现成绑定 | LGPL-3.0-or-later，会静态编进 Rust 二进制；我们只需约 10 个函数 | LGPL | 不采用 |
| 自研 WFP callout（ALE_CONNECT_REDIRECT） | 技术最佳：直接改 socket 目的，零包操作 | EV 证书 + 微软 attestation 签名 + 驱动维护 | 自有 | 暂不采用；接口已预留 |
| Wintun / TUN + 按进程路由 | 成熟 | 本质全局劫持；需用户态网络栈 | 混合 | 不采用 |
| NDISAPI / Windows Packet Filter | ProxiFyre 在用 | 驱动需单独安装，商业授权受限 | 限制性 | 不采用 |
| DLL 注入 | 精确 | 覆盖面、安全软件、签名周期 | — | 不采用 |

**WinDivert FFI**：只绑定 `WinDivertOpen/Recv/Send/Close/SetParam/Shutdown/HelperCalcChecksums`；包解析由 Rust 实现（含单测）。DLL 用完整路径 `LoadLibraryExW` 加载，失败时给出明确错误。驱动服务由 WinDivert 自己管理，我们不删除名为 “WinDivert” 的驱动服务，以免影响其他软件。

### 8.2 ETW
手写（`windows` crate）：`StartTraceW` + `EnableTraceEx2`（EVENT_ID 过滤 {1,2,15}）+ `CAPTURE_STATE` + BufferCallback 丢失检测 + TDH 字段计划缓存，移植 Clew 约 600 行已验证逻辑。

### 8.3 GUI：Tauri 2 + Vue 3
- 插件：single-instance、autostart（HKCU Run）；窗口几何按 fork 语义自行实现（逻辑尺寸 + 桌面坐标 + 工作区夹紧）。
- 托盘用 Tauri tray API；资源管理器重启后托盘重新注册列入回归清单。
- 无边框窗口 + 自定义标题栏；嵌入 PerMonitorV2 manifest。
- 安全：CSP 锁定，不加载远程内容；capability 只放行自有命令；DevTools 仅 debug 或 `--devtools` 开启。
- 托盘和原生对话框文案与前端共享 `zh-CN.json`；“跟随系统”用 `sys-locale`。
- 备选对比：egui（需重写全部 UI）、iced（生态成熟度）、Slint（许可证不符合纯 MIT 目标，排除）。

### 8.4 其他选型

| 领域 | 选型 | 许可证 |
|---|---|---|
| 异步运行时 | tokio | MIT |
| 核心通道 | crossbeam-channel（`select_biased!`） | MIT/Apache |
| 快照 / 配置发布 | arc-swap | MIT/Apache |
| Win32 | windows | MIT/Apache |
| 服务 | windows-service | MIT/Apache |
| 日志 | tracing + tracing-subscriber（reload）+ 滚动文件 | MIT |
| 配置 | serde + serde_json | MIT/Apache |
| CIDR | ipnet | MIT/Apache |
| 错误 | thiserror / anyhow | MIT/Apache |
| 测试 | proptest；loom（可选） | MIT/Apache |
| 安装器 | Inno Setup（固定哈希版本） | Inno Setup License（宽松） |
| 许可证审计 | cargo-deny + cargo-about；npm 用 license-checker | MIT/Apache |

---

## 9. 可靠性：fail-open 与崩溃恢复

1. **fail-open**：任何致命错误都先关闭 WinDivert 句柄（流量立即恢复直连）。进程被强杀时内核也会释放句柄。
2. **panic 策略**：release 使用 `panic = "abort"`，panic hook 记日志、尽力恢复 DNS 后退出；SCM 恢复策略 5s / 10s / 30s 重启服务，服务启动时根据 journal 恢复 DNS。
3. **看门狗**：NETWORK worker 心跳；有积压但超过阈值无进展 → 关闭句柄并告警。
4. **DNS journal**：先写 journal（fsync + 原子 rename）再改系统；恢复后回读确认一致才删除。触发点：服务启动、Disengage、服务停止、panic hook、卸载、`cladus-engine restore-dns`。
5. **DNS 可用性**：上游经代理连续失败时回退到原 DNS（默认）或严格模式不回退，都在 UI 告警。转发器同时处理 UDP 和 TCP。
6. **ETW 会话残留**：启动时停止 `CladusProcessEtw`；卸载时再清理一次。
7. **配置安全写入**：临时文件 → flush → `ReplaceFileW`，保留 `.bak`；解析失败时拒绝加载并在 UI 报告，绝不静默覆盖。

---

## 10. 安装 / 升级 / 卸载

**安装目录内容**：`cladus.exe`、`cladus-engine.exe`、`WinDivert.dll`、`WinDivert64.sys`、`licenses\*`、`unins000.exe/.dat`。静态 CRT，无需 VC++ redist；前端资源内嵌；WebView2 Runtime 按需安装（Win11 自带）。

**安装 / 升级**：
1. `PrepareToInstall`：若服务已存在，执行 `cladus-engine stop --for-upgrade`（恢复 DNS、关闭 WinDivert），并通知 GUI 退出；检测到 Clew 正在运行则提示先退出 Clew。
2. 复制文件，执行 `cladus-engine install`：创建服务（自动启动、描述、恢复策略、SID 类型）、创建受保护 DACL 的 `%ProgramData%\Cladus`。
3. **首次安装**：创建全新的 Cladus 配置，不执行旧产品迁移或自动导入。
4. `[Run]` 以 `runasoriginaluser` 启动 GUI（非特权）。

**卸载**：
1. `cladus-engine uninstall`：Disengage → 恢复 DNS 并确认 journal 清空 → 清理 ETW 会话 → 停止并删除服务。
2. 清理所有用户配置档的 HKCU Run `Cladus` 值（已加载的 HKU 直接处理；未加载的临时挂载 NTUSER.DAT）。
3. 删除 `%ProgramData%\Cladus\{logs,state}` 和当前用户的 `%LOCALAPPDATA%\Cladus`；**保留** `%ProgramData%\Cladus\config.json` 和 `%APPDATA%\Cladus\ui.json`。交互式卸载提供“同时删除所有设置”复选框，静默卸载默认保留。
4. `WinDivert64.sys` 若仍被占用，重启后删除。

**CI 安装测试**：中文路径下安装 → 服务运行 → 升级（配置保留）→ 卸载 → 断言服务不存在、无 DNS journal、无 Run 值、无 ETW 会话、安装目录已清空、配置仍保留；兼容格式仅支持显式 CLI 导入，不参与安装流程。

---

## 11. CI / Release

- runner：`windows-2022`；Rust 版本固定；Node 24。
- 流水线：fmt → clippy `-D warnings` → 单元测试（core 同时在 Linux 上跑）→ 分层检查 → cargo-deny → 前端 typecheck、构建、Playwright（mock IPC）→ release 构建（`+crt-static`）→ **管理员 e2e**（真实 WinDivert）→ Inno 打包 → 安装 / 升级 / 卸载测试 → 上传产物。
- tag `vX.Y.Z`：全部通过后，由独立 job 发布 `cladus-X.Y.Z-windows-x64-setup.exe` 和 `SHA256SUMS`。
- 版本号唯一来源为 git tag，由 build.rs 注入 exe 版本资源并同步 Tauri 配置。
- 签名：暂不签名；后续可接入 SignPath 开源免费签名。

---

## 12. 测试策略

| 层级 | 内容 |
|---|---|
| core 单测 / 属性测试 | glob 与 cmdline 两种模式（移植 Clew 用例）、树的孤儿 / 墓碑 / PID 回收、Assignment 继承与优先级、排除子树、策略过滤 v4 / v6、Clew v2 配置导入 |
| 后端单测 | PortTracker 全部状态转移、包改写与校验和、TDH 解码、SOCKS5 编解码（IPv6 / 域名 BND / 认证） |
| net 集成测试 | 内置 SOCKS5 测试服务器（TCP + UDP ASSOCIATE），测 relay、UDP 回包源地址、DNS tx_id 重映射和超时 |
| **管理员 e2e（CI 真实 WinDivert）** | 引擎 console 模式运行，规则指向改名后的测试程序；测试程序连接 **TEST-NET 203.0.113.x:80**（不可路由）。测试 SOCKS5 服务器返回固定响应：拿到即证明被截获，失败则超时，**不依赖外网**。覆盖：20 顺序 + 20 并发全新进程；三级继承；规则禁用对照组；UDP；强杀后网络立即恢复；DNS 启用 → 强杀 → 重启服务 → DNS 精确恢复 |
| GUI | 移植 Playwright 本地化测试（mock IPC）；manifest DPI 检查；物理多显示器 DPI 验收清单 |

---

## 13. 分阶段计划

**MVP = P0–P6：功能对等并修复 D1–D15、可发布的 Windows 版本。** 每个阶段都是可运行的纵向切片。

| 阶段 | 内容 | 验收 |
|---|---|---|
| **P0 骨架** | workspace、分层检查、CI（fmt / clippy / test / deny）、WinDivert 固定哈希引导脚本 | CI 绿；cargo-deny 生效 |
| **P1 核心链路** | ETW 进程树 + ProcessKey；规则（名称 / cmdline / 路径）+ 树继承；WinDivert FFI；TCP SOCKET / NETWORK / PortTracker / SYN parking / 反射；acceptor（校验对端）；SOCKS5 TCP relay；不代理自身；全局 CIDR 排除；fail-open。以 `cladus-engine console --config <path>` 运行 | 管理员 e2e：40 个全新进程全部被截获，三级子进程继承成立，对照组直连；停车计数正常；强杀后网络正常 |
| **P2 流量完整性** | UDP；IPv6 防泄漏 → IPv6 反射；完整目的过滤；手动 hijack / 排除；多代理组；连接表；统计 | UDP e2e；UDP-only 规则不影响 TCP（D1） |
| **P3 DNS** | UDP + TCP forwarder、tx_id 重映射、v4 / v6 系统 DNS、journal、接口变化、失败回退 | 强杀 / 重启恢复 e2e |
| **P4 服务化 + IPC** | 服务宿主与子命令、管道协议 v1、访问控制、配置存储、日志、Engage / Disengage、SCM 恢复 | 经服务跑通 P1 e2e；非管理员令牌被拒；强杀服务后自动重启并恢复 DNS |
| **P5 GUI** | Tauri 2 + Vue 迁移、托盘、关闭到托盘、自启 + 最小化启动、语言、HiDPI 与窗口几何、进程图标、选择 exe / 定位 | Playwright 通过；DPI 手工验收；托盘在资源管理器重启后恢复 |
| **P6 安装器与发布** | Inno 脚本、Clew 配置导入、CI 打包与安装测试、第三方声明、release job | tag → Release；安装目录干净；卸载后不残留系统状态 |
| **P7+** | SOCKS5 认证 UI、增量推送、流量统计、无 UI 常驻、代码签名、Linux / macOS 调研 | — |

---

## 14. 风险与对策

| 风险 | 对策 |
|---|---|
| WinDivert 被安全软件拦截或误报 | 文档说明；保留原厂签名；以后可换 WFP 驱动（接口已预留） |
| 服务模型增加复杂度 | P4 单独成阶段；console 与服务共用同一引擎代码；IPC 协议带版本 |
| Tauri 托盘 / 无边框窗口在早期登录、DPI 切换时的边缘行为 | 列入回归清单；必要时自行处理 TaskbarCreated |
| 导入 Clew 配置出错 | 只读源文件；导入逻辑用真实样本单测 |
| 引擎停止期间的 DNS 可用性 | journal + 服务自启恢复 + 失败回退 |
| IPv6 反射复杂度 | 先交付防泄漏，再做完整反射 |
