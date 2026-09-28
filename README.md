# Cladus

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
