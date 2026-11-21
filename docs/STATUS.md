# Cladus verification status

## Windows 0.1.4 — 2026-11-11

- Added bounded IPv6 TLS handshake fallback with DNS identity verification and
  preservation of each flow's destination policy. Established streams are never
  replayed. The original transfer error is retained and fallback is observable.
- Rust workspace: 140 passed, one existing opt-in network test ignored.
- Frontend production build and 36 Playwright checks passed at four display
  scales. Clippy with denied warnings, formatting and layering checks passed.
- DOMPurify, source-map-js and Vite received compatible security patch updates;
  npm audit reports zero vulnerabilities. Frontend checks passed again afterward.
- Isolated live TLS probe returned HTTP 200 on a healthy IPv6 path without
  fallback. A test-owned IPv6 EOF shim followed by the real IPv4 upstream also
  returned HTTP 200, with one recorded fallback and no failure.
- No active-service restart or destructive service/installer tests were used for
  these checks. This does not establish that all remote API stream resets are
  fixed. See [the detailed report](diagnostics/2026-11-11-fallback.md).
- Final installer: `target/installer/cladus-0.1.4-windows-x64-setup.exe`,
  7,648,651 bytes. SHA-256:
  `3a4cea3186b4405cde797106a6e5a3313893f0fc1a03a4a1cf35f302d6987856`.
  Checksum verified. The active installation remains 0.1.3 pending a service
  restart; the separate Magpie process rule has already been applied live.

## Previous release verification

Updated 2026-09-28 for Windows 0.1.3. Linux/macOS implementation remains deferred.

## Product identity

| Component | Name |
| --- | --- |
| Desktop / executable | Cladus / `cladus.exe` |
| Engine executable | `cladus-engine.exe` |
| Windows service / IPC pipe | `CladusEngine` / `\\.\pipe\CladusEngine` |
| ETW session / engine mutex | `CladusProcessEtw` / `Global\CladusEngine` |
| Desktop application ID | `io.github.leooochen.cladus` |
| Installer AppId | `{A931F2F9-36B8-4C52-9C9B-76AC7B86E1A3}` |
| Data / UI / cache | `%ProgramData%\Cladus`, `%APPDATA%\Cladus`, `%LOCALAPPDATA%\Cladus` |
| Logon startup value | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Cladus` |
| Environment variables | `CLADUS_LOG`, `CLADUS_TEST_PROXY`, `CLADUS_TEST_URL` |
| Source applications | `apps/cladus-engine`, `apps/cladus-gui` |
| Source libraries | `cladus-core`, `cladus-ipc`, `cladus-platform-windows` |

The repository is now at `D:\Document\Claude项目\Cladus`. The previous workspace
location is an empty directory still held open by the current desktop chat.
Open the new directory for subsequent project work.

## Installation scope

This is a fresh, independent installation. It does not migrate another product,
look for its installation, or automatically import its configuration. Setup starts
an idle service with the default SOCKS5 endpoint `127.0.0.1:7890`, no process rules,
and DNS proxy disabled. Users configure their own endpoint and rules after setup.
Explicit CLI `import-config` remains an optional manual operation.

## Verification

- Rust workspace: 131 passed, one opt-in live-network test ignored by default;
  log: `target/cladus-tests.log`.
- Frontend typecheck/build and all 28 Playwright checks passed under the renamed
  application paths, including four viewport/device-scale combinations.
- Clippy with warnings denied, formatting and platform-boundary checks passed.
- Dependency policy checks passed against the locally cached advisory database.
  Refreshing the database failed with a network connection reset; no dependency
  versions were changed by this rename.
- Tracked file contents and paths have no previous product-name references.
  Frontend production assets were checked independently as well.

- Service acceptance passed: authenticated IPC, configuration persistence, SCM
  crash recovery and removal; `target/service-test-20260928-134435`.
- Installer acceptance: all five checks passed in `target/installer-test/test.log`:
  Chinese-path installation, fresh default settings without automatic import,
  upgrade preserving Cladus configuration, corrupt DNS journal blocking uninstall,
  and clean uninstall preserving configuration. Test-owned settings were then
  removed so a later real installation starts fresh.
- Packaged executable reports `cladus-engine 0.1.3`; GUI file metadata identifies
  the product as Cladus. The new installer checksum was verified.

## Delivery

`target/installer/cladus-0.1.3-windows-x64-setup.exe` (7,625,745 bytes).
SHA-256: `1e274879028d316e2474bbd381debf4e8be400096cb940d32295df7f1902ca45`.
The matching `SHA256SUMS` is in the same directory. This is a fresh installation;
configure the proxy endpoint and process rules after installing.

## Usage and remaining limits

- Keep overlapping traffic interception/TUN disabled. Keep the upstream SOCKS5
  listener running. Use DNS proxy where system DNS gives incorrect addresses;
  restart affected browsers after changing DNS to clear old cached addresses.
- Proxy connection lights check SOCKS5/authentication only. Website tests measure
  real HTTP response headers, including TLS, with proxy-side target DNS.
- The TCP accept loop is asynchronous and cancellable; exiting does not rely on
  creating a loopback wakeup connection.
- Fragmented/IPsec traffic is not relayed. Interception is fail-open; DNS falls
  back to original resolvers unless strict mode is selected.
- Code signing is not configured. Native tray
  recovery after Explorer restart and physical mixed-DPI monitor changes still
  require manual acceptance; browser mocks do not establish those results.
