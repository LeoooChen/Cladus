# Development status

Updated 2026-09-28. Windows 0.1.0 is packaged and has passed the local acceptance
suite. Linux/macOS implementation is explicitly deferred. The original design
is in DESIGN.md; this file records the actual implementation and verification.

## Delivered on Windows

- Rust TCP/UDP interception for IPv4 and IPv6, SOCKS5 relay, ordered rules,
  descendant inheritance, destination filters and manual process assignments.
- ETW process tracking, bounded SYN parking, PID reuse handling, single-engine
  ownership, UDP association invalidation on policy changes and stop counters.
- Windows service with idle startup, SCM crash restart, authenticated named-pipe
  control, durable configuration/backup and rotating logs.
- Optional system DNS forwarding over SOCKS5 TCP, UDP/TCP local listeners,
  journaled restoration, interface monitoring, strict mode and direct fallback.
  Reconfiguration discards stale upstream connections before queued requests;
  shutdown cancels child tasks and releases client sockets.
- Tauri/Vue desktop UI, rules/groups/process tree/connections, English/Chinese,
  tray, logon startup, preferences and remembered window geometry. Exit asks the
  service to disengage and reports recovery errors instead of silently exiting.
- Clew v2 importer with validation and warnings; original Clew config is untouched.
- Inno Setup installation/upgrade/uninstall, WebView2 bootstrap, protected install
  directory, fail-safe DNS recovery during uninstall, 396 dependency notices,
  local SHA256SUMS, CI packaging and tag-triggered release workflow.

## Latest local verification

| Check | Result / evidence |
| --- | --- |
| Rust unit tests | **126 passed**, `target/final-unit-tests.log` |
| Formatting, Clippy, layering | Passed; Clippy denies warnings |
| cargo-deny | Advisories, bans, licenses and sources passed; duplicate-version/unmaintained dependency warnings remain advisory |
| Frontend typecheck/build | Passed; Monaco/AG Grid bundle-size warning remains |
| npm audit | Zero vulnerabilities |
| Playwright mocked frontend | **20/20**, Chinese/English persistence, errors, editor, grid and four viewport/device-scale combinations |
| Release WinDivert IPv4/IPv6 | **24/24**, `target/e2e-20260928-110504/acceptance.log` |
| Service/IPC/crash persistence | Passed, `target/service-test-20260928-110652` |
| Real DNS UDP/TCP/system resolver | Passed; 4 proxied answers and no fallback, `target/dns-test-20260928-110711/dns-test.log` |
| DNS normal stop + forced service crash | Exact original settings restored in both cases; SCM restart verified |
| Final installer | **4/4**, `target/installer-test/test.log`: Chinese path, upgrade preserving config, corrupt journal blocks uninstall, normal cleanup |

The routing suite retains all 20 immediate-orphan attempts, 20 sequential new
processes and 20 concurrent new processes. All passed in the latest run, including
63 expected TCP relays and zero active relays/parked SYNs after shutdown. Earlier
intermittent orphan failures remain in historical logs; this pass does not make
bounded, fail-open interception a guarantee against every scheduling delay.

A test-server defect found during closing verification was fixed: it previously
closed after a single partial HTTP read, which could reset the socket and truncate
the reply. It now consumes the full request header before replying. Production
routing assertions and stress counts were not weakened.

Frontend testing initially hit one Vite connection reset with 8 workers; the full
suite passed with 2, which CI now uses. A unit run overlapping installer testing
also suffered local socket failures and one hang; after stopping that test runner,
engine tests and the full workspace suite passed with the installer test finished.
Run system-changing acceptance tests sequentially, separate from unit/UI tests.

The host's existing Clew was not stopped or reconfigured. DNS tests use the
service's explicit test-only coexistence option with no interception rules.
Test services were removed and DNS restored; the final installer was not left
installed as the user's daily proxy.

## Local delivery

- `target/installer/stemma-0.1.0-windows-x64-setup.exe` (7,412,529 bytes)
- `target/installer/SHA256SUMS`
- SHA-256: `e85ce8deab60beeec034e4ebe2503208cc42b98cf8b503b6daee929209471b01`
- Build: `scripts/package-windows.ps1`; usage and recovery: README.md.

## Deferred and release limits

- Linux/macOS interception and desktop support: deferred at the user's request.
  Existing portable boundaries/checks are retained; no new backend work was done.
- Public GitHub release: not published. This checkout has no Git remote; the CI
  workflow and tag-to-release job have not run on hosted runners.
- Stemma executable/installer code signing is not configured.
- Native tray restoration after Explorer restart and physical mixed-DPI monitor
  changes still need manual acceptance. Playwright's mocked browser tests do not
  substitute for those native checks.
- Dedicated SOCKS5 credential controls, incremental GUI updates and further
  telemetry remain future work. JSON credentials work in the engine.
- Fragmented/IPsec traffic is not relayed. Traffic interception is fail-open.
  DNS fallback is direct unless strict mode is selected.
