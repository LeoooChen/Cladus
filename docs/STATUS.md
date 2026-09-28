# Development status

Updated 2026-09-28. The 0.1.0 baseline is recorded below; see the final section
for 0.1.1 repairs and current verification. Linux/macOS is explicitly deferred. The original design
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

## 0.1.1 repair verification (2026-09-28)

- Reproduced the installed service stuck in TCP accept during Disengage. An
  explicit connection to its redirect listener immediately released shutdown,
  confirming that relying on a loopback wakeup could leave the service hanging.
  The implementation now cancels an asynchronous accept with a oneshot signal.
- The old website probe stopped after SOCKS5 CONNECT. The replacement waits for
  real HTTP response headers, verifies TLS, uses proxy-side target DNS and has
  a total timeout. The independent signal light checks only SOCKS5/authentication.
- 131 default Rust tests passed; 28 Playwright tests passed, including delayed
  stale health responses after saving new proxy settings. Clippy and dependency
  audit passed. An additional opt-in live test reached Google through the user's
  SOCKS5 endpoint and measured 222 ms including TLS.
- Local DNS + SOCKS5 failed Google's TLS handshake, while proxy-side domain
  resolution returned HTTP 200. The installed config had DNS proxy disabled;
  users in this situation should enable DNS proxy and restart affected browsers
  to clear cached DNS/connections. This is separate from SOCKS5 reachability.
- Browser automation is unavailable for the user's Edge session. Native Edge
  acceptance must not be inferred from the mocked frontend or HTTP client tests.
- The old installed service was recovered and GUI exited normally. Installation
  of the new build and post-upgrade native acceptance remain separate steps.

See CHANGELOG.md for 0.1.1 changes. The 0.1.0 evidence above is historical.

0.1.1 local package: `target/installer/stemma-0.1.1-windows-x64-setup.exe`,
7,625,515 bytes. SHA-256:
`14ab9c4a5f679ca30133e2973374bc42397e8fa50dbeda9ba25c0fe96dc59c54`.

### Installed 0.1.1 follow-up

The user installed 0.1.1. Edge and its descendants were assigned to the correct
rule, but the preserved configuration still had DNS proxy disabled. The local
router returned `2001::1` / `185.45.5.35` for Google, while Mihomo TUN supplied
synthetic IPv4 addresses. After the user's explicit approval, DNS proxy was
enabled and the original configuration backed up under `%ProgramData%/Stemma`.
Direct forwarder queries returned Google's actual IPv4/IPv6 addresses.

A temporary, narrowly matched curl test process using the correct Google IP
still timed out with TUN on: 2 proxy decisions, 0 accepted connections, 0 relays.
The redirect listener itself remained responsive. After the user disabled TUN,
the same test using ordinary system DNS succeeded for both families: IPv4 HTTP
200 (427 ms), IPv6 HTTP 302 (363 ms), with exactly 2 decisions, 2 accepted
connections, 2 relays and 2 proxied DNS queries. No direct SOCKS proxy option was
used for those requests: they actually traversed Stemma's WinDivert path.

Temporary diagnostic rules were removed; the user's Edge rule and proxy endpoint
were preserved. DNS proxy remains enabled. This verifies the installed data path
without TUN; it does not establish compatibility with simultaneous Mihomo TUN.
