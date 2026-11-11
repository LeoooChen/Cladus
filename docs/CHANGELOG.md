# Changelog

## 0.1.4 — 2026-11-11

- Add bounded IPv6-to-IPv4 fallback for TLS connections on port 443, enabled by
  default and configurable in Settings or `tcp_ipv6_fallback`. Only an intact
  ClientHello without early data/ECH can be retried, before any server response.
- Verify the original IPv6 address and candidate IPv4 addresses against the
  ClientHello hostname using DNS over the same SOCKS5 proxy. Preserve each
  connection's destination policy when considering an alternate address.
- Keep healthy IPv6 connections, system DNS answers and established streams
  unchanged. Log the original failure and track fallback attempts, selections
  and failures. Do not retry mid-stream POSTs or replay application data.
- Update DOMPurify to 3.4.17, source-map-js to 1.2.2 and Vite to 7.3.8 to resolve
  the existing frontend dependency advisories. No other npm packages changed.

- Preserve TCP tunnel read/write errors after SOCKS5 negotiation. Previously,
  connection resets were converted to a successful `(0, 0)` result, omitted
  from `relay.failed` and logged as a finished relay. Clean EOF and half-close
  remain normal completion. This improves error reporting; it does not restore
  connectivity on an upstream proxy with a failing IPv6 path.

## 0.1.3 — 2026-09-28

- Name the product Cladus throughout the workspace, crates, executable names,
  desktop identity, Windows service, IPC pipe, ETW session, mutexes, environment
  variables, configuration directories, installer, shortcuts and documentation.
- Use a new installer AppId and fresh Cladus settings. No old-product migration
  or automatic configuration import is performed during installation.
- Allow up to 150 ms for a new TCP connection's process decision before the
  fail-open SYN watchdog releases it directly on slower Windows hosts.
- Open a temporary program-and-port-scoped Windows Firewall rule for the
  internal TCP redirect listener; remove it on stop or service recovery.

## 0.1.2 — 2026-09-28

- Remove old-project branding and repository links from the About section.
- Use product-neutral wording for installer import options, conflict messages,
  CLI help and import results. The public import command is now `import-config`;
  its previous spelling remains accepted for existing scripts.
- Preserve compatibility detection/import behavior and required third-party
  copyright and license notices.

## 0.1.1 — 2026-09-28

- Fix service shutdown hanging on a blocking TCP accept after its loopback
  wakeup connection failed. The accept loop now uses Tokio and an independent
  cancellation signal, without polling or a network wakeup.
- Measure real HTTP response-header latency through SOCKS5, including TLS for
  HTTPS. Resolve website names through the proxy, validate certificates, report
  HTTP failures and apply a total timeout; a local SOCKS handshake no longer
  counts as successful website access.
- Add independent proxy connection lights beside proxy addresses. Check
  SOCKS5/authentication on tab opening and after saves, limit concurrent checks,
  discard stale responses and show failure details. Website tests remain separate.
- Keep proxy network checks asynchronous and cancellable during IPC shutdown;
  limit them so control requests retain capacity. Preserve GUI status observation
  after a failed exit attempt.
- Add CLI `test-proxy --group <id>` for reproducing website tests.

## 0.1.0

Initial packaged Windows implementation. Historical acceptance details are in
STATUS.md.
