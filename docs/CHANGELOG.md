# Changelog

## 0.1.3 — 2026-09-28

- Name the product Cladus throughout the workspace, crates, executable names,
  desktop identity, Windows service, IPC pipe, ETW session, mutexes, environment
  variables, configuration directories, installer, shortcuts and documentation.
- Use a new installer AppId and fresh Cladus settings. No old-product migration
  or automatic configuration import is performed during installation.

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
