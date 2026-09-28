# Changelog

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
