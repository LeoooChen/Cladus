# Development Status

Updated 2026-09-27. The user prioritizes Windows service, DNS and GUI.
Cross-platform implementation/extra verification is deferred until those work.

## Verified Baseline

- Existing P1/P2 code was preserved and extended, not reset.
- 98 unit tests passed before adding the IPC crate.
- Windows Clippy passed with warnings denied.
- Release WinDivert acceptance passed 23/23 with 5 immediate-orphan attempts:
  `C:\Users\CC\AppData\Local\Temp\stemma-e2e-12896-1790509671089131100`.
- IPv4/IPv6 TCP and UDP, multiple UDP peers, connected UDP, 4 KB datagrams,
  destination filters, protocol isolation, stop/kill/restart were tested.
- The host's existing Clew process was not stopped or reconfigured.
- A Linux cross-target check passed; this does not implement a Linux backend.

## Active Work

1. Windows service, secure named-pipe IPC, persistent configuration and logs.
2. DNS forwarding, durable recovery journal, service recovery.
3. GUI using the existing Vue frontend and a Tauri host.
4. Packaging, full regression and remaining routing reliability fixes.
5. Other platforms only after Windows is usable.

## Remaining Routing Issues

- Expanded immediate-orphan stress (20 attempts) passed 19/20 on the latest
  run. The first connection of an extremely short-lived launcher's child can
  still race ETW delivery. Keep the 20-attempt test; do not weaken it.
  Logs: `C:\Users\CC\AppData\Local\Temp\stemma-e2e-39556-1790509905060442000`.
- Reconfiguration must invalidate cached UDP decisions when service commands
  expose rule/manual changes.
- Counters on cancellation and the final parking snapshot need shutdown
  coverage. Unsupported fragmented/IPsec traffic is not relayed.
- The new single-instance guard passed its real acceptance check.

## Tooling

- `scripts/test-windows.ps1 -Release -IPv6` builds, elevates a hidden test
  runner, and records output under `target/e2e-*`.
- `cargo-deny` installed successfully. Advisories, licenses and sources passed.
  Internal path dependencies lacked version constraints; constraints have now
  been added but the complete audit needs rerunning.
- CI added but not run remotely. No commits or pushes were made.
- `cargo fmt` was applied to normalize the previously unformatted baseline.
