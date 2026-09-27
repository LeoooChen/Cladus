# Stemma

Windows per-process TCP/UDP proxying in Rust, without TUN or DLL injection.
Rules follow a process's descendants, including children that outlive their
launcher. Traffic is redirected with WinDivert to a SOCKS5 server.

This repository is under active development. The console engine works;
the service, GUI, DNS management, Clew configuration importer and installer
are not delivered yet. The full product plan is in [docs/DESIGN.md](docs/DESIGN.md).

## Build And Run

Windows x64, Rust (the version in `rust-toolchain.toml`), and the MSVC C++
build tools are required. Runtime interception requires administrator rights.

```powershell
.\scripts\bootstrap-windows.ps1
cargo build --release --workspace
.\target\release\stemma-engine.exe console `
  --config .\examples\antigravity.json `
  --windivert-dir .\third_party\windivert
```

The example uses the SOCKS5 endpoint `127.0.0.1:7890`. Set its port and host to
your actual proxy. It must support UDP ASSOCIATE to relay UDP. Do not enable
overlapping Clew and Stemma rules for the same programs. Stop with Ctrl+C;
the engine closes interception handles and subsequent connections go direct.
Existing proxied TCP connections cannot survive an engine stop.

## Configuration

The current console schema is version 1. Missing fields use defaults; unknown
fields and invalid group references are rejected. This is not yet the Clew
v2 importer described in the design.

- `proxy_groups`: SOCKS5 endpoints, optional `username` and `password`.
- `rules`: ordered name wildcards, optional command-line and image-path
  conditions, a `proxy_group_id`, and `protocol` (`tcp`, `udp`, or `both`).
- `dst_filter`: rule-local `include_cidrs`, `exclude_cidrs`,
  `include_ports`, `exclude_ports`. Port ranges are strings, e.g. `"8000-8100"`.
- `global_exclude_cidrs`: private IPv4 networks are excluded by default.
  Loopback, link-local, multicast and broadcast destinations are always direct.
- `tcp_syn_parking`: bounded first-packet parking, enabled by default.
- `log_level`: `trace`, `debug`, `info`, `warn`, or `error`.

IPv4 and IPv6 TCP/UDP are supported. Rules select processes, not just the
initial executable: an earlier matching/inherited rule takes precedence.
Manual assignments and exclusions currently exist in the core API only.
Changing a console configuration requires restarting the engine.

System DNS is not modified by this build. DNS performed by a separate system
resolver process is not automatically attributed to the requesting application.
Unsupported fragmented/IPsec traffic is not currently relayed. This engine
is an application-routing tool, not a fail-closed anonymity boundary.

## Verify

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
.\scripts\check-layering.ps1
.\scripts\test-windows.ps1 -Release -IPv6
```

Omit `-IPv6` on machines without an IPv6 route. The test script requests
elevation when needed, runs hidden, and saves output under `target/e2e-*`.
Detailed engine logs are in the temporary directory named in that output.
Tests use a local SOCKS5 server and documentation-only destination addresses,
not a public proxy. Failed tests clean up their engine process.

Cross-platform domain logic lives in `stemma-core`; Windows APIs and
interception stay in `stemma-platform-windows`. Linux/macOS interception
backends have not been implemented.

## License

Stemma is MIT licensed. WinDivert is an independent, dynamically loaded
component with its own license. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
