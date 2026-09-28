# Supplemental dependency licenses

These packages omit license text from their registry archive. The build uses
these copies only for the versions pinned in `scripts/package-licenses.mjs`.
The other dependency notices come directly from the installed locked packages.

| File | Package | Source |
| --- | --- | --- |
| alloc-stdlib.txt | alloc-stdlib 0.3.0 | [LICENSE at package commit](https://github.com/dropbox/rust-alloc-no-stdlib/blob/0a81fd6928ea3b33c8cd484aa4575d50ffb98012/LICENSE) |
| defmt-parser.txt | defmt-parser 1.0.0 | [LICENSE-MIT at package commit](https://github.com/knurling-rs/defmt/blob/4a8cdb44891ed57b8ff5a023b6bec7137c48708f/LICENSE-MIT) |
| tauri-plugin.txt | tauri-plugin 2.7.0 | [LICENSE-MIT at package commit](https://github.com/tauri-apps/tauri/blob/447fa9f3f993fe77724189e355078b38ce20baea/LICENSE-MIT) |
| webview2-rs.txt | webview2-com 0.39.1, webview2-com-macros 0.8.1, webview2-com-sys 0.39.1 | [LICENSE at package commit](https://github.com/wravery/webview2-rs/blob/edc2caf886175ccaebe86078c9cfe1ae2a187328/LICENSE) |
| selectors.txt | selectors 0.38.0 | Standard [MPL 2.0](https://mozilla.org/MPL/2.0/), copied from DOMPurify 3.4.16 LICENSE-MPL; [selectors source header](https://github.com/servo/stylo/blob/572ecba2d1600e7c3d490586692a209faf703baa/selectors/lib.rs) declares MPL 2.0. |

The generated notice links each Rust package's exact crates.io version, which
provides the corresponding unmodified source, including MPL-covered files.
