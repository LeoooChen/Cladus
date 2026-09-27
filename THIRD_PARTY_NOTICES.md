# Third-Party Notices

## Clew

Stemma's design and interception algorithms are derived from
[Clew](https://github.com/LeoooChen/clew-proxy), an MIT-licensed project.
The reference checkout used for this rewrite is identified in `docs/DESIGN.md`.
Its copyright and permission notice is reproduced below.

Copyright (c) 2026 ymonster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## WinDivert 2.2.2

Upstream: https://github.com/basil00/WinDivert

Stemma loads the unmodified WinDivert DLL at runtime. It does not compile a
WinDivert Rust binding into the application. The bootstrap script retrieves
the hash-pinned official binary archive, including its full `LICENSE` file.
Distributions must include that license alongside the DLL and driver.
WinDivert is available under LGPL-3.0 or GPL-2.0; see the upstream license
for the complete terms and corresponding source.

## Rust Dependencies

Rust dependencies retain their respective licenses. `deny.toml` defines the
allowed-license policy and CI checks it with `cargo-deny`. Complete release
attributions will accompany packaged builds.
