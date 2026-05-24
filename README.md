# ANAL

**Append-oriented, Narrow-access Language.**

A stack-based, strongly-typed programming language with consent-enforced
destructive operations. Sequential by design. Push-only.

```anal
ANAL "hello" VERSION 1

PUSH "Hello, World!"
EXPEL
```

## Status

v0.1 in development. This is the reference implementation, written in Rust.

## Specification

The complete language specification lives at [`docs/index.html`](docs/index.html)
and will be published at <https://anal-lang.github.io/anal/> when v0.1 ships.

## Install

Binary releases for Linux, macOS, and Windows are published on every tag.
The installer prompts for `CONSENT`, verifies a SHA-256 checksum, then
`INSERT`s `anal` onto your `PATH`.

**Linux / macOS**

```sh
curl -sSf https://github.com/anal-lang/anal/releases/latest/download/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/anal-lang/anal/releases/latest/download/install.ps1 | iex
```

Or grab a tarball directly from the [releases page](https://github.com/anal-lang/anal/releases/latest)
and unpack the `anal` binary onto your `PATH`.

Pin a specific version with `ANAL_VERSION=v0.1.0` (sh) or
`$env:ANAL_VERSION='v0.1.0'` (PowerShell) before piping. Change the
destination with `ANAL_INSTALL_DIR`.

## Contributing

ANAL does not accept pull requests. This is not a bug. All changes flow in
one direction. Patches are submitted by email; significant changes go through
the RFC PASSAGE process. See the [contributing policy](docs/index.html#contributing)
for details.

## Acknowledgements

ANAL was engineered in collaboration with Claude (Anthropic). Push-only
development practices apply to AI contributions as well as human ones — the
model is not granted commit access. Data still enters from one end, in
order, with consent.

## Licence

MIT. See [`LICENSE`](LICENSE).

The specification also references the Push-only Public Licence (PPL). The PPL
is not a real licence. ANAL is licensed under MIT.
