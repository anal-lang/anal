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

Not yet available. v0.1 will ship as binary releases for Linux, macOS, and
Windows on tag.

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
