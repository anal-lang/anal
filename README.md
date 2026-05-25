<div align="center">

<img src="docs/img/logo.png" alt="ANAL — Append-oriented, Narrow-access Language" width="360">

# ANAL

**Append-oriented, Narrow-access Language.**

*A stack-based, strongly-typed programming language with consent-enforced destructive operations.*

[![CI](https://github.com/1xn/anal/actions/workflows/ci.yml/badge.svg)](https://github.com/1xn/anal/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/1xn/anal?label=release)](https://github.com/1xn/anal/releases/latest)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-informational)](LICENSE)
[![Spec: v0.1](https://img.shields.io/badge/spec-v0.1-blue)](https://1xn.github.io/anal/)

> *Push-only by design, consent-enforced by default, append-oriented by conviction.*

</div>

---

```anal
ANAL "consent_dialog" VERSION 1

PUSH 1 PUSH 2 PUSH 3

PUSH "May I FLUSH the stack? (yes / no)" DISCHARGE
RECEIVE PUSH "yes" EQ

IF_TIGHT [
  CONSENT
  FLUSH
  PUSH "Consent given. Stack cleared." DISCHARGE
]
```

ANAL does not destroy without asking. When refused, it leaves things as they were and continues.

---

## When you get it wrong

The interpreter renders mistakes in spec-voice.

<p align="center">
  <img src="docs/img/error.png" alt="TIGHTNESS error rendered by the anal interpreter: squiggle under INSERT, help line, spec-voice note reading 'always prepare. ANAL does not stretch on demand.'" width="640">
</p>

<details>
<summary>Plain-text rendering</summary>

```text
[E001] Error: TIGHTNESS
   ╭─[ examples/bad.anal:7:1 ]
   │
 7 │ INSERT 1 99
   │ ───┬───
   │    ╰──── INSERT attempted without prior PREP
   │
   │ Help: add `PREP` immediately before this line
   │
   │ Note: always prepare. ANAL does not stretch on demand.
───╯
```

</details>

Other errors you can earn: `REFUSAL`, `PREMATURE_RELEASE`, `PENETRATION_DEPTH`, `MISMATCH`. The runtime does not apologise; the checker does not negotiate.

---

## Install

Binary releases for Linux, macOS, and Windows are published on every tag. The installer prompts for `CONSENT`, verifies a SHA-256 checksum, then `INSERT`s `anal` onto your `PATH`.

**Linux / macOS**

```sh
curl -sSf https://github.com/1xn/anal/releases/latest/download/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/1xn/anal/releases/latest/download/install.ps1 | iex
```

Or grab a tarball directly from the [releases page](https://github.com/1xn/anal/releases/latest) and unpack the `anal` binary onto your `PATH`.

Pin a specific version with `ANAL_VERSION=v0.1.1` (sh) or `$env:ANAL_VERSION='v0.1.1'` (PowerShell) before piping. Change the destination with `ANAL_INSTALL_DIR`.

---

## Examples

The [`examples/`](examples/) directory contains the canonical demonstrations. All of them run.

| Program | What it shows |
|---|---|
| [`hello.anal`](examples/hello.anal) | The obligatory greeting. |
| [`consent_dialog.anal`](examples/consent_dialog.anal) | The whole language compressed into one program: ask, then act. |
| [`deep_insert.anal`](examples/deep_insert.anal) | `PREP` / `CONSENT` as one-shot capability tokens. |
| [`countdown.anal`](examples/countdown.anal) | `DILATE` / `CONSTRICT` loops. |
| [`fizzbuzz.anal`](examples/fizzbuzz.anal) | FizzBuzz on a stack with no chained conditionals. |
| [`square.anal`](examples/square.anal) | First-class subroutines via `PASSAGE` / `ENTER` / `EXIT`. |
| [`add_two.anal`](examples/add_two.anal) | Reading from stdin with `RECEIVE`. |
| [`echo.anal`](examples/echo.anal) | The minimal `RECEIVE` / `DISCHARGE` round-trip. |
| [`expand.anal`](examples/expand.anal) | `EXPAND` reserves capacity. Push past it and the runtime raises `OVERFLOW`. |
| [`hold.anal`](examples/hold.anal) | `HOLD <ms>` pauses execution. Bare `HOLD` waits for a `RESUME` line on stdin. |
| [`bad.anal`](examples/bad.anal) | What a `TIGHTNESS` looks like. Run it on purpose. |

Run any of them:

```sh
anal run examples/consent_dialog.anal
```

Or validate without executing:

```sh
anal probe examples/consent_dialog.anal
```

---

## Status

**v0.1 has shipped.** The reference implementation in Rust runs every example in this repository end-to-end. The [language specification](https://1xn.github.io/anal/) documents what the v0.1 interpreter accepts.

What's in v0.1: stack ops (`PUSH`, `POP`, `DUP`, `SWAP`, `DEPTH`, `PROBE`), arithmetic, comparison, control flow (`IF_TIGHT`, `IF_LOOSE`, `DILATE`/`CONSTRICT`, `ABORT`), I/O (`EXPEL`, `DISCHARGE`, `RECEIVE`, `INGEST`, `EVACUATE`), the consent state machine (`PREP`, `CONSENT`, `RELAX`, `INSERT`, `EXTRACT`, `FLUSH`, `CLENCH`/`RELEASE`), subroutines (`PASSAGE`/`ENTER`/`EXIT`), `BLOC` as a first-class value, capacity management (`EXPAND` with real `OVERFLOW`), pause/resume signalling (`HOLD` / `RESUME`), and ariadne-rendered diagnostics.

**v0.2 in progress.** A static type checker runs between parse and execute, surfacing type errors as `MISMATCH` (E013) at probe time. Programs that would have raised `REJECTION` at runtime now fail to compile, with the same span. `ADD` on two `STRING`s now concatenates, per spec §7. PASSAGE bodies are re-checked at every call site, giving simple ad-hoc polymorphism (`PASSAGE square: DUP MUL EXIT` works on both `INT` and `FLOAT`) without generics.

What is not in v0.2 yet: a module system, FFI, a REPL, or any form of concurrency.

---

## Milestones

- **v0.1** ✓ shipped — reference interpreter, full spec coverage of the core ops, install pipeline.
- **v0.2** — in progress. Static type checker landed (this release); module system still ahead.
- **v1.0** — `analc`, the self-hosted compiler. ANAL compiling ANAL into `.sph` bytecode.
- **Ecosystem** — `suppository`, the package manager, and `registry.sph`, the registry it talks to. Both fully spec'd at [§9](https://1xn.github.io/anal/#suppository); neither shipped.

No timelines. ANAL does not rush.

---

## Prior art

Influenced by Forth (stack semantics), INTERCAL (institutional voice), and a misreading of a 2014 Hacker News comment.

---

## FAQ

**Is this a joke?**
The name is. The interpreter isn't.

**Should I use this in production?**
ANAL has no concurrency model, no module system, no FFI, and a sub-1000-line spec. The question answers itself.

**Why does the language enforce consent?**
Because destructive operations are destructive. The metaphor is juvenile; the underlying claim — that data loss should not be silent — is not.

**Will you add async / generics / a borrow checker / pattern matching?**
Proposals go through the RFC PASSAGE process. The PASSAGE process typically takes 6–18 months. ANAL does not rush.

**Why is the error rendering so polite?**
It isn't. It is precise. Politeness and precision are easily confused.

**Can I write a linter / formatter / language server?**
Yes. The reference grammar is in the [specification](https://1xn.github.io/anal/); the lexer and parser live in [`crates/anal-core`](crates/anal-core). Tooling is welcome. It still cannot be submitted as a pull request.

**Will the compiler ever be written in ANAL itself?**
That is the eventual goal — a self-hosted `analc` that emits `.sph` bytecode. Until then, the reference compiler is Rust and reserves the [`ast`](crates/anal-core/src/ast.rs) and [`compiler`](crates/anal-core/src/compiler.rs) namespaces for the bootstrap.

---

## Contributing

ANAL does not accept pull requests. This is not a bug. All changes flow in one direction.

- **Pull requests** are closed automatically on arrival. The rejection is polite. The closure is not negotiable.
- **Patches** are submitted by email.
- **Significant changes** go through the **RFC PASSAGE** process. RFCs are PUSHed to the repository; the core team PROBEs them, deliberates, and either INSERTs them into the roadmap or EXTRACTs them with a written explanation. Acceptance requires CONSENT of a majority of core maintainers.

The PASSAGE process typically takes 6–18 months. ANAL does not rush.

---

## Acknowledgements

ANAL was engineered in tight collaboration with Claude (Anthropic). The model proposes patches; the maintainer `INSERT`s them. The maintainer reserves the right to `RELAX` and rewrite history. The model does not.

---

## Licence

MIT. See [`LICENSE`](LICENSE).

The specification also references the Push-only Public Licence (PPL). The PPL is not a real licence. ANAL is licensed under MIT.

---

<div align="center">

*Data arrives. In order. With consent.*

</div>
