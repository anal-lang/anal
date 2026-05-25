# vscode-anal

Syntax highlighting and language configuration for the ANAL programming language in Visual Studio Code.

## Features

- Syntax highlighting for every op in the v0.3 spec: stack, control, consent, I/O, storage, arithmetic, comparison, conversion.
- Distinct scope for the consent vocabulary (`PREP`, `CONSENT`, `CLENCH`, `RELEASE`, `RELAX`) so it stands out visually — these are the ops that gate destructive operations and the highlighting reflects that.
- Distinct scope for `PASSAGE` declarations and `ENTER <name>` calls, so subroutine names look like function names.
- Line comments (`;` to end of line), auto-closing brackets and string quotes, indentation rules for `DILATE`/`CONSTRICT` and `PASSAGE`/`EXIT`.

## Install (development)

From the repository root:

```sh
code --install-extension tools/vscode-anal
```

Or open `tools/vscode-anal/` in VS Code and press F5 to launch an Extension Development Host with the extension loaded.

To open an ANAL file:

```sh
code examples/collatz.anal
```

The file extension `.anal` is registered automatically.

## Scopes

The grammar maps each token class to a distinct TextMate scope so themes can colour them independently:

| Op class | Scope | Examples |
|---|---|---|
| Header | `keyword.declaration.anal` | `ANAL`, `VERSION`, `INGEST` |
| Control flow | `keyword.control.anal` | `DILATE`, `IF_TIGHT`, `PASSAGE`, `EXIT` |
| Consent ceremony | `storage.modifier.consent.anal` | `PREP`, `CONSENT`, `CLENCH`, `RELEASE`, `RELAX` |
| Stack ops | `keyword.operator.stack.anal` | `PUSH`, `DUP`, `OVER`, `ROT`, `NIP` |
| Arithmetic | `keyword.operator.arithmetic.anal` | `ADD`, `SUB`, `MUL`, `DIV`, `MOD` |
| Comparison | `keyword.operator.comparison.anal` | `EQ`, `LT`, `GT`, `NOT` |
| Conversion | `keyword.operator.conversion.anal` | `TO_INT`, `TO_FLOAT`, `TO_STRING` |
| I/O | `support.function.io.anal` | `RECEIVE`, `EXPEL`, `DISCHARGE` |
| Storage (CAVITY) | `support.function.storage.anal` | `BUFFER`, `BUFGET`, `STORE`, `LOAD` |
| String inspection | `support.function.string.anal` | `STRLEN`, `CHARAT`, `SUBSTR` |
| Booleans | `constant.language.anal` | `TRUE`, `FALSE` |
| Strings | `string.quoted.double.anal` | `"hello"` |
| Numbers | `constant.numeric.{integer,float}.anal` | `42`, `3.14` |
| Comments | `comment.line.semicolon.anal` | `; this is a comment` |
| PASSAGE names | `entity.name.function.anal` | the `square` in `PASSAGE square:` |

## Status

v0.1.0 — TextMate grammar only. A language server (LSP) integration with the reference type checker is on the roadmap; not in this release.

## Licence

MIT, matching the language repository.
