# stdisplay tests

Comprehensive test + fuzz for **`stdisplay()`** -- the helper-scripts
`stdisplay`-package function that sanitizes untrusted text to be safe to print to
a terminal. It is the security core that the whole `stcat` family (`stcat`,
`stcatn`, `stecho`, `stprint`, `stsponge`, `sttee`) routes its input through.

## Why a separate suite from `stcat-family-tests`

`stcat-family-tests` drives the six CLIs and only exercises `stdisplay()` at two
colour settings (`NO_COLOR`, i.e. `sgr=-1`, and `COLORTERM=truecolor`, i.e.
`sgr=2**24`). The bug-prone part of `stdisplay` lives *in between*:
`get_sgr_pattern()` builds a graded allow-list regex whose behaviour changes at
every colour depth (3-bit, 4-bit, 8-bit, 24-bit), plus an `exclude_sgr`
negative-lookahead, plus the `get_sgr_support()` environment logic. This suite
tests the **function directly**, across **every** colour depth, and is
intentionally exhaustive -- which is why it lives in dist-ai rather than as a
basic test in helper-scripts.

## Security contract

`stdisplay(untrusted_text, sgr, exclude_sgr) -> str`. The output must be safe to
write to a terminal: the **only** escape sequences that may survive are Select
Graphic Rendition (SGR, `ESC [ ... m`) colour/attribute codes -- and only those
the colour depth allows and `exclude_sgr` does not remove. Everything else --
every non-ASCII character, every control character other than newline and tab,
DEL, and every non-SGR escape (cursor movement, screen clear, device-status
*report* -- an input-injection vector -- OSC title / OSC-8 hyperlink, DCS/APC/PM,
single-byte C1 CSI/OSC, RIS reset, charset selection) -- is replaced with an
underscore.

## Independent safety oracle

Any `ESC [ <params> m` is, by definition, an SGR sequence (`m` is the SGR final
byte); SGR can only set colour/attributes -- never move the cursor, clear the
screen, report, or set the title. So terminal-safety is exactly: strip every
loose `\x1b\[[0-9;:]*m`, then forbid any remaining ESC or any character that is
not printable ASCII / newline / tab. This loose grammar is hand-written and does
**not** validate palette ranges or separator consistency, so it is genuinely
independent of the tool's own regex -- yet it is sound, because it permits
exactly the SGR class and flags everything that could inject.

## Checks

- **[P] pins**: the module's own docstring examples (`stdisplay`,
  `exclude_pattern`, `get_sgr_pattern`) as exact-string regression pins.
- **[B] benign**: printable ASCII / newline / tab pass through **unchanged** at
  every colour depth -- proves the sanitizer does not over-redact.
- **[G] graded**: a matrix of one representative sequence per SGR bit-mode
  (3-bit fg/bg/reset, 4-bit bright, 8-bit indexed with `;` and `:` separators,
  24-bit) against every colour depth, asserting each survives verbatim exactly
  when its depth is enabled and is redacted (`ESC -> _`) otherwise.
- **[R] redaction**: a corpus of dangerous non-SGR escapes (clear, cursor, DSR /
  DA reports, OSC title, OSC-8, DCS/APC/PM, RIS, charset), single-byte C1
  controls, C0 controls / NUL / DEL, and non-ASCII (bidi Trojan-Source,
  zero-width, BOM, homoglyph, line/paragraph separators) is neutralised at
  **every** colour depth, including truecolor.
- **[X] exclude**: `exclude_sgr` removes a code the depth would otherwise allow
  while leaving the others intact, and the output stays safe.
- **[E] env**: `get_sgr_support()` -- `NO_COLOR` (any non-empty disables; empty
  does **not**), `COLORTERM` `truecolor`/`24bit` (case-insensitive), `NO_COLOR`
  precedence, and the `TERM`/curses path fails **closed** (`< 8`, no escapes) on
  an unknown or dumb terminal (probed in a subprocess, since `setupterm()` is
  process-global).
- **[I] idempotence**: `stdisplay(stdisplay(x)) == stdisplay(x)` over the corpus.
- **[F] fuzz**: random Unicode, an escape-biased byte pool (the smuggling
  channel, heavy on `ESC` and the bytes that build CSI/OSC/DCS), and random
  `exclude_sgr` lists never raise, never break the safety oracle, and stay
  idempotent -- at every colour depth.

No root, no network. The test source is ASCII-only: every control / non-ASCII
character is written as a Python escape.

## Running

```
stdisplay-tests                          # pins + benign + graded + redaction +
                                         # exclude + env + idempotence + fuzz
stdisplay-tests --iterations 1000 --seed 7
stdisplay-tests-fuzz                     # heavy fuzz sweep

# test a checkout instead of the installed package
STDISPLAY_REPO=/path/to/helper-scripts stdisplay-tests
```

The function is resolved from `STDISPLAY_REPO` (a helper-scripts checkout) else
the installed `stdisplay` package.
