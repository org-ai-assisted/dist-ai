# stcat-family tests

Comprehensive test + fuzz for the **stcat family** -- the helper-scripts
`stdisplay`-package CLI tools that make untrusted text safe to print to a
terminal: `stcat`, `stcatn`, `stecho`, `stprint`, `stsponge`, `sttee`.

## Threat model

Each tool reads untrusted input (stdin, a file, or argv) and writes it to a
terminal (and, for `stsponge`/`sttee`, to a file). The output must not smuggle
anything dangerous to the terminal: no non-ASCII / Unicode (RLO, zero-width,
homoglyphs, C1, line/paragraph separators), no control characters other than
newline and tab, and no escape sequences other than colour (SGR) -- and SGR
only when colour is enabled. Each tool applies two layers: it routes input
through `stdisplay()` and forces its stdout (and file outputs) to ASCII with
`errors="replace"`.

## Checks

- **[U] no-colour** (`NO_COLOR=1`, i.e. `stdisplay` `sgr=-1`): output is pure
  printable ASCII plus newline/tab -- no Unicode, no control char, no ESC, no
  DEL -- over a hostile corpus and a byte-level fuzzer.
- **[C] colour** (`COLORTERM=truecolor`): Unicode is still stripped, and the
  only escapes that survive are well-formed SGR (`ESC [ ... m`); non-SGR
  escapes (OSC-8 hyperlinks, CSI cursor/clear) are neutralised. Also asserts
  SGR colour is *not* over-stripped.
- **[S] semantics**: on benign input each tool still does its job -- `stcat`
  (passthrough), `stcatn` (trim trailing whitespace + ensure final newline),
  `stecho` (space-joined + newline), `stprint` (concatenated, no newline),
  `stsponge` / `sttee` (stdin to stdout/file) -- including file paths, whose
  written content is also verified sanitised.
- **[F] fuzz**: random byte streams (Unicode, control, escapes, malformed
  UTF-8, NUL) never break the [U] invariant.

No root, no network.

## Running

```
stcat-family-tests                       # corpus + colour + semantics + fuzz
stcat-family-tests --iterations 1000 --seed 7
stcat-family-tests-fuzz                  # heavy fuzz sweep

# test a checkout instead of the installed tools
STDISPLAY_REPO=/path/to/helper-scripts stcat-family-tests
```

The tools are resolved from `STDISPLAY_REPO` (a helper-scripts checkout, run
via the Python module) else the installed `/usr/bin/<tool>`.
