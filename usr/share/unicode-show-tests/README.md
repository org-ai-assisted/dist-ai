# unicode-show tests

Comprehensive test + fuzz for **unicode-show** -- the helper-scripts
`unicode_show`-package scanner that **detects** non-ASCII / suspicious Unicode in
text or files. It is the mirror image of the `stcat` family: `stcat` *sanitizes*
untrusted text for a terminal, `unicode-show` *reports* the dangerous characters
instead.

## Contract

- exit `0`: input is clean (only visible ASCII plus newline/tab, ending in a
  newline).
- exit `1`: at least one suspicious character was found (non-ASCII, a control
  char other than newline/tab, DEL, trailing whitespace, or -- unless suppressed
  -- a missing final newline).
- exit `2`: error, e.g. the input is not valid UTF-8 or a file cannot be read.
  Decoding is strict (`errors="strict"`, never `"replace"`), so a non-UTF-8 byte
  fails closed rather than being silently mangled and slipped past.

## Checks

- **[D] detection**: for a hostile corpus (RLO / bidi Trojan-Source set,
  zero-width, BOM, homoglyph, combining, C1, line/paragraph separators, CJK,
  emoji, and C0 control bytes / NUL / DEL) the tool exits `1` and names the
  exact codepoint (e.g. `U+202E`) it found -- proving it flagged *that*
  character, not merely something.
- **[S] self-safety**: `unicode-show` itself writes to a terminal, so its own
  stdout must never leak the raw suspicious bytes it is reporting. Over the whole
  corpus and the fuzzer, stdout stays pure printable ASCII plus newline/tab -- no
  Unicode, no control char, no ESC, no DEL. (The tool relies on `ascii()` for
  exactly this; a regression to `repr()` would let a printable non-ASCII char
  slip through, and this catches it.)
- **[B] benign**: clean ASCII input (including tabs and multiple lines) exits
  `0` with no output -- so [D] is non-vacuous.
- **[N] newline / whitespace**: trailing whitespace is flagged; a missing final
  newline is flagged by default but suppressed with
  `UNICODE_SHOW_ALLOW_MISSING_FINAL_NEWLINE=1`; empty input is clean (no spurious
  "missing newline at end").
- **[E] fail-closed**: invalid UTF-8 (stdin or file) exits `2` without the raw
  bad bytes reaching stdout; a nonexistent path exits `2`.
- **[P] paths**: a file of hostile Unicode is detected via the path argument,
  and a filename that itself contains suspicious Unicode is sanitised in the
  output (stdout stays ASCII).
- **[F] fuzz**: random byte streams and random valid-Unicode strings never
  crash, hang, or break the [S] invariant; the exit code stays in `{0,1,2}`.

No root, no network. The test source is ASCII-only: every suspicious character
is written as a Python escape and encoded to real UTF-8 bytes at runtime.

## Running

```
unicode-show-tests                       # corpus + semantics + fail-closed + fuzz
unicode-show-tests --iterations 1000 --seed 7
unicode-show-tests-fuzz                  # heavy fuzz sweep

# test a checkout instead of the installed tool
UNICODE_SHOW_REPO=/path/to/helper-scripts unicode-show-tests
```

The tool is resolved from `UNICODE_SHOW_REPO` (a helper-scripts checkout, run via
the Python module) else the installed `/usr/bin/unicode-show`.
