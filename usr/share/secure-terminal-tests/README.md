# secure-terminal-tests

Tests for secure-terminal's pure, Qt-free sanitization core
(`secure_terminal.sanitize`), plus a static HTML-safety check of the widget
layer.

`sanitize.py` decides what output is safe to display and classifies anything that
is not, with no GUI dependency, the way output-lies keeps its analyzer DOM-free.
This suite drives it directly under `python3` with no PyQt6:

- `render_output()` across the three display modes -- `strip` (non-ASCII becomes
  `_`), `show` (legitimate unicode renders, but the invisible/bidi/format classes
  are still neutralized via `str.isprintable()`), and `reveal` (`<U+XXXX>`
  badges) -- and that escape sequences are always stripped while the interactive
  backspace/carriage-return/tab/newline controls always pass through.
- `sanitize_paste()` (homoglyph, bidi and zero-width stripped; newline to
  carriage return; tab kept) and `paste_findings()` classification.
- the safe-colour SGR parser `parse_sgr()` (16-colour fg/bg, bold, reset, 8-bit
  and 24-bit consumed and ignored) and the `too_close()` contrast guard that
  stops black-on-black.
- `colors_allowed()` honoring the `NO_COLOR` spec and `TERM=dumb`.
- a static scan asserting the widget files never use an HTML sink
  (`setHtml`/`insertHtml`/`QTextBrowser`/...), so printed markup stays inert.

It resolves the `secure_terminal` module from `SECURE_TERMINAL_REPO` (a
secure-terminal checkout) and SKIPs (exit 77) when it is absent. No root, no
network.
