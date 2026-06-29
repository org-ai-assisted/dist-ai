# sanitize-string tests

Deep test + fuzz harness for the helper-scripts "sanitize" family
(`stdisplay` -> `strip_markup` -> `sanitize-string`) as consumed by
msgcollector's `generic_gui_message` (a PyQt5 `QTextBrowser` with
`setOpenExternalLinks(True)`).

## Threat model

`sanitize-string` output is embedded, unescaped, into text shown to the user in
two renderers, so it must be safe in both:

1. a terminal (`stdisplay`'s original purpose), and
2. HTML / Qt rich text (msgcollector's confirmation and error dialogs).

The goal of this suite is to prove the sanitizers are perfect within that model
- no bypasses.

## What it adds over helper-scripts' own tests

helper-scripts already has hypothesis property tests and fuzzers, but they
check properties against **Python's** view of the string. The dialog renders
with **Qt's** more lenient HTML parser. The bug this suite was written for
lives in that gap: a `<` followed by whitespace then a tag name
(`< a href=...>`), or a `<` produced by entity decoding (`&lt img src=x>`), is
inert to Python's `html.parser` but Qt revives it into a clickable `<a href>` /
`<img>`. This harness drives the **real Qt engine**.

`qtextbrowser_repro.py` is a ~15-line standalone reproduction of that
differential.

## Checks

Each is run over a curated adversarial corpus (the exact bypass family plus
controls) and a biased fuzzer:

- **[T] terminal-safety invariants** - ASCII only, no control bytes except
  `\n`/`\t`, no ESC, length `<=` the requested cap, idempotent. Always hard.
- **[H] HTML-safety invariant** - no `<` survives. Without a `<`, no tag can
  form in any HTML parser, so this is the provable no-bypass guarantee.
- **[Q] Qt differential** - sanitized output embedded in the dialog template,
  parsed by a real `QTextDocument`, must yield no anchor and no image.
  Concrete end-to-end proof of [H]. Needs PyQt5; skipped if absent.
- **[F] content fidelity** - benign, display-safe inputs (notably any URL with
  a `&` query string) must round-trip, not be silently dropped. Guards the
  missing `HTMLParser.close()` bug that blanked such values, hiding the link
  the confirmation dialog asks the user to approve. Hard when fixed; otherwise
  reported as the deployed content-drop bug.
- **[L] length cap** - the output never exceeds `max_length` and equals the
  untruncated sanitization truncated to N (including multi-codepoint entity
  decoding). Always hard.

When the sanitizer under test is **fixed**, [H] and [Q] are hard requirements
and a clean run proves the sanitizer is bypass-free across that run. When it is
**unfixed** (e.g. an old installed package), those checks are reported as the
deployed bypass and the suite stays green with a loud note - [T] still holds.
Detection is automatic.

## Running

```
sanitize-string-tests                       # corpus + 3000 fuzz iterations
sanitize-string-tests --iterations 20000 --seed 7
sanitize-string-tests-fuzz                  # heavy fuzz sweep (50000)

# prove a not-yet-installed source fix: point at a wrapper that runs the
# checkout copy (PYTHONPATH set to the checkout dist-packages)
SANITIZE_STRING_BIN=/path/to/sanitize-string-wrapper sanitize-string-tests

# the minimal QTextBrowser reproduction
QT_QPA_PLATFORM=offscreen python3 \
  /usr/share/sanitize-string-tests/qtextbrowser_repro.py
```

No root, no network, no real browser. Qt runs offscreen
(`QT_QPA_PLATFORM=offscreen`).

## The fix

The bypass is fixed in helper-scripts `strip_markup`: any residual `<` left
after tag stripping is neutered to `_`, so no `<` survives and no downstream
HTML parser can revive a tag. See the helper-scripts change for rationale (a
blanket guarantee rather than modelling the downstream parser's tag grammar).
