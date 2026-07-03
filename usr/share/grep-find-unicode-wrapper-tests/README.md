# grep-find-unicode-wrapper tests

Comprehensive test + fuzz for **grep-find-unicode-wrapper** -- the helper-scripts
bash wrapper around `grep` that scans **files** for suspicious content and lists
the files that contain any. It is grep-like: exit `0` if a match was found, exit
`1` if not, and it fails loud (grep's error code, e.g. `2`) on a grep error such
as an unreadable path. Matching files are printed one path per line, sorted `-u`
and routed through `stecho` so a filename that itself contains Unicode cannot
smuggle anything to the terminal.

## What counts as suspicious

The union of four `grep` passes (`LC_ALL=C`, byte-oriented):

1. / 2. any non-ASCII byte (`>= 0x80`);
3. the bidi Trojan-Source control set (RHSB-2021-007) -- a subset of (1);
4. ASCII control bytes `[\x00-\x08 \x0B-\x1F \x7F]` (C0 minus tab/newline, plus
   DEL / NUL).

So a file matches iff it contains any byte that is **not** printable ASCII
(`0x20..0x7E`) and **not** tab/newline. Pass #4 is the one the non-ASCII passes
cannot cover: a pure-ASCII control byte (bell, DEL, NUL) is caught only there.

Unlike its sibling `unicode-show`, this wrapper does **not** flag trailing
whitespace or a missing final newline -- only the byte classes above.

## Checks

- **[D] detection**: a hostile corpus (bidi set, zero-width, BOM, homoglyph,
  combining, C1, CJK, emoji, accented, and C0 control / NUL / DEL) each makes the
  wrapper exit `0` and list the file.
- **[C] control-isolation**: a file whose only suspicious content is an ASCII
  control byte (no non-ASCII at all) still exits `0` -- proving pass #4's
  independent contribution.
- **[B] benign**: a pure printable-ASCII file (including tabs, and even trailing
  whitespace, which this tool does not flag) exits `1` with no output, so [D] is
  non-vacuous.
- **[M] multi-file**: given clean + dirty files, only the dirty ones are listed,
  sorted and de-duplicated.
- **[P] self-safety**: a filename that itself contains suspicious Unicode is
  sanitised by `stecho` -- the wrapper's stdout stays pure ASCII.
- **[E] errors**: a nonexistent path fails loud (exit `2`), not a silent
  "no match".
- **[K] known limitation**: stdin is broken (documented in the tool's own TODO).
  Only the first of the four greps consumes the piped bytes, so a control-only
  stdin input is a **false negative**. This is encoded as a strict
  known-limitation assertion: it pins the current (buggy) behaviour and flips to
  a hard failure if stdin is ever fixed, prompting a test update.
- **[F] fuzz**: random byte files are checked against an independent byte-level
  oracle (matches iff any non-clean byte is present) -- the exit code must agree
  exactly, and the output must stay pure ASCII.

No root, no network. The test source is ASCII-only: every suspicious character is
written as a Python escape and encoded to real UTF-8 bytes at runtime.

## Running

```
grep-find-unicode-wrapper-tests                  # corpus + semantics + fuzz
grep-find-unicode-wrapper-tests --iterations 1000 --seed 7
grep-find-unicode-wrapper-tests-fuzz             # heavy fuzz sweep

# test a checkout instead of the installed tool
GREP_FIND_UNICODE_WRAPPER_REPO=/path/to/helper-scripts grep-find-unicode-wrapper-tests
```

The wrapper is resolved from `GREP_FIND_UNICODE_WRAPPER_REPO` (a helper-scripts
checkout, whose `usr/bin` is put on `PATH` so its `stecho` is used) else the
installed `/usr/bin/grep-find-unicode-wrapper`.
