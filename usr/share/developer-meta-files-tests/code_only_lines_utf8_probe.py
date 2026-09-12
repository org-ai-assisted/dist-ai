#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit probe of dist_ai.rules._helpers.code_only_lines on a line that
## carries a multi-byte UTF-8 char before a trailing '#' comment. shfmt reports
## the comment's column as a BYTE offset; used as a Python codepoint index it
## overshoots by one per preceding multi-byte char, leaking comment text (the
## '#' itself, and any '/tmp' etc.) into the "code" slice -- a spurious R-170
## and friends on any ordinary non-ASCII line with a trailing comment. The code
## portion before the comment must survive intact. Drives the REAL shipped
## module (no copy). Used by test_code_only_lines_utf8.sh.
##
## Test source stays ASCII (no raw non-ASCII byte): the multi-byte chars are
## built via \u escapes, so the committed file and the tested string match.

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dist_ai import bash_ast  # noqa: E402
from dist_ai.rules import _helpers  # noqa: E402

_failures = 0


def _check(name, ok):
    global _failures
    if ok:
        print("PASS: %s" % name)
    else:
        print("FAIL: %s" % name)
        _failures += 1


## GREEK SMALL LETTER ALPHA (U+03B1) is 2 bytes in UTF-8; eight of them shift the
## byte column eight past the codepoint column of the following '#'.
alphas = "\u03b1" * 8
code_part = 'echo "%s"' % alphas
## A neutral sentinel (no '/tmp' literal, which bandit B108-flags as a temp path);
## it stands for any comment text a byte-column overshoot would leak into "code".
src = "%s # comment-bytes-must-not-leak\n" % code_part

tree = bash_ast.parse(src)
lines = _helpers.code_only_lines(src, tree)
line0 = lines[0]

## The whole trailing comment (its '#' and its text) must be gone from the code
## slice -- a byte-vs-codepoint overshoot would leak part of it (e.g. exposing a
## '/tmp' or similar to R-170) into what the rules treat as code.
_check("trailing '#' comment fully stripped", "#" not in line0)
_check("no comment text leaked into code", "comment-bytes" not in line0)
## The code before the comment is preserved byte-for-byte (not truncated early).
_check("code before the comment preserved intact", line0.rstrip() == code_part)

## A pure-ASCII line with a trailing comment still strips correctly (no regression).
src_ascii = 'echo hello # /tmp/x\n'
lines_ascii = _helpers.code_only_lines(src_ascii, bash_ast.parse(src_ascii))
_check("ASCII line comment still stripped", "#" not in lines_ascii[0]
       and lines_ascii[0].rstrip() == "echo hello")

if _failures:
    print("")
    print("FAILED (%d)" % _failures)
    sys.exit(1)
print("")
print("OK")
