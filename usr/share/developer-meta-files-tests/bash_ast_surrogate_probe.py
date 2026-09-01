#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit probe of dist_ai.bash_ast.parse on a lone surrogate. A lone
## surrogate (e.g. an ANSI-C $'\ud800') is not UTF-8 encodable; parse() must map
## that to BashParseError (source unparseable) so EVERY consumer fails CLOSED via
## its existing parse-error path. Letting the raw UnicodeEncodeError propagate is
## a fail-OPEN for a PreToolUse guard (an uncaught error is exit 1 = allow).
## Drives the REAL shipped module (no copy). Used by test_bash_ast_surrogate.sh.

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dist_ai import bash_ast  # noqa: E402

_failures = 0


def _check(name, ok):
    global _failures
    if ok:
        print("PASS: %s" % name)
    else:
        print("FAIL: %s" % name)
        _failures += 1


## The regression: a lone surrogate must fail CLOSED (BashParseError), never
## escape as UnicodeEncodeError (fail-OPEN) nor parse "successfully".
try:
    bash_ast.parse("\ud800")
    _check("lone surrogate raises (did not)", False)
except bash_ast.BashParseError:
    _check("lone surrogate -> BashParseError (fail-closed)", True)
except UnicodeEncodeError:
    _check("lone surrogate -> BashParseError (got UnicodeEncodeError = fail-OPEN)", False)

## A valid command still parses (the guard did not over-block).
try:
    bash_ast.parse("echo ok")
    _check("valid command still parses", True)
except Exception as exc:  # noqa: BLE001
    print("  (valid parse raised %s)" % type(exc).__name__)
    _check("valid command still parses", False)

if _failures:
    print("")
    print("FAILED (%d)" % _failures)
    sys.exit(1)
print("")
print("OK")
