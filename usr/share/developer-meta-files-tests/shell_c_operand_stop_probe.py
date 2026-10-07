#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit probe of the shell '-c' wrapper scans in dist_ai.rules._helpers:
## shell_c_programs (via _c_behind_wrapper, consumed by R-191/R-192) and
## shell_c_program_words (the separate-'-c' sibling, consumed by R-101). A script
## OPERAND, a bare '-' (stdin), or the '--' end-of-options marker ends the shell's
## own options -- everything after is the script's argv, so a later '-c' there is
## the SCRIPT's, not the shell's. Both scans must STOP at that boundary (they used
## to skip the operand and misread the script's '-c' as the shell's, a false
## positive). An expansion-bearing word is still skipped, and a non-'c' option
## does not stop the scan. Drives the REAL shipped module (no copy). Prints
## PASS/FAIL per case; exits non-zero if any case fails.

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dist_ai import bash_ast  # noqa: E402
from dist_ai.rules import _helpers as h  # noqa: E402

_failures = 0


def _programs(source):
    """The inline-program values shell_c_programs yields for SOURCE's tree."""
    tree = bash_ast.parse(source)
    return [program for _call, program, _lines in h.shell_c_programs(tree, source)]


def _separate_values(source):
    """The next-word program word_strings shell_c_program_words yields."""
    tree = bash_ast.parse(source)
    return [bash_ast.word_string(word) for _call, word in h.shell_c_program_words(tree)]


def _check(name, got, want):
    global _failures
    if got == want:
        print("PASS: %s (%r)" % (name, got))
    else:
        print("FAIL: %s -- got %r, want %r" % (name, got, want))
        _failures += 1


## shell_c_programs / _c_behind_wrapper: a '-c' after the script operand / '--' is
## the script's, not the wrapped shell's -> no inline program yielded.
_check("wrapper: operand before '-c' stops the scan",
       _programs('timeout 5 bash foo.sh -c"a;b"'), [])
_check("wrapper: '--' before '-c' stops the scan",
       _programs('timeout 5 bash -- -c"a;b"'), [])
_check("wrapper: bare '-' before '-c' stops the scan",
       _programs('timeout 5 bash - -c"a;b"'), [])
## A non-'c' option is skipped; the real later '-c' is still caught.
_check("wrapper: non-'c' option skipped, real '-c' caught",
       _programs('timeout 5 bash -x -c"a;b"'), ["a;b"])
## The genuine wrapped '-c' (no operand before it) is unchanged.
_check("wrapper: genuine attached '-c' still read",
       _programs('timeout 5 bash -c"a;b"'), ["a;b"])
## A value-taking option's ARGUMENT ('pipefail' after -o) is NOT the script operand:
## the real '-c' after it must still be caught (regression: the operand-stop used to
## read the argument as an operand and miss the '-c').
_check("wrapper: -o pipefail argument is not an operand",
       _programs('timeout 5 bash -o pipefail -c "a; b"'), ["a; b"])
_check("wrapper: -O extglob argument is not an operand",
       _programs('timeout 5 bash -O extglob -c "a; b"'), ["a; b"])
_check("wrapper: +o argument is not an operand",
       _programs('timeout 5 bash +o history -c "a;b"'), ["a;b"])
_check("wrapper: --rcfile argument is not an operand",
       _programs('timeout 5 bash --rcfile /dev/null -c "a; b"'), ["a; b"])
## Command position too (the shell is the command, not a wrapper operand).
_check("command: -o pipefail argument is not an operand",
       _programs('bash -o pipefail -c "a; b"'), ["a; b"])

## shell_c_program_words sibling (separate '-c PROG'): same operand/'--' stop.
_check("sibling: operand before separate '-c' stops the scan",
       _separate_values('bash foo.sh -c prog'), [])
_check("sibling: '--' before separate '-c' stops the scan",
       _separate_values('bash -- -c prog'), [])
_check("sibling: non-'c' option skipped, real separate '-c' caught",
       _separate_values('bash -x -c prog'), ["prog"])
_check("sibling: genuine separate '-c' still read",
       _separate_values('bash -c prog'), ["prog"])
_check("sibling: -o pipefail argument is not an operand",
       _separate_values('bash -o pipefail -c prog'), ["prog"])
_check("sibling: +o argument is not an operand",
       _separate_values('bash +o history -c prog'), ["prog"])

if _failures:
    print("")
    print("FAILED (%d)" % _failures)
    sys.exit(1)
print("")
print("OK")
