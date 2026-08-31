#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit probe of dist_ai.bash_ast.command_tokens' GNU getopt_long
## unambiguous-prefix handling of value-taking long options. Drives the REAL
## shipped module (no copy), parsing each fixture with shfmt via bash_ast.parse.
## Used by test_command_tokens_long_abbrev.sh. Prints PASS/FAIL per case; exits
## non-zero if any case fails.

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


def _first_call(source):
    tree = bash_ast.parse(source)
    return next(iter(bash_ast.call_exprs(tree)))


def _kind_of(source, target_lit, value_long):
    """The token kind command_tokens assigns the word whose literal is
    TARGET_LIT, classifying SOURCE's first call with VALUE_LONG."""
    call = _first_call(source)
    for kind, word, _text in bash_ast.command_tokens(
            call, source, frozenset(), frozenset(value_long)):
        if bash_ast.word_lit(word) == target_lit:
            return kind
    return None


def _check(name, got, want):
    global _failures
    if got == want:
        print("PASS: %s (%s)" % (name, got))
    else:
        print("FAIL: %s -- got %r, want %r" % (name, got, want))
        _failures += 1


## An unambiguous abbreviation of a value-taking long option consumes its
## next-word value, exactly as the full spelling does. This is the reported gap:
## the exact-match code read '--sig's value 'TERM' as an operand and flipped the
## operand region early.
_check("abbrev '--sig' value consumed",
       _kind_of("timeout --sig TERM 5", "TERM", {"signal"}), "value")
## The full spelling is unchanged.
_check("exact '--signal' value consumed",
       _kind_of("timeout --signal TERM 5", "TERM", {"signal"}), "value")
## '--sig=TERM' carries its value inline; the following word is an operand.
_check("abbrev with '=' does not consume next word",
       _kind_of("timeout --sig=TERM 5", "5", {"signal"}), "operand")
## An AMBIGUOUS prefix (two known value-takers share it) consumes nothing --
## getopt rejects it, so we conservatively do not skip the next word.
_check("ambiguous prefix does not consume value",
       _kind_of("grep --ex FOO bar", "FOO", {"exclude", "exclude-dir"}),
       "operand")
## A prefix matching NO known value-taker consumes nothing.
_check("unknown long does not consume value",
       _kind_of("grep --zzz FOO bar", "FOO", {"exclude"}), "operand")
## resolve_long itself: exact, unique-prefix, ambiguous, absent.
_check("resolve_long exact",
       bash_ast.resolve_long("signal", {"signal", "verbose"}), "signal")
_check("resolve_long unique prefix",
       bash_ast.resolve_long("sig", {"signal", "verbose"}), "signal")
_check("resolve_long ambiguous",
       bash_ast.resolve_long("v", {"verbose", "version"}), None)
_check("resolve_long absent",
       bash_ast.resolve_long("zzz", {"signal", "verbose"}), None)

if _failures:
    print("")
    print("FAILED (%d)" % _failures)
    sys.exit(1)
print("")
print("OK")
