#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Direct unit probe: two dist_ai shell-rule walkers must not overflow the
## interpreter stack on VALID input.
##   R-153 HelpFromComments.stage_stmts flattens a pipeline chain; a ~1000-stage
##     pipeline nests one BinaryCmd per stage.
##   R-220 UnauthorizedSkip._eval_const_arith walks an arithmetic AST; a
##     ~1200-term 'exit $((1+1+...))' nests one BinOp per term.
## Both once recursed with no depth guard, so engine.detect() raised an uncaught
## RecursionError -- aborting EVERY rule on that file, on the very anti-evasion
## path R-220 exists for. This drives the REAL shipped engine (no copy) and
## asserts completion, plus that the small-case arithmetic value is unchanged.
## Used by test_shell_recursion.sh.

import ast
import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dist_ai import context as ctxmod  # noqa: E402
from dist_ai import engine  # noqa: E402
from dist_ai.rules import shell as shellmod  # noqa: E402

_failures = 0


def _check(name, ok):
    global _failures
    if ok:
        print("PASS: %s" % name)
    else:
        print("FAIL: %s" % name)
        _failures += 1


def _detect_no_crash(name, src):
    ctx = ctxmod.FileContext("probe.sh", src)
    try:
        list(engine.detect(ctx))
        _check(name, True)
    except RecursionError:
        _check(name + " (got RecursionError)", False)


## R-153: a ~1000-stage pipeline is valid, shfmt-parseable shell.
_detect_no_crash(
    "R-153: ~1000-stage pipeline does not overflow the stack",
    "#!/bin/bash\n" + " | ".join(["true"] * 1000) + "\n")

## R-220: a ~1200-term constant 'exit $((...))'.
_detect_no_crash(
    "R-220: ~1200-term exit-code arithmetic does not overflow the stack",
    "#!/bin/bash\nexit $((%s))\n" % ("1" + "+1" * 1200))

## The iterative arithmetic evaluator still computes the value: the small skip
## detection R-220 depends on ('exit $((70+7))' == 77) must be unchanged, and the
## long chain evaluates rather than raising.
_check("_eval_const_arith(70+7) == 77",
       shellmod._eval_const_arith(ast.parse("70+7", mode="eval")) == 77)
try:
    _long = shellmod._eval_const_arith(ast.parse("1" + "+1" * 1200, mode="eval"))
    _check("_eval_const_arith long chain evaluates", _long == 1201)
except RecursionError:
    _check("_eval_const_arith long chain evaluates (got RecursionError)", False)
_check("_eval_const_arith(-5 + 2) == -3",
       shellmod._eval_const_arith(ast.parse("-5 + 2", mode="eval")) == -3)
_check("_eval_const_arith declines a non-constant (Name) -> None",
       shellmod._eval_const_arith(ast.parse("x", mode="eval")) is None)

if _failures:
    print("")
    print("FAILED (%d)" % _failures)
    sys.exit(1)
print("")
print("OK")
