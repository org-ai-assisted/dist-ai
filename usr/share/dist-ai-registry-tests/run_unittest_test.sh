#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## run-unittest.py: discover + run a unittest suite, mapping the outcome to the
## canonical result codes so an all-skipped / nothing-collected run cannot read
## as a green PASS (a bare `unittest discover` exits 0 when every test skips at
## import). Drives the REAL helper against synthetic suites.
##   0 pass, 1 fail/error, 77 nothing collected, 78 every collected test skipped.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
helper="${script_dir}/../dist-ai-tests-common/run-unittest.py"
if [ ! -r "${helper}" ]; then
   helper='/usr/share/dist-ai-tests-common/run-unittest.py'
fi
if [ ! -r "${helper}" ]; then
   printf '%s\n' "FATAL: run-unittest.py not found (checkout or installed)" >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Build a synthetic suite dir named $1 holding file test_a.py with body $2.
make_suite() {
   local name="$1" body="$2" dir
   dir="${work}/${name}"
   mkdir --parents -- "${dir}"
   printf '%s\n' "${body}" >"${dir}/test_a.py"
   printf '%s' "${dir}"
}

run_helper() {
   local rc=0
   "${helper}" --start-directory "$1" --pattern 'test_*.py' \
      >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

d="$(make_suite passing $'import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertTrue(True)')"
check "a passing test -> 0" "$(run_helper "${d}")" "0"

d="$(make_suite modskip $'import unittest\nraise unittest.SkipTest("subject absent")')"
check "module-level SkipTest at import (all skipped) -> 78" "$(run_helper "${d}")" "78"

d="$(make_suite methskip $'import unittest\nclass T(unittest.TestCase):\n    @unittest.skip("nope")\n    def test_x(self): pass')"
check "every method skipped -> 78" "$(run_helper "${d}")" "78"

d="$(make_suite empty $'x = 1  # no TestCase')"
check "no tests collected -> 77" "$(run_helper "${d}")" "77"

d="$(make_suite failing $'import unittest\nclass T(unittest.TestCase):\n    def test_bad(self): self.assertTrue(False)')"
check "a failing test -> 1" "$(run_helper "${d}")" "1"

d="$(make_suite mixed $'import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertTrue(True)\n    @unittest.skip("live only")\n    def test_live(self): pass')"
check "mix of pass + skip -> 0" "$(run_helper "${d}")" "0"

d="$(make_suite imperr $'import this_module_does_not_exist_xyz\nimport unittest\nclass T(unittest.TestCase):\n    def test_ok(self): pass')"
check "import error is an error, not a skip -> 1" "$(run_helper "${d}")" "1"

## An @expectedFailure that PASSES is an unexpected success -- unittest treats it
## as a failure (wasSuccessful() is False), so the helper must too, not exit 0.
d="$(make_suite xpass $'import unittest\nclass T(unittest.TestCase):\n    @unittest.expectedFailure\n    def test_x(self): self.assertTrue(True)')"
check "unexpected success -> 1 (not a false green)" "$(run_helper "${d}")" "1"

## An @expectedFailure that fails as expected ran real work -> PASS.
d="$(make_suite xfail $'import unittest\nclass T(unittest.TestCase):\n    @unittest.expectedFailure\n    def test_x(self): self.assertTrue(False)')"
check "expected failure (behaves) -> 0" "$(run_helper "${d}")" "0"

## A whole class skipped from setUpClass lands in result.skipped but NOT in
## testsRun, so a testsRun-based check would misread it as target-absent (77).
d="$(make_suite classskip $'import unittest\nclass T(unittest.TestCase):\n    @classmethod\n    def setUpClass(cls): raise unittest.SkipTest("no display")\n    def test_x(self): pass')"
check "class-level setUpClass skip -> 78 (env-unmet, not target-absent)" "$(run_helper "${d}")" "78"

## One passing class + one setUpClass-skipped class: testsRun=1, skipped=1, so a
## len(skipped)==testsRun check would misread the pass as all-skipped (78).
d="$(make_suite passclassskip $'import unittest\nclass A(unittest.TestCase):\n    def test_ok(self): self.assertTrue(True)\nclass B(unittest.TestCase):\n    @classmethod\n    def setUpClass(cls): raise unittest.SkipTest("x")\n    def test_y(self): pass')"
check "pass + class-skip -> 0 (partial mix is a pass)" "$(run_helper "${d}")" "0"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
