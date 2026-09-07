#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins a false-RED regression in usr/bin/privleap-tests' run_pytest. pytest
## exits 5 ("no tests collected") for TWO different causes, and only one is a
## failure:
##   - the property module MODULE-SKIPPED (privleap genuinely absent ->
##     pytest.skip(allow_module_level=True); pytest prints "N skipped"). That is
##     the suite's normal privleap-absent SKIP path, NOT a failure.
##   - the property file was genuinely NOT COLLECTED ("no tests ran", no skip):
##     the property layer silently ran nothing -- that IS a failure (the guard).
## Pre-fix, run_pytest mapped BOTH rc==5 causes to FAIL, so a bare run with
## privleap absent reported the whole privleap suite FAIL instead of SKIP.
##
## Drives the SHIPPED helper (run_pytest) against two throwaway pytest files.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
runner="${test_dir}/../../bin/privleap-tests"
[ -r "${runner}" ] || runner='/usr/bin/privleap-tests'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: privleap-tests not found" >&2
   exit 1
fi

## python3-pytest is a REQUIRED dist-ai dependency (privleap-tests itself needs
## it and runs in CI). Its absence is a broken environment, not a skip.
## style-ok: allow-python-interpreter -- probe the pytest module via PATH python3
if ! python3 -m pytest --version >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: python3-pytest required (declared dist-ai dep) but not installed' >&2
   exit 1
fi

eval "$(sed -n '/^run_pytest() {/,/^}/p' -- "${runner}")"
if ! declare -F run_pytest >/dev/null; then
   fail 'could not extract run_pytest from privleap-tests'
   printf '%s\n' "===== ${pass_count} passed, ${fail_count} failed =====" >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  # invoked via the EXIT trap
cleanup() { [ -z "${work}" ] || safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT

## Fixture 1: a MODULE-SKIP (mirrors test_property.py when privleap is absent).
cat > "${work}/test_modskip.py" <<'PYEOF'
import pytest
pytest.skip('privleap library not found', allow_module_level=True)
def test_never():
    assert True
PYEOF

## Fixture 2: a genuine NO-COLLECTION (no tests, no skip) -- the guarded failure.
cat > "${work}/test_nocollect.py" <<'PYEOF'
x = 1
PYEOF

## run_pytest reads/writes the globals overall + saw_pass; run each in a subshell
## and read the resulting overall back out.
run_case() {
   local file="$1"
   ( overall=0; saw_pass=0; run_pytest "${file}" >/dev/null 2>&1; printf '%s' "${overall}" )
}

## Module-skip -> NOT a failure (overall stays 0), so it can flow to the suite's
## OVERALL SKIPPED (77) path. This is the assertion that FAILS on the pre-fix runner.
mod_overall="$(run_case "${work}/test_modskip.py")"
if [ "${mod_overall}" = '0' ]; then
   pass 'module-skip (rc=5, "N skipped") does NOT set overall (privleap-absent SKIP, not FAIL)'
else
   fail "module-skip wrongly set overall=${mod_overall} (the false-RED: privleap-absent counted as FAIL)"
fi

## Genuine no-collection -> still a FAILURE (guard preserved).
noc_overall="$(run_case "${work}/test_nocollect.py")"
if [ "${noc_overall}" = '1' ]; then
   pass 'no-collection (rc=5, "no tests ran") still sets overall=1 (guard preserved)'
else
   fail "no-collection did not FAIL (overall=${noc_overall}); the not-running-property-layer guard is lost"
fi

printf '%s\n' "" "test_privleap_property_skip_vs_fail: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
