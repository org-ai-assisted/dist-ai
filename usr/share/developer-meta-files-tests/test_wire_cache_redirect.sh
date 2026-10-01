#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The dist-ai test wire runs pytest/mypy suites that import package modules FROM the
## subject checkout. Three separate caches would otherwise land in that checkout and
## trip the cache-dir gate (dm-packaging-helper-script / dm-check-unicode), which
## FATALs on any __pycache__ / .pytest_cache / .mypy_cache:
##   - python bytecode  -> __pycache__     (PYTHONDONTWRITEBYTECODE + PYTHONPYCACHEPREFIX)
##   - pytest cache      -> .pytest_cache   (PYTEST_ADDOPTS=-p no:cacheprovider)
##   - mypy cache        -> .mypy_cache     (MYPY_CACHE_DIR pointed OUT of the tree)
## PYTHONDONTWRITEBYTECODE covers ONLY the first; pytest and mypy caches are not
## bytecode and need their own redirection. This test guards BOTH halves:
##   1. the wire (dist-ai-tests-all + suite-parallel.bash) EXPORTS all three redirects;
##   2. those exact env settings actually keep a checkout cache-free -- with a CONTROL
##      run (no settings) that MUST produce every cache dir, so the assertion is not
##      vacuous (a self-contained canary).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
## Same-repo (dist-ai) wire files: usr/share/<this> -> usr/bin, usr/share/dist-ai-tests-common.
tests_all="${test_dir}/../../bin/dist-ai-tests-all"
suite_parallel="${test_dir}/../dist-ai-tests-common/suite-parallel.bash"

failures=0
ok()  { printf '%s\n' "PASS: $*"; }
bad() { printf '%s\n' "FAIL: $*" >&2; failures=$((failures + 1)); }

## Fail closed on an absent prerequisite (dist-ai convention: a missing required
## tool is an environment defect, never a silent skip). pytest + mypy are what the
## real suites run; the wire files must exist to be gated.
for f in "${tests_all}" "${suite_parallel}"; do
   [ -r "${f}" ] || { printf '%s\n' "FATAL: wire file not readable: '${f}'." >&2; exit 1; }
done
for tool in pytest mypy python3; do
   type -P "${tool}" >/dev/null 2>&1 \
      || { printf '%s\n' "FATAL: required tool '${tool}' absent." >&2; exit 1; }
done

## --- 1. the wire EXPORTS all three redirects, in BOTH entry points ----------------
assert_grep() {
   local file="$1" pattern="$2" good="$3" bad_msg="$4"
   if grep --quiet --extended-regexp -- "${pattern}" "${file}"; then
      ok "${good}"
   else
      bad "${bad_msg}"
   fi
}
assert_exports() {
   local file="$1" label="$2"
   assert_grep "${file}" 'export PYTHONDONTWRITEBYTECODE=1' \
      "${label} exports PYTHONDONTWRITEBYTECODE" \
      "${label} does not export PYTHONDONTWRITEBYTECODE"
   assert_grep "${file}" 'export PYTEST_ADDOPTS=.*-o cache_dir=' \
      "${label} redirects the pytest cache dir (-o cache_dir)" \
      "${label} does not redirect the pytest cache dir"
   assert_grep "${file}" 'export MYPY_CACHE_DIR=' \
      "${label} redirects MYPY_CACHE_DIR" \
      "${label} does not redirect MYPY_CACHE_DIR"
}
assert_exports "${tests_all}" "dist-ai-tests-all"
assert_exports "${suite_parallel}" "suite-parallel.bash"

## --- 2. functional: those settings keep a checkout cache-free (with a CONTROL) ----
## '|| true' on cleanup: safe-rm ships with private-ai-config and is ABSENT on a bare
## CI runner, where an unguarded call would exit 127 under errexit and (as the EXIT
## trap) become the whole test's status -- a green run reported red. The subject repo's
## own dist-ai-tests-all documents this exact trap; do not reintroduce it.
work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT

## Two SEPARATE checkouts (control vs with-redirect) so no mid-test cleanup is needed
## -- a mid-test safe-rm would hit the same absent-on-CI trap, and leftover control
## caches would then false-fail the with-redirect check.
make_checkout() {
   local dir="$1"
   mkdir --parents -- "${dir}"
   cat > "${dir}/sample.py" <<'PY'
def add(a: int, b: int) -> int:
    return a + b
PY
   cat > "${dir}/test_sample.py" <<'PY'
from sample import add


def test_add():
    assert add(1, 2) == 3
PY
}

## Exercise the cache producers in ${1}. Failures of the tools themselves are
## irrelevant -- we assert only on the cache dirs they leave. pytest imports sample.py
## + test_sample.py, so it is the __pycache__ producer too (an implicit import HONORS
## PYTHONDONTWRITEBYTECODE, unlike an explicit py_compile). It also produces
## .pytest_cache; mypy produces .mypy_cache.
run_producers() {
   (
      cd -- "$1" || exit 0
      pytest -q >/dev/null 2>&1 || true
      mypy sample.py >/dev/null 2>&1 || true
   )
}
## echo the cache dirs that exist under ${1} (empty = none)
cache_dirs_present() {
   local d found=""
   for d in __pycache__ .pytest_cache .mypy_cache; do
      [ -e "$1/${d}" ] && found="${found} ${d}"
   done
   printf '%s' "${found# }"
}

## CONTROL: no redirection -> every cache dir MUST appear (proves the tools produce
## them here, so the WITH-redirect assertion below is not vacuously true). The subshell
## unsets EVERY redirect var, incl. PYTHONPYCACHEPREFIX (this test itself runs UNDER the
## wire that exports these) so a pre-set bytecode redirect cannot rob the control of its
## __pycache__ and false-fail it.
co_control="${work}/checkout-control"
make_checkout "${co_control}"
( unset PYTHONDONTWRITEBYTECODE PYTHONPYCACHEPREFIX PYTEST_ADDOPTS MYPY_CACHE_DIR
  run_producers "${co_control}" )
control="$(cache_dirs_present "${co_control}")"
if [ "${control}" = "__pycache__ .pytest_cache .mypy_cache" ]; then
   ok "control (no redirection) produces all three cache dirs (assertion has teeth)"
else
   bad "control did not produce all three cache dirs (got '${control}'); test would be vacuous"
fi

## WITH the wire's redirection -> NO cache dir may appear in the checkout.
co_redir="${work}/checkout-redir"
make_checkout "${co_redir}"
pcache="${work}/pytest-cache"
mcache="${work}/mypy-cache"
(
   export PYTHONDONTWRITEBYTECODE=1
   export PYTEST_ADDOPTS="-o cache_dir=${pcache}"
   export MYPY_CACHE_DIR="${mcache}"
   run_producers "${co_redir}"
)
withredir="$(cache_dirs_present "${co_redir}")"
if [ -z "${withredir}" ]; then
   ok "the wire's redirect env leaves the checkout cache-free"
else
   bad "redirect env still left cache dir(s) in the checkout: '${withredir}'"
fi
## Positive: pytest's + mypy's caches landed at the redirected locations, not nowhere.
if [ -e "${pcache}" ]; then
   ok "pytest cache went to the redirected -o cache_dir"
else
   bad "pytest cache_dir redirect produced no cache (pytest may not have run)"
fi
if [ -e "${mcache}" ]; then
   ok "mypy cache went to the redirected MYPY_CACHE_DIR"
else
   bad "MYPY_CACHE_DIR redirect produced no cache dir (mypy may not have run)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "test_wire_cache_redirect: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "test_wire_cache_redirect: OK -- wire exports all three cache redirects and they keep the checkout cache-free (control-verified)."
