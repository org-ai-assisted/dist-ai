#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Pins the jsfuzz lane wiring + its env-unmet contract in usr/bin/webcheck-jsfuzz-sandbox and
## usr/bin/website-tests (sibling of test_website_jscov_lane.sh; jsfuzz shares jscov's local-first
## + 77 + <site>=<path> staging contract but runs the two fuzz sub-gates, not the unit-coverage
## gate). Drives the REAL shipped driver (no synthetic copy). WEBCHECK_NO_LOCAL=1 forces the
## non-local branch; WEBSITE_TESTS_NO_SANDBOX=1 trips the env-unmet short-circuit before any
## sandbox probe, so the 77 path is reached deterministically with no sandbox needed.

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
driver="${test_dir}/../../bin/webcheck-jsfuzz-sandbox"
[ -r "${driver}" ] || driver='/usr/bin/webcheck-jsfuzz-sandbox'
runner="${test_dir}/../../bin/website-tests"
[ -r "${runner}" ] || runner='/usr/bin/website-tests'
jsfuzz_dir="${test_dir}/../../share/website-tests/jsfuzz"
[ -d "${jsfuzz_dir}" ] || jsfuzz_dir='/usr/share/website-tests/jsfuzz'
for f in "${driver}" "${runner}" "${jsfuzz_dir}/run.sh"; do
   if [ ! -r "${f}" ]; then
      printf '%s\n' "FATAL: not found: ${f}" >&2
      exit 1
   fi
done

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## --- 1. env-unmet -> exit 77 (SKIP), never die 1 ---
site="${work}/site"
mkdir --parents -- "${site}"
touch -- "${site}/index.html"
skip_rc=0
skip_err="$(WEBCHECK_NO_LOCAL=1 WEBSITE_TESTS_NO_SANDBOX=1 \
   "${driver}" "${site}" 2>&1 1>/dev/null)" || skip_rc=$?
if [ "${skip_rc}" -eq 77 ] && [[ "${skip_err}" == *'SKIP (77)'* ]]; then
   pass 'webcheck-jsfuzz-sandbox: env-unmet (no local node+c8+fast-check, no usable sandbox) exits 77 SKIP, not die 1'
else
   fail "webcheck-jsfuzz-sandbox: env-unmet did not exit 77 (rc=${skip_rc}, err='${skip_err}')"
fi

## --- 2. the jsfuzz lane is wired into website-tests AND fed CANONICAL identities ---
## Must delegate to webcheck-jsfuzz-sandbox with the identity-tagged root set (jscov_roots, shared
## with the jscov lane), NOT bare "${roots[@]}" whose basename would mis-key fuzzed.txt for a
## non-canonical _REPO override and silently drop that site's fuzzing.
if grep --quiet --extended-regexp 'delegate_sandbox_lane .*webcheck-jsfuzz-sandbox .*jscov_roots' -- "${runner}" \
   && grep --quiet --fixed-strings 'root_sites[' -- "${runner}"; then
   pass 'website-tests: jsfuzz lane passes canonical <site>=<path> identities (jscov_roots from root_sites), not bare roots'
else
   fail 'website-tests: jsfuzz lane not fed identity-tagged roots (would key fuzzed.txt on basename -> silent fuzz drop)'
fi

## --- 3. a non-fuzzed-site root exits 77 SKIP, never a FATAL / die 1 ---
## A single root carrying NO fuzzed.txt site (a computer-security-research checkout) must never
## FATAL. Where a runtime is reachable it reaches the fuzzed.txt-scoping block, finds nothing, and
## exits 77; where none is reachable it exits 77 at the env-unmet gate. EITHER way 77.
csr="${work}/computer-security-research.github.io"
mkdir --parents -- "${csr}"
touch -- "${csr}/index.html"
empty_rc=0
empty_err="$("${driver}" "${csr}" 2>&1 1>/dev/null)" || empty_rc=$?
if [ "${empty_rc}" -eq 77 ]; then
   pass 'webcheck-jsfuzz-sandbox: a non-fuzzed-site root exits 77 SKIP, never a FATAL/die 1'
else
   fail "webcheck-jsfuzz-sandbox: non-fuzzed-site root did not exit 77 (rc=${empty_rc}, err='${empty_err}')"
fi

## --- 4. local-first requires GLOBAL fast-check (the NEW dependency), not just jsdom ---
## run.sh resolves fast-check from NODE_PATH=global, so local-first must gate on fast-check in the
## GLOBAL npm root -- a runner with node22+c8+npm+jsdom but NO fast-check must FALL THROUGH to the
## sandbox, never a false local run (every *.fuzz.js require('fast-check') would throw -> false
## RED). Stub node(v22)+c8+npm(global root WITH jsdom, WITHOUT fast-check); a COVERED site so a
## wrong run_local=1 would reach the gate and FATAL rather than hit the no-site 77;
## WEBSITE_TESTS_NO_SANDBOX=1 so a correct run_local=0 settles as env-unmet 77.
stub="${work}/stub"
mkdir --parents -- "${stub}"
printf '%s\n' '#!/bin/sh' 'echo v22.99.0' 'exit 0' > "${stub}/node"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${stub}/c8"
glob_nofc="${work}/global-no-fastcheck"      # global root with jsdom but NOT fast-check
mkdir --parents -- "${glob_nofc}/jsdom"
printf '%s\n' '{"name":"jsdom"}' > "${glob_nofc}/jsdom/package.json"
printf '%s\n' '#!/bin/sh' "echo ${glob_nofc}" 'exit 0' > "${stub}/npm"
chmod +x -- "${stub}/node" "${stub}/c8" "${stub}/npm"
site_fc="${work}/output-lies.github.io"      # a fuzzed-site basename (so a wrong run_local=1 reaches the gate)
mkdir --parents -- "${site_fc}"
touch -- "${site_fc}/index.html"
nofc_rc=0
nofc_err="$(PATH="${stub}:${PATH}" WEBSITE_TESTS_NO_SANDBOX=1 \
   "${driver}" "${site_fc}" 2>&1 1>/dev/null)" || nofc_rc=$?
if [ "${nofc_rc}" -eq 77 ]; then
   pass 'webcheck-jsfuzz-sandbox: missing GLOBAL fast-check does not engage local-first -> 77 (not a false local RED)'
else
   fail "webcheck-jsfuzz-sandbox: ran locally without global fast-check (rc=${nofc_rc}, err='${nofc_err}')"
fi

## --- 5. the driver keys fuzzed-site selection on the explicit <site>=<path> identity ---
## run_local engaged via stubs (node v22 + c8 + npm whose GLOBAL root has jsdom AND fast-check).
## POSITIVE-by-contrast: a FUZZED identity (output-lies.github.io=<non-canonical path>) is parsed
## AND selected -> reaches the gate (rc != 77, here a run.sh FATAL under the no-op stub toolchain);
## a NON-fuzzed identity (madeup.example=<same path>) is parsed but scoped out -> exit 77. Together
## they prove the driver parses <site>=<path> and keys fuzzed.txt on the explicit identity.
stub2="${work}/stub2"
mkdir --parents -- "${stub2}"
printf '%s\n' '#!/bin/sh' 'echo v22.99.0' 'exit 0' > "${stub2}/node"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${stub2}/c8"
glob_fc="${work}/global-with-fastcheck"
mkdir --parents -- "${glob_fc}/jsdom" "${glob_fc}/fast-check"
printf '%s\n' '{"name":"jsdom"}' > "${glob_fc}/jsdom/package.json"
printf '%s\n' '{"name":"fast-check"}' > "${glob_fc}/fast-check/package.json"
printf '%s\n' '#!/bin/sh' "echo ${glob_fc}" 'exit 0' > "${stub2}/npm"
chmod +x -- "${stub2}/node" "${stub2}/c8" "${stub2}/npm"
id_root="${work}/ci-ws"
mkdir --parents -- "${id_root}"
touch -- "${id_root}/index.html"
cov_rc=0
PATH="${stub2}:${PATH}" "${driver}" "output-lies.github.io=${id_root}" >/dev/null 2>&1 || cov_rc=$?
noncov_rc=0
PATH="${stub2}:${PATH}" "${driver}" "madeup.example=${id_root}" >/dev/null 2>&1 || noncov_rc=$?
if [ "${cov_rc}" -ne 77 ] && [ "${noncov_rc}" -eq 77 ]; then
   pass 'webcheck-jsfuzz-sandbox: fuzzed-selection keyed on <site>=<path> identity (fuzzed reaches gate, non-fuzzed -> 77)'
else
   fail "webcheck-jsfuzz-sandbox: identity not honored (fuzzed rc=${cov_rc} want !=77; non-fuzzed rc=${noncov_rc} want 77)"
fi

## --- 6. run.sh keeps a fail-closed jsfuzz-selftest, and the driver stages it ---
## The two sub-gates are only trustworthy because the selftest REQUIRES each to fail as designed
## (coverage: an unexercised include at 0%; invariants: a deliberately-false property). Pin that
## the selftest block is present (both failure classes asserted) and that the driver stages the
## jsfuzz-selftest fixture -- a removal would let a sub-gate silently regress to vacuous.
run_sh="${jsfuzz_dir}/run.sh"
if grep --quiet --fixed-strings 'coverage self-check PASSED but MUST FAIL' -- "${run_sh}" \
   && grep --quiet --fixed-strings 'invariants self-check PASSED but MUST FAIL' -- "${run_sh}" \
   && grep --quiet --fixed-strings 'jsfuzz-selftest' -- "${driver}"; then
   pass 'jsfuzz: run.sh enforces a fail-closed selftest for BOTH sub-gates and the driver stages the fixture (non-vacuity pinned)'
else
   fail 'jsfuzz: the fail-closed selftest wiring is missing -- a sub-gate could regress to a vacuous pass'
fi

## --- 7. unguarded `npm root -g` must not abort under errexit (a non-zero npm -> 77, not die 1) ---
## node+c8+npm all resolve (enter the local-first block) but `npm root -g` exits non-zero (bad
## .npmrc / EACCES on the global prefix). The bare `groot="$(npm root -g ...)"` assignment must be
## `|| true`-guarded, else errexit aborts the driver with exit 1 before the run_local decision or
## the env-unmet 77. WEBSITE_TESTS_NO_SANDBOX=1 so a correct run_local=0 settles as 77.
stub7="${work}/stub7"
mkdir --parents -- "${stub7}"
printf '%s\n' '#!/bin/sh' 'echo v22.99.0' 'exit 0' > "${stub7}/node"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${stub7}/c8"
printf '%s\n' '#!/bin/sh' 'exit 1' > "${stub7}/npm"   # present on PATH, but `npm root -g` fails
chmod +x -- "${stub7}/node" "${stub7}/c8" "${stub7}/npm"
site7="${work}/output-lies.github.io"
mkdir --parents -- "${site7}"
touch -- "${site7}/index.html"
groot_rc=0
PATH="${stub7}:${PATH}" WEBSITE_TESTS_NO_SANDBOX=1 "${driver}" "${site7}" >/dev/null 2>&1 || groot_rc=$?
if [ "${groot_rc}" -eq 77 ]; then
   pass 'webcheck-jsfuzz-sandbox: a non-zero npm-root-g falls through to env-unmet 77, does not abort (errexit) with 1'
else
   fail "webcheck-jsfuzz-sandbox: unguarded npm root -g aborted the driver (rc=${groot_rc}, want 77)"
fi

## --- 8. a '..' / traversal site identity is rejected, never used as a staging path component ---
## The site becomes roots/<site>/; a '..' identity would resolve outside roots/ and let rsync
## overwrite the staged harness. The driver must die on it, not stage it.
trav_rc=0
trav_err="$("${driver}" "..=${site7}" 2>&1 1>/dev/null)" || trav_rc=$?
if [ "${trav_rc}" -ne 0 ] && [[ "${trav_err}" == *'invalid site identity'* ]]; then
   pass 'webcheck-jsfuzz-sandbox: a .. / traversal site identity is rejected (no staging-path escape)'
else
   fail "webcheck-jsfuzz-sandbox: traversal site identity not rejected (rc=${trav_rc}, err='${trav_err}')"
fi

## --- 9. every fuzz test self-skips an absent site (partial-checkout safety) ---
## run.sh runs EVERY jsfuzz/**/*.fuzz.js; a test whose site was not passed must self-skip (an
## existsSync guard, like jscov), else its top-level require/loadScript throws -> false RED. Pins
## the guard across all fuzz files; a parametrized file (share/ol-copy) filters its path list by
## existsSync, so accept either the guard or the filter form.
fuzz_files='analyzer sandbox ui xray playback quiz hero mockup pastejack st-copy st-share share ol-copy'
missing_fguard=''
for t in ${fuzz_files}; do
   if ! grep --quiet --fixed-strings 'existsSync' -- "${jsfuzz_dir}/${t}.fuzz.js"; then
      missing_fguard="${missing_fguard} ${t}"
   fi
done
if [ -z "${missing_fguard}" ]; then
   pass 'jsfuzz: every fuzz test self-skips an absent site (existsSync guard/filter present)'
else
   fail "jsfuzz: fuzz test(s) missing an absent-site self-skip:${missing_fguard}"
fi

printf '%s\n' "" "test_website_jsfuzz_lane: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
