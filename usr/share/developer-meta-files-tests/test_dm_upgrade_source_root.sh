#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-safe-rm (rm -rf of our own mktemp work dir only)

## Behavioral regression test for developer-meta-files'
## dm-upgrade-from-local-repository source-root resolution.
##
## Bug: the tool derives the derivative-maker root as '${MYDIR}/../../../../..'
## (five levels up from .../developer-meta-files/usr/bin). Installed at /usr/bin
## that resolves to '/', so the tool died sourcing '//help-steps/pre' with a
## confusing "No such file" instead of a clear diagnostic. Fix: validate the
## derived root and fall back to DERIVATIVE_MAKER_ROOT / source_code_folder_dist /
## $HOME/derivative-maker, else fail with an actionable error.
##
## The REAL tool is driven via a SYMLINK placed at a shallow path: the tool does
## NOT canonicalize BASH_SOURCE, so its own-location derivation uses the symlink's
## directory and lands outside any checkout -- exactly the installed-layout
## condition -- with NO copy of the script (dist-ai rule: drive the real subject).
## The fixture 'help-steps/pre' is a resolution SINK (marks that it was sourced
## and stops), not a reimplementation of the real pre.
##
## Self-contained; no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
rel='packages/kicksecure/developer-meta-files/usr/bin/dm-upgrade-from-local-repository'
subject=""
for candidate in \
   "${DM_UPGRADE_FROM_LOCAL_REPOSITORY:-}" \
   "${DEVELOPER_META_FILES_DIR:+${DEVELOPER_META_FILES_DIR}/usr/bin/dm-upgrade-from-local-repository}" \
   "${dm_checkout}/${rel}" \
   "/usr/bin/dm-upgrade-from-local-repository"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="$( readlink --canonicalize -- "${candidate}" )"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-upgrade-from-local-repository not found (set DM_UPGRADE_FROM_LOCAL_REPOSITORY)." >&2
   exit 1
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work="$(mktemp --directory --tmpdir dm-upgrade-srcroot.XXXXXX)"
cleanup() {
   rm -rf -- "${work}"
}
trap cleanup EXIT

## Shallow symlink: its five-levels-up derivation cannot be a real checkout.
linkdir="${work}/install/usr/bin"
mkdir -p -- "${linkdir}"
ln -s -- "${subject}" "${linkdir}/dm-upgrade-from-local-repository"
link="${linkdir}/dm-upgrade-from-local-repository"

## Fixture checkout whose help-steps/pre only proves it was reached, then stops
## the tool before it sources variables / runs main (which need root + a raw).
fixture="${work}/fixture-checkout"
mkdir -p -- "${fixture}/help-steps"
printf '%s\n' 'printf "%s\n" FIXTURE_PRE_SOURCED' 'exit 0' > "${fixture}/help-steps/pre"
touch -- "${fixture}/help-steps/variables"

## Scenario 1: installed outside a checkout, DERIVATIVE_MAKER_ROOT points at one.
rc=0
out="$( DERIVATIVE_MAKER_ROOT="${fixture}" HOME="${work}/nohome" \
   bash "${link}" 2>&1 )" || rc=$?
if [ "${rc}" -eq 0 ] && grep --quiet --fixed-strings -- 'FIXTURE_PRE_SOURCED' <<< "${out}"; then
   pass "resolves the checkout via DERIVATIVE_MAKER_ROOT when installed outside a checkout"
else
   fail "DERIVATIVE_MAKER_ROOT fallback did not resolve (rc=${rc})"
fi

## Scenario 1b: resolves via source_code_folder_dist -- the project's canonical
## source-tree variable (help-steps/variables honors a pre-set value), so an
## operator pointing it at a checkout must be honored like DERIVATIVE_MAKER_ROOT.
rc=0
out="$( env --unset=DERIVATIVE_MAKER_ROOT source_code_folder_dist="${fixture}" HOME="${work}/nohome" \
   bash "${link}" 2>&1 )" || rc=$?
if [ "${rc}" -eq 0 ] && grep --quiet --fixed-strings -- 'FIXTURE_PRE_SOURCED' <<< "${out}"; then
   pass "resolves the checkout via source_code_folder_dist when installed outside a checkout"
else
   fail "source_code_folder_dist fallback did not resolve (rc=${rc})"
fi

## Scenario 2: nothing resolvable -> a clear, actionable error, and NOT the old
## '//help-steps/pre' confusion.
rc=0
out="$( env --unset=DERIVATIVE_MAKER_ROOT --unset=source_code_folder_dist HOME="${work}/nohome" \
   bash "${link}" 2>&1 )" || rc=$?
if [ "${rc}" -ne 0 ] && grep --quiet --fixed-strings -- 'cannot locate the derivative-maker checkout' <<< "${out}"; then
   pass "unresolvable install location fails with a clear, actionable error"
else
   fail "expected a clean 'cannot locate' error (rc=${rc})"
fi
if grep --quiet --extended-regexp -- '//help-steps/pre|/help-steps/pre: .*No such file' <<< "${out}"; then
   fail "regressed: still dies sourcing the mis-derived '//help-steps/pre'"
else
   pass "no longer dies sourcing a mis-derived '//help-steps/pre'"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-upgrade-from-local-repository source-root resolution (${pass_count} assertions)."
