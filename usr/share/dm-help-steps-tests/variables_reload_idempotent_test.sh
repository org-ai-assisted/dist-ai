#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: help-steps/variables must be IDEMPOTENT on a same-shell
## re-source.
##
## THE BUG IT GUARDS: the accumulators variables builds with '+=' / append --
## the DIST_APTGETOPT array (+ DIST_APTGETOPT_SERIALIZED, +_WITHOUT_APT_CACHE),
## pkg_list, SKIP_SCRIPTS, dist_build_script_build_dependency, and
## pbuilder_aptgetopt_block -- ran on EVERY 'source help-steps/variables'. A
## script (or helper) that sourced variables twice in the SAME shell therefore
## got each of these DOUBLED (e.g. DIST_APTGETOPT with every -o option listed
## twice), silently corrupting the apt / cowbuilder option sets. The fix is a
## same-shell re-source guard: the loader sets 'variables_finalized' after
## sourcing every buildconfig.d module and returns early on a second source. It is
## deliberately NOT exported -- a fresh process (every build step) must still
## resolve -- so this can only be observed by re-sourcing in one shell, which is
## exactly what this test does.
##
## Drives the REAL help-steps/pre + help-steps/variables end to end (no copy, no
## drift): sources them, snapshots 'declare -p', sources variables AGAIN in the
## same shell, snapshots again, and requires the two byte-identical. Because both
## snapshots come from ONE process the machine/clock/checkout values are constant
## between them, so no normalization is needed -- any difference is a real
## re-source side effect.
##
## No network, no build. Needs root (or dist_build_allow_root=true, as the suite
## runs) because sourcing variables shells out to sudo.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

if [ ! -r "${dm_checkout}/help-steps/variables" ]; then
   printf '%s\n' "FATAL: help-steps/variables not found at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

## A representative, always-valid build command (mirrors the snapshot suite's
## fixed axis): a real flavor/target with the mandatory freshness/arch/freedom
## choices, so variables resolves fully and builds every accumulator.
fixed_args=( --flavor kicksecure-cli --type vm --target raw --freshness current --arch amd64 --freedom false )

first="$(mktemp)"
second="$(mktemp)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() {
   safe-rm --force -- "${first}" "${second}"
}
trap cleanup EXIT

## One shell (the inner runner): source pre, source variables, snapshot, source
## variables AGAIN, snapshot. Run with CWD = the checkout so 'source help-steps/
## ...' resolves; 'dist_build_allow_root=true' lets pre source under the suite's
## root. The program lives in its own *_inner.sh (repo convention) rather than an
## inline 'bash -c'.
inner="${test_dir}/variables_reload_idempotent_inner.sh"
if [ ! -r "${inner}" ]; then
   printf '%s\n' "FATAL: inner runner not found at '${inner}'." >&2
   exit 1
fi
if ! (
   cd -- "${dm_checkout}" \
      && env dist_build_allow_root=true dist_build_unlock_dangerous_options=true \
         bash "${inner}" "${first}" "${second}" "${fixed_args[@]}"
) >/dev/null 2>&1; then
   fail "could not source help-steps/variables twice (see the run above)"
   printf '%s\n' "FAILED: 1 assertion(s)." >&2
   exit 1
fi

## Canary: an empty snapshot would make the diff pass vacuously (0 lines == 0
## lines), reporting a broken test as green -- exactly the "0 fail = 0 coverage"
## trap. Require both snapshots to actually carry variables.
if [ ! -s "${first}" ] || [ ! -s "${second}" ]; then
   fail "a variable snapshot is empty; variables did not source (test cannot verify anything)"
   printf '%s\n' "FAILED: 1 assertion(s)." >&2
   exit 1
fi

## Canary: the first snapshot MUST contain the accumulators this test is about,
## or a future rename would make the idempotency check pass against nothing.
if ! grep --quiet 'DIST_APTGETOPT=' "${first}"; then
   fail "first snapshot has no DIST_APTGETOPT; the accumulator under test is gone or renamed"
   printf '%s\n' "FAILED: 1 assertion(s)." >&2
   exit 1
fi

## The single assertion: re-sourcing changed nothing. On the pre-fix code the
## DIST_APTGETOPT/pkg_list/SKIP_SCRIPTS/... lines differ (doubled) and this diff
## is non-empty.
if diff --unified -- "${first}" "${second}" >/dev/null; then
   pass "re-sourcing help-steps/variables in the same shell is idempotent"
else
   fail "re-sourcing help-steps/variables changed the environment (accumulators re-appended):"
   diff --unified -- "${first}" "${second}" >&2 || true
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: help-steps/variables re-source is idempotent."
