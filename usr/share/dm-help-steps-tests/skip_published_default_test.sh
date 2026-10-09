#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the --skip-published-packages DEFAULT
## (variables.d/10_misc.bsh + help-steps/parse-cmd).
##
## WHY this exists: --skip-published-packages=true is the default for EVERY build (rebuild
## only changed packages, reuse the rest) with no per-path exceptions. '--skip-published-packages
## false' is the explicit opt-out for a from-scratch rebuild (e.g. a reproducible-build
## verification). A bare '--skip-published-packages' stays true.
##
## It drives the REAL help-steps/pre + help-steps/variables of a derivative-maker checkout
## in a subprocess (variables is sourced under the inherited errexit, as a real build step
## sources it) and inspects dist_build_skip_published_packages. '--repo true' is passed so
## the (separately-enforced) mandatory repository choice does not abort the run first.
## Source-tree test: the checkout is found via DERIVATIVE_MAKER_DIR or ~/derivative-maker;
## no checkout is an OPTIONAL SKIP (exit 77).

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

if [ ! -f "${dm_checkout}/help-steps/variables" ] || [ ! -f "${dm_checkout}/variables.d/10_misc.bsh" ]; then
   printf '%s\n' "skip-published-default-test: no derivative-maker checkout at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR). SKIP." >&2
   ## style-ok: allow-skip: cannot source help-steps/variables without a derivative-maker checkout (optional sibling).
   exit 77
fi

out_file="$(mktemp)"
cleanup() { safe-rm --force -- "${out_file}" || true; }
trap cleanup EXIT

## Source pre + variables with the given extra ARGS and print the resolved value.
resolve_skip() {
   local extra_args="$1"
   ( cd -- "${dm_checkout}/help-steps" || exit 90
     unset dist_build_redistributable dist_build_skip_published_packages
     ## dist_build_allow_root=true: the dm-help-steps suite re-runs itself as root
     ## (mount-cleanup requires it), so help-steps/pre's root_check would abort with
     ## "must NOT be run as root" unless this sanctioned CI/container override is
     ## set. Harmless when non-root (root_check only consults it under EUID=0).
     export CI=true dist_build_unlock_dangerous_options=true dist_build_allow_root=true
     ## user_name: the real dm-ci build runs via docker/derivative-maker-docker-run as a
     ## NON-root user AND passes user_name=<user>; variables.d/00_preamble.bsh deliberately
     ## will NOT derive user_name at EUID=0 (SUDO_USER unset + a container where logname
     ## fails -> "Variable user_name is empty" abort). This suite re-execs as root, so mirror
     ## the real invocation; else variables aborts before the choice logic under test runs.
     export user_name="${SUDO_USER:-user}"
     # shellcheck disable=SC2086  ## deliberate word-split of the arg string
     set -- ${extra_args}
     # shellcheck disable=SC1091  ## dynamic path in the derivative-maker checkout
     source pre >/dev/null 2>&1
     ## variables' own output must reach out_file (not /dev/null) so a rejected typo's
     ## error message is visible to the grep below. Capture variables' OWN exit status
     ## (R-011: no errexit toggle): the '( ) || true' wrapper suppresses errexit inside,
     ## so without this an unexpected failure would reach printf and masquerade as a
     ## resolved skip=. skip= prints ONLY when variables actually completed.
     var_rc=0
     # shellcheck disable=SC1091  ## dynamic path in the derivative-maker checkout
     source variables || var_rc=$?
     if [ "${var_rc}" -eq 0 ]; then
        printf '%s\n' "skip=${dist_build_skip_published_packages:-<unset>}"
     else
        printf '%s\n' "VARIABLES_FAILED rc=${var_rc}"
     fi
   ) > "${out_file}" 2>&1 || true
   if grep --quiet -- 'supported options for --skip-published-packages' "${out_file}"; then
      printf '%s\n' "rejected"
   elif grep --quiet -- '^skip=' "${out_file}"; then
      grep -- '^skip=' "${out_file}" | tail -n1
   else
      ## No 'skip=' line: pre/variables aborted for an unexpected reason. Surface
      ## the captured diagnostic to stderr so the failure names its cause instead
      ## of an opaque 'skip=<none>' (the subshell's output is otherwise swallowed).
      printf '%s\n' "skip=<none>"
      printf '%s\n' "DIAG(resolve_skip none): ---8<--- ${out_file} ---" >&2
      cat -- "${out_file}" >&2 || true
      printf '%s\n' "--->8--- end DIAG" >&2
   fi
}

## '--repo true' keeps the mandatory repository choice from aborting the run.
base_args="--repo true --arch amd64 --tb closed --freedom false --freshness frozen --target iso --flavor kicksecure-lxqt"

## --- Case 1 (CANARY): no --skip-published-packages flag -> default TRUE -----------
## Without the flipped default this resolves 'skip=<unset>' (rebuild all), so this
## assertion catches a regression of the default.
r="$(resolve_skip "${base_args}")"
if [ "${r}" = 'skip=true' ]; then
   pass "--skip-published-packages defaults to true (reuse unchanged packages)"
else
   fail "--skip-published-packages default is not true; got '${r}'"
fi

## --- Case 2: --skip-published-packages false -> opt-out --------------------------
r="$(resolve_skip "--skip-published-packages false ${base_args}")"
if [ "${r}" = 'skip=false' ]; then
   pass "--skip-published-packages false opts out (from-scratch rebuild)"
else
   fail "--skip-published-packages false did not resolve false; got '${r}'"
fi

## --- Case 3: a bare --skip-published-packages stays true -------------------------
r="$(resolve_skip "--skip-published-packages ${base_args}")"
if [ "${r}" = 'skip=true' ]; then
   pass "a bare --skip-published-packages stays true"
else
   fail "a bare --skip-published-packages did not resolve true; got '${r}'"
fi

## --- Case 4 (CANARY): a typo'd value is REJECTED, not silently treated as bare -------
## '--skip-published-packages False' (or 'no') must error, not quietly become true and
## leak the token to the parser -- otherwise a from-scratch request silently reuses.
r="$(resolve_skip "--skip-published-packages False ${base_args}")"
if [ "${r}" = 'rejected' ]; then
   pass "a typo'd --skip-published-packages value is rejected"
else
   fail "a typo'd --skip-published-packages value was not rejected; got '${r}'"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: --skip-published-packages defaults to true, '--skip-published-packages false' opts out, a bare flag stays true, and a typo'd value is rejected."
