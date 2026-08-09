#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for help-steps/variables: the dist_build_sign_and_tag /
## dist_build_ignore_unsigned default coupling.
##
## THE CONTRACT:
##   - dist_build_sign_and_tag defaults 'false' (signing rewrites submodule
##     HEADs + re-commits gitlinks; local/dev/AI builds do not want that).
##   - dist_build_ignore_unsigned defaults to the INVERSE of sign_and_tag, so a
##     non-signing build skips signature verification in lockstep instead of
##     failing git_sanity_test on its own unsigned tree.
##   - An explicit value still wins over both defaults.
##
## Sources the REAL help-steps/variables the same way help-steps/git_sanity_test
## bootstraps it standalone (dist_build_source_run=true; source pre; source
## variables), so it tests the shipped code, not a copy. FAILS on the pre-change
## code (old default 'true' + unconditional ignore_unsigned='false').
##
## Needs a full derivative-maker checkout (helper-scripts submodule present);
## self-skips 77 when absent. No root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

variables_file="${dm_checkout}/help-steps/variables"
helper_scripts_git="${dm_checkout}/packages/kicksecure/helper-scripts/.git"
if [ ! -r "${variables_file}" ] || [ ! -e "${helper_scripts_git}" ]; then
   printf '%s\n' "SKIP: no full derivative-maker checkout at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 77
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"
## variables refuses a binary folder whose path lacks 'derivative-binary'
## (a guard on its own 'rm --recursive'); honour it.
bin_dir="${workdir}/derivative-binary"
mkdir --parents -- "${bin_dir}"

## Resolve the two flags for a given set of PRESET env assignments by sourcing
## the real variables. Echoes '<sign_and_tag> <ignore_unsigned>'. pre installs
## an EXIT trap that logs a completion line to stdout AFTER the printf, so the
## result is emitted behind a 'RESULT=' marker and filtered out here -- otherwise
## the parse grabs the trap line's trailing word. An empty result (a source that
## died before the coupling) is treated as a failure by the caller, not a pass.
resolve() {
   ## Scope the config dirs to the IN-TREE buildconfig.d. The default list also
   ## sources /etc/buildconfig-dist.d and ${HOMEVAR}/buildconfig.d, so a
   ## developer's local override decides the answer and the test reports a code
   ## regression that is not one -- observed on a host carrying a
   ## 50_sign_and_tag.conf.
   env --unset=dist_build_sign_and_tag \
       --unset=dist_build_ignore_unsigned \
       --unset=dist_build_redistributable \
       dist_build_config_dirs_list="${dm_checkout}/buildconfig.d" \
       "$@" \
       binary_build_folder_dist="${bin_dir}" \
       source_code_folder_dist="${dm_checkout}" \
       dist_build_source_run=true \
       bash <<'INNER' | sed -n 's/^RESULT=//p'
cd "${source_code_folder_dist}/help-steps" || exit 9
source ./pre >/dev/null 2>/dev/null
source ./variables >/dev/null 2>/dev/null
printf '%s\n' "RESULT=${dist_build_sign_and_tag:-UNSET} ${dist_build_ignore_unsigned:-UNSET}"
INNER
}

assert_case() {
   local label="$1" want_sign="$2" want_ignore="$3"
   shift 3
   local got sign ignore resolve_rc
   ## Under errexit a failing 'resolve' would abort the whole test at the
   ## assignment, with no message at all: exit 1 and silence, which reads as a
   ## crash rather than as the verdict it is. Capture the status and SAY what
   ## happened instead.
   resolve_rc=0
   got="$(resolve "$@")" || resolve_rc=$?
   if [ "${resolve_rc}" -ne 0 ] || [ -z "${got}" ]; then
      fail "${label}: sourcing help-steps/variables failed (rc=${resolve_rc}); no values to compare"
      return 0
   fi
   sign="${got%% *}"
   ignore="${got##* }"
   if [ "${sign}" = "${want_sign}" ] && [ "${ignore}" = "${want_ignore}" ]; then
      pass "${label}: sign_and_tag=${sign} ignore_unsigned=${ignore}"
   else
      fail "${label}: got sign_and_tag=${sign} ignore_unsigned=${ignore}; want ${want_sign}/${want_ignore}"
   fi
}

## default (no presets): off, and verification skipped in lockstep.
## This is the case the pre-change code got wrong (it yielded true/false).
assert_case "default (local/dev)"          "false" "true"
## explicit opt-in: sign, and verify.
assert_case "opt-in --sign-and-tag true"   "true"  "false" dist_build_sign_and_tag=true
## redistributable dispatch opts in: sign, and verify.
assert_case "redistributable + opt-in"     "true"  "false" dist_build_redistributable=true dist_build_sign_and_tag=true
## an explicit ignore value wins over the inverse default.
assert_case "explicit ignore=false wins"   "false" "false" dist_build_ignore_unsigned=false

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: sign-and-tag default coupling."
