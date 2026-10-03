#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## variables.d/00_preamble.bsh makes dist_build_slot a PATH SEGMENT of binary_build_folder_dist.
## parse-cmd validates the --build-slot FLAG, but the dist_build_slot ENV var bypassed it, so an
## unchecked '..' / '/' / newline escaped the lane -- into a mounted host volume (.gnupg, source
## tree) inside the docker build, or made a later clean rm the wrong tree ($HOME). The preamble
## now validates the slot with helper-scripts' check_is_alpha_numeric before building the path.
## The REAL validation block is extracted + eval'd with a stubbed error(); strings.bsh is sourced.
## Canary: fails on the pre-validation preamble.

## File-wide: the sed pattern matches the LITERAL '${dist_build_slot}' text in the subject (not
## an expansion); dist_build_slot + error() are set/used via the eval'd block, not statically.
# shellcheck disable=SC2016,SC2034,SC2317
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
preamble="${dm_checkout}/variables.d/00_preamble.bsh"
if [ ! -r "${preamble}" ]; then
   printf '%s\n' "FAIL: cannot read ${preamble}" >&2
   exit 1
fi

# shellcheck disable=SC1091
if ! source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/strings.bsh 2>/dev/null; then
   printf '%s\n' "FATAL: cannot source helper-scripts strings.bsh (set HELPER_SCRIPTS_PATH)" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

## Extract the real validation block (the if ... check_is_alpha_numeric ... fi).
block="$(sed -n '/if \[ -n "\${dist_build_slot}" \] && ! check_is_alpha_numeric/,/^fi/p' -- "${preamble}")"
if [ -z "${block}" ]; then
   fail "00_preamble has no check_is_alpha_numeric validation for dist_build_slot"
   printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
   exit 1
fi

## error() in dm aborts; stub it to a non-zero return so we can run the block in a subshell.
## run_block <slot-value> -> rc 0 if accepted, non-zero if the validation fired.
run_block() {
   local dist_build_slot="$1"
   ( error() { return 1; }; eval "${block}" )
}

## Dangerous values that MUST be rejected (traversal, injection, path separator, newline).
rc=0
for bad in '..' '../.gnupg' 'a/b' 'a;b' 'a b' "$(printf 'laneA\nbinary_build_folder_dist=/home/user/.gnupg')"; do
   if run_block "${bad}"; then rc=1; printf '%s\n' "  ACCEPTED (should reject): '${bad}'"; fi
done
if [ "${rc}" -eq 0 ]; then pass "rejects traversal / separator / injection / newline slots"; else fail "a dangerous slot was accepted (see above)"; fi

## Valid values that MUST pass (a real session slug has '-'; empty = no slot, skipped by the guard).
rc=0
for good in 277f00ff-57c2-47bf-ac87-5e120a5fe030 kicksecure_lane lane-1 '' ; do
   if ! run_block "${good}"; then rc=1; printf '%s\n' "  REJECTED (should accept): '${good}'"; fi
done
if [ "${rc}" -eq 0 ]; then pass "accepts a UUID session slug, [A-Za-z0-9_-], and empty (no slot)"; else fail "a valid slot was rejected (see above)"; fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
