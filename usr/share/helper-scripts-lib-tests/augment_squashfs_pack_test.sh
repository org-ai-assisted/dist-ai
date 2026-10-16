#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## augment-squashfs-pack: source-count guard, stale-output removal, and the
## overlay-mode failure guard.
##  (1) The "choose exactly one source" guard counts into source_type_count, so
##      it must TEST source_type_count (a prior typo tested an unset source_count
##      which, under 'set -o nounset', aborted EVERY run before any packing).
##      Zero or two sources -> the friendly guard error; exactly one source
##      proceeds past the guard.
##  (2) The no-overlay-upperdir skip path removes any stale output from a prior
##      run before exiting, so a leftover image cannot be installed.
##  (3) mksquashfs is invoked with -exit-on-error so a per-file read error fails
##      the run instead of shipping a silently incomplete image.
##  (4) On mksquashfs failure the non-fatal warn path is gated on from_overlay
##      being NON-EMPTY (it holds the overlay path, never the literal 'true').
##
## Findings (1) and (2) are driven behaviorally through the REAL script via the
## no-upperdir skip path (reached with --from-overlay on a path that is not an
## overlay mount), which exits before any mksquashfs run. Findings (3) and (4)
## live on the mksquashfs-failure branch in OVERLAY mode, reachable only with a
## real overlay upperdir (root + mount), so they are asserted statically against
## the shipped source. mksquashfs (squashfs-tools) is a REQUIRED subject
## dependency -- the script's startup 'has' check demands it -- so its absence is
## a FATAL environment bug, never a stub. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/bin/augment-squashfs-pack"
   HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
else
   subject='/usr/bin/augment-squashfs-pack'
   HELPER_SCRIPTS_PATH=''
fi
export HELPER_SCRIPTS_PATH

## The SUBJECT and its runtime dependencies are REQUIRED: absent means
## helper-scripts is not installed / HELPER_SCRIPTS_REPO is unset, or the suite's
## declared apt packages are incomplete -- an environment bug -> FATAL, never a
## skip (R-220), matching the sibling lanes.
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

has_bsh="${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts/has.bsh"
if [ ! -r "${has_bsh}" ]; then
   printf '%s\n' "FATAL: has.bsh not readable at '${has_bsh}'" >&2
   exit 1
fi
# shellcheck disable=SC1090,SC1091
source "${has_bsh}"

## mksquashfs (squashfs-tools) plus the coreutils helpers are the subject's own
## startup 'has' preconditions; a missing one is a FATAL environment bug.
if ! has mksquashfs safe-rm cp mkdir chmod realpath; then
   printf '%s\n' "FATAL: a required dependency (mksquashfs/safe-rm/cp/mkdir/chmod/realpath) is missing" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${test_dir}" 2>/dev/null || true
}
trap cleanup EXIT

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Run the REAL script; capture combined output in RUN_OUT and exit code in RUN_RC.
RUN_OUT=''
RUN_RC=0
run_subject() {
   RUN_RC=0
   RUN_OUT="$(/usr/bin/bash "${subject}" "$@" 2>&1)" || RUN_RC=$?
}

## --- finding 1: source-count guard -----------------------------------------
## Zero sources -> friendly guard error (old code: 'source_count: unbound
## variable' under nounset, never the friendly message).
run_subject
if [ "${RUN_RC}" -ne 0 ] && [[ "${RUN_OUT}" == *'choose exactly one'* ]]; then
   ok "no source -> friendly 'choose exactly one' error"
else
   notok "no source: rc=${RUN_RC} out='${RUN_OUT}'"
fi

## Two sources -> same friendly guard error.
run_subject --from-dir "${test_dir}" --from-overlay "${test_dir}/noexist"
if [ "${RUN_RC}" -ne 0 ] && [[ "${RUN_OUT}" == *'choose exactly one'* ]]; then
   ok "two sources -> friendly 'choose exactly one' error"
else
   notok "two sources: rc=${RUN_RC} out='${RUN_OUT}'"
fi

## --- finding 1 (pass-through) + finding 2 (stale-output removal) ------------
## Exactly one source via --from-overlay on a non-overlay path: passes the guard
## (old code aborts here) and reaches the no-upperdir skip, which must drop any
## stale output before exiting 0.
stale_out="${test_dir}/augment.squashfs"
printf '%s\n' 'stale-from-a-previous-run' > "${stale_out}"
run_subject --from-overlay "${test_dir}/noexist" --output "${stale_out}"
if [ "${RUN_RC}" -eq 0 ] && [[ "${RUN_OUT}" == *'no overlay upperdir'* ]] && [ ! -e "${stale_out}" ]; then
   ok "one source, no upperdir -> exit 0, skip note, stale output removed"
else
   if [ -e "${stale_out}" ]; then stale_exists=yes; else stale_exists=no; fi
   notok "skip path: rc=${RUN_RC} stale_exists=${stale_exists} out='${RUN_OUT}'"
fi

## --- finding 3: mksquashfs -exit-on-error (static) --------------------------
if grep --quiet --fixed-strings -- '-exit-on-error' "${subject}"; then
   ok "mksquashfs invocation carries -exit-on-error"
else
   notok "mksquashfs invocation is missing -exit-on-error"
fi

## --- finding 4: overlay-mode failure guard tests non-emptiness (static) -----
## The discriminator is the ABSENCE of the broken literal comparison; the '-n'
## form also appears at the top-level overlay dispatch, so its presence alone
## would not distinguish the fixed failure guard.
# shellcheck disable=SC2016  # literal source-text match; no expansion wanted
if ! grep --quiet --fixed-strings -- '"${from_overlay}" = "true"' "${subject}"; then
   ok "overlay failure guard no longer compares from_overlay to literal 'true'"
else
   notok "overlay failure guard still compares from_overlay to literal 'true'"
fi

printf '%s\n' ""
printf '%s\n' "===== augment-squashfs-pack: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
