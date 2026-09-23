#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard for root_guard_structural_test.sh's library resolver.
##
## The sibling structural test picks the set-keyboard-layout.sh under test from
## SET_KEYBOARD_LAYOUT_REPO > HELPER_SCRIPTS_REPO > HELPER_SCRIPTS_PATH > the
## installed copy. An EXPLICITLY-set override names THE subject: if it is set but
## its library is unreadable, the test must fail closed, NOT silently fall through
## to a lower-precedence override or the installed copy (which would report green
## for a checkout whose library was renamed or deleted -- a false green).
##
## This lane drives the real sibling test as a subprocess with a controlled
## environment and asserts:
##   neg A/B -> an explicit-but-unreadable override exits nonzero with the
##              fail-closed FATAL (not the pre-existing 'not found' FATAL, so the
##              assertion is not vacuous).
##   pos     -> a VALID override still passes (the fix does not over-die).
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v SET_KEYBOARD_LAYOUT_REPO ] || SET_KEYBOARD_LAYOUT_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""

lib_rel='usr/libexec/helper-scripts/set-keyboard-layout.sh'
script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${script_dir}/root_guard_structural_test.sh"

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject '${subject}' not found" >&2
   exit 1
fi

## A known-good repo whose library the subject can actually resolve, for the
## positive control. Prefer an inherited valid override (dist-ai-tests-all wires
## these to a helper-scripts checkout); else the installed copy at '/'. A real
## library is a REQUIRED dependency -- its absence is FATAL, never a skip.
good_repo=""
for repo_val in "${SET_KEYBOARD_LAYOUT_REPO}" "${HELPER_SCRIPTS_REPO}" "${HELPER_SCRIPTS_PATH}"; do
   if [ -n "${repo_val}" ] && [ -r "${repo_val}/${lib_rel}" ]; then
      good_repo="${repo_val}"
      break
   fi
done
if [ -z "${good_repo}" ] && [ -r "/${lib_rel}" ]; then
   good_repo="/"
fi
if [ -z "${good_repo}" ]; then
   printf '%s\n' "FATAL: no readable set-keyboard-layout.sh for the positive control" >&2
   printf '%s\n' "set SET_KEYBOARD_LAYOUT_REPO / HELPER_SCRIPTS_REPO / HELPER_SCRIPTS_PATH, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/set-keyboard-layout-resolver-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap test_cleanup_handler EXIT

## A deliberately-broken override target: a real directory with NO library. Not a
## copy of any package script -- just an empty tree the resolver must reject.
missing_repo="${work_dir}/no-lib"
mkdir --parents -- "${missing_repo}"

pass_count=0
fail_count=0

ok() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "  ok: $1"
}
notok() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "  NOT OK: $1" >&2
}

## Run the subject with a fully-controlled override environment (inherited
## overrides cleared) so this lane decides exactly what the resolver sees.
## $1 SET_KEYBOARD_LAYOUT_REPO, $2 HELPER_SCRIPTS_REPO, $3 HELPER_SCRIPTS_PATH.
## Sets run_rc and run_out_file.
run_subject() {
   local skl hsr hsp rc
   skl="$1"
   hsr="$2"
   hsp="$3"
   run_out_file="${work_dir}/output.txt"
   rc=0
   env \
      SET_KEYBOARD_LAYOUT_REPO="${skl}" \
      HELPER_SCRIPTS_REPO="${hsr}" \
      HELPER_SCRIPTS_PATH="${hsp}" \
      "${subject}" >"${run_out_file}" 2>&1 || rc=$?
   run_rc="${rc}"
}

## The fail-closed FATAL is distinct from the pre-existing 'not found' FATAL; match
## its stable wording so a subject that merely could not find ANY library cannot
## satisfy the negative cases.
fail_closed_re='is not readable'

printf '%s\n' "== case: explicit-but-unreadable HELPER_SCRIPTS_REPO -> fail closed =="
run_subject '' "${missing_repo}" ''
if [ "${run_rc}" -ne 0 ]; then
   ok "exit nonzero (${run_rc})"
else
   notok "expected nonzero exit, got 0 (silent fall-through to another copy)"
   cat -- "${run_out_file}" >&2 || true
fi
if grep --quiet --fixed-strings -- "${fail_closed_re}" "${run_out_file}"; then
   ok "emitted the fail-closed FATAL"
else
   notok "fail-closed FATAL missing (wrong reason for the nonzero exit)"
   cat -- "${run_out_file}" >&2 || true
fi

printf '%s\n' "== case: explicit-but-unreadable SET_KEYBOARD_LAYOUT_REPO -> fail closed =="
run_subject "${missing_repo}" '' ''
if [ "${run_rc}" -ne 0 ]; then
   ok "exit nonzero (${run_rc})"
else
   notok "expected nonzero exit, got 0 (silent fall-through to another copy)"
   cat -- "${run_out_file}" >&2 || true
fi
if grep --quiet --fixed-strings -- "${fail_closed_re}" "${run_out_file}"; then
   ok "emitted the fail-closed FATAL"
else
   notok "fail-closed FATAL missing (wrong reason for the nonzero exit)"
   cat -- "${run_out_file}" >&2 || true
fi

printf '%s\n' "== case: valid override -> still passes (no over-die) =="
run_subject "${good_repo}" '' "${good_repo}"
if [ "${run_rc}" -eq 0 ]; then
   ok "valid override resolved and passed"
else
   notok "valid override rejected (over-die), exit ${run_rc}"
   cat -- "${run_out_file}" >&2 || true
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
