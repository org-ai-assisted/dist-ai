#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard for root_guard_structural_test.sh's library resolver and
## function-body extraction.
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
##   fail-closed -> an explicit-but-broken override (missing lib, or a lib path
##              that is a directory not a file) exits nonzero with the fail-closed
##              FATAL (not the pre-existing 'not found' FATAL, so it is not vacuous).
##   evasion  -> a duplicate set_console_keymap() whose SECOND header the definition
##              count can see (the common line-start forms: 'name()', 'name ()',
##              'name( )', brace-on-next-line, 'function name') does NOT pass -- bash
##              runs the LAST copy, so the count fails closed on it. A duplicate whose
##              header a line grep cannot see (glued after '};' on one line, a line
##              continuation, other exotic placement) is OUT OF SCOPE, per the SCOPE
##              note in root_guard_structural_test.sh -- not "any shape".
##   pos      -> a VALID override still passes (the fix does not over-die).
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## -n, not -v: an exported-but-empty TMP is 'set' to -v, which would leave the
## scratch dir under '/' -- treat empty as unset and fall back to /tmp.
[ -n "${TMP:-}" ] || TMP=/tmp
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
   if [ -n "${repo_val}" ] && [ -f "${repo_val}/${lib_rel}" ] && [ -r "${repo_val}/${lib_rel}" ]; then
      good_repo="${repo_val}"
      break
   fi
done
if [ -z "${good_repo}" ] && [ -f "/${lib_rel}" ] && [ -r "/${lib_rel}" ]; then
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

## Another broken target: the lib PATH exists but is a DIRECTORY, not a regular
## file. It is -r-readable, so a bare -r check would accept it and the extractor
## would read an empty body / mis-report the TODO check -- the resolver must
## reject a non-regular-file subject.
dir_lib_repo="${work_dir}/dir-lib"
mkdir --parents -- "${dir_lib_repo}/${lib_rel}"

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
fail_closed_re='is not a readable file'

## Assert the subject fails closed for one explicit-but-broken override: nonzero
## exit AND the fail-closed FATAL (never the 'not found' FATAL, which would mean it
## simply resolved nothing rather than rejecting the named-but-broken target).
## $1 label; $2/$3/$4 SET_KEYBOARD_LAYOUT_REPO / HELPER_SCRIPTS_REPO / HELPER_SCRIPTS_PATH.
expect_fail_closed() {
   printf '%s\n' "== case: $1 -> fail closed =="
   run_subject "$2" "$3" "$4"
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
}

expect_fail_closed "explicit-but-unreadable HELPER_SCRIPTS_REPO" '' "${missing_repo}" ''
expect_fail_closed "explicit-but-unreadable SET_KEYBOARD_LAYOUT_REPO" "${missing_repo}" '' ''
expect_fail_closed "explicit lib path is a directory, not a file" "${dir_lib_repo}" '' ''

## Write a crafted set-keyboard-layout.sh (NOT a copy of the real one) from stdin into
## a fresh repo under work_dir and echo the repo path.
make_lib_repo() {
   local repo="${work_dir}/$1"
   mkdir --parents -- "${repo}/usr/libexec/helper-scripts"
   cat >"${repo}/${lib_rel}"
   printf '%s' "${repo}"
}

## Assert the subject is NOT fooled by the crafted evasion library at $2: nonzero exit
## AND no satisfied-guard 'ok' line. $1 label, $2 repo.
expect_evasion_caught() {
   printf '%s\n' "== case: $1 -> guard NOT fooled =="
   run_subject "$2" '' ''
   if [ "${run_rc}" -ne 0 ]; then
      ok "exit nonzero (${run_rc})"
   else
      notok "guard passed an evasion library (false green)"
      cat -- "${run_out_file}" >&2 || true
   fi
   if grep --quiet --fixed-strings -- 'expected exactly one set_console_keymap definition' "${run_out_file}"; then
      ok "rejected the duplicate definition"
   else
      notok "did not reject the duplicate definition (wrong reason for the nonzero exit)"
      cat -- "${run_out_file}" >&2 || true
   fi
}

## The multiple-definition class: bash runs the LAST definition, so any duplicate makes
## a single extracted body unable to tell which copy runs. All shapes must fail closed.
## split: guard+return in the dead copy, bare restart in the live copy.
split_repo="$(make_lib_repo two-def-split <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
}
set_console_keymap() {
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"
## decoy: a complete, correctly-guarded dead copy above a bare-restart live copy.
decoy_repo="$(make_lib_repo two-def-decoy <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
set_console_keymap() {
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"
## indented: the dead copy's closing brace is indented, so a column-0 '}' end-anchor
## would spill the extraction into the live copy.
indented_repo="$(make_lib_repo two-def-indented <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
  }
set_console_keymap() {
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"
## The live copy hides behind an alternate (but legal) function-header syntax the
## same-line-brace pattern misses: a space before '()', the brace on the next line, or
## the 'function' keyword. The dead first copy is a COMPLETE, correctly-guarded decoy, so
## body extraction and the guard/restart-order check pass on it -- only a count that
## recognizes the full header grammar catches the unguarded live copy below.
spaceparen_repo="$(make_lib_repo two-def-spaceparen <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
set_console_keymap () {
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"
nextbrace_repo="$(make_lib_repo two-def-nextbrace <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
set_console_keymap()
{
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"
funckw_repo="$(make_lib_repo two-def-funckw <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
function set_console_keymap {
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"
inparen_repo="$(make_lib_repo two-def-inparen <<'LIB'
set_console_keymap() {
  if [ "$(id --user)" != '0' ]; then
    return 1
  fi
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
set_console_keymap( ) {
  log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service
}
LIB
)"

expect_evasion_caught "two defs, split guard/restart" "${split_repo}"
expect_evasion_caught "two defs, complete guarded decoy first" "${decoy_repo}"
expect_evasion_caught "two defs, indented first-def close" "${indented_repo}"
expect_evasion_caught "two defs, live copy uses 'name ()' spacing" "${spaceparen_repo}"
expect_evasion_caught "two defs, live copy brace on next line" "${nextbrace_repo}"
expect_evasion_caught "two defs, live copy uses 'function' keyword" "${funckw_repo}"
expect_evasion_caught "two defs, live copy uses 'name( )' inner space" "${inparen_repo}"

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
