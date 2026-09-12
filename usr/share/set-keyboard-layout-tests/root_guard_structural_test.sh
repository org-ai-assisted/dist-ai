#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## set_console_keymap must not attempt 'systemctl restart keyboard-setup.service'
## when not running as root. In practice the wrappers already gate root and the
## /etc/default/keyboard write fails first for non-root, so the guard is
## defense-in-depth that cannot be reached end to end without a contrived
## fakeroot. This is therefore a STRUCTURAL revert-guard, not a behavioural test:
## it asserts the guard is present in the shipped library and the resolved TODO
## is gone, so a silent revert of the fix fails the suite.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v SET_KEYBOARD_LAYOUT_REPO ] || SET_KEYBOARD_LAYOUT_REPO=""

lib_rel='usr/libexec/helper-scripts/set-keyboard-layout.sh'
lib=""
if [ -n "${SET_KEYBOARD_LAYOUT_REPO}" ] && [ -r "${SET_KEYBOARD_LAYOUT_REPO}/${lib_rel}" ]; then
   lib="${SET_KEYBOARD_LAYOUT_REPO}/${lib_rel}"
elif [ -n "${HELPER_SCRIPTS_PATH:-}" ] && [ -r "${HELPER_SCRIPTS_PATH}/${lib_rel}" ]; then
   lib="${HELPER_SCRIPTS_PATH}/${lib_rel}"
elif [ -r "/${lib_rel}" ]; then
   lib="/${lib_rel}"
fi

if [ -z "${lib}" ]; then
   printf '%s\n' "FATAL: set-keyboard-layout.sh not found" >&2
   printf '%s\n' "set SET_KEYBOARD_LAYOUT_REPO or HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install the package" >&2
   exit 1
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## The root guard must GATE the console restart WITHIN set_console_keymap. Two
## independent whole-file greps (the prior form) pass even when the guard text is
## an inert comment in another function and the real restart is unguarded, so
## extract the function body and require the guard 'if' to PRECEDE the actual
## restart command line (a 'log_run' invocation, not a quoted "Skipping..." log
## message that merely names it). A column-0 '}' ends the function.
console_body="$(awk '
   /^[[:space:]]*set_console_keymap\(\)[[:space:]]*\{/ { in_fn = 1 }
   in_fn { print }
   in_fn && /^\}/ { if (in_fn) exit }
' "${lib}")"

## Drop whole-line comments so an inert guard string parked in a comment cannot
## satisfy the check (the exact evasion this test exists to resist).
console_code="$(printf '%s\n' "${console_body}" | grep --invert-match -- '^[[:space:]]*#')"

## '|| true': grep exits 1 on no match, which under errexit+pipefail would abort
## the script before the notok below could report the missing/inert guard.
guard_line="$(printf '%s\n' "${console_code}" \
   | grep --line-number --fixed-strings -- 'if [ "$(id --user)" != 0 ]' \
   | head --lines 1 | cut --delimiter=: --fields=1 || true)"
restart_line="$(printf '%s\n' "${console_code}" \
   | grep --line-number --fixed-strings -- 'log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service' \
   | head --lines 1 | cut --delimiter=: --fields=1 || true)"

if [ -n "${guard_line}" ] && [ -n "${restart_line}" ] \
   && [ "${guard_line}" -lt "${restart_line}" ]; then
   ok "root guard 'if' gates the console restart in set_console_keymap"
else
   notok "root guard does not gate the console restart (guard='${guard_line}' restart='${restart_line}')"
fi

## The resolved TODO must be gone (an addressed marker is deleted).
if grep --quiet --fixed-strings -- 'TODO: Do not try this if not running as root' "${lib}"; then
   notok "resolved TODO still present"
else
   ok "resolved TODO removed"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
