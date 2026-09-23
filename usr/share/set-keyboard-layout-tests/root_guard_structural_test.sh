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
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""

lib_rel='usr/libexec/helper-scripts/set-keyboard-layout.sh'
lib=""

## Resolve the library under test, highest precedence first. An explicitly-set
## override (SET_KEYBOARD_LAYOUT_REPO > HELPER_SCRIPTS_REPO > HELPER_SCRIPTS_PATH)
## NAMES the subject: if it is set but its lib is not a readable regular file, fail
## closed -- do NOT fall through to a lower-precedence override or the installed copy.
## Falling through would silently test a different file than the one the caller pointed
## at, reporting green for a checkout whose library was renamed or deleted. Require a
## regular file (-f), not merely a readable path (-r): a directory, FIFO, or device at
## the lib path is -r-readable but would make the extractor below skip it (empty body)
## or block, both false results. The installed copy is used ONLY when no override is
## set at all.
for repo_var in SET_KEYBOARD_LAYOUT_REPO HELPER_SCRIPTS_REPO HELPER_SCRIPTS_PATH; do
   repo_val="${!repo_var}"
   [ -n "${repo_val}" ] || continue
   if [ -f "${repo_val}/${lib_rel}" ] && [ -r "${repo_val}/${lib_rel}" ]; then
      lib="${repo_val}/${lib_rel}"
   else
      printf '%s\n' "FATAL: ${repo_var}='${repo_val}' set but '${repo_val}/${lib_rel}' is not a readable file" >&2
      printf '%s\n' "an explicit override must point at a readable helper-scripts checkout; refusing to silently fall back" >&2
      exit 1
   fi
   break
done

if [ -z "${lib}" ] && [ -f "/${lib_rel}" ] && [ -r "/${lib_rel}" ]; then
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

## STRUCTURAL revert-guard (AI-accident scope). Extract the set_console_keymap body
## (a column-0 '}' ends it) and assert the root-guard 'if' is PRESENT as a real
## statement -- anchored to line start after comment-stripping, so the guard text
## parked in a comment or string cannot satisfy it -- and PRECEDES the actual restart
## command line (a 'log_run' invocation). Tracks the shipped guard
## 'if [ "$(id --user)" != '\''0'\'' ]' in set-keyboard-layout.sh.
## It does NOT prove the non-root branch RETURNS: deciding return-vs-fall-through
## across bash control flow (else / subshell / pipeline / nested-if, code vs string)
## is a bash-parser problem and deliberately out of scope. An accidental REMOVAL or
## reorder of the guard is caught; a hand-crafted evasion that keeps the 'if' text but
## neuters it is not this guard's job.
## Feed the library on STDIN, not as a filename argument: gawk treats an argument
## matching 'ident=value' as a variable assignment, so a relative lib path whose
## first component contains '=' (e.g. a repo checkout named 'x=y') would be consumed
## as an assignment and awk would silently read the terminal/stdin instead -- a false
## result. Redirection removes the filename entirely, so the path shape cannot matter.
console_body="$(awk '
   /^[[:space:]]*set_console_keymap\(\)[[:space:]]*\{/ { in_fn = 1 }
   in_fn { print }
   in_fn && /^\}/ { if (in_fn) exit }
' < "${lib}")"

## Drop whole-line comments so an inert guard string parked in a comment cannot
## satisfy the check (the exact evasion this test exists to resist).
console_code="$(printf '%s\n' "${console_body}" | grep --invert-match -- '^[[:space:]]*#')"

## '|| true': grep exits 1 on no match, which under errexit+pipefail would abort
## the script before the notok below could report the missing/inert guard.
guard_line="$(printf '%s\n' "${console_code}" \
   | grep --line-number --extended-regexp -- '^[[:space:]]*if \[ "\$\(id --user\)" != '\''?0'\''? \]' \
   | head --lines 1 | cut --delimiter=: --fields=1 || true)"
restart_line="$(printf '%s\n' "${console_code}" \
   | grep --line-number --fixed-strings -- 'log_run notice "${timeout_command[@]}" systemctl --no-block --no-pager restart keyboard-setup.service' \
   | head --lines 1 | cut --delimiter=: --fields=1 || true)"

if [ -n "${guard_line}" ] && [ -n "${restart_line}" ] \
   && [ "${guard_line}" -lt "${restart_line}" ]; then
   ok "root guard 'if' is present and precedes the console restart in set_console_keymap"
else
   notok "root guard 'if' missing or not before the console restart (guard='${guard_line}' restart='${restart_line}')"
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
