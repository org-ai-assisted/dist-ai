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

## STRUCTURAL revert-guard (AI-accident scope). A line-oriented TEXT check -- deliberately
## NOT a bash parser -- over the shipped library. It asserts set_console_keymap keeps its
## root guard: exactly ONE definition, the guard 'if' PRESENT, and the guard PRECEDING the
## restart command line. Tracks the shipped guard 'if [ "$(id --user)" != '\''0'\'' ]' and
## the canonical 'set_console_keymap() {' form in set-keyboard-layout.sh.
##
## Require EXACTLY ONE set_console_keymap definition. bash keeps the LAST definition of a
## repeated name, so a duplicate (e.g. a bad merge/rebase leaving a stale guarded copy above
## an unguarded live one) would let the dead copy be verified while the live one runs
## unguarded -- fail closed on any count != 1. The count matches a definition HEADER
## ('function name', or the name followed by an opening '(' -- so 'name(', 'name (', and
## 'name( )' all count), erring toward OVER-counting, a fail-CLOSED direction.
##
## SCOPE, stated honestly (per never-reinvent-a-bash-parser + the AI-accident threat model):
## this catches an ACCIDENTAL removal, reorder, or duplication of the guard: exactly one
## definition, the extraction bounded to the function (so an indented close cannot annex a
## following function), and the guard required before the FIRST mention of restarting
## keyboard-setup.service (so a bare unguarded restart before the guard is caught, not just
## the canonical wording). It FAILS CLOSED when it cannot verify -- a missing guard/restart,
## a duplicate, or a definition not in the canonical 'name() {' form. Because it is text, not
## code, a HAND-CRAFTED evasion that makes the live guard/restart inert or invisible to a
## line grep is OUT OF SCOPE and needs a real shell parser (a human reviews): guard text
## smuggled into a comment (whole-line OR trailing), a string, or a heredoc body; a guard
## neutered WITHIN one definition (else / subshell / pipeline / conditional return); or a
## definition in a lexical form the header grep misses (line continuations, exotic headers).
## Telling live code from inert or aliased text is precisely what this test does not attempt.
def_count="$(grep --count --extended-regexp -- '^[[:space:]]*(function[[:space:]]+set_console_keymap([[:space:]]|\(|$)|set_console_keymap[[:space:]]*\()' "${lib}" || true)"
if [ "${def_count}" -eq 1 ]; then
   ok "exactly one set_console_keymap definition"
else
   notok "expected exactly one set_console_keymap definition, found '${def_count}'"
fi

## Extract the set_console_keymap() body: the function-open line through the FIRST later
## line that starts in column 0. A top-level function's body lines are indented and its
## closing '}' sits in column 0, as does the next function's header -- so ending at the
## first column-0 line stops at the function boundary even if the closing '}' is
## accidentally indented (an editor/merge slip), which would otherwise let the range spill
## into and annex the following, unrelated function's body. '--' guards a lib path that
## begins with '-'.
console_body="$(sed --quiet -- '/^[[:space:]]*set_console_keymap()[[:space:]]*{/,/^[^[:space:]]/p' "${lib}")"

## Drop whole-line '#' comments so a guard string on its own comment line cannot satisfy
## the check. Trailing '#' comments and strings are NOT stripped (that needs shell
## tokenization) -- inert-text smuggling is out of scope, see the SCOPE note above.
console_code="$(printf '%s\n' "${console_body}" | grep --invert-match -- '^[[:space:]]*#')"

## '|| true': grep exits 1 on no match, which under errexit+pipefail would abort
## the script before the notok below could report the missing/inert guard.
guard_line="$(printf '%s\n' "${console_code}" \
   | grep --line-number --extended-regexp -- '^[[:space:]]*if \[ "\$\(id --user\)" != '\''?0'\''? \]' \
   | head --lines 1 | cut --delimiter=: --fields=1 || true)"
## Match the KEY ACTION -- restarting keyboard-setup.service -- not the full canonical
## 'log_run notice ...' wording, and take the FIRST such line. The guard must precede the
## FIRST mention: otherwise a bare 'systemctl ... restart keyboard-setup.service' placed
## before the guard (in addition to the canonical guarded one later) would run unguarded
## yet pass an order check that only looked at the canonical line. Real-lib mentions (the
## 'Skipping command ...' log lines and the real restart) all follow the guard, so this
## stays green there.
restart_line="$(printf '%s\n' "${console_code}" \
   | grep --line-number --fixed-strings -- 'restart keyboard-setup.service' \
   | head --lines 1 | cut --delimiter=: --fields=1 || true)"

if [ -z "${console_body}" ]; then
   ## The counter saw a definition (or none) but canonical extraction got nothing: the
   ## definition is absent or in a non-canonical header form this test cannot verify.
   ## Fail closed with an honest reason rather than mislabel it "guard missing".
   notok "set_console_keymap not found in the verifiable 'name() {' form (reformat or human review)"
elif [ -n "${guard_line}" ] && [ -n "${restart_line}" ] \
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
