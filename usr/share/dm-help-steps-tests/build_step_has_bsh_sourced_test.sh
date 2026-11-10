#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Root cause this gate exists for: the `has` command-availability helper is a
## FUNCTION defined only in helper-scripts' has.bsh. A build/help step that calls
## `has <tool>` without sourcing has.bsh hits an undefined command. Because the
## call sites sit in an `if` condition, errexit is suppressed there, so the
## failure is SILENT: `has <tool>` resolves to exit 127 (command not found), the
## branch is taken as false, and a gated action is skipped even when the tool is
## present (observed: 5200_prepare-release skipped the OpenPGP public-key export
## whenever DEBEMAIL was set, because `has sq` could never succeed).
##
## This gate DISCOVERS every build/help step that invokes the `has` FUNCTION (so
## a new consumer is covered without editing this test) and asserts each sources
## has.bsh, anchored to an overridable base, before the first call. A behavioral
## proof + canary back the structural check: sourcing has.bsh defines `has`;
## calling `has` without it fails.
##
## Sibling of build_step_helpers_source_resolves_test.sh, which guards the
## DIFFERENT concern that misc-helpers.bsh is sourced by a self-anchored path.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

has_bsh="${dm_checkout}/packages/kicksecure/helper-scripts/usr/libexec/helper-scripts/has.bsh"
if [ ! -r "${has_bsh}" ]; then
   printf '%s\n' "FAIL: cannot read ${has_bsh}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## A command-position call of the `has` FUNCTION: `has <token>` where the token
## ends the statement (newline, ';', '&&', '||', ')'). This ending is what
## separates a real call from English prose ("the chroot has working ..."), which
## is always followed by more words. Anchored to a command-position marker (line
## start, ';', '&', '|', 'then', 'do', '!', 'if') so a substring never matches.
has_call_re='(^|[;&|]|then |do |! |if )[[:space:]]*has[[:space:]]+[A-Za-z0-9_.-]+[[:space:]]*($|[;&|)])'

## first matching grep line, or empty -- no-match must not abort under errexit,
## and the grep is captured whole (not piped into head) to avoid a pipefail
## SIGPIPE when head closes the pipe early.
first_grep_line() {
   local out
   out="$( grep -nE "$1" -- "$2" 2>/dev/null )" || true
   printf '%s\n' "${out}" | head -1
}

## the line NUMBER of the first command-position `has` call in a file
first_has_call_line() {
   first_grep_line "${has_call_re}" "$1" | cut -d: -f1
}

## the full first (anchored) has.bsh source line in a file, if any
has_bsh_source_line_text() {
   first_grep_line '^[[:space:]]*source[[:space:]].*has\.bsh' "$1"
}

## --- discover every consumer of the `has` function and require it source has.bsh
## Any file under build-steps.d/ or help-steps/ that calls `has`. Discovery, not a
## hardcoded list, so a new consumer cannot silently escape the check.
mapfile -t consumers < <(
   grep -rlE "${has_call_re}" \
      -- "${dm_checkout}/build-steps.d" "${dm_checkout}/help-steps" 2>/dev/null \
   | sort)

if [ "${#consumers[@]}" -eq 0 ]; then
   fail 'discovery found no consumer of the has function (grep broken?)'
fi

for consumer in "${consumers[@]}"; do
   name="${consumer##*/}"
   src_line_text="$( has_bsh_source_line_text "${consumer}" )"
   if [ -z "${src_line_text}" ]; then
      fail "${name}: calls the has function but never sources has.bsh"
      continue
   fi
   src_ln="${src_line_text%%:*}"
   ## The source argument must anchor to an overridable base so it resolves from
   ## any CWD: HELPER_SCRIPTS_PATH (the env-prefixed idiom) or the script's own
   ## location (MYDIR / BASH_SOURCE). A bare/CWD-relative name has neither.
   # shellcheck disable=SC2016  # literal ${HELPER_SCRIPTS_PATH}/${MYDIR}/BASH_SOURCE tokens matched, not expanded
   case "${src_line_text}" in
      *'HELPER_SCRIPTS_PATH'*|*'${MYDIR}'*|*'BASH_SOURCE'*)
         anchored=yes
         ;;
      *)
         anchored=no
         ;;
   esac
   if [ "${anchored}" = "no" ]; then
      fail "${name}: has.bsh source is not anchored (bare/CWD-relative): ${src_line_text#*:}"
      continue
   fi
   ## Sourcing after the first call would not help: errexit-suppressed `has`
   ## would already have run undefined.
   call_ln="$( first_has_call_line "${consumer}" )"
   if [ -n "${call_ln}" ] && [ "${src_ln}" -gt "${call_ln}" ]; then
      fail "${name}: sources has.bsh (line ${src_ln}) AFTER its first has call (line ${call_ln})"
      continue
   fi
   pass "${name}: sources has.bsh before its first has call"
done

## --- behavioral proof: sourcing has.bsh defines `has` and it evaluates ---------
if (
      # shellcheck disable=SC1090
      source "${has_bsh}" || exit 1
      declare -F has >/dev/null 2>&1 || exit 2
      ## a command that certainly exists -> true; absence of a crash is the point
      has sh || exit 3
   ); then
   pass 'behavioral: sourcing has.bsh defines has and it evaluates without crash'
else
   fail 'behavioral: sourcing has.bsh did not yield a working has function'
fi

## --- CANARY: reproduce the SILENT skip when has.bsh is not sourced -------------
## Mirror the real site: `if cond && has <tool>; then ACTION; fi` in a shell that
## never sourced has.bsh. `has` is undefined -> exit 127 -> the branch is skipped
## even though the condition and the tool are both fine. This is the exact bug the
## structural check above guards against.
branch="$(
   if true && has sh 2>/dev/null; then
      printf '%s' taken
   else
      printf '%s' skipped
   fi
)"
if [ "${branch}" = "skipped" ]; then
   pass 'canary: has call without has.bsh silently skips its branch (the guarded regression)'
else
   fail "canary broken: branch was '${branch}', expected 'skipped' without has.bsh"
fi

summary_line="===== build-step has.bsh source: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
