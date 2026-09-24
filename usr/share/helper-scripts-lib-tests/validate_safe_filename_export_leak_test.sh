#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh: validate_safe_filename must NOT change the caller's LC_ALL state
## -- neither its value nor its EXPORT state -- across a call.
##
## THE BUG: an earlier implementation pinned the locale with 'export LC_ALL=C'
## and hand-restored it, but tracked only whether LC_ALL was SET, not whether it
## was EXPORTED. If the caller held a PLAIN (non-exported) LC_ALL, the restore
## re-'export'ed it, so after the call LC_ALL leaked into every subsequently
## spawned child -- a permanent environment side effect from a pure validator,
## even on a valid input. The fix pins with a LOCAL LC_ALL=C, which auto-restores
## the caller's value AND export attribute on return.
##
## Probes three initial caller states (unset / plain / exported) and asserts a
## grandchild's view of LC_ALL (i.e. the EXPORTED value) is identical before and
## after the call. The locale value need not be installed: this tests export
## PROPAGATION, not collation. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

tree_root="${HELPER_SCRIPTS_REPO:-${HELPER_SCRIPTS_PATH:-}}"
tree_root="${tree_root%/}"
strings_bsh="${tree_root}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

## strings.bsh sources its siblings via ${HELPER_SCRIPTS_PATH:-}; point it at the
## same tree so a checkout is not mixed with the installed copy.
export HELPER_SCRIPTS_PATH="${tree_root}"

pass_count=0
fail_count=0

## Run validate_safe_filename under an initial LC_ALL state in a child shell and
## echo 'child_before|child_after|rc'. child_* is a GRANDCHILD's view of LC_ALL:
## 'unset' when LC_ALL is not in its environment (i.e. unset OR merely a plain,
## non-exported shell variable), 'set:<value>' when it was EXPORTED to it. So a
## plain caller variable that our call wrongly exports flips 'unset' -> 'set:...'.
run_scenario() {
   local scenario="$1"
   # shellcheck disable=SC2016
   local body='
      set -e
      source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1
      set +e
      case "$1" in
         unset)    unset LC_ALL ;;
         plain)    unset LC_ALL; LC_ALL=en_US.UTF-8 ;;
         exported) export LC_ALL=en_US.UTF-8 ;;
      esac
      view='"'"'if [ -v LC_ALL ]; then printf "set:%s" "$LC_ALL"; else printf unset; fi'"'"'
      child_before="$(bash -c "$view")"
      probe_value="hello.txt"
      validate_safe_filename probe_value >/dev/null 2>&1
      rc=$?
      child_after="$(bash -c "$view")"
      printf "%s|%s|%s" "$child_before" "$child_after" "$rc"
   '
   HELPER_SCRIPTS_PATH="${tree_root}" /usr/bin/bash -c "${body}" _ "${scenario}"
}

## After the call the exported-LC_ALL view must be UNCHANGED, and a valid
## filename must still be accepted (rc 0) -- proving the locale pin neither
## leaked nor broke validation.
assert_no_leak() {
   local scenario="$1" result before after rc
   result="$(run_scenario "${scenario}")"
   before="${result%%|*}"
   rc="${result##*|}"
   after="${result#*|}"
   after="${after%|*}"
   if [ "${before}" != "${after}" ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: [${scenario}] LC_ALL export state changed: before='${before}' after='${after}'" >&2
      return 0
   fi
   if [ "${rc}" != '0' ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: [${scenario}] a valid filename was not accepted (rc=${rc}); check the tree under test" >&2
      return 0
   fi
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: [${scenario}] LC_ALL export state preserved (view='${before}'), valid filename accepted"
}

## Guard: the function must be defined by the sourced library.
# shellcheck disable=SC2016
defined="$(HELPER_SCRIPTS_PATH="${tree_root}" /usr/bin/bash -c 'source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" >/dev/null 2>&1; printf "%s" "$(type -t validate_safe_filename)"' 2>/dev/null || true)"
if [ "${defined}" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${strings_bsh}' defined no 'validate_safe_filename' (got type '${defined}')" >&2
   exit 1
fi

assert_no_leak unset
assert_no_leak plain
assert_no_leak exported

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
