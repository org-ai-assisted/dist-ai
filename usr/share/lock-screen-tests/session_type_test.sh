#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## lock-screen: an unset or unknown XDG_SESSION_TYPE must reach the script's
## own error MESSAGE, not abort before it.
##
## THE BUG, and why the assertion is worded the way it is: lock-screen runs
## under nounset, and the FIRST attempt at this fix defaulted only the 'case'
## while leaving the '*' arm's message interpolating ${XDG_SESSION_TYPE} bare.
## The script therefore still aborted on exactly the path the fix was for. So
## these cases assert the MESSAGE is produced -- not merely that the case
## statement was reached, which the broken fix would also have satisfied.
##
## Only the session-type dispatch is driven: the real script goes on to exec a
## screen locker, which is not under test. The two lockers are stubbed so the
## dispatch arms are observable.
##
## No root, no network, no session.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v LOCK_SCREEN_REPO ] || LOCK_SCREEN_REPO=""

if [ -n "${LOCK_SCREEN_REPO}" ]; then
   subject="${LOCK_SCREEN_REPO}/usr/bin/lock-screen"
else
   subject='/usr/bin/lock-screen'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: lock-screen not found at '${subject}'" >&2
   printf '%s\n' "set LOCK_SCREEN_REPO to a helper-scripts checkout, or install the package" >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/lock-screen-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver body is LITERAL code written into a file.
## SC2086: env_spec is a pre-split assignment list, deliberately unquoted.
# shellcheck disable=SC2016,SC2086
run_dispatch() {
   local env_spec base bin tool real

   env_spec="$1"
   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   bin="${base}/bin"
   mkdir --parents -- "${bin}"

   ## The case body calls REAL binaries and reads ${title}, which the full
   ## script sets earlier. Stubbing invented function names instead tested
   ## nothing.
   printf '%s\n' '#!/bin/bash' 'printf "%s\n" "LOCKED x11"' >"${bin}/xscreensaver-command"
   printf '%s\n' '#!/bin/bash' 'printf "%s\n" "LOCKED wayland"' >"${bin}/swaylock"
   chmod 0755 -- "${bin}/xscreensaver-command" "${bin}/swaylock"
   for tool in bash sh printf grep sed cat timeout env; do
      real="$(type -P "${tool}" || true)"
      if [ -n "${real}" ]; then
         ln --symbolic --force -- "$(realpath -- "${real}")" "${bin}/${tool}"
      fi
   done

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail'
      printf '%s\n' 'title="Lock Screen"'
      printf '%s\n' 'lock_failure_warn() { printf "%s\n" "WARN: $4"; }'
      printf '%s\n' 'error_exit() { printf "%s\n" "ERROR_EXIT $1"; exit "$1"; }'
      sed -n '/^XDG_SESSION_TYPE=\|^case "[$]{\?XDG_SESSION_TYPE}\?" in$/,/^esac$/p' "${subject}"
      printf '%s\n' 'printf "%s\n" "REACHED_END"'
   } >"${base}/driver"

   ## An empty extraction is the silent killer here: the driver still runs,
   ## still prints REACHED_END, and every case reads as a pass.
   if ! grep --fixed-strings -- 'esac' "${base}/driver" >/dev/null; then
      printf '%s' 'EXTRACTION_EMPTY'
      return 0
   fi

   ( env ${env_spec} PATH="${bin}" timeout 20 bash "${base}/driver" 2>&1 ) || true
}

## check <description> <must-contain> <env spec>
check() {
   local description must_contain output verdict

   description="$1"
   must_contain="$2"
   output="$(run_dispatch "$3")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --fixed-strings -- 'EXTRACTION_EMPTY' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the dispatch block extracted EMPTY; this test would pass vacuously"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort -- this is the bug"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${must_contain}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${must_contain}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## The path the fix was for: the MESSAGE, not merely the case statement.
check 'an UNSET XDG_SESSION_TYPE reaches the error message' 'must be set to' \
   '--unset=XDG_SESSION_TYPE'
check 'an unknown value reaches the error message' 'must be set to' \
   'XDG_SESSION_TYPE=weird'
## The working arms, so the fix cannot be bought by erroring on everything.
check 'x11 still dispatches to its locker' 'LOCKED x11' 'XDG_SESSION_TYPE=x11'
check 'wayland still reaches the end' 'REACHED_END' 'XDG_SESSION_TYPE=wayland'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
