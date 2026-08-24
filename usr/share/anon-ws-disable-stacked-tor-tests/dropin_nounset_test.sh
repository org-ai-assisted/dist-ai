#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## socat-unix-sockets: a user config drop-in must not be able to abort the
## service.
##
## THE BUG: the drop-ins are sourced into a shell with nounset, and the idiom
## this package's OWN template documents is
##
##   [ -n "$pre_command" ] || pre_command=""
##
## which READS the variable before setting it. A user following that
## documented example aborted the service. The first case below uses that line
## verbatim, because the documentation is the reason it happens.
##
## Only the sourcing loop is driven, with the glob repointed at a fixture, so
## no service is started and nothing outside the temp tree is touched.
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
[ -v ANON_WS_DISABLE_STACKED_TOR_REPO ] || ANON_WS_DISABLE_STACKED_TOR_REPO=""

if [ -n "${ANON_WS_DISABLE_STACKED_TOR_REPO}" ]; then
   subject="${ANON_WS_DISABLE_STACKED_TOR_REPO}/usr/libexec/anon-ws-disable-stacked-tor/socat-unix-sockets"
else
   subject='/usr/libexec/anon-ws-disable-stacked-tor/socat-unix-sockets'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: socat-unix-sockets not found at '${subject}'" >&2
   printf '%s\n' "set ANON_WS_DISABLE_STACKED_TOR_REPO to a checkout, or install the package" >&2
   exit 1
fi

## The sourcing loop is lifted out by anchor. If the loop is renamed or
## reformatted the extraction yields NOTHING, the driver runs clean, and every
## case below would pass while testing no code at all.
if ! grep --quiet -- '^for i in /etc/anon-ws-disable-stacked-tor.d' "${subject}"; then
   printf '%s\n' "FATAL: no drop-in sourcing loop found in '${subject}'" >&2
   printf '%s\n' "the extraction anchor no longer matches; this test would pass vacuously" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/socat-dropin-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver body below is LITERAL code written into a file.
# shellcheck disable=SC2016
run_dropin() {
   local body base conf

   body="$1"
   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   conf="${base}/conf"
   mkdir --parents -- "${conf}"
   printf '%s\n' "${body}" >"${conf}/50_test.conf"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit'
      printf '%s\n' 'shopt -s nullglob'
      sed -n '/^for i in \/etc\/anon-ws-disable-stacked-tor.d/,/^done$/p' "${subject}" \
         | sed "1s|^for i in .*|for i in ${conf}/*.conf; do|"
      ## '${x-}' not '${x:-}': the difference between UNSET and set-but-EMPTY
      ## is exactly what the first case is about, and ':-' collapses them.
      printf '%s\n' 'if [ "${pre_command-UNSET}" = "" ]; then'
      printf '%s\n' '   printf "%s\n" "PRE_COMMAND_EMPTY"'
      printf '%s\n' 'else'
      printf '%s\n' '   printf "%s\n" "PRE_COMMAND=${pre_command-UNSET}"'
      printf '%s\n' 'fi'
      printf '%s\n' 'printf "%s\n" "REACHED_END"'
   } >"${base}/driver"

   timeout --kill-after=20 20 bash "${base}/driver" 2>&1 || true
}

## check <description> <must-contain> <drop-in body>
check() {
   local description must_contain output verdict

   description="$1"
   must_contain="$2"
   output="$(run_dropin "$3")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort -- a drop-in must not be able to do this"
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

## Verbatim from the package's own documented template.
check 'the documented [ -n "$pre_command" ] idiom' 'PRE_COMMAND_EMPTY' \
   '[ -n "$pre_command" ] || pre_command=""'
## Any other unset variable a user might read.
check 'a drop-in reading some other unset variable' 'REACHED_END' \
   'printf "%s\n" "${some_user_variable}" >/dev/null'
## The ordinary cases, so the fix cannot be bought by ignoring drop-ins.
check 'a well-behaved drop-in that sets a value' 'PRE_COMMAND=sudo' \
   'pre_command="sudo"'
check 'an empty drop-in' 'REACHED_END' \
   '## nothing here'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
