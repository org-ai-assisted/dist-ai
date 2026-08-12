#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgfallbacks' fallbacks(): deciding there is no GUI must work in the one
## environment the no-GUI fallback exists for.
##
## THE BUG: fallbacks() decides by reading DISPLAY and WAYLAND_DISPLAY. In a
## headless or pure-Wayland session those are exactly the variables that are
## unset -- so under the callers' nounset it aborted precisely where it was
## needed. A GUI session, where both are set, was never affected, which is why
## the two "both set" cases are asserted here as well.
##
## msgfallbacks is a SOURCED file with no strict mode of its own, so the trap
## only appears when it is driven the way its callers drive it: sourced into a
## nounset shell. A driver without nounset would pass no matter what.
##
## No root, no network, no display.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""

if [ -n "${MSGCOLLECTOR_REPO}" ]; then
   subject="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector/msgfallbacks"
else
   subject='/usr/libexec/msgcollector/msgfallbacks'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: msgfallbacks not found at '${subject}'" >&2
   printf '%s\n' "set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
   exit 77
fi

## msgfallbacks sources helper-scripts has.sh itself; require it (do not stub).
if [ ! -r "${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts/has.sh" ]; then
   printf '%s\n' "SKIP: helper-scripts has.sh not available at ${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts" >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/msgfallbacks-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver body is LITERAL code written into a file.
## SC2086: env_spec is a pre-split assignment list, deliberately unquoted --
## quoting it hands env the whole string as ONE name.
# shellcheck disable=SC2016,SC2086
run_fallbacks() {
   local env_spec base

   env_spec="$1"
   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   mkdir --parents -- "${base}"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit'
      ## The caller provides error_handler before sourcing the file; msgfallbacks
      ## sources the real has.sh itself, so has is NOT stubbed here.
      printf '%s\n' 'error_handler() { printf "%s\n" "STUB error_handler"; }'
      printf '%s\n' "source ${subject}"
      printf '%s\n' 'fallbacks'
      printf '%s\n' 'printf "%s\n" "no_gui=[${no_gui}]"'
      printf '%s\n' 'printf "%s\n" "REACHED_END"'
   } >"${base}/driver"

   ( env ${env_spec} timeout 20 bash "${base}/driver" 2>&1 ) || true
}

## check <description> <expected no_gui line> <env spec>
check() {
   local description want output verdict

   description="$1"
   want="$2"
   output="$(run_fallbacks "$3")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --extended-regexp -- '^(env|timeout):' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the driver never ran"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort -- this is the bug"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${want}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${want}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}: ${want}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## The two environments the fallback exists for, and the two that aborted.
check 'headless: neither DISPLAY nor WAYLAND_DISPLAY set' 'no_gui=[1]' \
   '--unset=DISPLAY --unset=WAYLAND_DISPLAY'
check 'pure Wayland: DISPLAY unset' 'no_gui=[0]' \
   '--unset=DISPLAY WAYLAND_DISPLAY=wayland-0'
## A GUI session was never affected; asserted so the fix cannot be bought by
## always answering "no GUI".
check 'X11: DISPLAY set' 'no_gui=[0]' 'DISPLAY=:0 WAYLAND_DISPLAY='
check 'both set but EMPTY means no GUI' 'no_gui=[1]' 'DISPLAY= WAYLAND_DISPLAY='

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
