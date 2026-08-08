#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgdispatcher's session-type dispatch must leave BOTH 'gui' and 'cli' set,
## on every arm.
##
## THE BUG: the tty arm set only 'cli', and msgdispatcher_handler reads ${gui}
## unconditionally -- so under nounset the first CLI message aborted. The x11,
## wayland, X-QUBES, DISPLAY and WAYLAND_DISPLAY arms all set both, which is
## precisely what made the gap easy to miss: every arm anyone tested was fine.
##
## The dispatch block is driven directly. Reaching it through the real
## msgdispatcher needs inotify, a run directory and a live session.
##
## No root, no network, no session.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""

if [ -n "${MSGCOLLECTOR_REPO}" ]; then
   subject="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector/msgdispatcher"
else
   subject='/usr/libexec/msgcollector/msgdispatcher'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: msgdispatcher not found at '${subject}'" >&2
   printf '%s\n' "set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/msgdispatcher-session-test.XXXXXX")"

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
   local env_spec base

   env_spec="$1"
   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   mkdir --parents -- "${base}"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail'
      printf '%s\n' 'XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-}"'
      printf '%s\n' 'DISPLAY="${DISPLAY:-}"'
      printf '%s\n' 'WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}"'
      printf '%s\n' 'true() { :; }'
      ## tty is stubbed so the /dev/tty1 guard does not decide the outcome.
      printf '%s\n' 'tty() { printf "%s\n" "/dev/tty1"; }'
      printf '%s\n' 'XDG_SESSION_TYPE="${XDG_SESSION_TYPE:-}"'
      ## Anchored on the WAYLAND_DISPLAY trace line, which exists in every
      ## version. The obvious anchor -- the XDG_SESSION_TYPE default -- is a
      ## line the FIX itself added, so a range starting there never began on an
      ## older subject and the extraction came out empty; every case then failed
      ## on an unbound 'gui' that had nothing to do with the code under test.
      sed -n '/^   true "WAYLAND_DISPLAY: /,/^   fi$/p' "${subject}" | sed 's/^   //'
      ## msgdispatcher_handler reads ${gui} unconditionally; this IS that read,
      ## and it is where the abort happened.
      printf '%s\n' 'printf "%s\n" "gui=[${gui}] cli=[${cli}]"'
      printf '%s\n' 'printf "%s\n" "REACHED_HANDLER"'
   } >"${base}/driver"

   if ! grep --fixed-strings -- 'WAYLAND_DISPLAY' "${base}/driver" >/dev/null; then
      printf '%s' 'EXTRACTION_EMPTY'
      return 0
   fi

   ( env ${env_spec} timeout 20 bash "${base}/driver" 2>&1 ) || true
}

## check <description> <expected gui/cli> <env spec>
check() {
   local description want output verdict

   description="$1"
   want="$2"
   output="$(run_dispatch "$3")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --fixed-strings -- 'EXTRACTION_EMPTY' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the dispatch block extracted EMPTY; this would pass vacuously"
   elif printf '%s\n' "${output}" | grep --extended-regexp -- '^(env|timeout):' >/dev/null; then
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

## The arm that was broken.
check 'a tty session leaves both gui and cli set' 'gui=[0] cli=[1]' \
   '--unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=XDG_CURRENT_DESKTOP XDG_SESSION_TYPE=tty'
## The arms that were always fine, which is why the gap went unnoticed.
check 'an x11 session' 'gui=[1] cli=[0]' \
   '--unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=XDG_CURRENT_DESKTOP XDG_SESSION_TYPE=x11'
check 'a wayland session' 'gui=[1] cli=[0]' \
   '--unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=XDG_CURRENT_DESKTOP XDG_SESSION_TYPE=wayland'
check 'DISPLAY set with an unknown session type' 'gui=[1] cli=[0]' \
   '--unset=WAYLAND_DISPLAY --unset=XDG_CURRENT_DESKTOP XDG_SESSION_TYPE=other DISPLAY=:0'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
