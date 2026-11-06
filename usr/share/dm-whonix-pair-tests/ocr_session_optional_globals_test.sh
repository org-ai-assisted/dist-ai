#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ocr-session.bsh documents shot_dir + check_log as OPTIONAL, so a caller that leaves them
## UNSET must not crash -- dm-whonix-pair --mode functional sources the lib under
## `set -o nounset` and sets NEITHER. Regression for the wait_ready resize-nudge branch
## aborting with `shot_dir: unbound variable`: force the nudge branch (width < 1024,
## nudge-after 0, setvideomodehint succeeds) with shot_dir unset and assert wait_ready takes
## the NORMAL deadline die (desktop-not-ready, FAIL_RC) instead of crashing.
## Canary: the pre-fix code (`${shot_dir}`, no `:-`) aborts with `unbound variable`.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## OCR_SESSION_BSH overrides the subject (the canary points it at a pre-fix copy).
lib="${OCR_SESSION_BSH:-${here}/../dm-smbios-reader-boot-tests/ocr-session.bsh}"
[ -r "${lib}" ] || lib='/usr/share/dm-smbios-reader-boot-tests/ocr-session.bsh'
[ -r "${lib}" ] || { printf '%s\n' "FATAL: ocr-session.bsh not found" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## res reader returns a sub-1024 width (never "ready"), forcing the nudge branch each poll.
cat > "${work}/guestctl" <<'STUB'
#!/bin/bash
[ "$2" = 'res' ] && printf '%s\n' "800 600"
exit 0
STUB
## setvideomodehint SUCCEEDS so the nudge branch reaches the shot_dir reference.
cat > "${work}/vboxmanage" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "${work}/guestctl" "${work}/vboxmanage"

## Required globals the lib reads; deliberately DO NOT set shot_dir or check_log.
vm='testvm'
me='ocr-session-test'
FAIL_RC=5
GUESTCTL="${work}/guestctl"
VBOXMANAGE="${work}/vboxmanage"
export DM_CALAMARES_RESIZE_NUDGE_AFTER=0   ## nudge on the first poll
## die() and gui_scan() the lib calls (gui-drive.bsh is NOT sourced here).
die() { printf '%s\n' "${me}: DIE ${1}: ${2}" >&2; exit "${1}"; }
gui_scan() { :; }

# shellcheck source=../dm-smbios-reader-boot-tests/ocr-session.bsh
source "${lib}"

## timeout 1 + a single real `sleep 10` in the loop body -> one poll (the nudge), then the
## deadline is passed and wait_ready die()s desktop-not-ready. Capture stderr + rc.
err="${work}/err"
rc=0
( wait_ready 1 ) >/dev/null 2>"${err}" || rc=$?

fail=0
if grep --quiet --fixed-strings 'unbound variable' "${err}"; then
   printf '%s\n' "FAIL: wait_ready crashed on an unset shot_dir: $(cat -- "${err}")" >&2
   fail=1
else
   printf '%s\n' "ok: wait_ready does not crash with shot_dir unset (nounset)"
fi
if [ "${rc}" -eq 5 ]; then
   printf '%s\n' "ok: wait_ready took the normal deadline die (FAIL_RC=5)"
else
   printf '%s\n' "FAIL: wait_ready exited ${rc}, expected the deadline die FAIL_RC=5" >&2
   fail=1
fi
if grep --quiet --fixed-strings 'desktop not ready' "${err}"; then
   printf '%s\n' "ok: died for the right reason (desktop not ready)"
else
   printf '%s\n' "FAIL: wrong die reason: $(cat -- "${err}")" >&2
   fail=1
fi

[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' "" "ocr-session optional-globals: all assertions passed"
