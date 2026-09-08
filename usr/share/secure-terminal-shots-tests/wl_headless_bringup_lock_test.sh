#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (structural): the wl_headless_start bringup flock must not deadlock concurrent
## callers. A flock is held while ANY fd on the open-file-description stays open, so:
##   1. labwc MUST be started with the lock fd CLOSED in the child ({fd}>&-). Otherwise labwc
##      (and the Xwayland it spawns) inherit the fd and hold the lock for labwc's whole LIFETIME
##      -- serializing every bringup against every running compositor and deadlocking parallel
##      --jobs / cross-session callers (observed: a wedged tt_capture + favicon e2e).
##   2. the flock MUST be bounded (`flock -w`), so a wedged holder makes a caller proceed
##      unlocked rather than block forever.
## A functional test would need a real long-lived compositor and precise timing; this asserts
## the two load-bearing tokens are present in the CURRENT lib text (they are subtle and easy to
## drop in a refactor). Non-tautological: remove either and this fails.
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-lib.bash (override WL_HEADLESS_LIB).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${WL_HEADLESS_LIB:-}" \
   "${script_dir}/../dist-ai-tests-common/wl-headless-lib.bash" \
   '/usr/share/dist-ai-tests-common/wl-headless-lib.bash'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: wl-headless-lib.bash not found (set WL_HEADLESS_LIB)' >&2
   exit 1
fi

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

## 1. labwc started with the lock fd closed in the child.
if grep --extended-regexp --quiet 'labwc -C .*\{_wl_lock_fd\}>&- &' "${lib}"; then
   check 'labwc is started with the bringup lock fd closed in the child ({fd}>&-)' '1'
else
   check 'labwc is started with the bringup lock fd closed in the child ({fd}>&-)' ''
fi

## 2. the bringup flock is bounded (-w), so a wedged holder cannot deadlock a caller.
if grep --extended-regexp --quiet 'flock -w [0-9]+ "\$\{_wl_lock_fd\}"' "${lib}"; then
   check 'the bringup flock is bounded with -w (no indefinite deadlock)' '1'
else
   check 'the bringup flock is bounded with -w (no indefinite deadlock)' ''
fi

## 3. a caller-supplied --runtime is mkdir'd before the chmod, so a chmod of a missing dir cannot
## abort the caller's set -e shell.
if grep --extended-regexp --quiet 'mkdir --parents -- "\$\{runtime\}"' "${lib}"; then
   check 'a caller-supplied --runtime is created before chmod (no set -e abort)' '1'
else
   check 'a caller-supplied --runtime is created before chmod (no set -e abort)' ''
fi

## 4. the fallback /tmp lock dir is created with mkdir --mode=700 (atomic) and NOT a separate
## chmod that would follow a symlink planted between the check and the chmod (TOCTOU).
if grep --extended-regexp --quiet 'mkdir --mode=700 -- "\$\{_wl_lock_dir\}"' "${lib}" \
   && ! grep --extended-regexp --quiet 'chmod 700 -- "\$\{_wl_lock_dir\}"' "${lib}"; then
   check 'the fallback lock dir is created atomically (mkdir --mode=700, no chmod-after TOCTOU)' '1'
else
   check 'the fallback lock dir is created atomically (mkdir --mode=700, no chmod-after TOCTOU)' ''
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: bringup lock cannot deadlock (labwc fd-closed + bounded flock)'
