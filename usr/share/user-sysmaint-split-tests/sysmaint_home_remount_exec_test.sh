#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## style-ok: R-003 - 3-space indent to match the user-sysmaint-split-tests suite.

## AI-Assisted

## Guards the sysmaint-home-remount-exec pam_exec hook's decision tree:
##  - it acts ONLY for the sysmaint account (a non-sysmaint login must never
##    trigger a root bind-remount -- the security-critical gate),
##  - ONLY on session open (never on close),
##  - ONLY when /home/sysmaint is currently noexec (remount-secure level 3),
##  - and then issues exactly the self-bind + exec remount.
##
## Drives the REAL helper from the checkout. mount/findmnt are exported shell
## functions: a child `bash <helper>` imports them, and a shell function wins
## command lookup over the helper's own `PATH=` reset, so the subject runs
## unmodified with no root, no real mount, no production test seam.
##
## Every helper code path exits early when /home/sysmaint is absent, so the
## subject is only meaningfully exercisable on a sysmaint-split system; the run
## is environment-gated on that directory.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v USER_SYSMAINT_SPLIT_REPO ] || USER_SYSMAINT_SPLIT_REPO=""

if [ -n "${USER_SYSMAINT_SPLIT_REPO}" ]; then
   helper="${USER_SYSMAINT_SPLIT_REPO}/usr/libexec/user-sysmaint-split/sysmaint-home-remount-exec"
else
   helper='/usr/libexec/user-sysmaint-split/sysmaint-home-remount-exec'
fi

if [ ! -x "${helper}" ]; then
   printf '%s\n' "FATAL: subject not found at '${helper}'" >&2
   exit 1
fi

## Every helper path short-circuits at `[ ! -d /home/sysmaint ]`, so without the
## account's home the subject cannot be exercised at all.
if [ ! -d /home/sysmaint ]; then
   printf '%s\n' "SKIP: /home/sysmaint absent; not a user-sysmaint-split system" >&2
   ## style-ok: allow-skip: /home/sysmaint exists only on a user-sysmaint-split system
   exit 77
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # invoked via EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT
call_log="${work_dir}/calls"
export call_log

## Exported stubs: record invocation instead of touching the real system.
# shellcheck disable=SC2317  # called indirectly in a child `bash <helper>`
findmnt() {
   printf '%s\n' 'FINDMNT' >>"${call_log}"
   printf '%s\n' "${FAKE_MOUNT_OPTIONS:-}"
}
# shellcheck disable=SC2317  # called indirectly in a child `bash <helper>`
mount() {
   printf '%s\n' "MOUNT $*" >>"${call_log}"
}
export -f findmnt mount

fail=0
checked=0

## Run the real helper with a controlled pam environment; echo what it did.
run_helper() {
   true >"${call_log}"
   local rc=0
   env "$@" bash "${helper}" >/dev/null 2>&1 || rc=$?
   helper_rc="${rc}"
}

report() {
   local name="$1" ok="$2"
   if [ "${ok}" = 'yes' ]; then
      checked=$(( checked + 1 ))
   else
      printf '%s\n' "FAIL: ${name}" >&2
      printf '%s\n' "  exit=${helper_rc} calls:" >&2
      sed 's/^/    /' -- "${call_log}" >&2 || true
      fail=1
   fi
}

mount_count() {
   grep --count '^MOUNT ' -- "${call_log}" 2>/dev/null || true
}

findmnt_seen() {
   grep --quiet '^FINDMNT$' -- "${call_log}"
}

## 1. A non-sysmaint login must NEVER reach findmnt or a remount, even when the
## home is noexec. This is the gate that keeps root from re-execing a stranger's
## path.
run_helper PAM_USER=root PAM_TYPE=open_session FAKE_MOUNT_OPTIONS='rw,nosuid,nodev,noexec'
if [ "${helper_rc}" -eq 0 ] && ! findmnt_seen && [ "$(mount_count)" -eq 0 ]; then
   report 'non-sysmaint user is a no-op' yes
else
   report 'non-sysmaint user is a no-op' no
fi

## 2. Session CLOSE is a no-op (the open-session hook must not re-run teardown).
run_helper PAM_USER=sysmaint PAM_TYPE=close_session FAKE_MOUNT_OPTIONS='rw,nosuid,nodev,noexec'
if [ "${helper_rc}" -eq 0 ] && ! findmnt_seen && [ "$(mount_count)" -eq 0 ]; then
   report 'session close is a no-op' yes
else
   report 'session close is a no-op' no
fi

## 3. An unset PAM_USER is a no-op (defensive: never act without an explicit
## sysmaint identity).
run_helper PAM_TYPE=open_session FAKE_MOUNT_OPTIONS='rw,nosuid,nodev,noexec'
if [ "${helper_rc}" -eq 0 ] && ! findmnt_seen && [ "$(mount_count)" -eq 0 ]; then
   report 'unset PAM_USER is a no-op' yes
else
   report 'unset PAM_USER is a no-op' no
fi

## 4. sysmaint + session open + noexec home -> exactly the self-bind then the
## exec remount, dropping noexec while keeping nosuid,nodev.
run_helper PAM_USER=sysmaint PAM_TYPE=open_session FAKE_MOUNT_OPTIONS='rw,nosuid,nodev,noexec,relatime'
if [ "${helper_rc}" -eq 0 ] \
   && findmnt_seen \
   && [ "$(mount_count)" -eq 2 ] \
   && grep --quiet -- '^MOUNT --bind -- /home/sysmaint /home/sysmaint$' "${call_log}" \
   && grep --quiet -- '^MOUNT --options remount,bind,nosuid,nodev -- /home/sysmaint /home/sysmaint$' "${call_log}" \
   && ! grep --quiet 'noexec' "${call_log}"; then
   report 'noexec home gets the exec remount' yes
else
   report 'noexec home gets the exec remount' no
fi

## 5. sysmaint + session open + already-exec home -> detect, then do nothing
## (findmnt consulted, no remount issued).
run_helper PAM_USER=sysmaint PAM_TYPE=open_session FAKE_MOUNT_OPTIONS='rw,nosuid,nodev,relatime'
if [ "${helper_rc}" -eq 0 ] && findmnt_seen && [ "$(mount_count)" -eq 0 ]; then
   report 'already-exec home is left alone' yes
else
   report 'already-exec home is left alone' no
fi

if [ "${checked}" -eq 0 ] && [ "${fail}" -eq 0 ]; then
   printf '%s\n' "FATAL: no case ran" >&2
   exit 1
fi

printf '%s\n' "" "${checked} case(s) checked"
exit "${fail}"
