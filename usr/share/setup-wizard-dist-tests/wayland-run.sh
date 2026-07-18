#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run a command against a private, headless weston compositor, analogous to
## xvfb-run for X11. Starts weston with the headless backend on a fresh socket
## in a private XDG_RUNTIME_DIR, exports WAYLAND_DISPLAY and QT_QPA_PLATFORM,
## runs the command, then tears down the exact weston pid and the runtime dir.
##
##   wayland-run.sh <command> [args...]

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit

if ! command -v weston >/dev/null 2>&1; then
   printf 'wayland-run.sh: weston is not installed\n' >&2
   exit 127
fi

runtime_dir="$(mktemp --directory)"
chmod 700 "${runtime_dir}"
export XDG_RUNTIME_DIR="${runtime_dir}"

socket="wayland-swdtest-$$"

## --idle-time=0 keeps the compositor from going idle; the headless backend
## needs no GPU or display hardware.
weston --backend=headless-backend.so --socket="${socket}" --idle-time=0 \
   >"${runtime_dir}/weston.log" 2>&1 &
weston_pid=$!

cleanup() {
   ## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
   # shellcheck disable=SC2317
   kill "${weston_pid}" 2>/dev/null || true
   # shellcheck disable=SC2317
   wait "${weston_pid}" 2>/dev/null || true
   # shellcheck disable=SC2317
   rm --recursive --force -- "${runtime_dir}"
}
trap cleanup EXIT

## Wait for the compositor socket to appear.
socket_ready="false"
for _ in $(seq 1 100); do
   if [ -S "${runtime_dir}/${socket}" ]; then
      socket_ready="true"
      break
   fi
   sleep 0.1
done

if [ "${socket_ready}" != "true" ]; then
   printf 'wayland-run.sh: weston socket did not appear\n' >&2
   cat "${runtime_dir}/weston.log" >&2 || true
   exit 1
fi

export WAYLAND_DISPLAY="${socket}"
export QT_QPA_PLATFORM="wayland"

## Run the target; its exit code is the script's exit code (cleanup runs on EXIT).
rc=0
"$@" || rc=$?
exit "${rc}"
