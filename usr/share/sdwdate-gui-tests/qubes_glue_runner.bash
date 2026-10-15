#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs INSIDE `unshare --user --mount --map-root-user`. Gives the real
## sdwdate-gui Qubes glue script a private, empty tmpfs /run, the checkout's
## real config-read + scripts (bind-mounted over the installed copy), a crafted
## /etc/sdwdate-gui.d, and PATH stubs for the qrexec-client-vm / qubesdb-read
## externals -- then runs the REAL script (no synthetic copy) and emits its
## stdout, exit code, and the /run side effects for the test to assert.
##
## All inputs arrive via GLUE_* env set by the test harness. Output is
## KEY=VALUE lines on stdout.

## GLUE_* are provided by the test harness via the process environment, so
## shellcheck cannot see their assignment (file-wide directive, before any
## command).
# shellcheck disable=SC2154

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

mount -t tmpfs tmpfs /run
mkdir --parents -- /run/qubes-rpc "/run/user/${GLUE_UID}/sdwdate-gui" /run/sdwdate-gui

if [ "${GLUE_PRECREATE_PROXY_FLAG:-0}" = '1' ]; then
   touch -- "/run/user/${GLUE_UID}/sdwdate-gui/proxy-should-run"
fi
if [ "${GLUE_PRECREATE_CONNECT:-0}" = '1' ]; then
   "${GLUE_MKSOCK}" '/run/qubes-rpc/sdwdate-gui.Connect'
fi
if [ "${GLUE_PRECREATE_CONNECT_SYMLINK:-0}" = '1' ]; then
   ## A stale symlink from a prior proxy-helper run (restart / #7 case).
   ln -s -- /dev/null '/run/qubes-rpc/sdwdate-gui.Connect'
fi
if [ "${GLUE_PRECREATE_SERVER_SOCK:-0}" = '1' ]; then
   "${GLUE_MKSOCK}" "/run/user/${GLUE_UID}/sdwdate-gui/sdwdate-gui-server.socket"
fi

## Real 3c512d1 scripts + config-read over the (stale) installed copy.
mount --bind "${GLUE_SUBJECT}/usr/libexec/sdwdate-gui" /usr/libexec/sdwdate-gui
## Crafted config.
mount --bind "${GLUE_CONFDIR}" /etc/sdwdate-gui.d
## A no-op systemd-notify so the socket-activated proxy can source it and call
## `--ready` without a live systemd (the file must already exist to bind over).
if [ -f /usr/libexec/helper-scripts/systemd-notify.bsh ] \
   && [ -n "${GLUE_SYSTEMD_NOTIFY_STUB:-}" ]; then
   mount --bind "${GLUE_SYSTEMD_NOTIFY_STUB}" \
      /usr/libexec/helper-scripts/systemd-notify.bsh
fi

export PATH="${GLUE_STUBDIR}:${PATH}"
export PYTHONPATH="${GLUE_SUBJECT}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"

## The script may legitimately exit non-zero; capture rather than abort (an
## `if` condition suppresses errexit, so no set +o toggle is needed).
script_rc=0
if script_out="$( "${GLUE_SCRIPT}" < /dev/null 2>/dev/null )"; then
   script_rc=0
else
   script_rc=$?
fi

printf '%s\n' "RESULT_RC=${script_rc}"
printf '%s\n' "RESULT_OUT_B64=$(printf '%s' "${script_out}" | base64 -w0)"

emit_flag() {
   if [ -e "$1" ] || [ -L "$1" ]; then
      printf '%s\n' "$2=1"
   else
      printf '%s\n' "$2=0"
   fi
}
emit_flag "/run/user/${GLUE_UID}/sdwdate-gui/proxy-should-run" PROXY_SHOULD_RUN
emit_flag /run/sdwdate-gui-qubes-should-proxy SHOULD_PROXY_FLAG
emit_flag /run/sdwdate-gui/qubes-gateway-server-disabled DISABLED_FLAG
emit_flag /run/qubes-rpc/sdwdate-gui.Connect CONNECT_ENDPOINT
emit_flag /run/.connect_called CONNECT_CALLED
