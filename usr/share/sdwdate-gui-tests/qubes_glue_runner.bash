#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs INSIDE `unshare --user --mount --map-root-user`. Builds a SELF-CONTAINED
## root for the real sdwdate-gui Qubes glue script -- it does NOT depend on an
## installed sdwdate-gui (a clean CI container has none): a private tmpfs /run,
## tmpfs over /usr/libexec and /usr/local, and an overlay over /etc, so the glue
## scripts' hardcoded absolute paths exist as mount points even with nothing
## installed. The REAL checkout scripts + config-read are bind-mounted in (no
## synthetic copy); BOTH config dirs the subject reads (/etc/sdwdate-gui.d and
## the higher-priority /usr/local/etc/sdwdate-gui.d) are isolated so no host
## config can leak in. It runs the REAL script and emits its stdout, exit code,
## and the /run side effects for the test to assert.
##
## All inputs arrive via GLUE_* env set by the test harness. Output is
## KEY=VALUE lines on stdout.
##
## Adversary-controlled process env is OUT OF SCOPE (dist-ai policy: trust the
## env). The BASH_ENV / exported-function clearing below is a cheap guard
## against an ACCIDENTAL inherited `mount`/`mkdir` shadow polluting the host
## /run, not an adversarial hardening claim.

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

## Drop any inherited BASH_ENV / exported shell functions so a shadowed
## `mount` (etc.) cannot run before the real binaries. No command that matters
## runs before this point (only set/shopt/export builtins).
unset BASH_ENV ENV || true
while read -r _inherited_fn; do
   unset -f "${_inherited_fn}" || true
done < <(compgen -A function || true)

## Fail loud if a mount did not actually take -- a silently no-op mount would
## let /run side effects and config reads fall through to the HOST.
assert_mounted() {
   if ! mountpoint -q -- "$1"; then
      printf '%s\n' "FATAL: expected a mount at '$1' but found none" >&2
      exit 1
   fi
}

## Private, empty /run first -- the overlay workdirs and all side effects live
## here, so this must be a fresh tmpfs before anything writes under /run.
mount -t tmpfs tmpfs /run
assert_mounted /run
mkdir --parents -- /run/qubes-rpc "/run/user/${GLUE_UID}/sdwdate-gui" \
   /run/sdwdate-gui /run/.etc-upper /run/.etc-work

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

## Writable, EMPTY /usr/libexec -- the glue scripts' hardcoded sibling + helper
## paths get created here with no installed sdwdate-gui present.
mount -t tmpfs tmpfs /usr/libexec
assert_mounted /usr/libexec
mkdir --parents -- /usr/libexec/sdwdate-gui /usr/libexec/helper-scripts

## Writable, EMPTY /usr/local so the higher-priority /usr/local/etc/sdwdate-gui.d
## is empty in the namespace -- a host file there must not override the test.
mount -t tmpfs tmpfs /usr/local
assert_mounted /usr/local
mkdir --parents -- /usr/local/etc/sdwdate-gui.d

## Writable /etc via overlay (NOT tmpfs): preserves /etc/passwd so the
## proxy-helper's `id -u "${default_user}"` still resolves, while letting us
## create the /etc/sdwdate-gui.d mount point on a clean system.
mount -t overlay overlay \
   -o lowerdir=/etc,upperdir=/run/.etc-upper,workdir=/run/.etc-work /etc
assert_mounted /etc
mkdir --parents -- /etc/sdwdate-gui.d

## Real checkout scripts + config-read (no synthetic copy).
mount --bind "${GLUE_SUBJECT}/usr/libexec/sdwdate-gui" /usr/libexec/sdwdate-gui
assert_mounted /usr/libexec/sdwdate-gui
## Crafted config, bound OVER /etc/sdwdate-gui.d so only the test config is
## visible (any overlay-merged host config is shadowed).
mount --bind "${GLUE_CONFDIR}" /etc/sdwdate-gui.d
assert_mounted /etc/sdwdate-gui.d
## A no-op systemd-notify so the socket-activated proxy can source it and call
## `--ready` without a live systemd. /usr/libexec/helper-scripts is a fresh
## tmpfs, so write the stub straight in (a test stub, not a subject script).
cp -- "${GLUE_SYSTEMD_NOTIFY_STUB}" /usr/libexec/helper-scripts/systemd-notify.bsh

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

## The .Connect endpoint must be a SYMLINK to the server socket, not merely a
## path that exists (a bare `touch` would satisfy existence). Report symlink-ness
## and the link TARGET so the test can assert both.
if [ -L /run/qubes-rpc/sdwdate-gui.Connect ]; then
   printf '%s\n' "CONNECT_IS_SYMLINK=1"
   connect_link_target="$(readlink -- /run/qubes-rpc/sdwdate-gui.Connect)"
else
   printf '%s\n' "CONNECT_IS_SYMLINK=0"
   connect_link_target=''
fi
printf '%s\n' "CONNECT_LINK_TARGET_B64=$(printf '%s' "${connect_link_target}" | base64 -w0)"

## Every target VM the glue passed to qrexec-client-vm (one per line), so the
## test can assert the proxy talks to the CONFIGURED gateway, not an attacker VM.
qrexec_targets=''
if [ -f /run/.qrexec_targets ]; then
   qrexec_targets="$(cat -- /run/.qrexec_targets)"
fi
printf '%s\n' "QREXEC_TARGETS_B64=$(printf '%s' "${qrexec_targets}" | base64 -w0)"
