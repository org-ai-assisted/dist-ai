#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (behavioral): wl-headless-lib's X11 socket-dir id-squash self-heal.
## A user-namespaced sandbox (Qubes 'sandbox' DEFAULT) idmaps root->nobody, so a root-owned X
## socket dir reads as nobody INSIDE the namespace, Xwayland refuses it, and labwc never publishes
## its Wayland socket. The lib detects that squash and re-execs the entry script inside a private
## user+mount+net namespace with a root-owned socket dir. This asserts:
##   - the squash gate fires ONLY on the squashed view (owner != 0 and != us), not on a
##     root-owned / us-owned / absent dir (a false positive would needlessly namespace CI/host);
##   - the re-exec forwards the EXACT namespace recipe + the original argv;
##   - the WL_HEADLESS_UNSHARED loop-guard runs the private-dir setup and does NOT re-exec;
##   - a non-squashed view is a byte-for-byte no-op (no re-exec).
## The real namespace bringup is proven by a sandbox e2e (not portable to a CI unit); here the
## owner view is faked with PATH shims (stat/id) and the exec is captured via the
## WL_HEADLESS_UNSHARE recorder seam.
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
# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${lib}"

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

## Fake the owner view via PATH shims: stat echoes ${MOCK_STAT_OWNER}, id echoes a fixed uid.
## _wl_headless_x11_squashed reads exactly `stat -c %u` and `id -u`, so this drives its gate
## without needing a really-foreign-owned dir (which a non-root test cannot create).
mkdir --parents -- "${work}/bin"
{
   printf '%s\n' '#!/bin/bash'
   ## The owner value must expand at shim-RUN time, not now -- the single quotes are deliberate.
   # shellcheck disable=SC2016
   printf '%s\n' 'printf "%s\n" "${MOCK_STAT_OWNER:-0}"'
} > "${work}/bin/stat"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" 1000'
} > "${work}/bin/id"
chmod +x "${work}/bin/stat" "${work}/bin/id"
export PATH="${work}/bin:${PATH}"

## Recorder standing in for `env ... unshare ...`: prints the argv it was handed and exits, so
## the exec is captured without spawning a real (unassertable) nested namespace.
recorder="${work}/recorder.sh"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "$*"'
   printf '%s\n' 'exit 0'
} > "${recorder}"
chmod +x "${recorder}"

## Point the gate at a test dir so its existence is under our control (the real socket dir may or
## may not exist on a CI box); the owner is supplied by the stat shim above.
mkdir --parents -- "${work}/x11"
_wl_x11_socket_dir="${work}/x11"

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"
      fail=$(( fail + 1 ))
   fi
}

## --- squash detection -----------------------------------------------------------------------
if MOCK_STAT_OWNER=65534 _wl_headless_x11_squashed; then sq=1; else sq=''; fi
check 'squash detected when owner is neither root nor us (65534)' "${sq}"

if MOCK_STAT_OWNER=0 _wl_headless_x11_squashed; then sq=''; else sq=1; fi
check 'NOT squashed when the dir is root-owned (owner 0)' "${sq}"

if MOCK_STAT_OWNER=1000 _wl_headless_x11_squashed; then sq=''; else sq=1; fi
check 'NOT squashed when the dir is owned by us' "${sq}"

_wl_x11_socket_dir="${work}/absent"
if MOCK_STAT_OWNER=65534 _wl_headless_x11_squashed; then sq=''; else sq=1; fi
check 'NOT squashed when the dir is absent (Xwayland/setup creates it owned by us)' "${sq}"
_wl_x11_socket_dir="${work}/x11"

## --- re-exec recipe + argv forwarding (forced squash) ---------------------------------------
argv="$( MOCK_STAT_OWNER=65534 WL_HEADLESS_UNSHARE="${recorder}" \
   wl_headless_selfheal_reexec /entry/script --line-editing full arg1 )"
ok=1
for tok in 'env' 'WL_HEADLESS_UNSHARED=1' 'unshare' '--user' '--map-root-user' '--mount' '--net' '--' \
   '/entry/script' '--line-editing full arg1'; do
   case " ${argv} " in
      *"${tok}"*)
         ;;
      *)
         ok=''
         ;;
   esac
done
check 'squashed re-exec forwards env WL_HEADLESS_UNSHARED=1 unshare --user --map-root-user --mount --net + original argv' "${ok}"

## --- WL_HEADLESS_UNSHARED loop-guard: run setup, do NOT re-exec ------------------------------
## Stub the privileged setup (mount needs a real namespace) so the guard branch is observable.
# shellcheck disable=SC2317  # invoked indirectly by wl_headless_selfheal_reexec
_wl_headless_setup_private_x11() { printf '%s\n' 'SETUP_CALLED'; }
guard_out="$( MOCK_STAT_OWNER=65534 WL_HEADLESS_UNSHARED=1 WL_HEADLESS_UNSHARE="${recorder}" \
   wl_headless_selfheal_reexec /entry/script arg )"
g1=''
case "${guard_out}" in
   *SETUP_CALLED*)
      g1=1
      ;;
esac
case "${guard_out}" in
   *unshare*)
      g1=''
      ;;
esac
check 'inside the namespace (WL_HEADLESS_UNSHARED) it runs private-dir setup and does not re-exec' "${g1}"

## --- non-squashed is a no-op (no re-exec) ----------------------------------------------------
noop_out="$( MOCK_STAT_OWNER=0 WL_HEADLESS_UNSHARE="${recorder}" \
   wl_headless_selfheal_reexec /entry/script arg )"
if [ -z "${noop_out}" ]; then n1=1; else n1=''; fi
check 'not squashed -> no re-exec, no output (byte-for-byte the existing path)' "${n1}"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: X11 socket-dir id-squash self-heal detects + re-execs correctly'
