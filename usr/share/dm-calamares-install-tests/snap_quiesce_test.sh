#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-calamares-install's snap() milestone capture.
##
## THE BUG IT GUARDS: the live desktop's expected-but-racy notify-send passive popups landed
## nondeterministically in a milestone screenshot and pushed the golden-screenshot diff past
## tolerance (welcome/install-done "differs beyond tolerance"). snap() now QUIESCES the live
## session's notifications (kills the LXQt notification daemon over guestcontrol) and settles
## BEFORE capturing the frame. This pins: the quiesce is issued, as the live 'user' role, with
## the right target, STRICTLY BEFORE the shot -- and that an unset --shot-dir still no-ops.
##
## Drives the REAL snap()/quiesce_notifications (sourced define-only from the shipped script),
## with the guestcontrol boundaries stubbed: gc_run records the quiesce, the GUESTCTL stub
## records the shot, both into one ordered log so the ordering is asserted. No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## One ordered log for both boundaries, so "quiesce before shot" is a line-order assertion.
order="${work}/order"
true > "${order}"

## GUESTCTL stub: snap calls `GUESTCTL vm shot <path>`; record the whole argv.
# shellcheck disable=SC2016  ## the stub body expands ${ORDER} at ITS runtime, not here
printf '%s\n' '#!/bin/bash' 'printf "GUESTCTL %s\n" "$*" >> "${ORDER}"' > "${work}/guestctl"
chmod +x "${work}/guestctl"
export GUESTCTL="${work}/guestctl"
export ORDER="${order}"

# shellcheck disable=SC1090
source "${subject}"

## Stub the in-guest exec + the settle. gc_run records the quiesce (role + snippet) AND runs the
## snippet LOCALLY -- so the REAL kill command fires against a local decoy, catching a kill form
## that silently matches nothing (the 15-char comm-truncation bug). sleep is a no-op.
# shellcheck disable=SC2317
gc_run() {
   printf '%s\n' "GCRUN role=$1 snippet=$2" >> "${order}"
   eval "$2"
   return 0
}
# shellcheck disable=SC2317
sleep() {
   return 0
}

## Globals snap() reads (consumed by the sourced function, not seen by shellcheck).
# shellcheck disable=SC2034
vm="testvm"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}
has() {
   case "$2" in
      *"$1"*)
         return 0
         ;;
      *)
         return 1
         ;;
   esac
}

## --- shot-dir set: quiesce (live user, kill the daemon) STRICTLY before the shot ------------
shot_dir="${work}/shots"
mkdir -- "${shot_dir}"
true > "${order}"

## Decoy that mimics the REAL daemon's /proc comm: a copy of `sleep` named 'lxqt-notificationd'
## gets comm 'lxqt-notificati' (kernel truncates to 15 bytes), exactly like the live daemon.
## The quiesce's kill (run locally by the gc_run stub) must TERMINATE it; a kill form matching
## the full 18-char name hits nothing and the decoy lives to its own short natural exit.
## A short lifetime bounds the FAIL case (no 300s hang) while leaving ample margin to be killed.
cp -- /bin/sleep "${work}/lxqt-notificationd"
"${work}/lxqt-notificationd" 5 &
decoy_pid=$!
## Readiness: wait for the fork to exec and set its truncated comm BEFORE snap fires the
## kill -- else the correct kill form misses a not-yet-exec'd decoy and the pkill assertion
## below reports a FALSE failure. `command sleep` is the real sleep (the SUT's `sleep` is
## stubbed to a no-op above); the wait is bounded (~2s, well under the decoy's 5s lifetime).
decoy_ready=1
for _ in $(seq 1 200); do
   if [ "$(cat "/proc/${decoy_pid}/comm" 2>/dev/null)" = "lxqt-notificati" ]; then
      decoy_ready=0
      break
   fi
   command sleep 0.01
done
## Fail CLOSED + honestly: a decoy that never reached its comm is a harness problem, not a
## pkill bug -- surface it as "decoy not ready", never let it masquerade as a kill failure.
check "decoy reached its truncated comm before snap" "${decoy_ready}"

rc=0
snap 01 welcome || rc=$?
check "snap returns success" "${rc}"

## || true: a MISSING line (old snap with no quiesce) must yield empty + a clean FAIL below,
## not an errexit abort on grep's exit 1.
gc_line="$(grep -n '^GCRUN ' -- "${order}" | head -1 | cut -d: -f1 || true)"
shot_line="$(grep -n '^GUESTCTL ' -- "${order}" | head -1 | cut -d: -f1 || true)"

got=0
[ -n "${gc_line}" ] || got=1
check "snap issues an in-guest quiesce (gc_run)" "${got}"

got=0
[ -n "${shot_line}" ] || got=1
check "snap still captures the frame (GUESTCTL shot)" "${got}"

got=0
{ [ -n "${gc_line}" ] && [ -n "${shot_line}" ] && [ "${gc_line}" -lt "${shot_line}" ]; } || got=1
check "the quiesce happens BEFORE the shot" "${got}"

order_text="$(cat -- "${order}")"
got=0
has 'role=user' "${order_text}" || got=1
check "the quiesce runs in the live 'user' session" "${got}"

## Behavioral: the decoy (comm 'lxqt-notificati') must be TERMINATED BY SIGNAL. wait returns
## >128 for a signal-killed child; 0 means it survived to its own exit -- the comm-truncation
## bug (a kill matching the full 18-char name hits nothing). Bounded by the decoy's short life.
## || capture: a signal-killed child makes wait return >128 (nonzero), which errexit would
## otherwise abort on before wrc is read.
wrc=0
wait "${decoy_pid}" 2>/dev/null || wrc=$?
got=0
[ "${wrc}" -gt 128 ] || got=1
check "the quiesce actually KILLS the daemon (decoy signalled, not survived)" "${got}"

got=0
has '01-welcome.png' "${order_text}" || got=1
check "the shot path carries the milestone NN-name" "${got}"

## --- shot-dir UNSET: snap is a no-op (no quiesce, no shot) ---------------------------------
shot_dir=""
true > "${order}"
rc=0
snap 02 partitions || rc=$?
check "snap with no --shot-dir returns success" "${rc}"
got=0
[ ! -s "${order}" ] || got=1
check "snap with no --shot-dir issues neither quiesce nor shot" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
