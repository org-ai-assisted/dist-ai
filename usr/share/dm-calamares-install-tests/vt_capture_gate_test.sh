#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-calamares-install's post-install VT console capture gate.
##
## WHAT IT GUARDS: the --checks lane screenshots four virtual-terminal milestones
## (vt-switched, vt-logged-in, vt-logged-out, vt-graphical-restored). story_snap is
## best-effort, so an empty/partial set must NOT silently skip the gate (a false green).
## require_vt_captures REQUIRES each capture this run and blank-checks them --uniform-only;
## vt_console_lane first clears stale *-vt-*.png so a reused shot_dir cannot be satisfied by a
## prior run's files. The gate's four names are duplicated from vt_console_lane's story_snap
## calls -- a future rename/glob drift between them would regress the gate silently.
##
## Drives the REAL functions (sourced define-only from the shipped script). Boundaries stubbed:
## GUESTCTL (writes the shot file story_snap asks for), sleep (no-op), image-blank-check (records
## its argv, exit code controlled per-case). No VM, no root, no network.

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

# shellcheck disable=SC1090
source "${subject}"

## image-blank-check stub: records its argv to BLANK_LOG, exits BLANK_RC (default 0). Lets a case
## assert the flag/paths passed and force the blank branch.
export BLANK_LOG="${work}/blank-args"
export BLANK_RC=0
touch -- "${BLANK_LOG}"
# shellcheck disable=SC2016  ## the stub body expands ${BLANK_LOG}/${BLANK_RC} at ITS runtime
printf '%s\n' \
   '#!/bin/bash' \
   'printf "%s\n" "$*" >> "${BLANK_LOG}"' \
   'exit "${BLANK_RC:-0}"' \
   > "${work}/image-blank-check"
chmod +x "${work}/image-blank-check"
export IMAGE_BLANK_CHECK="${work}/image-blank-check"

## GUESTCTL stub: story_snap runs `GUESTCTL vm shot <path>` -- create the file so the REAL
## story_snap populates shot_dir; drain the type-stdin pipe. Everything else is a no-op.
# shellcheck disable=SC2016  ## the stub body uses ITS OWN $2/$3 at runtime, not the test's
printf '%s\n' \
   '#!/bin/bash' \
   'case "$2" in' \
   '   shot) touch -- "$3" ;;' \
   '   type-stdin) cat > /dev/null 2>&1 || true ;;' \
   'esac' \
   'exit 0' \
   > "${work}/guestctl"
chmod +x "${work}/guestctl"
export GUESTCTL="${work}/guestctl"

## sleep paces the real lane -- no-op here.
# shellcheck disable=SC2317
sleep() {
   return 0
}

## Globals the sourced functions read (consumed by them, not seen by shellcheck).
# shellcheck disable=SC2034
vm="testvm"
## The gate's die code, defined by the sourced subject (invisible to shellcheck here).
# shellcheck disable=SC2154
expected_rc="${FAIL_RC}"

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

## --- Case A: end-to-end drift guard -- lane output satisfies the gate --------------------------
## Runs the REAL vt_console_lane (GUESTCTL stub writes each story_snap file), then the REAL
## require_vt_captures over the same dir. Ties the gate's four names to story_snap's four names:
## a rename on EITHER side breaks this.
## CANARY: rename one story_snap or one require_vt_captures name and this FAILS.
shots_a="${work}/a"
mkdir --parents -- "${shots_a}"
# shellcheck disable=SC2034  ## read by the sourced vt_console_lane/story_snap, not the test
shot_dir="${shots_a}"
( vt_console_lane ) >/dev/null 2>&1 || true

got=0
for n in 70-vt-switched 71-vt-logged-in 72-vt-logged-out 73-vt-graphical-restored; do
   [ -e "${shots_a}/${n}.png" ] || got=1
done
check "vt_console_lane produced all four story_snap captures" "${got}"

rc=0
( require_vt_captures "${shots_a}" ) >/dev/null 2>&1 || rc=$?
check "require_vt_captures passes on a complete lane (names in sync)" "${rc}"

blank_line="$(tail -n 1 -- "${BLANK_LOG}")"
got=0
has '--uniform-only' "${blank_line}" || got=1
check "blank-check invoked --uniform-only" "${got}"
got=0
for n in vt-switched vt-logged-in vt-logged-out vt-graphical-restored; do
   has "${n}.png" "${blank_line}" || got=1
done
check "blank-check invoked with all four VT captures" "${got}"

## --- Case B: a missing capture dies ------------------------------------------------------------
## CANARY: pre-#705 a partial set was not required -- the gate passed (false green).
shots_b="${work}/b"
mkdir --parents -- "${shots_b}"
for n in 70-vt-switched 71-vt-logged-in 72-vt-logged-out; do
   touch -- "${shots_b}/${n}.png"
done
rc=0
out="$(require_vt_captures "${shots_b}" 2>&1)" || rc=$?
got=0; [ "${rc}" -eq "${expected_rc}" ] || got=1
check "missing capture dies with FAIL_RC" "${got}"
got=0; has 'vt-graphical-restored' "${out}" || got=1
check "missing-capture message names the absent capture" "${got}"

## --- Case C: an empty set dies (the exact false-green #705 closed) ------------------------------
## CANARY: pre-#705 an empty story_snap set silently skipped the gate.
shots_c="${work}/c"
mkdir --parents -- "${shots_c}"
rc=0
out="$(require_vt_captures "${shots_c}" 2>&1)" || rc=$?
got=0; [ "${rc}" -eq "${expected_rc}" ] || got=1
check "empty set dies with FAIL_RC" "${got}"
got=0; has 'missing' "${out}" || got=1
check "empty-set message reports a missing capture" "${got}"

## --- Case D: a blank VT grab dies (blank branch + --uniform-only) ------------------------------
## CANARY: without the --uniform-only blank-check a truly-blank VT grab passes.
shots_d="${work}/d"
mkdir --parents -- "${shots_d}"
for n in 70-vt-switched 71-vt-logged-in 72-vt-logged-out 73-vt-graphical-restored; do
   touch -- "${shots_d}/${n}.png"
done
export BLANK_RC=1
rc=0
out="$(require_vt_captures "${shots_d}" 2>&1)" || rc=$?
export BLANK_RC=0
got=0; [ "${rc}" -eq "${expected_rc}" ] || got=1
check "blank VT grab dies with FAIL_RC" "${got}"
got=0; has 'blank' "${out}" || got=1
check "blank-grab message reports a blank grab" "${got}"

## --- Case E: stale-clear drops prior VT grabs, keeps non-VT cards ------------------------------
## CANARY: pre-#705 there was no stale-clear -- a reused shot_dir satisfied the gate with old files.
shots_e="${work}/e"
mkdir --parents -- "${shots_e}"
for n in 60-vt-switched 61-vt-logged-in 73-vt-graphical-restored; do
   touch -- "${shots_e}/${n}.png"
done
touch -- "${shots_e}/10-firmware-state.png"
clear_stale_vt_captures "${shots_e}"
got=0
for f in "${shots_e}"/*-vt-*.png; do
   [ -e "${f}" ] && got=1
done
check "stale-clear removed every *-vt-*.png" "${got}"
got=0; [ -e "${shots_e}/10-firmware-state.png" ] || got=1
check "stale-clear kept the non-VT state card" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
