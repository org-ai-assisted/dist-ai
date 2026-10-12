#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-image-build's leaked-loop release being LANE-SCOPED to the invoking
## user's own build tree, so concurrent builds by different users on one host do not clobber
## each other.
##
## THE BUG IT GUARDS (cross-user leak-cleanup): the release matched any loop whose backing file
## contained the bare substring '/derivative-binary/'. On a shared host that matches ANOTHER
## user's '/home/<other>/derivative-binary/...' loop too, so user A's pre-build cleanup would
## `kpartx -d` + `losetup -d` user B's IN-FLIGHT build loop -- corrupting B's build. The release
## is now scoped to the caller's own tree ("${HOME}/derivative-binary/"); a peer's loop under a
## different home is left alone.
##
## Drives the REAL release_leaked_build_loops (sourced define-only) with sudo/losetup/kpartx
## stubbed. No loop devices, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_IMAGE_BUILD:-}" \
   "${test_dir}/../../bin/dm-image-build" \
   "/usr/bin/dm-image-build"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-image-build not found (set DM_IMAGE_BUILD)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

RELEASED="${work}/released"
LOSETUP_LISTING="${work}/losetup.txt"
true > "${RELEASED}"

## A system-wide `losetup -a` listing: this user's build loop, a CONCURRENT peer's build loop
## under a different home, and an unrelated ISO loop. Realistic format so `cut -d: -f1` yields
## the device node.
cat > "${LOSETUP_LISTING}" <<'EOF'
/dev/loop0: [64773]:3 (/home/admin/derivative-binary/1981/base-image.raw)
/dev/loop1: [64773]:7 (/home/other/derivative-binary/1981/base-image.raw)
/dev/loop2: [64773]:9 (/usr/local/share/some-unrelated.iso)
EOF

## sudo stub: serve `losetup -a`, record every `kpartx -d` / `losetup -d` target.
# shellcheck disable=SC2317  ## invoked by the sourced function
sudo() {
   [ "$1" = "--non-interactive" ] && shift
   case "$1 $2" in
      "losetup -a")
         cat -- "${LOSETUP_LISTING}"
         ;;
      "kpartx -d"|"losetup -d")
         printf '%s\n' "$3" >> "${RELEASED}"
         ;;
   esac
   return 0
}

# shellcheck disable=SC1090
source "${subject}"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- Case SCOPED: release only THIS user's loop ---------------------------------------------
true > "${RELEASED}"
release_leaked_build_loops "/home/admin/derivative-binary/"
released_out="$(cat -- "${RELEASED}")"
got=0; has '/dev/loop0' "${released_out}" || got=1
check "this user's build loop IS released" "${got}"
## CANARY: a concurrent peer's loop under another home must NOT be touched. On the old bare
## '/derivative-binary/' match this loop WAS released (the cross-user clobber); it must not be.
got=0; if has '/dev/loop1' "${released_out}"; then got=1; fi
check "peer user's in-flight build loop is NOT released (no cross-user clobber)" "${got}"
got=0; if has '/dev/loop2' "${released_out}"; then got=1; fi
check "unrelated ISO loop is NOT released" "${got}"

## --- Case CANARY-PROOF: the bare global pattern WOULD clobber the peer (what we removed) -----
## Confirms the stub + assertions actually distinguish scoped from global: with the old global
## prefix the peer loop is released, which the scoped Case above forbids.
true > "${RELEASED}"
release_leaked_build_loops "/derivative-binary/"
released_out="$(cat -- "${RELEASED}")"
got=0; has '/dev/loop1' "${released_out}" || got=1
check "canary-proof: global prefix DOES release the peer loop (so scoping is what protects it)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
