#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## grub-select-next-boot-mode sets grubenv next_entry to the per-mode menuentry --id,
## so an installed system boots a chosen mode deterministically (no OCR). Drives the
## REAL helper end-to-end against a fixture mounted root + a real grubenv (grub-editenv).
##
## Needs grub-editenv (grub-common); absent -> SKIP 77. No root, no VM, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.bsh

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
if [ -x "${script_dir}/../../libexec/image-test/grub-select-next-boot-mode" ]; then
   helper="${script_dir}/../../libexec/image-test/grub-select-next-boot-mode"
else
   helper='/usr/libexec/image-test/grub-select-next-boot-mode'
fi
[ -x "${helper}" ] || { printf '%s\n' "FATAL: helper not found: '${helper}'" >&2; exit 1; }

if ! has grub-editenv; then
   printf '%s\n' "SKIP: grub-editenv (grub-common) not installed" >&2
   ## style-ok: allow-skip: grub-common is an unavailable runtime in the core dist-ai CI job
   exit 77
fi

dev='11111111-2222-3333-4444-555555555555'
work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  ## reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

pass=0
fail=0

## Write a fixture mounted root whose grub.cfg carries a menuentry per given --id.
make_root() {
   local root="$1" id
   shift
   mkdir --parents -- "${root}/boot/grub"
   for id in "$@"; do
      printf '%s\n' \
         "menuentry 'Kicksecure GNU/Linux' --class os \$menuentry_id_option '${id}' {" \
         "	true" \
         "}"
   done > "${root}/boot/grub/grub.cfg"
}

next_entry_of() {
   grub-editenv "${1}/boot/grub/grubenv" list 2>/dev/null | sed -n 's/^next_entry=//p'
}

check() {
   local label="$1" want="$2" got="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label}: got '${got}' want '${want}'"
      fail=$(( fail + 1 ))
   fi
}

## 1. Unique per-mode ids -> helper selects the sysmaint entry's exact id.
root1="${work_dir}/patched"
make_root "${root1}" \
   "gnulinux-user-${dev}" \
   "gnulinux-persistent-sysmaint-${dev}" \
   "gnulinux-live-sysmaint-${dev}" \
   "gnulinux-remove-sysmaint-${dev}" \
   "gnulinux-simple-${dev}"
MOUNTPOINT="${root1}" "${helper}" persistent-sysmaint >/dev/null
check "selects persistent-sysmaint by its unique id" \
   "gnulinux-persistent-sysmaint-${dev}" "$(next_entry_of "${root1}")"

## live-sysmaint resolves to its OWN id, never the persistent one.
MOUNTPOINT="${root1}" "${helper}" live-sysmaint >/dev/null
check "selects live-sysmaint distinctly" \
   "gnulinux-live-sysmaint-${dev}" "$(next_entry_of "${root1}")"

## 2. CANARY: a pre-patch image shares gnulinux-simple-<dev> across modes, so there is
## no gnulinux-persistent-sysmaint-* id -> the helper MUST fail loud, never select blindly.
root2="${work_dir}/sharedid"
make_root "${root2}" "gnulinux-simple-${dev}" "gnulinux-simple-${dev}"
rc=0
MOUNTPOINT="${root2}" "${helper}" persistent-sysmaint >/dev/null 2>&1 || rc=$?
envdump="$(grub-editenv "${root2}/boot/grub/grubenv" list 2>/dev/null || true)"
if [ "${rc}" -ne 0 ] && [[ "${envdump}" != *"next_entry="* ]]; then
   printf '%s\n' "PASS: shared-id image -> helper fails, next_entry left unset"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: shared-id image: helper rc=${rc}, envdump='${envdump}'"
   fail=$(( fail + 1 ))
fi

## 3. A mode with a regex metachar must be REJECTED, not matched against a valid entry
## ('.' would otherwise match the hyphen in gnulinux-live-sysmaint).
rc2=0
MOUNTPOINT="${root1}" "${helper}" 'live.sysmaint' >/dev/null 2>&1 || rc2=$?
if [ "${rc2}" -ne 0 ]; then
   printf '%s\n' "PASS: invalid mode 'live.sysmaint' rejected (no regex match)"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: invalid mode 'live.sysmaint' was accepted"
   fail=$(( fail + 1 ))
fi

## 4. CANARY: a symlinked boot/grub pointing OUTSIDE the mounted root MUST be refused, so
## the root grub-editenv WRITE cannot escape onto a host path via a crafted guest filesystem.
root3="${work_dir}/escape_root"
escape="${work_dir}/escape_target"
mkdir --parents -- "${root3}/boot" "${escape}"
ln --symbolic -- "${escape}" "${root3}/boot/grub"
rc3=0
MOUNTPOINT="${root3}" "${helper}" persistent-sysmaint >/dev/null 2>&1 || rc3=$?
if [ "${rc3}" -ne 0 ] && [ ! -e "${escape}/grubenv" ]; then
   printf '%s\n' "PASS: symlinked boot/grub escaping the mount refused, no outside write"
   pass=$(( pass + 1 ))
else
   escaped='no'; [ -e "${escape}/grubenv" ] && escaped='yes'
   printf '%s\n' "FAIL: symlink-escape not refused (rc=${rc3}, escape grubenv written=${escaped})"
   fail=$(( fail + 1 ))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ]
