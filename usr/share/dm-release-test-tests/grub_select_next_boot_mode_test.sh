#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## grub-select-next-boot-mode sets grubenv next_entry to the per-mode menuentry, so an
## installed system boots a chosen mode deterministically (no OCR). It prefers the per-mode
## --id (patched image) and falls back to the exact menuentry TITLE (pre-patch image with a
## shared gnulinux-simple-<dev>) -- GRUB next_entry matches either. Drives the REAL helper
## end-to-end against a fixture mounted root + a real grubenv (grub-editenv).
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

## Write a fixture mounted root modelling a PRE-PATCH installed menu: the real per-mode
## TITLES (Template:BootEntries) but a SINGLE shared gnulinux-simple-<dev> id across every
## entry, so id-based selection is impossible and only the title fallback can resolve a mode.
make_root_titled() {
   local root="$1" shared_id="$2"
   mkdir --parents -- "${root}/boot/grub"
   local title
   for title in \
      'PERSISTENT Mode | USER Session | daily activities' \
      'PERSISTENT Mode | SYSMAINT Session | system maintenance tasks' \
      'LIVE Mode | USER Session | disposable use' \
      'LIVE Mode | SYSMAINT Session | maintenance testing' \
      'REMOVE user-sysmaint-split | enable unrestricted admin mode'
   do
      printf '%s\n' \
         "menuentry '${title}' --class os \$menuentry_id_option '${shared_id}' {" \
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

## 2. CANARY: an image with NEITHER a per-mode id NOR a per-mode menu title (shared
## gnulinux-simple-<dev> and only a generic 'Kicksecure GNU/Linux' title) -> the helper
## MUST fail loud, never select blindly.
root2="${work_dir}/sharedid"
make_root "${root2}" "gnulinux-simple-${dev}" "gnulinux-simple-${dev}"
rc=0
MOUNTPOINT="${root2}" "${helper}" persistent-sysmaint >/dev/null 2>&1 || rc=$?
envdump="$(grub-editenv "${root2}/boot/grub/grubenv" list 2>/dev/null || true)"
if [ "${rc}" -ne 0 ] && [[ "${envdump}" != *"next_entry="* ]]; then
   printf '%s\n' "PASS: no id and no titled menu -> helper fails, next_entry left unset"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: no-id/no-title image: helper rc=${rc}, envdump='${envdump}'"
   fail=$(( fail + 1 ))
fi

## 2b. TITLE FALLBACK: a pre-patch image shares gnulinux-simple-<dev> across modes (no
## per-mode id) but carries the real per-mode TITLES -> the helper selects by the exact
## full title, which GRUB next_entry matches, so every lane works before Part A ships in a
## release. persistent-sysmaint and live-sysmaint must resolve to their OWN distinct titles.
root2b="${work_dir}/sharedid_titled"
make_root_titled "${root2b}" "gnulinux-simple-${dev}"
MOUNTPOINT="${root2b}" "${helper}" persistent-sysmaint >/dev/null
check "title fallback selects the persistent-sysmaint menu title" \
   'PERSISTENT Mode | SYSMAINT Session | system maintenance tasks' "$(next_entry_of "${root2b}")"
MOUNTPOINT="${root2b}" "${helper}" live-sysmaint >/dev/null
check "title fallback selects the live-sysmaint menu title distinctly" \
   'LIVE Mode | SYSMAINT Session | maintenance testing' "$(next_entry_of "${root2b}")"

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

## 5. CANARY (finding 5): a mode that is a PREFIX of a real mode must FAIL, never silently
## select the longer entry. With only the *-sysmaint entries present, mode=persistent must not
## pick gnulinux-persistent-sysmaint-<uuid> (and live must not pick live-sysmaint).
root_pfx="${work_dir}/prefix"
make_root "${root_pfx}" \
   "gnulinux-persistent-sysmaint-${dev}" \
   "gnulinux-live-sysmaint-${dev}" \
   "gnulinux-user-${dev}"
for pm in persistent live; do
   rcp=0
   MOUNTPOINT="${root_pfx}" "${helper}" "${pm}" >/dev/null 2>&1 || rcp=$?
   envdump="$(grub-editenv "${root_pfx}/boot/grub/grubenv" list 2>/dev/null || true)"
   if [ "${rcp}" -ne 0 ] && [[ "${envdump}" != *"next_entry="* ]]; then
      printf '%s\n' "PASS: prefix mode '${pm}' rejected, next_entry left unset"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: prefix mode '${pm}': rc=${rcp}, envdump='${envdump}'"
      fail=$(( fail + 1 ))
   fi
done

## 6. CANARY (finding 2, grubenv.new half): grub-editenv writes <grubenv>.new (fopen FOLLOWS a
## symlink) then renames it onto grubenv. A guest-planted grubenv.new symlink pointing OUTSIDE
## the mount MUST be refused, so the root write cannot escape onto a host path even when grubenv
## itself is absent.
root_gn="${work_dir}/grubenv_new_escape"
gn_escape="${work_dir}/gn_escape_target"
make_root "${root_gn}" "gnulinux-persistent-sysmaint-${dev}"
mkdir --parents -- "${gn_escape%/*}"
ln --symbolic -- "${gn_escape}" "${root_gn}/boot/grub/grubenv.new"
rc5=0
MOUNTPOINT="${root_gn}" "${helper}" persistent-sysmaint >/dev/null 2>&1 || rc5=$?
if [ "${rc5}" -ne 0 ] && [ ! -e "${gn_escape}" ]; then
   printf '%s\n' "PASS: symlinked grubenv.new escaping the mount refused, no outside write"
   pass=$(( pass + 1 ))
else
   gn_written='no'; [ -e "${gn_escape}" ] && gn_written='yes'
   printf '%s\n' "FAIL: grubenv.new symlink-escape not refused (rc=${rc5}, outside written=${gn_written})"
   fail=$(( fail + 1 ))
fi

## 7. CANARY (device-leak/DoS): a crafted guest with grub.cfg as a FIFO (no writer) would
## block the 'grep ^menuentry' FOREVER, so image-mount never reaches its device-teardown trap
## -> leaked nbd/LUKS. nosymfollow does NOT stop FIFOs. The helper MUST refuse a non-regular
## grub.cfg up front. Run under 'timeout': the fix exits fast (refused, rc=1); the pre-fix grep
## hangs until timeout kills it (rc 124).
root_fifo="${work_dir}/fifo_cfg"
mkdir --parents -- "${root_fifo}/boot/grub"
mkfifo -- "${root_fifo}/boot/grub/grub.cfg"
rc_f=0
MOUNTPOINT="${root_fifo}" timeout --kill-after=10 10 "${helper}" persistent-sysmaint >/dev/null 2>&1 || rc_f=$?
if [ "${rc_f}" -ne 0 ] && [ "${rc_f}" -ne 124 ]; then
   printf '%s\n' "PASS: FIFO grub.cfg refused promptly (rc=${rc_f}), no hang"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: FIFO grub.cfg not refused cleanly (rc=${rc_f}; 124 = hung until timeout)"
   fail=$(( fail + 1 ))
fi

## 8. CANARY: grubenv as a FIFO (grub-editenv OPENS it) would likewise block this root process.
## With a valid regular grub.cfg, a FIFO grubenv must be refused at the path-confine step,
## before any grub-editenv open -- same timeout discriminator.
root_fifo_env="${work_dir}/fifo_grubenv"
make_root "${root_fifo_env}" "gnulinux-persistent-sysmaint-${dev}"
mkfifo -- "${root_fifo_env}/boot/grub/grubenv"
rc_fe=0
MOUNTPOINT="${root_fifo_env}" timeout --kill-after=10 10 "${helper}" persistent-sysmaint >/dev/null 2>&1 || rc_fe=$?
if [ "${rc_fe}" -ne 0 ] && [ "${rc_fe}" -ne 124 ]; then
   printf '%s\n' "PASS: FIFO grubenv refused promptly (rc=${rc_fe}), no hang"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: FIFO grubenv not refused cleanly (rc=${rc_fe}; 124 = hung until timeout)"
   fail=$(( fail + 1 ))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ]
