#!/bin/bash

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the kernel-image selection in dm-raw-to-iso.
##
## The tool picks the newest /boot/vmlinuz-* with:
##   kernel_img="$(chroot ... | grep '^vmlinuz-' | sort -V | tail -n 1 || true)"
##   [ -n "${kernel_img}" ] || error "no /boot/vmlinuz-* kernel found ..."
##
## Two properties, both against the REAL lines pulled out of the script (no copy,
## so it cannot drift from the source):
##   1. version sort: vmlinuz-5.19 is newer than vmlinuz-5.9 (a lexical sort
##      would wrongly pick 5.9).
##   2. no-kernel diagnostic FIRES: without the '|| true', grep's exit 1 (no
##      match) trips pipefail+errexit and aborts the assignment, making the error
##      line dead code -- the operator gets a bare exit 1, no message. This case
##      FAILS on that old code (no diagnostic, wrong rc) and passes once the guard
##      can run.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

bin="${DM_RAW_TO_ISO_BIN:-/usr/bin/dm-raw-to-iso}"
[ -r "${bin}" ] || { printf 'FATAL: dm-raw-to-iso not readable: %s\n' "${bin}" >&2 ; exit 1 ; }

pass=0
fail=0

tmp="$(mktemp --directory --tmpdir dm-raw-to-iso-kerneltest.XXXXXX)"
cleanup() {
   # shellcheck disable=SC2317  # reached only via the EXIT trap
   safe-rm --recursive --force -- "${tmp}" 2>/dev/null || true
}
trap cleanup EXIT

## Pull the two real selection lines out of the script: from the 'kernel_img='
## assignment through the 'no /boot/vmlinuz-*' guard. Reading the current text
## means the test exercises exactly what ships.
snippet="$(awk '/^kernel_img=/{f=1} f{print} /no \/boot\/vmlinuz/{f=0}' "${bin}")"
case "${snippet}" in
   *kernel_img=*"no /boot/vmlinuz-"*)
      ;;
   *)
      printf 'FATAL: could not extract the kernel-selection lines from %s\n' "${bin}" >&2
      exit 1
      ;;
esac

## Run the extracted lines as the TOP LEVEL of a child bash under the tool's own
## 'set -e -o pipefail' -- the real dm-raw-to-iso is exactly such a top-level
## script, and errexit on a failing 'var=$(pipeline)' assignment behaves
## differently when nested in a function/subshell, so wrapping the lines in a
## function here would mask the very bug under test. A stub chroot lists the
## fixture /boot (no root, no real chroot); a stub error records + exits 3.
run_snippet() {
   local rootfs="$1"
   local child="${tmp}/child.sh"
   {
      cat <<'PROLOGUE'
set -o errexit
set -o pipefail
chroot() { local root="$1" ; ls -1 "${root}/boot" ; }
error() { printf 'KERNEL_ERROR: %s\n' "$*" >&2 ; exit 3 ; }
rootfs="$1"
PROLOGUE
      printf '%s\n' "${snippet}"
      printf '%s\n' 'printf '\''SELECTED:%s\n'\'' "${kernel_img}"'
   } > "${child}"
   bash -- "${child}" "${rootfs}"
}

expect() {
   local desc="$1" want_rc="$2" needle="$3" rootfs="$4"
   local out rc=0
   out="$(run_snippet "${rootfs}" 2>&1)" || rc=$?
   local ok=true
   [ "${rc}" -eq "${want_rc}" ] || ok=false
   case "${out}" in *"${needle}"*) : ;; *) ok=false ;; esac
   if [ "${ok}" = true ]; then
      printf 'PASS: %s (rc=%s, matched "%s")\n' "${desc}" "${rc}" "${needle}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL: %s: want rc=%s + "%s", got rc=%s:\n%s\n' "${desc}" "${want_rc}" "${needle}" "${rc}" "${out}" >&2
      fail=$(( fail + 1 ))
   fi
}

## Fixture A: two kernels -> newest by version sort wins.
mkdir -p -- "${tmp}/multi/boot"
touch -- "${tmp}/multi/boot/vmlinuz-5.9.0-1-amd64"
touch -- "${tmp}/multi/boot/vmlinuz-5.19.0-1-amd64"
touch -- "${tmp}/multi/boot/config-5.19.0-1-amd64"
touch -- "${tmp}/multi/boot/initrd.img-5.19.0-1-amd64"
expect 'newest kernel by version sort' 0 'SELECTED:vmlinuz-5.19.0-1-amd64' "${tmp}/multi"

## Fixture B: no vmlinuz-* -> the diagnostic must fire (dead on the pre-fix code).
mkdir -p -- "${tmp}/nokernel/boot"
touch -- "${tmp}/nokernel/boot/config-5.19.0-1-amd64"
expect 'no-kernel diagnostic fires (not a bare exit)' 3 'no /boot/vmlinuz-* kernel found' "${tmp}/nokernel"

printf '\nkernel_selection: %s pass, %s fail\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
[ "${pass}" -gt 0 ] || { printf 'FATAL: no assertions ran\n' >&2 ; exit 1 ; }
exit 0
