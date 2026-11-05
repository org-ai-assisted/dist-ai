#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: the '--target utm' bundle ships a qcow2 disk, and the plist
## drive filename agrees with what 4600_export-utm-packages actually writes.
##
## '--target utm' previously shipped a RAW image. A raw image on an APFS host
## triggers an unaligned-discard error via VirtIO TRIM on Apple Silicon; qcow2
## (UTM's own default drive format) lets QEMU own sparsity instead. The export
## step converts raw -> qcow2 into Data/${VMNAME}.qcow2 via the shared
## 'convert_raw_to_qcow2_image' helper, and each plist template references
## '_FLAVOR_.qcow2' (4600 substitutes _FLAVOR_ -> ${VMNAME}). The plist filename
## and the exported filename MUST agree or UTM cannot find the disk.
##
## THE BUGS IT GUARDS:
##   1. 4600 reverting to shipping a raw image (or any non-qcow2 copy), and
##   2. a plist ImageName whose extension no longer matches the exported file,
##      and
##   3. the shared convert helper losing its real qemu-img qcow2 recipe (a
##      dangling call that converts nothing).
##
## Reads the REAL shipped files (no drift). No root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

## --- Part 1: 4600 converts the raw into a qcow2 disk in the bundle ----------
export_step="${DM_EXPORT_UTM:-${dm_checkout}/build-steps.d/4600_export-utm-packages}"
if [ ! -r "${export_step}" ]; then
   fail "4600_export-utm-packages not found (set DM_EXPORT_UTM or DERIVATIVE_MAKER_DIR)"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi

## The disk path 4600 writes into the bundle: Data/${VMNAME}.<ext>. The '{'/'}'
## are literal shell text, so the ERE single-quotes them.
# shellcheck disable=SC2016
export_disk="$(grep -oE 'Data/\$\{VMNAME\}\.[A-Za-z0-9]+' -- "${export_step}" | head -n 1)"
case "${export_disk}" in
   '')
      fail "canary: could not find the Data/\${VMNAME}.<ext> disk 4600 writes; later assertions would prove nothing"
      printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
      exit 1
      ;;
   *)
      pass "canary: 4600 export disk path extracted (${export_disk})"
      ;;
esac
export_ext="${export_disk##*.}"

case "${export_ext}" in
   qcow2)
      pass "4600 exports a qcow2 disk into the UTM bundle"
      ;;
   *)
      fail "4600 exports a .${export_ext} disk, not qcow2; a raw image hits the APFS discard bug on Apple Silicon"
      ;;
esac

## It must CONVERT via the shared helper, not 'cp' a raw image into the bundle.
case "$(grep -E -- 'convert_raw_to_qcow2_image[[:space:]]' "${export_step}")" in
   '')
      fail "4600 no longer calls 'convert_raw_to_qcow2_image'; the exported disk may be an unconverted raw copy"
      ;;
   *)
      pass "4600 converts the raw image via the shared 'convert_raw_to_qcow2_image' helper"
      ;;
esac
if grep --quiet -E 'Data/\$\{VMNAME\}\.raw' -- "${export_step}"; then
   fail "4600 still copies a raw image (Data/\${VMNAME}.raw) into the UTM bundle"
else
   pass "4600 no longer ships a raw disk in the UTM bundle"
fi

## --- Part 2: the shared helper carries a real qemu-img qcow2 recipe ---------
helpers="${DM_MISC_HELPERS:-${dm_checkout}/help-steps/misc-helpers.bsh}"
if [ ! -r "${helpers}" ]; then
   fail "misc-helpers.bsh not found (set DM_MISC_HELPERS or DERIVATIVE_MAKER_DIR)"
else
   recipe="$(sed -n '/^convert_raw_to_qcow2_image() {$/,/^}$/p' -- "${helpers}")"
   case "${recipe}" in
      '')
         fail "canary: could not extract convert_raw_to_qcow2_image() from misc-helpers.bsh; the assertion below would prove nothing"
         ;;
      *'-O qcow2'*)
         pass "convert_raw_to_qcow2_image() runs 'qemu-img ... -O qcow2'"
         ;;
      *)
         fail "convert_raw_to_qcow2_image() no longer runs 'qemu-img ... -O qcow2'; the call in 4600/4400 converts nothing"
         ;;
   esac
fi

## --- Part 3: each UTM plist references the same-extension disk --------------
utm_dir="${DM_UTM_TEMPLATES:-${dm_checkout}/packages/kicksecure/libvirt-dist/usr/share/utm}"
templates=( Kicksecure Whonix-Gateway Whonix-Workstation )
for name in "${templates[@]}"; do
   template="${utm_dir}/${name}.plist.template"
   if [ ! -r "${template}" ]; then
      fail "${name}.plist.template not found (set DM_UTM_TEMPLATES or DERIVATIVE_MAKER_DIR)"
      continue
   fi
   ## The <ImageName> value, e.g. _FLAVOR_.qcow2. 4600 substitutes
   ## _FLAVOR_ -> ${VMNAME}, so the extension is the whole compatibility story.
   image_name="$(grep -A1 '<key>ImageName</key>' -- "${template}" | grep -oE '_FLAVOR_\.[A-Za-z0-9]+' | head -n 1)"
   case "${image_name}" in
      '')
         fail "canary: could not read ImageName from ${name}.plist.template"
         continue
         ;;
      *)
         pass "canary: ${name} ImageName extracted (${image_name})"
         ;;
   esac
   image_ext="${image_name##*.}"
   if [ "${image_ext}" = "${export_ext}" ]; then
      pass "${name} plist disk .${image_ext} matches the exported .${export_ext}"
   else
      fail "${name} plist references .${image_ext} but 4600 writes .${export_ext}; UTM cannot find the disk"
   fi
done

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: UTM bundle ships qcow2 and plist/export filenames agree."
