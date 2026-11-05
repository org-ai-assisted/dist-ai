#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: the '--target utm' bundle ships a qcow2 disk, and the plist
## drive filename agrees with what 4600_export-utm-packages actually writes.
##
## '--target utm' previously shipped a RAW image. A raw image on an APFS host
## triggers an unaligned-discard error via VirtIO TRIM on Apple Silicon; qcow2
## (UTM's own default drive format) lets QEMU own sparsity instead.
##
## The build reuses 4400_convert-raw-to-qcow2 (which now runs for '--target utm'
## too) to produce ${binary_image_qcow2_file}; 4600 copies that into
## Data/${VMNAME}.qcow2, and each plist template references '_FLAVOR_.qcow2'
## (4600 substitutes _FLAVOR_ -> ${VMNAME}). The plist filename and the exported
## filename MUST agree or UTM cannot find the disk.
##
## THE BUGS IT GUARDS:
##   1. 4600 reverting to shipping a raw image (or any non-qcow2 copy), and
##   2. a plist ImageName whose extension no longer matches the exported file,
##      and
##   3. 4400 no longer running for the utm target (its guard dropping
##      dist_build_utm), so the qcow2 4600 copies would never be produced.
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

## It must ship 4400's qcow2 output (${binary_image_qcow2_file}) -- mv for a
## utm-only build, cp when --target qcow2 also wants the standalone -- not a raw.
# shellcheck disable=SC2016
case "$(grep -E -- '(cp|mv) .*\$\{binary_image_qcow2_file\}' "${export_step}")" in
   '')
      fail "4600 no longer ships \${binary_image_qcow2_file} into the bundle; the exported disk may be an unconverted raw"
      ;;
   *)
      pass "4600 ships 4400's qcow2 output (\${binary_image_qcow2_file})"
      ;;
esac
# shellcheck disable=SC2016
if grep --quiet -E 'Data/\$\{VMNAME\}\.raw' -- "${export_step}"; then
   fail "4600 still copies a raw image (Data/\${VMNAME}.raw) into the UTM bundle"
else
   pass "4600 no longer ships a raw disk in the UTM bundle"
fi

## --- Part 2: 4400 runs for the utm target ----------------------------------
## 4600 copies ${binary_image_qcow2_file}, which only exists if 4400 ran. 4400
## self-gates, so its guard MUST fire for dist_build_utm, not qcow2 alone.
convert_step="${DM_CONVERT_QCOW2:-${dm_checkout}/build-steps.d/4400_convert-raw-to-qcow2}"
if [ ! -r "${convert_step}" ]; then
   fail "4400_convert-raw-to-qcow2 not found (set DM_CONVERT_QCOW2 or DERIVATIVE_MAKER_DIR)"
else
   case "$(grep -E -- 'dist_build_utm' "${convert_step}")" in
      '')
         fail "4400 does not gate on dist_build_utm; it would skip a utm build and 4600 would copy a missing qcow2"
         ;;
      *)
         pass "4400 runs for the utm target (gates on dist_build_utm)"
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
