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
## are literal shell text, so the ERE single-quotes them. Capture THROUGH the
## closing quote and strip it, so a 'Data/${VMNAME}.qcow2.bak' destination reads
## as extension '.bak' (a mismatch that fails) rather than being silently
## truncated to '.qcow2' -- the extension must be the COMPLETE basename.
# shellcheck disable=SC2016
## || true: a no-match (grep exit 1) or head-closes-early SIGPIPE (141) must
## reach the canary '' branch below, not errexit-kill the shell at this assignment.
export_disk="$(grep -oE 'Data/\$\{VMNAME\}\.[A-Za-z0-9.]+"' -- "${export_step}" | head -n 1 || true)"
export_disk="${export_disk%\"}"
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

## The SAME cp/mv operation must read ${binary_image_qcow2_file} (4400's output)
## AND write the bundle disk. A split check (source somewhere, a .qcow2-named
## destination somewhere) would pass a 4600 that copies a raw to the bundle disk
## while copying the qcow2 elsewhere -- so assert source and destination on one op.
# shellcheck disable=SC2016
case "$(grep -E -- '(cp|mv) -- "\$\{binary_image_qcow2_file\}" "\$\{bundle_qcow2_file\}"' "${export_step}")" in
   '')
      fail "4600 does not ship \${binary_image_qcow2_file} -> \${bundle_qcow2_file} in one op; the bundle disk may be an unconverted raw"
      ;;
   *)
      pass "4600 ships 4400's qcow2 output into the bundle disk in one cp/mv op"
      ;;
esac
## ...and that single destination resolves to the COMPLETE basename
## Data/${VMNAME}.qcow2 (trailing quote required, so a '.qcow2.bak' target fails).
# shellcheck disable=SC2016
case "$(grep -E -- 'bundle_qcow2_file=.*Data/\$\{VMNAME\}\.qcow2"' "${export_step}")" in
   '')
      fail "4600's \${bundle_qcow2_file} target is not Data/\${VMNAME}.qcow2"
      ;;
   *)
      pass "4600 bundle disk target resolves to Data/\${VMNAME}.qcow2"
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
## self-gates, so the guard that CONTROLS conversion -- not a mere mention of
## dist_build_utm in a comment -- MUST test dist_build_utm, or a utm-only build
## produces no qcow2.
convert_step="${DM_CONVERT_QCOW2:-${dm_checkout}/build-steps.d/4400_convert-raw-to-qcow2}"
if [ ! -r "${convert_step}" ]; then
   fail "4400_convert-raw-to-qcow2 not found (set DM_CONVERT_QCOW2 or DERIVATIVE_MAKER_DIR)"
else
   guard_fn="$(sed -n '/^qcow2_build_requested() {$/,/^}$/p' -- "${convert_step}")"
   case "${guard_fn}" in
      '')
         fail "canary: could not extract qcow2_build_requested() from 4400; the assertions below would prove nothing"
         ;;
      *)
         pass "canary: qcow2_build_requested() extracted from 4400"
         ;;
   esac

   ## Execute the REAL predicate (not merely grep its text): a predicate that
   ## CONTAINS the dist_build_utm equality yet is wired to return the wrong
   ## result for a utm-only build would satisfy a text check while still skipping
   ## conversion. Define it in a clean subshell and drive it with each flag.
   run_predicate() {
      (
         unset dist_build_qcow2 dist_build_utm
         [ "$1" = none ] || export "$1=true"
         eval "${guard_fn}"
         qcow2_build_requested
      )
   }
   if run_predicate dist_build_utm; then
      pass "4400's qcow2_build_requested() is TRUE for a utm-only build"
   else
      fail "4400's qcow2_build_requested() is FALSE for dist_build_utm=true; a utm-only build would skip conversion"
   fi
   if run_predicate dist_build_qcow2; then
      pass "4400's qcow2_build_requested() is TRUE for dist_build_qcow2=true"
   else
      fail "4400's qcow2_build_requested() is FALSE for dist_build_qcow2=true"
   fi
   if run_predicate none; then
      fail "4400's qcow2_build_requested() is TRUE with neither flag set; conversion would always run"
   else
      pass "4400's qcow2_build_requested() is FALSE when neither flag is set"
   fi
   ## ...and conversion is actually gated on that predicate, not dead code.
   case "$(grep -E -- 'if qcow2_build_requested' "${convert_step}")" in
      '')
         fail "4400 does not gate conversion on qcow2_build_requested(); the dist_build_utm test would be dead code"
         ;;
      *)
         pass "4400 gates conversion on qcow2_build_requested()"
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
   ## || true: a no-match or head-closes-early SIGPIPE must reach the canary ''
   ## branch (and its continue to the next template), not errexit-kill the shell.
   image_name="$(grep -A1 '<key>ImageName</key>' -- "${template}" | grep -oE '_FLAVOR_\.[A-Za-z0-9]+' | head -n 1 || true)"
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
