#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for kicksecure-base-files
## 'etc/default/grub.d/30_kicksecure.cfg'.
##
## THE BUG IT GUARDS: the snippet chose the grub theme and resolution with
## 'if [ -d /sys/firmware/efi ]'. grub-mkconfig sources it inside the BUILD
## chroot, and help-steps/chroot-raw mounts a fresh sysfs there, so that test read
## the BUILD HOST's firmware rather than the target's. Consequences, both real:
##   - two build hosts produced two different images from identical source, which
##     a reproducibility comparison reports as a mismatch with no defect behind it
##   - a BIOS-booted build host stamped the 4:3 theme onto every image, whatever
##     display it would run on
## Firmware type does not indicate panel aspect ratio in the first place.
##
## The snippet also created and removed symlinks under an absolute /boot/grub
## path at grub-mkconfig time; the variant is now a shipped symlink, so the file
## is declarative and sourcing it has no effect on the system doing the sourcing.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

package_dir=""
locate_subject() {
   local candidate

   for candidate in "${KICKSECURE_BASE_FILES_DIR:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/packages/kicksecure/kicksecure-base-files" \
      "${HOME}/derivative-maker/packages/kicksecure/kicksecure-base-files"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}/etc/default/grub.d/30_kicksecure.cfg" ]; then
         package_dir="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: kicksecure-base-files not checked out (set KICKSECURE_BASE_FILES_DIR)." >&2
   exit 77
fi

subject="${package_dir}/etc/default/grub.d/30_kicksecure.cfg"
links_file="${package_dir}/debian/kicksecure-base-files.links"

## Every assertion below is about what the file DOES, so comments are stripped
## first: the snippet's own rationale comments name the very constructs the
## assertions forbid, and would match them.
code_only="$(grep --invert-match --extended-regexp -- '^[[:space:]]*#' "${subject}" || true)"
if [ -z "${code_only}" ]; then
   fail "30_kicksecure.cfg has no non-comment lines; it would set nothing"
fi

## --- the bug itself --------------------------------------------------------
case "${code_only}" in
   *'/sys/firmware/efi'*)
      fail "30_kicksecure.cfg still branches on /sys/firmware/efi, which is the BUILD HOST's firmware at grub-mkconfig time"
      ;;
   *)
      pass "30_kicksecure.cfg does not inspect the build host's firmware"
      ;;
esac

## Any conditional at all reintroduces the same class of defect: whatever it
## tests, it is testing the build environment, because that is where it runs.
if printf '%s\n' "${code_only}" | grep --quiet --extended-regexp -- '^[[:space:]]*(if|case)[[:space:]]'; then
   fail "30_kicksecure.cfg branches on something; at grub-mkconfig time any condition reads the build environment"
else
   pass "30_kicksecure.cfg is unconditional, so every build host produces the same result"
fi

## --- no filesystem writes --------------------------------------------------
## This is also what makes sourcing it below safe.
write_hits=""
for forbidden in 'rm ' 'ln ' 'mkdir ' 'cp ' 'mv '; do
   case "${code_only}" in
      *"${forbidden}"*)
         write_hits="${write_hits} ${forbidden%% }"
         ;;
   esac
done
safe_to_source=true
if [ -z "${write_hits}" ]; then
   pass "30_kicksecure.cfg performs no filesystem writes"
else
   safe_to_source=false
   fail "30_kicksecure.cfg still runs:${write_hits} -- grub-mkconfig sources this, so it mutates whatever machine runs it"
fi

## --- the variant is shipped, not created -----------------------------------
if [ ! -r "${links_file}" ]; then
   fail "debian/kicksecure-base-files.links not found; the theme symlinks cannot be shipped"
else
   for link_pair in \
      "background-16x9.png:background.png" \
      "theme-16x9.txt:theme.txt"; do
      link_target="${link_pair%%:*}"
      link_name="${link_pair#*:}"
      if grep --quiet --fixed-strings -- \
         "/boot/grub/themes/kicksecure/${link_target} /boot/grub/themes/kicksecure/${link_name}" \
         "${links_file}"; then
         pass "${link_name} is shipped as a symlink to ${link_target}"
      else
         fail "${link_name} is not declared in debian/kicksecure-base-files.links; nothing creates it now"
      fi
      if [ -r "${package_dir}/boot/grub/themes/kicksecure/${link_target}" ]; then
         pass "symlink target ${link_target} exists in the package"
      else
         fail "symlink target ${link_target} is missing; the shipped symlink would dangle"
      fi
   done
fi

## --- the values the snippet actually sets ----------------------------------
## Gated on the write-freedom assertion above, and not merely documented as
## depending on it: the pre-fix file removed and recreated symlinks under an
## ABSOLUTE /boot/grub path, so sourcing a file that failed that assertion would
## rewrite the bootloader theme of the machine running the test. It has to be
## refused, not warned about.
if [ ! "${safe_to_source}" = "true" ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s); refusing to source a snippet that writes to /boot." >&2
   exit 1
fi

values="$(bash -- "${test_dir}/grub_theme_pinning_inner.sh" "${subject}")"

case "${values}" in
   *"GRUB_THEME=/boot/grub/themes/kicksecure/theme.txt"*)
      pass "GRUB_THEME points at the shipped theme.txt symlink"
      ;;
   *)
      fail "GRUB_THEME is not the shipped theme.txt -- ${values}"
      ;;
esac

case "${values}" in
   *"GRUB_GFXMODE=1280x720"*)
      pass "GRUB_GFXMODE pins 1280x720 (16:9)"
      ;;
   *)
      fail "GRUB_GFXMODE is not 1280x720 -- ${values}"
      ;;
esac

## A mode the firmware cannot set must degrade to grub's own choice rather than
## to an unreadable console.
case "${values}" in
   *"GRUB_GFXMODE="*",auto"*)
      pass "GRUB_GFXMODE carries an 'auto' fallback"
      ;;
   *)
      fail "GRUB_GFXMODE has no fallback; firmware that cannot set the mode gets no menu -- ${values}"
      ;;
esac

## CANARY: the sourcing above must really be reading this file, not reporting
## defaults. GRUB_DISTRIBUTOR is set by the same file and is unrelated to the fix.
case "${values}" in
   *"GRUB_DISTRIBUTOR=Kicksecure"*)
      pass "canary: the snippet was actually sourced (GRUB_DISTRIBUTOR came through)"
      ;;
   *)
      fail "canary broken: GRUB_DISTRIBUTOR is unset, so the assertions above read nothing -- ${values}"
      ;;
esac

## --- the postinst must not clobber the shipped aliases ----------------------
## kicksecure-base-files.postinst enumerates every file in the dist-base-files
## 'dist-common' theme directory and, for each, removes the same-named file under
## themes/kicksecure and symlinks it to '../dist-common/<name>'. If dist-common
## ever gains 'background.png' or 'theme.txt', it would delete the 16:9 aliases
## this package ships and silently repoint them -- undoing the pinning at install
## time, with nothing in this repo changing.
##
## The collision is enforced here rather than left as a note, so the day
## dist-base-files adds one of those names it fails a test instead of shipping.
dist_common=""
for candidate in "${DIST_COMMON_DIR:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/packages/kicksecure/dist-base-files/boot/grub/themes/dist-common" \
   "${HOME}/derivative-maker/packages/kicksecure/dist-base-files/boot/grub/themes/dist-common"; do
   [ -n "${candidate}" ] || continue
   if [ -d "${candidate}" ]; then
      dist_common="${candidate}"
      break
   fi
done

if [ -z "${dist_common}" ]; then
   printf '%s\n' 'NOTE: dist-base-files dist-common not checked out; collision check skipped.' >&2
else
   collision=""
   for alias_name in background.png theme.txt; do
      if [ -e "${dist_common}/${alias_name}" ]; then
         collision="${collision} ${alias_name}"
      fi
   done
   if [ -z "${collision}" ]; then
      pass "dist-common ships no name that would clobber the shipped aliases"
   else
      fail "dist-common now ships:${collision} -- the postinst would replace the pinned 16:9 alias(es) with links to dist-common"
   fi
   ## CANARY: the directory must be non-empty, or the check above passes
   ## vacuously against a missing/empty checkout.
   if [ -n "$(ls -A -- "${dist_common}" 2>/dev/null)" ]; then
      pass "canary: dist-common is populated, so the collision check is meaningful"
   else
      fail "canary: dist-common is empty; the collision check proves nothing"
   fi
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: grub theme pinning."
