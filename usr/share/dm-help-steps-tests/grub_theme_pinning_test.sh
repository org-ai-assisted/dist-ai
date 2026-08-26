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
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

dm_root=""
for candidate in "${DERIVATIVE_MAKER_DIR:-}" "${dm_checkout}"; do
   [ -n "${candidate}" ] || continue
   if [ -d "${candidate}/packages" ]; then
      dm_root="${candidate}"
      break
   fi
done
## KICKSECURE_BASE_FILES_DIR still overrides, so a single package can be checked
## in isolation (the canary run does exactly that).
single_pkg="${KICKSECURE_BASE_FILES_DIR:-}"
if [ -z "${dm_root}" ] && [ -z "${single_pkg}" ]; then
   printf '%s\n' "FATAL: derivative-maker not checked out (set DERIVATIVE_MAKER_DIR or KICKSECURE_BASE_FILES_DIR)." >&2
   exit 1
fi

## Packages actually inspected. A run where every submodule is uninitialized
## proves nothing, so it must FAIL rather than report success.
packages_checked=0

## Each package selects its own theme variant with the same snippet shape, so the
## checks are run per package rather than copied per file. A package that IS
## checked out but has lost its snippet is reported, never skipped silently.
check_package() {
   local pkg_dir="$1" snippet="$2" label="$3"
   local subject links_file code_only values write_hits forbidden candidate_links
   local link_target link_name alias_name shipped variant helper_matches theme_name

   subject="${pkg_dir}/etc/default/grub.d/${snippet}"
   ## A glob, not 'ls': the file is named after the package and there is at most
   ## one, so a plain expansion is both correct and quoting-safe.
   links_file=""
   for candidate_links in "${pkg_dir}"/debian/*.links; do
      if [ -r "${candidate_links}" ]; then
         links_file="${candidate_links}"
         break
      fi
   done

   ## An uninitialized submodule is not a defect in the package: the directory is
   ## absent or empty because nobody ran 'git submodule update --init', and
   ## reporting that as a missing snippet sends the reader after a file that was
   ## never meant to be there. A CHECKED-OUT package missing its snippet still
   ## fails below.
   if [ ! -d "${pkg_dir}" ] || [ -z "$(ls -A -- "${pkg_dir}" 2>/dev/null)" ]; then
      printf '%s\n' "NOTE: ${label}: not checked out under '${pkg_dir}'; skipping this package." >&2
      return 0
   fi
   packages_checked=$(( packages_checked + 1 ))

   if [ ! -r "${subject}" ]; then
      fail "${label}: ${snippet} not found under ${pkg_dir}"
      return 0
   fi

   ## The theme directory name differs per package (kicksecure, whonix-gateway,
   ## whonix-workstation), so read it from the snippet instead of assuming one.
   theme_name="$(sed -n 's|^GRUB_THEME="/boot/grub/themes/\([^/]*\)/theme.txt"|\1|p' -- "${subject}" | head -1)"
   if [ -z "${theme_name}" ]; then
      fail "${label}: could not read the theme directory from GRUB_THEME"
      return 0
   fi


   ## Every assertion below is about what the file DOES, so comments are stripped
   ## first: the snippet's own rationale comments name the very constructs the
   ## assertions forbid, and would match them.
   code_only="$(grep --invert-match --extended-regexp -- '^[[:space:]]*#' "${subject}" || true)"
   if [ -z "${code_only}" ]; then
      fail "${label} ${snippet} has no non-comment lines; it would set nothing"
   fi

   ## --- the bug itself --------------------------------------------------------
   case "${code_only}" in
      *'/sys/firmware/efi'*)
         fail "${label} ${snippet} still branches on /sys/firmware/efi, which is the BUILD HOST's firmware at grub-mkconfig time"
         ;;
      *)
         pass "${label} ${snippet} does not inspect the build host's firmware"
         ;;
   esac

   ## A conditional that reads the BUILD ENVIRONMENT reintroduces the defect. A
   ## guard on a PACKAGE-SHIPPED image file ('if test -f "/boot/grub/themes/..."')
   ## is deterministic on every build host -- the refactor added one so a
   ## removed-not-purged theme file cannot abort update-grub. Strip that allowed
   ## guard; any REMAINING branch is build-environment-dependent.
   residual="$( grep --invert-match --extended-regexp -- '^[[:space:]]*if[[:space:]]+(test|\[)[[:space:]].*/boot/grub/themes/' <<< "${code_only}" )"
   if grep --quiet --extended-regexp -- '^[[:space:]]*(if|case)[[:space:]]' <<< "${residual}"; then
      fail "${label} ${snippet} branches on the build environment, not a shipped-theme-file guard"
   else
      pass "${label} ${snippet} branches only on shipped image files, deterministic per build host"
   fi

   ## --- the copy must be 'cp', never 'ln' -------------------------------------
   ## The variant is selected at grub-mkconfig time rather than shipped as a dpkg
   ## symlink: at install time /boot may not be mounted, and a /boot that is itself
   ## a symlink makes a packaged link under it fail. A COPY is inert; a symlink
   ## under /boot carries the same hazards the packaged link had.
   case "${code_only}" in
      *"ln "*)
         fail "${label} ${snippet} creates a SYMLINK under /boot; use cp -- a link there hits the same /boot-not-mounted and /boot-is-a-symlink hazards"
         ;;
      *)
         pass "${label} ${snippet} creates no symlink under /boot"
         ;;
   esac

   case "${code_only}" in
      *"cp --remove-destination"*)
         pass "the variant is copied with --remove-destination"
         ;;
      *cp*)
         fail "${label} ${snippet} copies without --remove-destination: an existing background.png left as a SYMLINK would be written THROUGH, corrupting its target"
         ;;
      *)
         fail "${label} ${snippet} does not copy the 16:9 variant into place at all"
         ;;
   esac

   ## Both names must be produced, or grub renders a half-applied theme.
   for produced in background.png theme.txt; do
      case "${code_only}" in
         *"${produced}"*)
            pass "${produced} is produced by the snippet"
            ;;
         *)
            fail "${produced} is never produced; GRUB_THEME would point at a missing file"
            ;;
      esac
   done

   ## --- the aliases must NOT be shipped by dpkg -------------------------------
   ## A packaged link under /boot is exactly what this design avoids, so its
   ## reappearance in debian/*.links is a regression, not an alternative.
   if [ ! -r "${links_file}" ]; then
      pass "no debian/kicksecure-base-files.links to ship /boot aliases from"
   else
      shipped=""
      for alias_name in background.png theme.txt; do
         if grep --quiet --fixed-strings -- "/boot/grub/themes/${theme_name}/${alias_name}" "${links_file}"; then
            shipped="${shipped} ${alias_name}"
         fi
      done
      if [ -z "${shipped}" ]; then
         pass "debian/*.links ships no /boot theme alias"
      else
         fail "debian/*.links ships:${shipped} -- a packaged link under /boot fails when /boot is unmounted or is itself a symlink"
      fi
   fi

   ## The source variants must exist in the package, or the copy has nothing to copy.
   for variant in background-16x9.png theme-16x9.txt; do
      if [ -r "${pkg_dir}/boot/grub/themes/${theme_name}/${variant}" ]; then
         pass "${label}: source variant ${variant} exists in the package"
      else
         fail "${label}: source variant ${variant} is missing under themes/${theme_name}; the copy would fail at grub-mkconfig time"
      fi
   done

   ## --- the values the snippet sets -------------------------------------------
   ## Read STATICALLY, not by sourcing: the snippet writes to /boot by design now,
   ## so sourcing it here would rewrite this machine's bootloader theme. That is
   ## also why the write-freedom assertion above was replaced rather than kept -- it
   ## no longer describes the intended behaviour.
   values="$(grep --extended-regexp -- '^(GRUB_THEME|GRUB_GFXMODE|GRUB_DISTRIBUTOR)=' "${subject}" || true)"

   ## CANARY: the sourcing above must really be reading this file, not reporting
   ## defaults. GRUB_DISTRIBUTOR is set by the same file and is unrelated to the fix.
   case "${values}" in
      *GRUB_DISTRIBUTOR=?*)
         pass "${label}: canary: the file really was read (GRUB_DISTRIBUTOR came through)"
         ;;
      *)
         fail "${label}: canary broken: GRUB_DISTRIBUTOR not found, so the assertions above read nothing -- ${values}"
         ;;
   esac

}

if [ -n "${single_pkg}" ]; then
   check_package "${single_pkg}" 30_kicksecure.cfg kicksecure-base-files
else
   check_package "${dm_root}/packages/kicksecure/kicksecure-base-files" 30_kicksecure.cfg kicksecure-base-files
   check_package "${dm_root}/packages/whonix/anon-ws-base-files" 30_whonix-workstation.cfg anon-ws-base-files
   check_package "${dm_root}/packages/whonix/anon-gw-base-files" 30_whonix-gateway.cfg anon-gw-base-files
fi

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
   "${dm_root}/packages/kicksecure/dist-base-files/boot/grub/themes/dist-common" \
   "${dm_checkout}/packages/kicksecure/dist-base-files/boot/grub/themes/dist-common"; do
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
## Zero packages inspected is a SKIP, never an OK: nothing was verified, and
## "OK: grub theme pinning" over an empty run is the silent-green failure mode
## this suite exists to avoid.
if [ "${packages_checked}" -eq 0 ]; then
   printf '%s\n' "FATAL: no grub-theme package is checked out; nothing was verified." >&2
   exit 1
fi
printf '%s\n' "OK: grub theme pinning (${packages_checked} package(s))."
