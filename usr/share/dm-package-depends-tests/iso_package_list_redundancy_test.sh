#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The ISO installer package lists (iso-build-data/package-list-*) must not list
## a package from build-steps.d/3500_install-packages's
## efi_weak_recommended_packages_list.
##
## THE HARM: 3500 installs that EFI-signing set with a per-package availability
## dry-run, so it silently drops a package unavailable on the target arch. The
## ISO lists install their entries as HARD requirements. An EFI package present
## in BOTH turns 3500's graceful arch handling into a build break: the hard ISO
## entry fails the build on an arch where the package does not exist.
##
## Scope is deliberately the efi_weak set only. Other duplication is benign:
## base-system / metapackage-graph packages (ca-certificates, dracut, ...) and
## packages 3500 installs via an explicit pkg-install / pkg-add-to-install-list
## are de-duplicated by apt and cannot break a build, and some of those installs
## are conditional (spice-vdagent, user-sysmaint-split) so an ISO-list entry is
## the real source. Deciding those needs the build's control flow, not a grep;
## the header comment in the lists governs them.
##
## No root, no network. Reads the checkout only.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v DERIVATIVE_MAKER_DIR ] || DERIVATIVE_MAKER_DIR=""

if [ -z "${DERIVATIVE_MAKER_DIR}" ] || [ ! -d "${DERIVATIVE_MAKER_DIR}/iso-build-data" ]; then
   printf '%s\n' "FATAL: no derivative-maker checkout to scan" >&2
   printf '%s\n' "set DERIVATIVE_MAKER_DIR to one" >&2
   exit 1
fi

install_step="${DERIVATIVE_MAKER_DIR}/build-steps.d/3500_install-packages"
list_kicksecure="${DERIVATIVE_MAKER_DIR}/iso-build-data/package-list-kicksecure"
list_live="${DERIVATIVE_MAKER_DIR}/iso-build-data/package-list-live"

for required in "${install_step}" "${list_kicksecure}" "${list_live}"; do
   if [ ! -f "${required}" ]; then
      printf '%s\n' "FATAL: expected file missing: ${required}" >&2
      exit 1
   fi
done

## The EFI-signing set 3500 installs unconditionally (availability-checked): the
## words of efi_weak_recommended_packages_list="...".
declare -A installed_by_step=()

efi_line="$(grep -E 'efi_weak_recommended_packages_list="' -- "${install_step}" || true)"
efi_set="$(printf '%s\n' "${efi_line}" | sed -E 's/.*="([^"]*)".*/\1/')"
for pkg in ${efi_set}; do
   installed_by_step["${pkg}"]="efi_weak_recommended_packages_list"
done

if [ "${#installed_by_step[@]}" -eq 0 ]; then
   printf '%s\n' "FAIL: extracted no efi_weak_recommended_packages_list from ${install_step}"
   printf '%s\n' "      -- the check tested nothing (parsing likely drifted)"
   exit 1
fi

## Emit each real package token from an ISO list, one per line: strip a trailing
## comment, trim, resolve the one placeholder that maps to an installed package,
## and drop the remaining XXX_..._XXX template placeholders.
list_packages() {
   local file="$1" line
   while IFS= read -r line || [ -n "${line}" ]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      [ -n "${line}" ] || continue
      line="${line//XXX_FWUPD_SIGNED_XXX/fwupd-signed}"
      case "${line}" in
         *XXX_*_XXX*)
            continue
            ;;
      esac
      printf '%s\n' "${line}"
   done < "${file}"
}

fail=0
checked=0
for list in "${list_kicksecure}" "${list_live}"; do
   while IFS= read -r pkg; do
      [ -n "${pkg}" ] || continue
      checked=$(( checked + 1 ))
      if [ -n "${installed_by_step["${pkg}"]:-}" ]; then
         printf '%s\n' "FAIL: ${list##*/} hard-lists EFI package '${pkg}', already installed by 3500 (${installed_by_step["${pkg}"]})"
         fail=1
      fi
   done < <(list_packages "${list}")
done

printf '%s\n' ""
printf '%s\n' "${#installed_by_step[@]} efi_weak package(s); ${checked} ISO-list entr(ies) checked"

## A list that parsed to nothing means the parser matched nothing -- a moved file,
## a changed format -- and the run would otherwise report a clean sweep over no data.
if [ "${checked}" -eq 0 ]; then
   printf '%s\n' "FAIL: no ISO-list entries parsed at all -- the check tested nothing"
   exit 1
fi

if [ "${fail}" -eq 0 ]; then
   printf '%s\n' "PASS: no ISO-list entry duplicates an efi_weak package 3500 installs"
fi

exit "${fail}"
