#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## A package whose shipped code sources get_colors.sh UNCONDITIONALLY must
## declare helper-scripts in debian/control.
##
## THE BUG: the get_colors.sh port replaced inline 'tput' colour handling in
## usr/bin/kicksecure, usr/bin/whonix and the tor-ctrl helpers with a source of
## ANOTHER package's file, and did not declare the new dependency. On a minimal
## install those commands then exit at the source line -- a breakage introduced
## by the port itself, in packages that had worked fine before it.
##
## A GUARDED source is exempt: it degrades instead of failing, which is the
## whole difference between a hard dependency and a soft one.
##
## Tree-wide by design: the same omission can recur in any package, which is
## the only reason this is worth having as a standing check rather than a
## one-off audit.
##
## No root, no network. Reads the checkout only.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v DERIVATIVE_MAKER_DIR ] || DERIVATIVE_MAKER_DIR=""

if [ -z "${DERIVATIVE_MAKER_DIR}" ] || [ ! -d "${DERIVATIVE_MAKER_DIR}/packages" ]; then
   printf '%s\n' "SKIP: no derivative-maker checkout to scan" >&2
   printf '%s\n' "set DERIVATIVE_MAKER_DIR to one" >&2
   exit 77
fi

packages_root="${DERIVATIVE_MAKER_DIR}/packages"

fail=0
checked=0

for control in "${packages_root}"/*/*/debian/control; do
   if [ ! -f "${control}" ]; then
      continue
   fi
   package_dir="${control%/debian/control}"
   package_name="${package_dir#"${packages_root}"/}"

   hits=""
   hits="$(grep --recursive --files-with-matches -- \
      'source /usr/libexec/helper-scripts/get_colors.sh' "${package_dir}/usr" 2>/dev/null || true)"
   if [ -z "${hits}" ]; then
      continue
   fi

   ## Unconditional = the source line carries no '||' fallback. A guarded
   ## source degrades rather than failing, so it needs no hard dependency.
   unguarded=""
   while IFS= read -r file; do
      if [ -z "${file}" ]; then
         continue
      fi
      if grep -- 'source /usr/libexec/helper-scripts/get_colors.sh' "${file}" \
         | grep --invert-match -- '||' >/dev/null; then
         unguarded="${unguarded} ${file#"${package_dir}"/}"
      fi
   done <<< "${hits}"

   if [ -z "${unguarded}" ]; then
      continue
   fi
   checked=$(( checked + 1 ))

   if grep --extended-regexp -- '^Depends:.*helper-scripts|^ +helper-scripts' "${control}" >/dev/null; then
      printf '%s\n' "PASS: ${package_name} declares helper-scripts"
   else
      printf '%s\n' "FAIL: ${package_name} sources get_colors.sh unguarded but does NOT declare helper-scripts"
      printf '%s\n' "      ${unguarded# }"
      fail=1
   fi
done

printf '%s\n' ""
printf '%s\n' "${checked} package(s) source get_colors.sh unguarded"

## Finding nothing at all means the scan matched nothing -- a moved path, a
## changed source line -- and the run would otherwise report a clean sweep over
## no packages.
if [ "${checked}" -eq 0 ]; then
   printf '%s\n' "FAIL: no unguarded sources found at all -- the check tested nothing"
   exit 1
fi

exit "${fail}"
