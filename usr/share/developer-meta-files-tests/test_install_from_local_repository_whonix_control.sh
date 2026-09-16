#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-install-from-local-repository
## Whonix branch (EXISTENCE layer). Every meta-package name the mapping can
## produce -- the cartesian product whonix-<gateway|workstation>-<qubes|vm>-<cli|gui-lxqt>
## -- must be a real 'Package:' stanza in the anon-meta-packages control file.
## This is the exact property the OLD code violated ('apt-get install' found zero
## Package: stanzas and the build failed).
##
## That control file is a derivative-maker artifact
## (packages/whonix/anon-meta-packages/debian/control), NOT part of a standalone
## developer-meta-files component checkout, so this cross-check runs in the
## dm-submodule layout / dev host and self-skips (77) otherwise. The subject's
## own name composition is covered standalone by the sibling
## test_install_from_local_repository_whonix_pkg.sh.
##
## Self-contained; greps one file. Needs no root, no network, no build.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

## The canonical meta-package list lives in the anon-meta-packages control file,
## a derivative-maker artifact with no equivalent under a standalone dmf checkout.
control=""
for candidate in "${ANON_META_PACKAGES_CONTROL:-}" \
   "${dm_checkout}/packages/whonix/anon-meta-packages/debian/control"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      control="${candidate}"
      break
   fi
done
if [ -z "${control}" ]; then
   printf '%s\n' "SKIP: anon-meta-packages/debian/control not available (set ANON_META_PACKAGES_CONTROL or DERIVATIVE_MAKER_DIR to run the existence cross-check)." >&2
   ## style-ok: allow-skip: anon-meta-packages control is a derivative-maker artifact, absent in a standalone dmf component checkout
   exit 77
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

## --- EXISTENCE: every producible name is a real package ---------------------
## The mapping's output space is the cartesian product of the three axes; the
## virt axis mirrors the subject's qubes / vm derivation (the installable leaves).
all_exist=true
for whonix_role in gateway workstation; do
   for whonix_virt in qubes vm; do
      for whonix_ui in cli gui-lxqt; do
         pkg="whonix-${whonix_role}-${whonix_virt}-${whonix_ui}"
         if grep --quiet --extended-regexp -- "^Package: ${pkg}\$" "${control}"; then
            pass "existence: ${pkg} is a real Package: stanza"
         else
            fail "existence: ${pkg} is NOT a Package: stanza in the control file"
            all_exist=false
         fi
      done
   done
done
if [ "${all_exist}" = true ]; then
   pass "existence: the whole mapping output space resolves to installable packages"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: install-from-local-repository whonix existence cross-check (${pass_count} assertions)."
