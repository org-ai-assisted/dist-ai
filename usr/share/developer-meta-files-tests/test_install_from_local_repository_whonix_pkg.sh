#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-install-from-local-repository
## Whonix branch. It rewrites the flavor -> meta-package mapping to the current
## naming: whonix-<gateway|workstation>-<qubes|nonqubes>-<cli|gui-lxqt>. The bug
## it fixes is that the OLD branch named packages that no longer exist
## ('non-qubes-whonix-gateway', 'qubes-whonix-gateway-kde', ...), so 'apt-get
## install' found zero Package: stanzas and the build failed.
##
## Two layers:
##   * STRUCTURAL -- the tool composes the canonical
##     'whonix-${whonix_role}-${whonix_virt}-${whonix_ui}' name and no longer
##     mentions any of the retired names;
##   * EXISTENCE -- every name that mapping can produce (role x virt x ui) is a
##     real 'Package:' stanza in packages/whonix/anon-meta-packages/debian/control.
##     This is the exact property the old code violated.
## End-to-end 'apt-get install' in a chroot needs a real Whonix build and is out
## of scope here.
##
## Self-contained; greps two files. Needs no root, no network, no build.
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
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

rel='packages/kicksecure/developer-meta-files/usr/bin/dm-install-from-local-repository'
subject=""
for candidate in "${DM_INSTALL_FROM_LOCAL_REPOSITORY:-}" \
   "${dm_checkout}/${rel}" \
   "/usr/bin/dm-install-from-local-repository"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-install-from-local-repository not found (set DM_INSTALL_FROM_LOCAL_REPOSITORY)." >&2
   exit 77
fi
## The canonical meta-package list lives in the anon-meta-packages control file.
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
   printf '%s\n' "SKIP: anon-meta-packages/debian/control not found (set ANON_META_PACKAGES_CONTROL)." >&2
   exit 77
fi

## --- STRUCTURAL -------------------------------------------------------------
if grep --quiet --fixed-strings -- 'pkg="whonix-${whonix_role}-${whonix_virt}-${whonix_ui}"' "${subject}"; then
   pass "structural: composes the canonical whonix-<role>-<virt>-<ui> meta-package name"
else
   fail "structural: the canonical name composition is missing"
fi
## The retired names must be gone (each once produced an apt 'no such package').
for retired in 'non-qubes-whonix-gateway' 'qubes-whonix-gateway-kde' \
   'qubes-whonix-workstation' 'non-qubes-whonix-workstation-kde'; do
   if grep --quiet --fixed-strings -- "${retired}" "${subject}"; then
      fail "structural: the retired name '${retired}' is still present"
   else
      pass "structural: the retired name '${retired}' is gone"
   fi
done
## The virt axis must derive from dist_build_qubes with the current 'nonqubes' word.
if grep --quiet --fixed-strings -- 'whonix_virt="nonqubes"' "${subject}" \
   && grep --quiet --fixed-strings -- 'whonix_virt="qubes"' "${subject}"; then
   pass "structural: qubes-ness maps to qubes / nonqubes"
else
   fail "structural: the qubes/nonqubes derivation is missing"
fi

## --- EXISTENCE: every producible name is a real package ---------------------
## The mapping's output space is the cartesian product of the three axes.
all_exist=true
for whonix_role in gateway workstation; do
   for whonix_virt in qubes nonqubes; do
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
printf '%s\n' "OK: install-from-local-repository whonix mapping (${pass_count} assertions)."
