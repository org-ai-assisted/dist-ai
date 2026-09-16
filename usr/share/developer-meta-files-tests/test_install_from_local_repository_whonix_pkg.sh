#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-install-from-local-repository
## Whonix branch (STRUCTURAL layer). It rewrites the flavor -> meta-package
## mapping to the current naming: whonix-<gateway|workstation>-<qubes|vm>-<cli|gui-lxqt>.
## The bug it fixes is that the OLD branch named packages that no longer exist
## ('non-qubes-whonix-gateway', 'qubes-whonix-gateway-kde', ...), so 'apt-get
## install' found zero Package: stanzas and the build failed.
##
## STRUCTURAL: the tool composes the canonical
## 'whonix-${whonix_role}-${whonix_virt}-${whonix_ui}' name, derives the virt
## axis as qubes / vm, and no longer mentions any retired name. The EXISTENCE
## cross-check (that every producible name is a real Package: stanza in
## packages/whonix/anon-meta-packages/debian/control) lives in the sibling
## test_install_from_local_repository_whonix_control.sh, because that control
## file is a derivative-maker artifact absent in a standalone dmf checkout.
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
   "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-install-from-local-repository" \
   "${dm_checkout}/${rel}" \
   "/usr/bin/dm-install-from-local-repository"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-install-from-local-repository not found (set DM_INSTALL_FROM_LOCAL_REPOSITORY)." >&2
   exit 1
fi

## --- STRUCTURAL -------------------------------------------------------------
## Match CODE only (drop full-line comments): a migration comment naming a retired
## package name must not read as the name being present, nor may a comment satisfy
## the composition / virt-axis checks.
code="$(grep --invert-match --extended-regexp -- '^[[:space:]]*#' "${subject}" || true)"
if grep --quiet --fixed-strings -- 'pkg="whonix-${whonix_role}-${whonix_virt}-${whonix_ui}"' <<< "${code}"; then
   pass "structural: composes the canonical whonix-<role>-<virt>-<ui> meta-package name"
else
   fail "structural: the canonical name composition is missing"
fi
## The retired names must be gone (each once produced an apt 'no such package').
for retired in 'non-qubes-whonix-gateway' 'qubes-whonix-gateway-kde' \
   'qubes-whonix-workstation' 'non-qubes-whonix-workstation-kde'; do
   if grep --quiet --fixed-strings -- "${retired}" <<< "${code}"; then
      fail "structural: the retired name '${retired}' is still present"
   else
      pass "structural: the retired name '${retired}' is gone"
   fi
done
## The virt axis derives from dist_build_qubes: 'qubes' or the current 'vm' word
## (the non-qubes leaf; 'nonqubes' is a shared intermediate node, not installed
## directly -- see https://www.kicksecure.com/wiki/Dev/Metapackages).
if grep --quiet --fixed-strings -- 'whonix_virt="vm"' <<< "${code}" \
   && grep --quiet --fixed-strings -- 'whonix_virt="qubes"' <<< "${code}"; then
   pass "structural: qubes-ness maps to qubes / vm"
else
   fail "structural: the qubes/vm derivation is missing"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: install-from-local-repository whonix structural mapping (${pass_count} assertions)."
