#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-safe-rm (rm -rf of our own mktemp fixture dir only)

## local-apt-repo-sources.bsh: the ONE generator of the derivative local apt
## repository deb822 stanza. It is the single source of truth shared by the
## build-time mounter (derivative-maker help-steps/create-local-apt-repo) and
## the on-system enabler (repo-add-local); this suite pins the exact stanza so
## the two consumers can never drift.
##
## Sources the INSTALLED lib by default; HELPER_SCRIPTS_REPO points it at a
## checkout, which is what the suite runner wires in CI. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   lib_path="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/local-apt-repo-sources.bsh"
else
   lib_path='/usr/libexec/helper-scripts/local-apt-repo-sources.bsh'
fi

if [ ! -r "${lib_path}" ]; then
   printf '%s\n' "FATAL: local-apt-repo-sources.bsh not readable at '${lib_path}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## shellcheck resolves the file statically from dist-ai's own tree, which has no
## helper-scripts copy, so there is nothing to point 'source=' at.
# shellcheck disable=SC1090,SC1091
source "${lib_path}"

if [ ! "$(type -t local_apt_repo_sources_stanza)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${lib_path}' defined no 'local_apt_repo_sources_stanza' function" >&2
   exit 1
fi

pass_count=0
fail_count=0

check_eq() {
   ## check_eq <label> <expected> <actual>
   if [ "$2" = "$3" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1"
      printf '%s\n' "  expected: $(printf '%q' "$2")"
      printf '%s\n' "  actual:   $(printf '%q' "$3")"
   fi
}

## --- exact stanza: /srv vm-created repo -------------------------------------
expected_srv="Types: deb
URIs: file:/srv/derivative-maker/aptrepo_local/kicksecure
Suites: local
Components: main contrib non-free
Enabled: yes
Trusted: yes"
actual_srv="$(local_apt_repo_sources_stanza 'file:/srv/derivative-maker/aptrepo_local/kicksecure' 'local')"
check_eq "exact stanza for a /srv file: URI, suite 'local'" "${expected_srv}" "${actual_srv}"

## --- exact stanza: /mnt host-injected repo, whonix --------------------------
expected_mnt="Types: deb
URIs: file:/mnt/local-apt-repo/whonix
Suites: local
Components: main contrib non-free
Enabled: yes
Trusted: yes"
actual_mnt="$(local_apt_repo_sources_stanza 'file:/mnt/local-apt-repo/whonix' 'local')"
check_eq "exact stanza for a /mnt file: URI, derivative whonix" "${expected_mnt}" "${actual_mnt}"

## --- no leading blank line (caller owns multi-stanza separation) ------------
if [ "${actual_srv:0:1}" = $'\n' ]; then
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: stanza starts with a blank line; the generator must not add a separator"
else
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: no leading blank line"
fi

## --- misuse: missing args -> return 2 ---------------------------------------
rc=0; local_apt_repo_sources_stanza >/dev/null 2>&1 || rc=$?
check_eq "no args returns 2" "2" "${rc}"
rc=0; local_apt_repo_sources_stanza 'file:/x' >/dev/null 2>&1 || rc=$?
check_eq "missing suite returns 2" "2" "${rc}"
rc=0; local_apt_repo_sources_stanza '' 'local' >/dev/null 2>&1 || rc=$?
check_eq "empty uri returns 2" "2" "${rc}"

## --- CANARY: the trust + component contract --------------------------------
## This stanza MUST carry 'Trusted: yes' (apt 3.0 fatally refuses the unsigned
## local repo without it) and the full 'main contrib non-free' component set. If
## either is dropped or altered, the two consumers silently diverge from apt's
## expectations -- that is exactly the drift this single source of truth exists
## to prevent, so assert them explicitly rather than trusting the block above.
nl=$'\n'
if [[ "${nl}${actual_srv}${nl}" == *"${nl}Trusted: yes${nl}"* ]] \
   && [[ "${nl}${actual_srv}${nl}" == *"${nl}Components: main contrib non-free${nl}"* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: Trusted: yes and the full component set are present"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: missing 'Trusted: yes' or the 'main contrib non-free' components"
fi

## --- local_apt_repo_base_stanza + local_apt_repo_pin: Debian-base mirror sources ----------------
## A local Debian mirror stores the COMPRESSED index (Packages.gz/.xz) and typically NO uncompressed
## Packages and NO by-hash tree, so residency must accept any index form. A component the signed
## InRelease OFFERS but whose index is ABSENT on disk MUST still be excluded (an offered-but-absent
## component makes apt-get update hard-fail exit 100); the genuine signed Release means NO
## 'Trusted: yes'; an uncompressed 'Packages' InRelease entry anchors the per-component enumeration.
if [ "$(type -t local_apt_repo_base_stanza)" = 'function' ] && [ "$(type -t local_apt_repo_pin)" = 'function' ]; then
   base_fix="$(mktemp --directory)"
   mkdir --parents -- \
      "${base_fix}/debian/dists/trixie/main/binary-amd64" \
      "${base_fix}/debian/dists/trixie/non-free/binary-amd64/by-hash/SHA256"
   main_hash="$(printf '%s' mainidx | sha256sum | cut -d' ' -f1)"
   contrib_hash="$(printf '%s' contribidx | sha256sum | cut -d' ' -f1)"
   nf_hash="$(printf '%s' nfidx | sha256sum | cut -d' ' -f1)"
   ## main resident via COMPRESSED index ONLY (no uncompressed Packages, no by-hash) -- the F1
   ## canary: the old uncompressed-hash probe wrongly found this empty. non-free resident via a
   ## by-hash tree. contrib OFFERED by InRelease but ABSENT on disk (the partial-mirror gap).
   touch -- \
      "${base_fix}/debian/dists/trixie/main/binary-amd64/Packages.gz" \
      "${base_fix}/debian/dists/trixie/main/binary-amd64/Packages.xz" \
      "${base_fix}/debian/dists/trixie/non-free/binary-amd64/by-hash/SHA256/${nf_hash}"
   printf '%s\n' "SHA256:" \
      " ${main_hash} 12345 main/binary-amd64/Packages" \
      " ${contrib_hash} 6789 contrib/binary-amd64/Packages" \
      " ${nf_hash} 222 non-free/binary-amd64/Packages" \
      > "${base_fix}/debian/dists/trixie/InRelease"

   base_expected="Types: deb
URIs: file:${base_fix}/debian
Suites: trixie
Components: main non-free
Enabled: yes"
   base_actual="$(local_apt_repo_base_stanza "${base_fix}" debian trixie amd64)"
   check_eq "base stanza: resident via compressed index + by-hash, offered-but-absent excluded" \
      "${base_expected}" "${base_actual}"

   ## CANARY: a component resident ONLY via the compressed index MUST be included (the F1 fix), the
   ## stanza must NOT carry 'Trusted: yes' (genuine signed Release), and an offered-but-absent
   ## component MUST be excluded.
   if [[ "${nl}${base_actual}${nl}" == *"${nl}Components: main non-free${nl}"* ]] \
      && [[ "${nl}${base_actual}${nl}" != *"${nl}Trusted: yes${nl}"* ]] \
      && [[ "${base_actual}" != *contrib* ]]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: canary: compressed-only component included, signed (no Trusted:yes), absent contrib excluded"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: canary: compressed-only component missed, Trusted:yes present, or absent component included"
   fi

   ## A suite with no InRelease -> rc 1, no stanza (caller skips it -> remote/Tor fallback).
   rc=0; out="$(local_apt_repo_base_stanza "${base_fix}" debian trixie-updates amd64)" || rc=$?
   check_eq "base stanza: absent suite InRelease returns 1" "1" "${rc}"
   check_eq "base stanza: absent suite emits nothing" "" "${out}"

   ## Missing args -> rc 2.
   rc=0; local_apt_repo_base_stanza "${base_fix}" debian trixie >/dev/null 2>&1 || rc=$?
   check_eq "base stanza: missing arch returns 2" "2" "${rc}"

   ## pin stanza: prefers the file: local sources above the Tor remotes, at priority 990 (NOT
   ## >=1000, which would 'install even if a DOWNGRADE' and let a lagging mirror force a downgrade).
   pin_expected='Package: *
Pin: origin ""
Pin-Priority: 990'
   check_eq "pin stanza: empty-origin priority 990 (no forced downgrade)" "${pin_expected}" "$(local_apt_repo_pin)"

   rm --recursive --force -- "${base_fix}"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: local_apt_repo_base_stanza / local_apt_repo_pin not defined (Debian-base cache generator missing)"
fi

printf '%s\n' ""
printf '%s\n' "===== local_apt_repo_sources: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
