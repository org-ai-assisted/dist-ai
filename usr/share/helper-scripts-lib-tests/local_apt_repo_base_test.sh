#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-safe-rm (rm -rf of our own mktemp fixture dir only)

## local-apt-repo-base.bsh: the dist-ai DEV-ONLY generator of the Debian-base mirror
## deb822 stanza (local_apt_repo_base_stanza), used by repo-add-local + dm-whonix-pair.
## Split out of helper-scripts' local-apt-repo-sources.bsh because the dm image build
## never uses it (create-local-apt-repo uses only local_apt_repo_sources_stanza, tested
## in local_apt_repo_sources_test.sh). This suite pins the exact base stanza. No root, no
## network.
##
## Sources the INSTALLED lib by default; DIST_AI_REPO points it at a checkout, else it is
## resolved relative to this test. The lib is REQUIRED -- its absence is FATAL, not a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_AI_REPO:-}" ]; then
   lib_path="${DIST_AI_REPO}/usr/libexec/dist-ai/local-apt-repo-base.bsh"
else
   test_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
   lib_path="${test_dir}/../../libexec/dist-ai/local-apt-repo-base.bsh"
   [ -r "${lib_path}" ] || lib_path='/usr/libexec/dist-ai/local-apt-repo-base.bsh'
fi

if [ ! -r "${lib_path}" ]; then
   printf '%s\n' "FATAL: local-apt-repo-base.bsh not readable at '${lib_path}'" >&2
   printf '%s\n' "set DIST_AI_REPO to a checkout, or install dist-ai" >&2
   exit 1
fi

## shellcheck resolves the file statically; the dynamic path has nothing constant to point at.
# shellcheck disable=SC1090,SC1091
source "${lib_path}"

if [ "$(type -t local_apt_repo_base_stanza)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${lib_path}' defined no 'local_apt_repo_base_stanza' function" >&2
   exit 1
fi

pass_count=0
fail_count=0
nl=$'\n'

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

## A local Debian mirror stores the COMPRESSED index (Packages.gz/.xz) and typically NO uncompressed
## Packages and NO by-hash tree, so residency must accept any index form. A component the signed
## InRelease OFFERS but whose index is ABSENT on disk MUST still be excluded (an offered-but-absent
## component makes apt-get update hard-fail exit 100); the genuine signed Release means NO
## 'Trusted: yes'; an uncompressed 'Packages' InRelease entry anchors the per-component enumeration.
base_fix="$(mktemp --directory)"
mkdir --parents -- \
   "${base_fix}/debian/dists/trixie/main/binary-amd64" \
   "${base_fix}/debian/dists/trixie/main/debian-installer/binary-amd64" \
   "${base_fix}/debian/dists/trixie/non-free/binary-amd64/by-hash/SHA256" \
   "${base_fix}/debian/dists/trixie/non-free-firmware/binary-amd64"
main_hash="$(printf '%s' mainidx | sha256sum | cut -d' ' -f1)"
di_hash="$(printf '%s' diidx | sha256sum | cut -d' ' -f1)"
contrib_hash="$(printf '%s' contribidx | sha256sum | cut -d' ' -f1)"
nf_hash="$(printf '%s' nfidx | sha256sum | cut -d' ' -f1)"
nff_hash="$(printf '%s' nffidx | sha256sum | cut -d' ' -f1)"
## main resident via COMPRESSED index ONLY (no uncompressed Packages, no by-hash) -- the F1
## canary: the old uncompressed-hash probe wrongly found this empty. non-free resident via a
## by-hash tree. contrib OFFERED but ABSENT on disk (the partial-mirror gap). non-free-firmware
## has a 0-BYTE index (truncated sync) -- must be excluded (-s). main/debian-installer is a udeb
## SUB-index with a real index on disk -- must be excluded (not a component).
printf '%s' idx > "${base_fix}/debian/dists/trixie/main/binary-amd64/Packages.gz"
printf '%s' idx > "${base_fix}/debian/dists/trixie/main/binary-amd64/Packages.xz"
printf '%s' idx > "${base_fix}/debian/dists/trixie/main/debian-installer/binary-amd64/Packages.gz"
printf '%s' idx > "${base_fix}/debian/dists/trixie/non-free/binary-amd64/by-hash/SHA256/${nf_hash}"
touch -- "${base_fix}/debian/dists/trixie/non-free-firmware/binary-amd64/Packages.gz"
printf '%s\n' "SHA256:" \
   " ${main_hash} 12345 main/binary-amd64/Packages" \
   " ${di_hash} 333 main/debian-installer/binary-amd64/Packages" \
   " ${contrib_hash} 6789 contrib/binary-amd64/Packages" \
   " ${nf_hash} 222 non-free/binary-amd64/Packages" \
   " ${nff_hash} 44 non-free-firmware/binary-amd64/Packages" \
   > "${base_fix}/debian/dists/trixie/InRelease"

base_expected="Types: deb
URIs: file:${base_fix}/debian
Suites: trixie
Components: main non-free
Architectures: amd64
Enabled: yes"
base_actual="$(local_apt_repo_base_stanza "${base_fix}" debian trixie amd64)"
check_eq "base stanza: compressed/by-hash resident; absent, 0-byte, and udeb sub-index excluded" \
   "${base_expected}" "${base_actual}"

## CANARY: a component resident ONLY via the compressed index MUST be included (the F1 fix); the
## stanza must NOT carry 'Trusted: yes' (genuine signed Release); it MUST carry 'Architectures:
## amd64' (else a multi-arch guest hard-fails); and the absent/0-byte/udeb entries MUST be out.
if [[ "${nl}${base_actual}${nl}" == *"${nl}Components: main non-free${nl}"* ]] \
   && [[ "${nl}${base_actual}${nl}" == *"${nl}Architectures: amd64${nl}"* ]] \
   && [[ "${nl}${base_actual}${nl}" != *"${nl}Trusted: yes${nl}"* ]] \
   && [[ "${base_actual}" != *contrib* ]] \
   && [[ "${base_actual}" != *non-free-firmware* ]] \
   && [[ "${base_actual}" != *debian-installer* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: compressed-only included, arch-restricted, signed; absent/0-byte/udeb excluded"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: wrong component set, missing Architectures, Trusted:yes, or a bad component slipped in"
fi

## uri_root override: READ residency from the host cache_root, but EMIT a different file: path
## (the guest mount). A host-side caller needs this -- it reads /srv/... but the guest sees /mnt.
uri_actual="$(local_apt_repo_base_stanza "${base_fix}" debian trixie amd64 /mnt/shared/aptcache)"
if [[ "${nl}${uri_actual}${nl}" == *"${nl}URIs: file:/mnt/shared/aptcache/debian${nl}"* ]] \
   && [[ "${nl}${uri_actual}${nl}" == *"${nl}Components: main non-free${nl}"* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: uri_root override emits the guest path while reading residency from cache_root"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: uri_root override wrong -- got: ${uri_actual}"
fi

## A suite with no InRelease -> rc 1, no stanza (caller skips it -> remote/Tor fallback).
rc=0; out="$(local_apt_repo_base_stanza "${base_fix}" debian trixie-updates amd64)" || rc=$?
check_eq "base stanza: absent suite InRelease returns 1" "1" "${rc}"
check_eq "base stanza: absent suite emits nothing" "" "${out}"

## Missing args -> rc 2.
rc=0; local_apt_repo_base_stanza "${base_fix}" debian trixie >/dev/null 2>&1 || rc=$?
check_eq "base stanza: missing arch returns 2" "2" "${rc}"

## No pin generator: the caller points the upgrade at the local sources ONLY, so there is no
## remote to out-prefer. Assert the function is GONE so a reintroduced pin is caught.
if [ "$(type -t local_apt_repo_pin)" = 'function' ]; then
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: local_apt_repo_pin reintroduced -- the design points apt at local sources only, no pin"
else
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: no pin generator (local-sources-only upgrade needs none)"
fi

rm --recursive --force -- "${base_fix}"

printf '%s\n' ""
printf '%s\n' "===== local_apt_repo_base: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
