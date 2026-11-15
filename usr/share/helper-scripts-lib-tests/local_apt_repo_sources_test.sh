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

nl=$'\n'

## Build a reprepro-shaped local repo fixture under <root>/dists/local. Each remaining arg is
## 'component[:<arch>]:<bytes>': <arch> defaults to amd64 (so 'main:120' is amd64); <bytes>=0 writes
## a 0-byte Packages (reprepro's configured-but-unpopulated component). Pass an explicit arch (e.g.
## 'contrib:arm64:40') to seed a component only under a non-native binary-<arch>.
mk_local_repo() {
   local root suite comp arch target spec rest bytes
   root="$1"; suite="$2"; shift 2
   for spec in "$@"; do
      comp="${spec%%:*}"; rest="${spec#*:}"
      if [ "${rest}" != "${rest#*:}" ]; then
         arch="${rest%%:*}"; bytes="${rest#*:}"
      else
         arch='amd64'; bytes="${rest}"
      fi
      target="${root}/dists/${suite}/${comp}/binary-${arch}"
      mkdir --parents -- "${target}"
      if [ "${bytes}" = '0' ]; then
         true > "${target}/Packages"
      else
         head --bytes="${bytes}" /dev/zero | tr '\0' 'x' > "${target}/Packages"
      fi
   done
}

repo_fix="$(mktemp --directory)"

## --- full repo: all three components populated ------------------------------
## Component order is the LC_ALL=C glob order of the on-disk dists/<suite>/*/
## dirs (contrib main non-free) -- deterministic, and apt is order-agnostic.
mk_local_repo "${repo_fix}/kicksecure" local main:120 contrib:40 non-free:30
expected_full="Types: deb
URIs: file:${repo_fix}/kicksecure
Suites: local
Components: contrib main non-free
Enabled: yes
Trusted: yes"
actual_full="$(local_apt_repo_sources_stanza "file:${repo_fix}/kicksecure" 'local')"
check_eq "full repo: all populated components listed" "${expected_full}" "${actual_full}"

## --- whonix-shaped repo: contrib/non-free EMPTY (0-byte) --------------------
## REGRESSION: reprepro writes a 0-byte Packages for a configured-but-unpopulated
## component; apt on a file: source HARD-FAILS fetching that empty index (ENOENT
## on the vboxsf guest), so an empty component MUST be dropped. Pre-fix this
## hardcoded 'main contrib non-free' and the whonix local-repo lane aborted at
## apt-get update. (Component DIRS exist on disk, Packages is 0 bytes.)
mk_local_repo "${repo_fix}/whonix" local main:60 contrib:0 non-free:0
expected_whonix="Types: deb
URIs: file:${repo_fix}/whonix
Suites: local
Components: main
Enabled: yes
Trusted: yes"
actual_whonix="$(local_apt_repo_sources_stanza "file:${repo_fix}/whonix" 'local')"
check_eq "whonix repo: empty contrib/non-free dropped, only main listed" \
   "${expected_whonix}" "${actual_whonix}"
if [[ "${actual_whonix}" != *contrib* ]] && [[ "${actual_whonix}" != *non-free* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: no empty component (contrib/non-free) slipped into the whonix stanza"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: an empty component leaked into the whonix stanza -- apt-get update will hard-fail"
fi

## --- arch-aware residency: the probe reads binary-<arch>, defaulting to the NATIVE arch ----------
## REGRESSION (F1): a component resident only under a NON-native binary-<arch> must be invisible by
## default (the native-arch probe never looks there) but appear when that arch is passed explicitly.
## A hard-coded amd64 default would wrongly mark an arm64-only repo's components present/absent.
native_arch="$(dpkg --print-architecture 2>/dev/null || printf '%s' amd64)"
other_arch='arm64'; [ "${native_arch}" = 'arm64' ] && other_arch='amd64'
## contrib resident ONLY under binary-<other_arch>; main empty under binary-<native_arch>.
mk_local_repo "${repo_fix}/archcross" local "main:${native_arch}:0" "contrib:${other_arch}:40"
default_comps="$(local_apt_repo_sources_stanza "file:${repo_fix}/archcross" 'local' | sed -n 's/^Components: //p')"
check_eq "native-arch default: a ${other_arch}-only component is NOT seen; falls back to main" \
   "main" "${default_comps}"
other_comps="$(local_apt_repo_sources_stanza "file:${repo_fix}/archcross" 'local' '' "${other_arch}" | sed -n 's/^Components: //p')"
check_eq "explicit arch ${other_arch}: the ${other_arch}-resident contrib component IS listed" \
   "contrib" "${other_comps}"

## --- binary-all is NOT consulted: a component resident ONLY under binary-all must be dropped ------
## reprepro folds arch:all into each binary-<arch> index and makes no binary-all tree; counting
## binary-all would keep a component whose native binary-<arch>/Packages is absent/0-byte, which apt
## then hard-fails fetching. Seed contrib only under binary-all + empty native main -> fallback main.
mk_local_repo "${repo_fix}/allonly" local "main:${native_arch}:0" contrib:all:50
allonly_comps="$(local_apt_repo_sources_stanza "file:${repo_fix}/allonly" 'local' | sed -n 's/^Components: //p')"
check_eq "binary-all-only component is dropped (native binary-<arch> is the sole signal)" \
   "main" "${allonly_comps}"

## --- read_root override: emit guest URI, read residency from host path ------
## A host-side caller (dm-whonix-pair) emits the GUEST mount URI but must probe
## residency at the readable HOST path.
actual_override="$(local_apt_repo_sources_stanza 'file:/mnt/shared/aptrepo_local/whonix' 'local' "${repo_fix}/whonix")"
if [[ "${nl}${actual_override}${nl}" == *"${nl}URIs: file:/mnt/shared/aptrepo_local/whonix${nl}"* ]] \
   && [[ "${nl}${actual_override}${nl}" == *"${nl}Components: main${nl}"* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: read_root override emits the guest URI while reading residency from the host path"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: read_root override wrong -- got: ${actual_override}"
fi

## --- unreadable repo path -> safe fallback 'main' ---------------------------
## Residency undeterminable (path absent): fall back to 'main' -- always present
## in a derivative local repo -- never the over-broad set that breaks on an empty
## component.
actual_absent="$(local_apt_repo_sources_stanza 'file:/nonexistent/local-apt-repo/kicksecure' 'local')"
check_eq "absent repo path falls back to Components: main" \
   "main" "$(printf '%s\n' "${actual_absent}" | sed -n 's/^Components: //p')"

## --- no leading blank line (caller owns multi-stanza separation) ------------
if [ "${actual_full:0:1}" = $'\n' ]; then
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

## --- CANARY: the trust contract --------------------------------------------
## This stanza MUST carry 'Trusted: yes' (apt 3.0 fatally refuses the unsigned
## local repo without it). If dropped, the two consumers silently diverge from
## apt's expectations -- assert it explicitly rather than trusting the block above.
if [[ "${nl}${actual_full}${nl}" == *"${nl}Trusted: yes${nl}"* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: canary: Trusted: yes is present"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: canary: missing 'Trusted: yes'"
fi

rm --recursive --force -- "${repo_fix}"

## --- local_apt_repo_base_stanza + local_apt_repo_pin: Debian-base mirror sources ----------------
## A local Debian mirror stores the COMPRESSED index (Packages.gz/.xz) and typically NO uncompressed
## Packages and NO by-hash tree, so residency must accept any index form. A component the signed
## InRelease OFFERS but whose index is ABSENT on disk MUST still be excluded (an offered-but-absent
## component makes apt-get update hard-fail exit 100); the genuine signed Release means NO
## 'Trusted: yes'; an uncompressed 'Packages' InRelease entry anchors the per-component enumeration.
if [ "$(type -t local_apt_repo_base_stanza)" = 'function' ]; then
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
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: local_apt_repo_base_stanza not defined (Debian-base mirror generator missing)"
fi

printf '%s\n' ""
printf '%s\n' "===== local_apt_repo_sources: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
