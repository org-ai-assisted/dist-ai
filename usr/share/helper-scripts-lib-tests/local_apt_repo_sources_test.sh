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
## The fixtures are keyed to the REAL native arch, so the test must KNOW it, not guess: a
## fabricated amd64 fallback would silently mislabel which binary-<arch> is "native" on an arm64
## host and invert this very regression. dpkg is a hard test dependency; its absence is an env bug.
if ! native_arch="$(dpkg --print-architecture 2>/dev/null)" || [ -z "${native_arch}" ]; then
   printf '%s\n' "FATAL: dpkg --print-architecture unavailable; cannot determine the native arch" >&2
   exit 1
fi
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

## --- compressed-only index: a component whose binary-<arch> ships ONLY a non-empty
## compressed Packages.gz/.xz (reprepro / a real mirror form, no uncompressed Packages)
## must still be seen. CANARY: an uncompressed-Packages-only probe drops it, and with
## an empty native main this falls back to 'main' -- the exact silent contrib/non-free
## drop this guards. main is 0-byte here, so a correct probe lists ONLY the two
## compressed components.
mk_local_repo "${repo_fix}/compressed" local "main:${native_arch}:0"
for comp_idx in "contrib:Packages.gz" "non-free:Packages.xz"; do
   comp="${comp_idx%%:*}"; idx_name="${comp_idx##*:}"
   comp_dir="${repo_fix}/compressed/dists/local/${comp}/binary-${native_arch}"
   mkdir --parents -- "${comp_dir}"
   printf '%s' idx > "${comp_dir}/${idx_name}"
done
compressed_comps="$(local_apt_repo_sources_stanza "file:${repo_fix}/compressed" 'local' | sed -n 's/^Components: //p')"
check_eq "compressed-only Packages.gz/.xz components are recognized (empty main dropped)" \
   "contrib non-free" "${compressed_comps}"

## --- component-name charset guard: a dir name embedding a newline + a forged deb822
## field must be skipped, never copied into this Trusted stanza (a forged Suites:
## would override the suite and point apt elsewhere). CANARY: without the guard the
## injected 'Suites: trixie' appears in the output and the component leaks in.
evil_root="${repo_fix}/evilname"
mk_local_repo "${evil_root}" local "main:${native_arch}:40"
evil_comp="evil${nl}Suites: trixie"
evil_dir="${evil_root}/dists/local/${evil_comp}/binary-${native_arch}"
mkdir --parents -- "${evil_dir}"
printf '%s' x > "${evil_dir}/Packages"
evil_out="$(local_apt_repo_sources_stanza "file:${evil_root}" 'local')"
## The forged value must not leak ANYWHERE in the stanza (the injected field
## renders as 'Suites: trixie main' -- the next component is appended -- so an
## exact 'Suites: trixie' line match would miss it); and the suite must stay 'local'.
if [ "$(printf '%s\n' "${evil_out}" | sed -n 's/^Components: //p')" = "main" ] \
   && [[ "${evil_out}" != *trixie* ]] \
   && [[ "${nl}${evil_out}${nl}" == *"${nl}Suites: local${nl}"* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: malicious component dir name (newline + forged field) is skipped"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: malicious component name leaked into the stanza -- got: ${evil_out}"
fi

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

## The Debian-base mirror stanza (local_apt_repo_base_stanza) moved to dist-ai's own
## library; its unit tests live in local_apt_repo_base_test.sh.

printf '%s\n' ""
printf '%s\n' "===== local_apt_repo_sources: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
