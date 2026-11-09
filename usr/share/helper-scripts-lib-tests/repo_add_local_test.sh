#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL repo-add-local (helper-scripts usr/bin) end to end with
## --repo-dir against a fake local repo. The root check (id) and apt-get are
## PATH-stubbed, and the sources file is written into a temp dir via the tool's
## REPO_ADD_LOCAL_SOURCES_LIST_D env seam -- so no root, no network, and nothing
## touches the real /etc/apt. Asserts the tool emits the SHARED generator's exact
## [trusted=yes] stanza to local-apt-repo-srv.sources and runs 'apt-get update';
## canary: a repo missing dists/local is refused non-zero.

## style-ok: no-safe-rm (rm -rf of our own mktemp work dir only)

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/bin/repo-add-local"
   lib="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/local-apt-repo-sources.bsh"
   hs_path="${HELPER_SCRIPTS_REPO}"
else
   subject="/usr/bin/repo-add-local"
   lib="/usr/libexec/helper-scripts/local-apt-repo-sources.bsh"
   hs_path=""
fi

if [ ! -x "${subject}" ]; then
   printf '%s\n' "FATAL: repo-add-local not executable at '${subject}'; set HELPER_SCRIPTS_REPO or install helper-scripts." >&2
   exit 1
fi
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FATAL: local-apt-repo-sources.bsh not readable at '${lib}'." >&2
   exit 1
fi

# shellcheck disable=SC1090
source "${lib}"

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"; }
bad() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1"; }

tmp="$(mktemp --directory)"
cleanup() { rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT

## Fixtures: a fake 'local' repo, a sources dir, PATH stubs (root/network actions).
mkdir --parents -- "${tmp}/repo/dists/local" "${tmp}/sources" "${tmp}/prefs" "${tmp}/stubs" "${tmp}/apt"
printf '%s\n' '#!/bin/bash' 'printf %s\\n 0' > "${tmp}/stubs/id"
printf '%s\n' '#!/bin/bash' "printf '%s\\n' \"apt-get \$*\" >> \"${tmp}/apt/log\"" > "${tmp}/stubs/apt-get"
chmod +x -- "${tmp}/stubs/id" "${tmp}/stubs/apt-get"

## --- happy path: --repo-dir, kicksecure, srv location --------------------------
rc=0
PATH="${tmp}/stubs:${PATH}" \
   REPO_ADD_LOCAL_SOURCES_LIST_D="${tmp}/sources" \
   REPO_ADD_LOCAL_PREFERENCES_D="${tmp}/prefs" \
   HELPER_SCRIPTS_PATH="${hs_path}" \
   "${subject}" --repo-dir "${tmp}/repo" kicksecure >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
   ok "runs clean with --repo-dir against a valid repo"
else
   bad "exited ${rc} on a valid repo"
fi

sources_file="${tmp}/sources/local-apt-repo-srv.sources"
if [ -f "${sources_file}" ]; then
   ok "wrote the srv-location sources file (${sources_file##*/})"
else
   bad "did not write ${sources_file}"
fi

## Drift guard: the file is EXACTLY the shared generator's stanza.
expected="$(local_apt_repo_sources_stanza "file:${tmp}/repo" "local")"
if [ -f "${sources_file}" ] && [ "$(cat -- "${sources_file}")" = "${expected}" ]; then
   ok "sources file matches the shared stanza generator verbatim"
else
   bad "sources file diverges from the shared stanza generator"
fi

## It only ENABLES the repo (writes the stanza); running apt-get is the caller's
## job, so the stubbed apt-get must NOT have been invoked.
if [ ! -e "${tmp}/apt/log" ]; then
   ok "does NOT run apt-get (enabling only)"
else
   bad "ran apt-get (not its task): $(cat -- "${tmp}/apt/log")"
fi

## The pin preferences file is written unconditionally -- it forces the file: local sources above
## the Tor remotes (covering this derivative repo and the Debian-base cache sources).
pin_file="${tmp}/prefs/local-apt-repo.pref"
if [ -f "${pin_file}" ] && [ "$(cat -- "${pin_file}")" = "$(local_apt_repo_pin)" ]; then
   ok "wrote the local-sources pin (priority 1000) matching the shared generator"
else
   bad "did not write the expected pin to ${pin_file}"
fi

## --- mnt location + Debian-base cache: resident-component base sources + pin --------------------
## Drive the mnt path via the REPO_ADD_LOCAL_GUEST_MOUNT seam (fixture, no real mountpoint): a
## derivative 'local' repo PLUS an aptcache whose 'debian' nick offers main (RESIDENT) + contrib
## (OFFERED but uncached) for the host codename. Expect base sources with ONLY the resident
## component, not Trusted:yes, plus the pin.
mnt_cn="$( . /etc/os-release 2>/dev/null || true; printf '%s' "${VERSION_CODENAME:-trixie}" )"
mnt_arch="$(dpkg --print-architecture 2>/dev/null || printf '%s' amd64)"
mnt_dists="${tmp}/mnt/aptcache/debian/dists/${mnt_cn}"
mkdir --parents -- \
   "${tmp}/mnt/aptrepo_local/whonix/dists/local" \
   "${mnt_dists}/main/binary-${mnt_arch}/by-hash/SHA256" \
   "${mnt_dists}/contrib/binary-${mnt_arch}/by-hash/SHA256" \
   "${tmp}/mnt-sources" "${tmp}/mnt-prefs"
mnt_mh="$(printf '%s' mainidx | sha256sum | cut -d' ' -f1)"
mnt_ch="$(printf '%s' contribidx | sha256sum | cut -d' ' -f1)"
touch -- "${mnt_dists}/main/binary-${mnt_arch}/by-hash/SHA256/${mnt_mh}"
printf '%s\n' "SHA256:" \
   " ${mnt_mh} 12345 main/binary-${mnt_arch}/Packages" \
   " ${mnt_ch} 6789 contrib/binary-${mnt_arch}/Packages" \
   > "${mnt_dists}/InRelease"

rc=0
PATH="${tmp}/stubs:${PATH}" \
   REPO_ADD_LOCAL_GUEST_MOUNT="${tmp}/mnt" \
   REPO_ADD_LOCAL_SOURCES_LIST_D="${tmp}/mnt-sources" \
   REPO_ADD_LOCAL_PREFERENCES_D="${tmp}/mnt-prefs" \
   HELPER_SCRIPTS_PATH="${hs_path}" \
   "${subject}" whonix >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
   ok "runs clean in the mnt case with an aptcache present"
else
   bad "exited ${rc} in the mnt+aptcache case"
fi

base_sources="${tmp}/mnt-sources/local-apt-repo-base-mnt.sources"
if [ -f "${base_sources}" ] \
   && grep --quiet --fixed-strings "URIs: file:${tmp}/mnt/aptcache/debian" -- "${base_sources}" \
   && grep --quiet "^Suites: ${mnt_cn}$" -- "${base_sources}" \
   && grep --quiet '^Components: main$' -- "${base_sources}"; then
   ok "mnt: wrote Debian-base sources for the cache-resident component (main)"
else
   bad "mnt: base sources missing or wrong$( [ -f "${base_sources}" ] && printf '%s' " -- $(cat -- "${base_sources}")" )"
fi
## CANARY: the offered-but-uncached contrib must NOT appear, and the base source must NOT be Trusted.
if [ -f "${base_sources}" ] && ! grep --quiet 'contrib' -- "${base_sources}" && ! grep --quiet 'Trusted:' -- "${base_sources}"; then
   ok "mnt canary: offered-but-uncached contrib excluded; base source not Trusted:yes"
else
   bad "mnt canary: base source included an uncached component or Trusted:yes"
fi
if [ -f "${tmp}/mnt-prefs/local-apt-repo.pref" ]; then
   ok "mnt: wrote the local-sources pin"
else
   bad "mnt: did not write the pin"
fi

## --- canary: a repo WITHOUT dists/local is refused -----------------------------
mkdir --parents -- "${tmp}/empty"
rc=0
PATH="${tmp}/stubs:${PATH}" \
   REPO_ADD_LOCAL_SOURCES_LIST_D="${tmp}/sources" \
   HELPER_SCRIPTS_PATH="${hs_path}" \
   "${subject}" --repo-dir "${tmp}/empty" kicksecure >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
   ok "canary: refuses a repo missing dists/local (exit ${rc})"
else
   bad "canary: accepted a repo with no dists/local"
fi

printf '%s\n' ""
printf '%s\n' "===== repo_add_local: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
