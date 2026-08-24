#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-reproducible-fetch Whonix support.
## In --version mode the tool builds a download URL that MIRRORS the build's own
## image naming (help-steps/variables): Kicksecure-<desktop> and, for Whonix,
## Whonix-<desktop> (combined image, no role), on the project download domain. This
## drives the REAL tool with a stubbed scurl (so the URL is built but nothing is
## downloaded) and asserts the constructed URL for kicksecure (regression) and
## whonix (new) flavors, including the whonix.org default domain.
##
## A naming drift only ever yields a 404, never a wrong download (the tool says
## so), so this URL-shape check is the meaningful guard; a live download is not.
##
## Self-contained apart from the shipped reproducible-target-map.bsh the tool
## sources. Needs no root, no network, no build.
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

rel='usr/bin/dm-reproducible-fetch'
candidates=()
[ -z "${DM_REPRODUCIBLE_FETCH:-}" ] || candidates+=( "${DM_REPRODUCIBLE_FETCH}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-reproducible-fetch not found (set DM_REPRODUCIBLE_FETCH)." >&2
   exit 1
fi

workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## Stub scurl: the tool builds and prints the URL, THEN downloads; a scurl that
## exits immediately lets us capture the URL without any network.
stub_bin="${workdir}/bin"
mkdir --parents -- "${stub_bin}"
printf '%s\n' '#!/bin/bash' 'exit 22' > "${stub_bin}/scurl"
chmod 0755 -- "${stub_bin}/scurl"

## Build the URL the tool would fetch for (flavor, target); echo it. The tool
## exits non-zero once the stubbed scurl "download" fails, and the URL is printed
## before that -- so capture the output (|| true) then extract, rather than
## piping through the tool (which would SIGPIPE under pipefail).
built_url() {
   local out
   out="$(PATH="${stub_bin}:${PATH}" bash -- "${subject}" \
      --version 18.2.1.7 --arch amd64 --target "$2" --flavor "$1" \
      --output-dir "${workdir}/out" 2>&1 || true)"
   printf '%s\n' "${out}" | grep --only-matching --max-count=1 --extended-regexp 'https://download[^ ]+' || true
}

expect_url() {
   local flavor="$1" target="$2" want="$3" got
   got="$(built_url "${flavor}" "${target}")"
   if [ "${got}" = "${want}" ]; then
      pass "${flavor}/${target} -> ${got}"
   else
      fail "${flavor}/${target} -> '${got}', wanted '${want}'"
   fi
}

## Kicksecure (regression: domain kicksecure.com, name Kicksecure-<desktop>).
expect_url kicksecure-cli qcow2 \
   'https://download.kicksecure.com/libvirt/18.2.1.7/Kicksecure-CLI-18.2.1.7.Intel_AMD64.qcow2.libvirt.xz'
expect_url kicksecure-lxqt iso \
   'https://download.kicksecure.com/iso/18.2.1.7/Kicksecure-LXQt-18.2.1.7.Intel_AMD64.iso'

## Whonix: domain whonix.org, name Whonix-<desktop> (COMBINED image, no role --
## verified against download.whonix.org: 'Whonix-CLI-<v>...' resolves, the roled
## 'Whonix-Gateway-CLI-<v>...' 404s).
expect_url whonix-cli qcow2 \
   'https://download.whonix.org/libvirt/18.2.1.7/Whonix-CLI-18.2.1.7.Intel_AMD64.qcow2.libvirt.xz'
expect_url whonix-lxqt virtualbox \
   'https://download.whonix.org/ova/18.2.1.7/Whonix-LXQt-18.2.1.7.Intel_AMD64.ova'
expect_url whonix-lxqt iso \
   'https://download.whonix.org/iso/18.2.1.7/Whonix-LXQt-18.2.1.7.Intel_AMD64.iso'

## An explicit --project overrides the flavor default.
override_out="$(PATH="${stub_bin}:${PATH}" bash -- "${subject}" \
   --version 18.2.1.7 --arch amd64 --target qcow2 --flavor whonix-cli \
   --project example.com --output-dir "${workdir}/out" 2>&1 || true)"
override_url="$(printf '%s\n' "${override_out}" | grep --only-matching --max-count=1 --extended-regexp 'https://download[^ ]+' || true)"
case "${override_url}" in
   https://download.example.com/*)
      pass "--project overrides the flavor default (${override_url})"
      ;;
   *)
      fail "--project did not override the domain: ${override_url}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-reproducible-fetch Whonix URL construction (${pass_count} assertions)."
