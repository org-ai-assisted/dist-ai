#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1100_sanity-tests'
## check-libvirt-xml.
##
## THE BUG IT GUARDS: the libvirt XML that 1600_export-libvirt-xml copies for every
## raw or qcow2 target is named after SHORT_VMNAME, which is derived from the
## FLAVOR. A flavor with no such XML was accepted, and the build then ran for ~15
## minutes -- through the whole cowbuilder package phase -- before dying on a bare
## "cp: cannot stat '.../source.xml'", naming neither the flavor nor the
## combination that produced it. '--flavor source --target raw' is the concrete
## case; it reached the CI dry-run lane.
##
## Drives the SHIPPED function, so a regression in the real gate or the real
## message fails here.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

sanity_tests=""
locate_subject() {
   local candidate

   for candidate in "${DM_SANITY_TESTS:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1100_sanity-tests" \
      "${HOME}/derivative-maker/build-steps.d/1100_sanity-tests"; do
      case "${candidate}" in
         ''|'/build-steps.d/1100_sanity-tests')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         sanity_tests="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: 1100_sanity-tests not found (set DM_SANITY_TESTS)." >&2
   exit 77
fi

if grep --quiet -- '^check-libvirt-xml()' "${sanity_tests}"; then
   pass "1100_sanity-tests defines check-libvirt-xml"
else
   fail "1100_sanity-tests does not define check-libvirt-xml"
fi

## A guard that is never called guards nothing.
if sed -n '/^main()/,/^}/p' -- "${sanity_tests}" | grep --quiet -- 'check-libvirt-xml'; then
   pass "check-libvirt-xml is called from main"
else
   fail "check-libvirt-xml is defined but never called from main"
fi

## The guard and the step it protects must read the SAME variable, or the guard
## silently checks a different file than the one 1600 copies.
export_step="$(dirname -- "${sanity_tests}")/1600_export-libvirt-xml"
if [ -r "${export_step}" ]; then
   if grep --quiet --fixed-strings -- 'libvirt_source_kvm_file' "${export_step}"; then
      pass "1600_export-libvirt-xml copies the same libvirt_source_kvm_file the guard checks"
   else
      fail "1600_export-libvirt-xml no longer reads libvirt_source_kvm_file; the guard now protects nothing"
   fi
else
   fail "1600_export-libvirt-xml not found beside ${sanity_tests}"
fi

guard="$(sed -n '/^check-libvirt-xml()/,/^}/p' -- "${sanity_tests}")"
if [ -z "${guard}" ]; then
   printf '%s\n' "FAILED: could not extract check-libvirt-xml." >&2
   exit 1
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## A realistic xml/ directory: the flavors that DO have an XML, and no 'source.xml'.
xml_dir="${workdir}/xml"
mkdir --parents -- "${xml_dir}"
for present in Kicksecure Whonix-Gateway Whonix-Workstation; do
   printf '%s\n' '<domain/>' > "${xml_dir}/${present}.xml"
done

run_guard() {
   local raw="$1" qcow2="$2" xml_file="$3" flavor="$4"

   env dist_build_raw="${raw}" dist_build_qcow2="${qcow2}" \
      libvirt_source_kvm_file="${xml_file}" dist_build_flavor="${flavor}" \
      bash -- "${test_dir}/libvirt_xml_guard_inner.sh" "${guard}" 2>&1
}

## --- raw target, flavor has no XML -> must fail, and say what and why -------
rc=0
out="$(run_guard true false "${xml_dir}/source.xml" source)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "raw target with no libvirt XML: rejected (${rc})"
else
   fail "raw target with no libvirt XML: accepted -- the build would die ~15 minutes later in 1600"
fi
case "${out}" in
   *"source.xml"*)
      pass "rejection names the file it looked for"
      ;;
   *)
      fail "rejection does not name the missing file -- ${out}"
      ;;
esac
case "${out}" in
   *"flavor"*"source"*)
      pass "rejection names the flavor"
      ;;
   *)
      fail "rejection does not name the flavor -- ${out}"
      ;;
esac
case "${out}" in
   *Kicksecure*)
      pass "rejection lists the flavors that do have an XML"
      ;;
   *)
      fail "rejection does not list the available XML files, leaving no way forward -- ${out}"
      ;;
esac

## --- qcow2 reaches 1600 too, so it must be gated the same way ---------------
rc=0
run_guard false true "${xml_dir}/source.xml" source >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "qcow2 target with no libvirt XML: rejected"
else
   fail "qcow2 target with no libvirt XML: accepted -- 1600 runs for qcow2 as well as raw"
fi

## --- CANARY: a valid combination must PASS ---------------------------------
## Without this the assertions above are satisfied by a guard that rejects
## everything, which would break every real build.
rc=0
out="$(run_guard true false "${xml_dir}/Kicksecure.xml" kicksecure-cli)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "canary: raw target whose flavor HAS an XML is accepted"
else
   fail "canary broken: a valid raw build was rejected (${rc}) -- ${out}"
fi

## --- CANARY: no image target -> not this guard's business -------------------
## 1600 skips entirely when neither raw nor qcow2 is set, so a missing XML is
## irrelevant there and must not fail a source-only build.
rc=0
out="$(run_guard false false "${xml_dir}/source.xml" source)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "canary: source-only build is not gated on a libvirt XML"
else
   fail "canary broken: source-only build rejected (${rc}) -- 1600 does not even run -- ${out}"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: libvirt XML precondition."
