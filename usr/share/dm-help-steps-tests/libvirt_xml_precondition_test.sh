#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker
## 'build-steps.d/1600_export-libvirt-xml'.
##
## THE BUG IT GUARDS: the libvirt XML this step copies for every raw or qcow2
## target is named after SHORT_VMNAME, which is derived from the FLAVOR. A source
## build sets SHORT_VMNAME to the literal 'source', for which no XML has ever
## existed, so '--flavor source' plus an image target ran for ~15 minutes --
## through the whole cowbuilder package phase -- and then died on a bare
## "cp: cannot stat '.../source.xml'", naming neither the flavor nor the
## combination that produced it. It reached the CI dry-run lane.
##
## Two separate properties, both asserted below:
##   1. a source build SKIPS this step outright (there is no VM to export)
##   2. any other missing XML fails with a message that names the flavor, the
##      file, and the flavors that do have one
##
## Drives the SHIPPED functions, so a regression in the real gate or the real
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

build_steps_dir=""
locate_subject() {
   local candidate

   for candidate in "${DM_SANITY_TESTS:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1100_sanity-tests" \
      "${dm_checkout}/build-steps.d/1100_sanity-tests"; do
      case "${candidate}" in
         ''|'/build-steps.d/1100_sanity-tests')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         build_steps_dir="$(dirname -- "${candidate}")"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: build-steps.d not found (set DM_SANITY_TESTS)." >&2
   exit 77
fi

sanity_tests="${build_steps_dir}/1100_sanity-tests"
export_step="${build_steps_dir}/1600_export-libvirt-xml"
if [ ! -r "${export_step}" ]; then
   printf '%s\n' "FAILED: ${export_step} not found." >&2
   exit 1
fi

## The precondition belongs to the step that does the copy, in ONE place. A
## second copy in 1100_sanity-tests has to duplicate 1600's target gating to stay
## correct, and drifts the moment either side changes.
if sed -n '/^main()/,/^}/p' -- "${sanity_tests}" | grep --quiet -- 'libvirt'; then
   fail "1100_sanity-tests calls a libvirt check again; 1600_export-libvirt-xml owns this precondition"
else
   pass "1100_sanity-tests does not duplicate the libvirt precondition"
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

run_step() {
   local source_run="$1" raw="$2" qcow2="$3" xml_file="$4" flavor="$5"

   env dist_build_source_run="${source_run}" \
      dist_build_raw="${raw}" dist_build_qcow2="${qcow2}" \
      libvirt_source_kvm_file="${xml_file}" dist_build_flavor="${flavor}" \
      binary_build_folder_dist="${workdir}/binary" \
      libvirt_target_kvm_file="${workdir}/binary/out.xml" \
      bash -- "${test_dir}/libvirt_xml_guard_inner.sh" "${export_step}" 2>&1
}

## --- the source build must SKIP, not look for a 'source.xml' ---------------
## '--flavor source' still sets dist_build_qcow2 for an image target, so the
## target gate alone does not stop it.
rc=0
out="$(run_step true false true "${xml_dir}/source.xml" source)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "source build with a qcow2 target: skipped, not failed"
else
   fail "source build with a qcow2 target: exited ${rc} -- ${out}"
fi
case "${out}" in
   *STUB-CP*)
      fail "source build reached the copy; it must skip -- ${out}"
      ;;
   *)
      pass "source build did not reach the copy"
      ;;
esac

## Same for a raw target, since 1600 exports for either.
rc=0
out="$(run_step true true false "${xml_dir}/source.xml" source)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "source build with a raw target: skipped"
else
   fail "source build with a raw target: exited ${rc} -- ${out}"
fi
## Exit 0 alone does not distinguish "skipped" from "copied the wrong file
## successfully", which is exactly what the pre-fix code did.
case "${out}" in
   *STUB-CP*)
      fail "source build with a raw target reached the copy -- ${out}"
      ;;
   *)
      pass "source build with a raw target did not reach the copy"
      ;;
esac

## --- a non-source flavor with no XML must fail, and say what and why -------
rc=0
out="$(run_step false true false "${xml_dir}/kicksecure-nonexistent.xml" kicksecure-nonexistent)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "raw target with no libvirt XML: rejected"
else
   fail "raw target with no libvirt XML: accepted -- the build would die on a bare 'cp: cannot stat'"
fi
case "${out}" in
   *"kicksecure-nonexistent.xml"*)
      pass "rejection names the file it looked for"
      ;;
   *)
      fail "rejection does not name the missing file -- ${out}"
      ;;
esac
case "${out}" in
   *"flavor"*"kicksecure-nonexistent"*)
      pass "rejection names the flavor"
      ;;
   *)
      fail "rejection does not name the flavor -- ${out}"
      ;;
esac
case "${out}" in
   *Kicksecure.xml*)
      pass "rejection lists the flavors that do have an XML"
      ;;
   *)
      fail "rejection does not list the available XML files, leaving no way forward -- ${out}"
      ;;
esac

## --- qcow2 reaches the copy too, so it must be gated the same way ----------
rc=0
run_step false false true "${xml_dir}/kicksecure-nonexistent.xml" kicksecure-nonexistent >/dev/null 2>&1 || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "qcow2 target with no libvirt XML: rejected"
else
   fail "qcow2 target with no libvirt XML: accepted -- 1600 exports for qcow2 as well as raw"
fi

## --- CANARY: a valid combination must reach the copy ------------------------
## Without this the assertions above are satisfied by a step that rejects
## everything, which would break every real image build.
rc=0
out="$(run_step false true false "${xml_dir}/Kicksecure.xml" kicksecure-cli)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "canary: raw target whose flavor HAS an XML is accepted"
else
   fail "canary broken: a valid raw build was rejected (${rc}) -- ${out}"
fi
case "${out}" in
   *STUB-CP*Kicksecure.xml*)
      pass "canary: the valid build actually reached the copy"
      ;;
   *)
      fail "canary broken: a valid raw build never reached the copy -- ${out}"
      ;;
esac

## --- CANARY: no image target -> the step does not run at all ---------------
rc=0
out="$(run_step false false false "${xml_dir}/source.xml" kicksecure-cli)" || rc="$?"
if [ "${rc}" -eq 0 ]; then
   pass "canary: build with no image target is not gated on a libvirt XML"
else
   fail "canary broken: build with no image target rejected (${rc}) -- ${out}"
fi

## --- an EMPTY libvirt_source_kvm_file is its own failure --------------------
## 'dirname -- ""' is '.', which exists, so a naive listing dumps the entire
## source root into the error message instead of naming the XML files.
rc=0
out="$(run_step false true false "" kicksecure-cli)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "empty libvirt_source_kvm_file: rejected"
else
   fail "empty libvirt_source_kvm_file: accepted"
fi
case "${out}" in
   *"libvirt_source_kvm_file is empty"*)
      pass "empty value: named as its own failure"
      ;;
   *)
      fail "empty value: not identified as an empty variable -- ${out}"
      ;;
esac
## The tell for the bug is the LISTING branch running at all: with an empty value
## it computes '.' as the XML directory and lists the caller's cwd under this
## header.
case "${out}" in
   *"Flavors that do have one"*)
      fail "empty value: took the listing branch, so it dumped a directory that is not an XML dir -- ${out}"
      ;;
   *)
      pass "empty value: did not take the listing branch"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: libvirt XML precondition."
