#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'dm-buildinfo-compare.py', the input half of
## local-vs-CI reproducibility verification.
##
## THE DISTINCTION IT EXISTS TO PROTECT: two images that differ tell you nothing
## until you know they were built from the same inputs. A local build and a CI
## build of the same Source-Commit can still differ in the SUBMODULE commits that
## commit resolved to -- CI checks submodules out to a moving branch TIP -- or in
## the APT snapshot, or in SOURCE_DATE_EPOCH. Reporting that as "not
## reproducible" sends someone hunting a nondeterminism bug that is not there.
##
## So: inputs differ -> exit 3, a byte difference is EXPECTED.
##     inputs match  -> exit 0, and only then does a byte difference mean
##                      something.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

subject=""
for candidate in "${DM_BUILDINFO_COMPARE:-}" \
   "${test_dir}/../../libexec/dist-ai/dm-buildinfo-compare.py" \
   "/usr/libexec/dist-ai/dm-buildinfo-compare.py"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-buildinfo-compare.py not found (set DM_BUILDINFO_COMPARE)." >&2
   exit 1
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## $1 name, $2 Source-Commit, $3 submodule sha, $4 APT snapshot, $5 epoch
write_record() {
   {
      printf '%s\n' 'Format: 1.0'
      printf '%s\n' 'Buildinfo-Type: derivative-image'
      printf '%s\n' 'Source-Repo: https://example.com/dm'
      printf '%s\n' "Source-Commit: $2"
      printf '%s\n' 'Submodule-State:'
      printf '%s\n' " $3 packages/kicksecure/developer-meta-files (heads/ai)"
      printf '%s\n' 'Source-Version: 18.2.2.0'
      printf '%s\n' 'Flavor: kicksecure-debug'
      printf '%s\n' 'Target: qcow2'
      printf '%s\n' 'Build-Type: vm'
      printf '%s\n' 'Architecture: amd64'
      printf '%s\n' 'Freedom: false'
      printf '%s\n' 'Debian-Suite: trixie'
      printf '%s\n' "APT-Snapshot: $4"
      printf '%s\n' "Source-Date-Epoch: $5"
      printf '%s\n' 'Image-File: img.qcow2.libvirt.xz'
      printf '%s\n' ''
   } > "${workdir}/$1"
}

run_compare() {
   local rc=0
   python3 -- "${subject}" "${workdir}/$1" "${workdir}/$2" > "${workdir}/out.txt" 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

write_record base.info aaaa111 bbbb222 snap-1 1600000000

## --- identical inputs -------------------------------------------------------
## The canary for everything below: a comparator that always reported a
## difference would satisfy every negative assertion here.
write_record same.info aaaa111 bbbb222 snap-1 1600000000
rc="$(run_compare base.info same.info)"
if [ "${rc}" -eq 0 ]; then
   pass "canary: identical inputs compare equal"
else
   fail "canary broken: identical inputs reported as differing (${rc})"
   cat -- "${workdir}/out.txt" >&2
fi

## --- the submodule SHA: the case this whole exercise turned on --------------
## A commit does NOT pin its submodules when CI checks them out to a branch tip,
## so this is the input that silently differed before it was recorded.
write_record sub.info aaaa111 CCCC999 snap-1 1600000000
rc="$(run_compare base.info sub.info)"
if [ "${rc}" -eq 3 ]; then
   pass "a differing submodule SHA is reported as an INPUT difference"
else
   fail "a differing submodule SHA gave exit ${rc}; expected 3"
   cat -- "${workdir}/out.txt" >&2
fi
if grep --quiet --fixed-strings -- 'Submodule-State' "${workdir}/out.txt"; then
   pass "the report names the field that differed"
else
   fail "the report does not name Submodule-State"
   cat -- "${workdir}/out.txt" >&2
fi

## --- the other inputs that make a byte comparison meaningless ---------------
write_record snap.info aaaa111 bbbb222 snap-2 1600000000
rc="$(run_compare base.info snap.info)"
if [ "${rc}" -eq 3 ]; then
   pass "a differing APT snapshot is an INPUT difference"
else
   fail "a differing APT snapshot gave exit ${rc}; expected 3"
fi
write_record epoch.info aaaa111 bbbb222 snap-1 1700000000
rc="$(run_compare base.info epoch.info)"
if [ "${rc}" -eq 3 ]; then
   pass "a differing SOURCE_DATE_EPOCH is an INPUT difference"
else
   fail "a differing SOURCE_DATE_EPOCH gave exit ${rc}; expected 3"
fi

## --- an INFORMATIONAL field must NOT be treated as an input -----------------
## Otherwise every comparison of two differently-named files would report an
## input difference and the tool would never reach the bytes.
sed -e 's|^Image-File: .*|Image-File: other-name.qcow2.libvirt.xz|' \
   "${workdir}/base.info" > "${workdir}/name.info"
rc="$(run_compare base.info name.info)"
if [ "${rc}" -eq 0 ]; then
   pass "a differing Image-File is NOT an input difference"
else
   fail "a differing Image-File was treated as an input (${rc}); the tool would never compare bytes"
   cat -- "${workdir}/out.txt" >&2
fi

## --- an UNCLASSIFIED field must refuse, not pass silently -------------------
## A new input added upstream and not classified here would otherwise be
## compared by nobody, and a difference in it would go unreported.
sed -e 's|^Freedom: false|Freedom: false\nBrand-New-Input: x|' \
   "${workdir}/base.info" > "${workdir}/unknown.info"
rc="$(run_compare unknown.info base.info)"
if [ "${rc}" -eq 2 ]; then
   pass "an unclassified field refuses a verdict"
else
   fail "an unclassified field gave exit ${rc}; expected 2 -- it would go uncompared"
   cat -- "${workdir}/out.txt" >&2
fi

## The unclassified field must be caught regardless of WHICH record carries it.
## A field present only in the SECOND (B) record and scanned only via the first
## would slip past unclassified, get compared by nobody, and let B drift.
rc="$(run_compare base.info unknown.info)"
if [ "${rc}" -eq 2 ]; then
   pass "an unclassified field present only in the B record refuses a verdict"
else
   fail "a B-only unclassified field gave exit ${rc}; expected 2 -- it would go uncompared"
   cat -- "${workdir}/out.txt" >&2
fi

## --- a malformed record refuses too ----------------------------------------
printf '%s\n' 'this is not deb822' > "${workdir}/junk.info"
rc="$(run_compare base.info junk.info)"
if [ "${rc}" -eq 2 ]; then
   pass "a malformed record refuses a verdict"
else
   fail "a malformed record gave exit ${rc}; expected 2"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: buildinfo input comparison."
