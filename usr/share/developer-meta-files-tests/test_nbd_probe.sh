#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-reproducible-compare-artifacts':
## a missing 'modprobe' must not abandon the filesystem comparison when the nbd
## device is already usable.
##
## THE BUG IT GUARDS: the function opened with
##     sudo --non-interactive modprobe nbd max_part=16 || return 1
## and this tool runs INSIDE the derivative-maker container, which ships no kmod.
## So 'modprobe' was "command not found", the whole qemu-nbd + diffoscope descent
## was abandoned, and the run reported only
##     diffoscope could not explain the diff (exit 2)
## on a host where the nbd module was already loaded and '/dev/nbd0' visible
## through the container's '--volume /dev:/dev'. The diagnostic that exists to
## explain a reproducibility failure was unavailable precisely when one occurred.
##
## Loading the module is a MEANS; a usable '/dev/nbd*' is the requirement.
##
## Extracts the shipped 'filesystem_mounts_setup' preamble and drives it with
## 'modprobe' forced to fail, so the REAL logic is exercised. Asserts both
## directions -- device present: continue; device absent: fail, by name -- and
## canaries the pre-fix form, which must abandon on the same fixture.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

subject=""
locate_subject() {
   local candidate

   for candidate in "${DM_COMPARE_ARTIFACTS:-}" \
      "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-reproducible-compare-artifacts" \
      "${HOME}/derivative-maker/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-compare-artifacts" \
      "/usr/bin/dm-reproducible-compare-artifacts"; do
      case "${candidate}" in
         ''|'/usr/bin/dm-reproducible-compare-artifacts')
            [ -r "${candidate}" ] || continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         subject="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: dm-reproducible-compare-artifacts not found." >&2
   exit 77
fi

## The guard under test: from the function head down to the 'mkdir' that follows
## it. Driving that slice keeps the test on the real shipped text without needing
## qemu-nbd, an image, or root.
guard="$(sed -n '/^filesystem_mounts_setup()/,/mkdir --parents/p' -- "${subject}")"

if [ -z "${guard}" ]; then
   fail "could not extract filesystem_mounts_setup from ${subject}"
   printf '%s\n' "FAILED: 1 assertion(s)." >&2
   exit 1
fi

## Drive the extracted guard with 'modprobe' guaranteed to fail (a 'sudo' stub
## that reports command-not-found, exactly as the kmod-less container does).
##
## The DEVICE PATH is parameterised rather than the '[' builtin stubbed: '[' and
## 'test' are separate builtins, so overriding the 'test' function does not
## intercept '[ -b ... ]' at all -- an earlier version of this test did that and
## both cases silently ran against the real /dev/nbd0, so one assertion passed
## vacuously and the other could not be satisfied. Substituting the path leaves
## the branch structure under test untouched.
run_guard() {
   local body="$1" device="$2"

   bash -c '
      set -o nounset
      body="$1"
      ## Referenced by the mkdir the guard falls through to.
      mount_a=/nonexistent/a
      mount_b=/nonexistent/b
      sudo() {
         printf "%s\n" "sudo: modprobe: command not found" >&2
         return 1
      }
      eval "${body}
      }"
      filesystem_mounts_setup /a /b
   ' _ "${body//\/dev\/nbd0/${device}}" 2>&1
}

if [ ! -b /dev/nbd0 ]; then
   printf '%s\n' "SKIP: /dev/nbd0 is not a block device here; cannot exercise the device-present branch." >&2
   exit 77
fi

## Device present -> must NOT abandon at the modprobe, and must say why it went on.
out="$(run_guard "${guard}" /dev/nbd0 || true)"
case "${out}" in
   *"using the already-present"*)
      pass "modprobe unavailable + device present: continues, and says so"
      ;;
   *)
      fail "modprobe unavailable + device present: did not continue; got: ${out}"
      ;;
esac

## Device absent -> must fail, naming BOTH reasons so the operator is not left
## guessing which applies.
out="$(run_guard "${guard}" /dev/nbd-absent-for-test || true)"
case "${out}" in
   *"nbd unavailable"*"is not a block device"*)
      pass "modprobe unavailable + device absent: fails with a named reason"
      ;;
   *)
      fail "modprobe unavailable + device absent: no named failure; got: ${out}"
      ;;
esac

## CANARY: the pre-fix one-liner must abandon even with the device present, or
## the checks above are not distinguishing the two forms at all.
prefix_guard='filesystem_mounts_setup() {
   sudo --non-interactive modprobe nbd max_part=16 || return 1
   mkdir --parents'
out="$(run_guard "${prefix_guard}" /dev/nbd0 || true)"
case "${out}" in
   *"using the already-present"*)
      fail "canary broken: the pre-fix form also continued; the fixture proves nothing"
      ;;
   *)
      pass "canary: pre-fix form abandons even though the device is present"
      ;;
esac

## Contract: the shipped file must not still hard-fail on the modprobe alone.
if grep --quiet --fixed-strings -- 'modprobe nbd max_part=16 || return 1' "${subject}"; then
   fail "shipped file still aborts on 'modprobe ... || return 1'"
else
   pass "shipped file no longer aborts on the modprobe alone"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: nbd probe."
