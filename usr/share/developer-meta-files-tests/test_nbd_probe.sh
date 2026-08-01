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

## The branch is selected by the stubs in nbd_probe_guard_inner.sh: the modprobe
## attempt's status and whether any usable nbd device exists. Both are inputs the
## guard must react to independently, which is exactly what the bugs below were.
run_guard() {
   local modprobe_rc="$1" claim_rc="$2"

   env GUARD_MODPROBE_RC="${modprobe_rc}" GUARD_CLAIM_RC="${claim_rc}" \
      bash -- "${test_dir}/nbd_probe_guard_inner.sh" "${guard}" 2>&1
}

## --- modprobe unavailable, device present -> continue, and say why ----------
## The container ships no kmod, so 'modprobe' is command-not-found there while
## the module is already loaded on the host and the nodes arrive through
## '--volume /dev:/dev'. Failing on the modprobe abandoned the whole descent.
out="$(run_guard 1 0 || true)"
case "${out}" in
   *"already-present"*)
      pass "modprobe unavailable + device present: continues, and says so"
      ;;
   *)
      fail "modprobe unavailable + device present: did not continue; got: ${out}"
      ;;
esac

## --- modprobe unavailable, no device -> fail, naming BOTH reasons -----------
out="$(run_guard 1 1 || true)"
case "${out}" in
   *"nbd unavailable"*"'modprobe nbd' failed"*"no usable /dev/nbd*"*)
      pass "modprobe unavailable + no device: fails, naming both reasons"
      ;;
   *)
      fail "modprobe unavailable + no device: no named failure; got: ${out}"
      ;;
esac

## --- modprobe SUCCEEDS, no device -> must still fail ------------------------
## The device probe used to be nested inside the modprobe-failure branch, so a
## modprobe that succeeded without producing a node (nbds_max=0, or every node
## busy) skipped the check entirely and the route failed later, unpredictably,
## with no diagnostic. Loading the module is a means; the device is the
## requirement.
rc=0
out="$(run_guard 0 1)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "modprobe succeeded + no device: still fails (${rc})"
else
   fail "modprobe succeeded + no device: accepted; the probe is only reached when modprobe fails"
fi
case "${out}" in
   *"nbd unavailable"*"succeeded"*)
      pass "modprobe succeeded + no device: message says the modprobe was not the problem"
      ;;
   *)
      fail "modprobe succeeded + no device: message does not distinguish this from a modprobe failure; got: ${out}"
      ;;
esac

## --- CANARY: the normal path must NOT be rejected ---------------------------
## Without this, every assertion above is satisfied by a guard that always fails,
## which would disable the descent this route exists to provide.
rc=0
out="$(run_guard 0 0)" || rc="$?"
case "${out}" in
   *"nbd unavailable"*)
      fail "canary broken: modprobe succeeded and a device is present, yet the guard reported nbd unavailable -- ${out}"
      ;;
   *)
      pass "canary: modprobe succeeded + device present is not rejected"
      ;;
esac
case "${out}" in
   *"already-present"*)
      fail "canary broken: reports the modprobe-unavailable fallback although the modprobe succeeded"
      ;;
   *)
      pass "canary: the fallback notice is not printed when modprobe worked"
      ;;
esac

## --- the shipped file, not just the slice -----------------------------------
if grep --quiet --fixed-strings -- 'if [ ! -b /dev/nbd0 ]' "${subject}"; then
   fail "shipped file still hardcodes /dev/nbd0; a host whose nbd0 is busy but nbd1 free reads as unusable"
else
   pass "shipped file no longer hardcodes /dev/nbd0"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: nbd probe."
