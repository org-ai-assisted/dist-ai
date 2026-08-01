#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the nbd route of developer-meta-files
## 'dm-reproducible-compare-artifacts', and for the preflight that makes it
## usable.
##
## THE BUG IT GUARDS: the filesystem-comparison route opens with
##     sudo --non-interactive modprobe nbd max_part=16 || return 1
## and this tool runs INSIDE the derivative-maker container, which shipped no
## kmod. 'modprobe' was command-not-found, the whole qemu-nbd + diffoscope
## descent was abandoned, and the run reported only
##     diffoscope could not explain the diff (exit 2)
## The diagnostic that exists to explain a reproducibility failure was
## unavailable precisely when one occurred.
##
## The fix is the PACKAGE, not a fallback: ci/reproducible-install-deps -- the
## compare job's only preflight, since it runs no build step -- installs kmod and
## then ASSERTS modprobe, failing loudly. Teaching the route to proceed without
## modprobe was tried and is worse: it makes a genuinely broken environment look
## like a working one, and only happens to work when some other process already
## loaded the module.
##
## So what must hold is: the tool is installed, its absence is a loud failure at
## the preflight, and the route itself still treats a failed modprobe as fatal.
##
## SCOPE: this asserts the preflight and the route's failure contract. It does
## NOT drive nbd_device_claim against real devices -- that needs root, a loaded
## module and free /dev/nbd* nodes.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## The derivative-maker checkout under test. An explicitly named tree is the ONLY
## answer: falling back to '~/derivative-maker' reports on a DIFFERENT tree than
## the caller asked about, and a stale checkout there then reads as a defect in
## the code under test rather than as a stale checkout.
if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

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
      "${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-reproducible-compare-artifacts" \
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

## --- the route still treats a failed modprobe as fatal ----------------------
## A fallback that continues without it turns a broken environment into one that
## reads as working, and only succeeds when something else loaded the module.
setup_head="$(sed -n '/^filesystem_mounts_setup()/,/mkdir --parents/p' -- "${subject}")"
if [ -z "${setup_head}" ]; then
   fail "could not extract filesystem_mounts_setup from ${subject}"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
case "${setup_head}" in
   *"modprobe nbd"*"|| return 1"*)
      pass "a failed 'modprobe nbd' aborts the route rather than continuing"
      ;;
   *)
      fail "filesystem_mounts_setup no longer aborts on a failed modprobe -- ${setup_head}"
      ;;
esac

## --- no hardcoded device ----------------------------------------------------
## A host whose nbd0 is busy but nbd1 free reads as unusable.
if grep --quiet --fixed-strings -- 'if [ ! -b /dev/nbd0 ]' "${subject}"; then
   fail "shipped file hardcodes /dev/nbd0"
else
   pass "shipped file does not hardcode /dev/nbd0"
fi

## --- the preflight: install kmod, then ASSERT it ----------------------------
## Located relative to the subject, which lives at
## <dm>/packages/kicksecure/developer-meta-files/usr/bin/.
dm_root="$(cd -- "$(dirname -- "${subject}")/../../../../.." && pwd)"
install_deps="${dm_root}/ci/reproducible-install-deps"
if [ ! -r "${install_deps}" ]; then
   printf '%s\n' "SKIP: ci/reproducible-install-deps not found at ${install_deps}." >&2
   exit 77
fi

if grep --quiet --extended-regexp -- '^ *kmod *\\?$' "${install_deps}"; then
   pass "preflight installs kmod"
else
   fail "ci/reproducible-install-deps does not install kmod; the container ships none"
fi

## Installing is not enough: apt can succeed and still leave the tool absent
## (wrong suite, held package). The preflight must verify and FAIL, because it is
## the compare job's only chance -- it runs no build step, so 1100_sanity-tests
## never executes there.
if grep --quiet --fixed-strings -- 'modprobe' "${install_deps}" \
   && grep --quiet --fixed-strings -- 'missing_tools' "${install_deps}"; then
   pass "preflight asserts modprobe is present after installing"
else
   fail "ci/reproducible-install-deps does not assert modprobe; a silent gap degrades the report to 'could not explain the diff'"
fi

if sed -n '/missing_tools/,$p' -- "${install_deps}" | grep --quiet --fixed-strings -- 'exit 1'; then
   pass "a missing tool fails the preflight rather than warning"
else
   fail "ci/reproducible-install-deps reports a missing tool without failing"
fi

## CANARY: the greps above must be able to MISS, or every assertion is vacuous.
if grep --quiet --fixed-strings -- 'definitely-not-in-this-file' "${install_deps}"; then
   fail "canary broken: the preflight grep matches a string that is not there"
else
   pass "canary: the preflight greps can report absence"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: nbd probe."
