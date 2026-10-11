#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-calamares-install's run_check.
##
## THE BUG IT GUARDS: tesseract flaked on the on-screen PASS/FAIL marker, timing a COMPLETED
## check out as "did not complete". run_check now detects completion PRIMARILY by an exit-code
## FILE read over guestcontrol (gc_run -- deterministic, confirmed working on the LXQt install
## disk), FALLING BACK to the OCR marker when the guestcontrol channel is unavailable (a
## Guest-Additions-less image). The '.rc' file is removed before the run so a stale value from
## a prior attempt (check 8 retries) cannot be read as the verdict.
##
## Drives the REAL run_check (sourced define-only from the shipped script), with the
## guestcontrol + OCR boundaries stubbed: GUESTCTL records the typed command, gc_run serves
## the .rc / .out reads, gui_ocr serves the fallback marker. No VM, no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-calamares-install not found (set DM_CALAMARES_INSTALL)." >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## GUESTCTL stub: run_check pipes the typed command to `GUESTCTL vm type-stdin`; capture it.
export GUESTCTL_CAPTURE="${work}/typed"
# shellcheck disable=SC2016  ## the stub body expands ${GUESTCTL_CAPTURE} at ITS runtime, not here
printf '%s\n' '#!/bin/bash' 'cat >> "${GUESTCTL_CAPTURE}"' > "${work}/guestctl"
chmod +x "${work}/guestctl"
export GUESTCTL="${work}/guestctl"

# shellcheck disable=SC1090
source "${subject}"

## Stub the in-guest boundaries. gui_scan sends scancodes; sleep paces the real poll -- both
## no-ops here. gc_run serves the .rc (completion) and .out (failure output); gui_ocr serves
## the fallback marker. Values are controlled per-case via TEST_RC / TEST_OUT / TEST_OCR.
TEST_RC=""
TEST_OUT=""
TEST_OCR=""
# shellcheck disable=SC2317
gui_scan() {
   return 0
}
# shellcheck disable=SC2317
sleep() {
   return 0
}
# shellcheck disable=SC2317
gui_ocr() {
   printf '%s' "${TEST_OCR}"
}
# shellcheck disable=SC2317
gc_run() {
   case "$2" in
      *dmcheck-*.rc*)
         printf '%s' "${TEST_RC}"
         ;;
      *dmcheck-*.out*)
         printf '%s' "${TEST_OUT}"
         ;;
      *)
         return 0
         ;;
   esac
}

## Globals run_check reads (consumed by the sourced function, not seen by shellcheck).
# shellcheck disable=SC2034
vm="testvm"
check_log="${work}/checklog"
# shellcheck disable=SC2034
RELEASE_CHECK_SESSION[8]="user"
# shellcheck disable=SC2034
RELEASE_CHECK_DESC[8]="systemcheck"

pass=0
fail=0
check() {
   if [ "$2" -eq 0 ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}
has() {
   case "$2" in
      *"$1"*)
         return 0
         ;;
      *)
         return 1
         ;;
   esac
}

## --- typed command: stale-rc removal + rc file + OCR marker (no gc_run-only assumption) ----
TEST_RC="0"
TEST_OUT=""
TEST_OCR=""
rc=0
( run_check 8 "systemcheck --ci" 30 ) >"${work}/out.pass" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 0 ] || got=1
check "gc_run rc 0 -> PASS (primary path)" "${got}"
typed="$(cat -- "${GUESTCTL_CAPTURE}")"
got=0
has 'rm -f /var/tmp/dmcheck-8.rc' "${typed}" || got=1
check "typed command removes a stale .rc first" "${got}"
got=0
# shellcheck disable=SC2016  ## literal guest-command text; ${rc} is the guest shell's var
has 'echo ${rc} > /var/tmp/dmcheck-8.rc' "${typed}" || got=1
check "typed command writes the exit code to the .rc file" "${got}"
got=0
# shellcheck disable=SC2016  ## literal guest-command text; ${M} is the guest shell's var
has 'DM${M}PASSMARK' "${typed}" || got=1
check "typed command still emits the OCR fallback marker" "${got}"

## --- gc_run nonzero -> FAIL, output surfaced to the check log -----------------------------
TEST_RC="5"
TEST_OUT="systemcheck: unknown option: --ci"
rc=0
( run_check 8 "systemcheck --ci" 30 ) >"${work}/out.fail" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 1 ] || got=1
check "gc_run rc 5 -> FAIL" "${got}"
got=0
has 'unknown option: --ci' "$(cat -- "${check_log}")" || got=1
check "the failing check's output is written to the check log" "${got}"

## --- GA-less image: gc_run blank, OCR fallback classifies PASS ----------------------------
TEST_RC=""
TEST_OUT=""
TEST_OCR="dmchkpassmark"
rc=0
( run_check 8 "systemcheck --ci" 30 ) >"${work}/out.ocrpass" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 0 ] || got=1
check "no gc_run rc + OCR pass marker -> PASS (fallback path)" "${got}"

## --- GA-less image: OCR fallback classifies FAIL ------------------------------------------
TEST_RC=""
TEST_OUT="boom"
TEST_OCR="dmchkfailmark"
rc=0
( run_check 8 "systemcheck --ci" 30 ) >"${work}/out.ocrfail" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 1 ] || got=1
check "no gc_run rc + OCR fail marker -> FAIL (fallback path)" "${got}"

## --- neither signal ever appears -> did-not-complete (die) --------------------------------
TEST_RC=""
TEST_OUT=""
TEST_OCR=""
rc=0
( run_check 8 "systemcheck --ci" 1 ) >"${work}/out.to" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 5 ] || got=1
check "neither rc file nor OCR marker -> times out (die rc 5)" "${got}"
got=0
has 'did not complete' "$(cat -- "${work}/out.to")" || got=1
check "the timeout says the check did not complete" "${got}"

## --- a torn / non-integer .rc read is NOT accepted (falls through to OCR / retry) ---------
TEST_RC="not-an-integer"
TEST_OUT=""
TEST_OCR=""
rc=0
( run_check 8 "systemcheck --ci" 1 ) >"${work}/out.torn" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 5 ] || got=1
check "a non-integer .rc read is ignored (times out, not a false verdict)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
