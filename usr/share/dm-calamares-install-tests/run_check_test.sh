#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-calamares-install's run_check.
##
## THE BUG IT GUARDS: check 8 reported "did not complete in 300s" while systemcheck
## HAD finished -- run_check OCR'd an on-screen marker (DMCHKPASSMARK/FAILMARK) and
## tesseract flaked on it. The fix types the SAME command into the real graphical
## terminal but detects completion by polling an exit-code FILE over the guestcontrol
## exec channel (gc_run), which needs no OCR.
##
## Drives the REAL run_check (sourced define-only from the shipped script), with the
## guestcontrol boundary stubbed: GUESTCTL records the typed command, gc_run serves the
## .rc / .out file contents. No VM, no root, no network, no tesseract.

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

## Source the real script define-only (the shipped `if BASH_SOURCE==0` guard keeps main
## from running). The sourced script's own strict-mode preamble stays in effect; the driver
## below is written errexit-safe (explicit `|| rc=...`, each check in a subshell).
# shellcheck disable=SC1090
source "${subject}"

## Stub the two in-guest boundaries. gui_scan sends scancodes to a VM; make it a no-op.
## gc_run serves file reads: the .rc value (completion signal) and the .out (failure
## output), both controlled per-case via TEST_RC_VALUE / TEST_OUT_VALUE.
TEST_RC_VALUE=""
TEST_OUT_VALUE=""
# shellcheck disable=SC2317  ## invoked by the sourced run_check, not directly
gui_scan() {
   return 0
}
# shellcheck disable=SC2317  ## invoked by the sourced run_check, not directly
gc_run() {
   case "$2" in
      *dmcheck-*.rc*)
         printf '%s' "${TEST_RC_VALUE}"
         ;;
      *dmcheck-*.out*)
         printf '%s' "${TEST_OUT_VALUE}"
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

## --- the typed command writes an rc file and is NOT the old OCR marker --------------------
TEST_RC_VALUE="0"
TEST_OUT_VALUE=""
rc=0
( run_check 8 "systemcheck --ci" 30 ) >"${work}/out.pass" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 0 ] || got=1
check "exit 0 when the guest wrote rc 0" "${got}"
typed="$(cat -- "${GUESTCTL_CAPTURE}")"
got=0
has '/var/tmp/dmcheck-8.rc' "${typed}" || got=1
check "typed command writes the per-check .rc file" "${got}"
got=0
has 'echo $? > /var/tmp/dmcheck-8.rc' "${typed}" || got=1
check "typed command captures the real exit code (echo \$?)" "${got}"
got=0
if has 'DMCHKPASSMARK' "${typed}" || has 'DMCHKFAILMARK' "${typed}"; then
   got=1
fi
check "canary: the OCR marker is gone from the typed command" "${got}"

## --- a nonzero rc is a FAIL, and the .out is surfaced to the check log --------------------
TEST_RC_VALUE="5"
TEST_OUT_VALUE="systemcheck: unknown option: --ci"
rc=0
( run_check 8 "systemcheck --ci" 30 ) >"${work}/out.fail" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 1 ] || got=1
check "exit 1 when the guest wrote a nonzero rc" "${got}"
got=0
has 'FAIL (rc=5)' "$(cat -- "${work}/out.fail")" || got=1
check "the failure reports the real rc" "${got}"
got=0
has 'unknown option: --ci' "$(cat -- "${check_log}")" || got=1
check "the failing check's own output is written to the check log" "${got}"

## --- no rc file ever -> did-not-complete (die), never a false pass/fail -------------------
TEST_RC_VALUE=""
TEST_OUT_VALUE=""
rc=0
( run_check 8 "systemcheck --ci" 1 ) >"${work}/out.to" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 5 ] || got=1
check "a check whose rc file never appears times out (die rc 5)" "${got}"
got=0
has 'did not complete' "$(cat -- "${work}/out.to")" || got=1
check "the timeout says the check did not complete" "${got}"

## --- a torn / non-integer read is NOT accepted as completion ------------------------------
## Canary: only a clean integer counts; a partial read must be retried, never misclassified.
TEST_RC_VALUE="not-an-integer"
TEST_OUT_VALUE=""
rc=0
( run_check 8 "systemcheck --ci" 1 ) >"${work}/out.torn" 2>&1 || rc=$?
got=0
[ "${rc}" -eq 5 ] || got=1
check "a non-integer .rc read is ignored (times out, not a false verdict)" "${got}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
