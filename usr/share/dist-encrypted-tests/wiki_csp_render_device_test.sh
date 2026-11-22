#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The CSP render gate (wiki-csp-render-test -> wiki-csp-render/check.py) must render BOTH desktop
## AND mobile (verify-desktop-AND-mobile): a CSP violation that fires only under the MOBILE code path
## (a responsive image/source, a touch-only widget, a mobile-specific script) renders clean on desktop
## and would ship unseen. check.py takes a --device knob (emulate a Playwright device) and the driver
## renders desktop + mobile (Pixel 5).
##
## Phase 1 (hermetic, always): the wiring is present in the REAL sources -- check.py takes --device
## and applies the Playwright device registry; the driver renders a mobile device and threads
## --device. RED if the mobile leg is dropped.
##
## Phase 2 (behavioral, Playwright venv required): wiki_csp_render_device_canary.py (beside this test)
## drives the REAL check.py against a local page that injects a CSP-blocked <img> ONLY on a narrow
## (mobile) viewport -- desktop renders CLEAN (exit 0), the mobile (--device "Pixel 5") render TRIPS
## the violation (exit 1), an unknown device exits 2. CANARY: a check.py without --device rejects the
## mobile run (argparse, exit 2), so the mobile-only break could not be caught. The Playwright venv is
## a host-side-only capability (the gate itself is host-side); absent -> Phase 2 is noted, not run
## (Phase 1 still verifies the wiring). No unwaived skip: the test still exits on Phase 1's assertions.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_ENCRYPTED_TESTS_REPO:-}" ]; then
   base="${DIST_ENCRYPTED_TESTS_REPO}"
else
   base=""
fi
check_py="${base}/usr/share/dist-encrypted/wiki-csp-render/check.py"
driver="${base}/usr/local/bin/wiki-csp-render-test"
[ -n "${base}" ] || { check_py='/usr/share/dist-encrypted/wiki-csp-render/check.py'; driver='/usr/local/bin/wiki-csp-render-test'; }
if [ ! -r "${check_py}" ] || [ ! -r "${driver}" ]; then
   printf '%s\n' "check.py / wiki-csp-render-test not readable (set DIST_ENCRYPTED_TESTS_REPO); skipping." >&2
   ## style-ok: allow-skip: dist-encrypted-tests target unavailable (optional component checkout)
   exit 77
fi

pass=0
fail=0
check() {
   local label got want
   label="$1"; got="$2"; want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"; pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')" >&2; fail=$((fail + 1))
   fi
}
has() {
   if grep --extended-regexp --quiet -- "$1" "$2"; then
      printf '%s' yes
   else
      printf '%s' no
   fi
}

## ===== Phase 1: wiring present in the real sources (hermetic) =====
check "check.py adds the --device option" "$(has 'add_argument\("--device"' "${check_py}")" "yes"
check "check.py applies the Playwright device registry (pw.devices)" "$(has 'pw\.devices' "${check_py}")" "yes"
check "driver renders a mobile device (Pixel 5)" "$(has 'Pixel 5' "${driver}")" "yes"
check "driver threads --device into the render helper" "$(has '--device' "${driver}")" "yes"

## ===== Phase 2: behavioral mobile-only-violation canary (needs the Playwright venv) =====
## The orchestrator (serves the mobile-only-violation page + drives the REAL check.py desktop /
## Pixel 5 / unknown) is a standalone python file beside this test, run under the Playwright venv.
self_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
canary_py="${self_dir}/wiki_csp_render_device_canary.py"
PLAYWRIGHT_PYTHON="${PLAYWRIGHT_PYTHON:-${HOME}/.venvs/playwright/bin/python}"
if [ ! -x "${PLAYWRIGHT_PYTHON}" ]; then
   printf '%s\n' "NOTE: no Playwright venv at '${PLAYWRIGHT_PYTHON}'; Phase 2 behavioral canary not run (wiring verified above)." >&2
elif [ ! -r "${canary_py}" ]; then
   printf '%s\n' "FATAL: Phase 2 canary missing at '${canary_py}'" >&2
   exit 1
else
   ## All-pass (desktop clean / mobile trips / unknown exits 2) -> the orchestrator exits 0. It prints
   ## its own per-case PASS/FAIL; its single exit status is the Phase 2 verdict here.
   canary_rc=0
   "${PLAYWRIGHT_PYTHON}" "${canary_py}" "${check_py}" || canary_rc=$?
   check "Phase 2 canary: mobile-only CSP violation caught only with --device" "${canary_rc}" "0"
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
