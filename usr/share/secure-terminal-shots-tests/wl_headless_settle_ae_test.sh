#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: wl_headless_capture_settled must NOT declare a frame "settled" when compare's
## absolute-error (differing-pixel) count is large enough to print in SCIENTIFIC notation
## (e.g. "1.44e+06", which compare emits above ~1e6). The old parse `${ae%%[!0-9]*}` truncated
## at the first non-digit ('.') -> "1", which then passed any caller-supplied max-diff-px >= 1,
## publishing a MID-PAINT frame and violating the function's documented "never publish an
## unsettled frame" contract. The fix rounds the whole value via printf '%.0f'.
##
## Unit test: source the lib, stub `compare` (the AE value is data-driven) and
## wl_headless_capture_window (always succeeds), and drive wl_headless_capture_settled. No real
## compositor / imagemagick needed. This FAILS on the pre-fix code (arm 1 wrongly settles).
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-lib.bash (override WL_HEADLESS_LIB).
## helper-scripts has.bsh (sourced by the lib) is REQUIRED (exit 1, R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${WL_HEADLESS_LIB:-}" \
   "${script_dir}/../dist-ai-tests-common/wl-headless-lib.bash" \
   '/usr/share/dist-ai-tests-common/wl-headless-lib.bash'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: wl-headless-lib.bash not found (set WL_HEADLESS_LIB)' >&2
   exit 1
fi
if [ ! -f /usr/libexec/helper-scripts/has.bsh ]; then
   printf '%s\n' 'FATAL: /usr/libexec/helper-scripts/has.bsh not found (required by wl-headless-lib.bash)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## `compare` stub: emit the AE value under test (data-driven via AE_STUB_FILE) on stderr, just
## like `compare -metric AE ... null:`, and exit 0 only when the count is 0 (as real compare
## does for identical images). The settled function reads the stderr text, not the exit code.
stub_bin="${work}/bin"
mkdir --parents -- "${stub_bin}"
cat > "${stub_bin}/compare" <<'STUB'
#!/bin/bash
ae="$(cat -- "${AE_STUB_FILE}")"
printf '%s' "${ae}" >&2
if [ "${ae}" = '0' ]; then
   exit 0
fi
exit 1
STUB
chmod +x -- "${stub_bin}/compare"
export PATH="${stub_bin}:${PATH}"
export AE_STUB_FILE="${work}/ae"

## Source the lib (defines wl_headless_capture_settled + wl_headless_capture_window + has).
# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${lib}"

## Replace the real grab with a no-compositor stub that always "succeeds" writing a dummy PNG,
## so only the settle/AE-parse logic is under test.
wl_headless_capture_window() {
   printf 'x' > "$1"
}

pass=0
fail=0
check() {  ## $1=label $2=actual $3=expected
   if [ "$2" = "$3" ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1 (got '$2', expected '$3')"
      fail=$(( fail + 1 ))
   fi
}

## ARM 1 (canary): a large AE in scientific notation must NOT settle at maxdiff=1, and must
## publish NO frame. Pre-fix: "1.44e+06" -> "1" -> 1<=1 -> wrongly settles + writes out1.png.
printf '1.44e+06' > "${AE_STUB_FILE}"
rc=0; wl_headless_capture_settled "${work}/out1.png" 2 1 >/dev/null 2>&1 || rc=$?
check 'scientific-notation AE (1.44e+06) does not falsely settle at maxdiff=1' "$([ "${rc}" -ne 0 ] && printf notsettled || printf settled)" 'notsettled'
check 'no mid-paint frame is published' "$([ -f "${work}/out1.png" ] && printf written || printf absent)" 'absent'

## ARM 2: a genuinely settled frame (AE=0, maxdiff=0) settles and writes the output.
printf '0' > "${AE_STUB_FILE}"
rc=0; wl_headless_capture_settled "${work}/out2.png" 3 0 >/dev/null 2>&1 || rc=$?
check 'a zero-diff frame settles' "$([ "${rc}" -eq 0 ] && printf settled || printf notsettled)" 'settled'
check 'the settled frame is written' "$([ -f "${work}/out2.png" ] && printf written || printf absent)" 'written'

## ARM 3: a non-numeric compare error (size mismatch, window still resizing) must NOT settle.
printf 'compare: image widths or heights differ' > "${AE_STUB_FILE}"
rc=0; wl_headless_capture_settled "${work}/out3.png" 2 5 >/dev/null 2>&1 || rc=$?
check 'a non-numeric compare error does not settle' "$([ "${rc}" -ne 0 ] && printf notsettled || printf settled)" 'notsettled'
check 'no frame published on a compare error' "$([ -f "${work}/out3.png" ] && printf written || printf absent)" 'absent'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: wl_headless_capture_settled parses AE robustly (no scientific-notation truncation)'
