#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: wl_headless_capture_window must NOT leave a degenerate outfile behind. When
## nothing mapped, grim grabs an all-black output and `convert -trim` collapses it to ~1x1; the
## function reports that (return 2), but if it leaves the 1x1 file, a later blanket step
## (comparison-capture's --optimize-only webp-converts EVERY shots/*.png) publishes a 1x1 "shot"
## -- a real bug seen as xterm.escape.webp = 1x1 on the site. A never-mapped window must yield NO
## file, so the caller's discard/retry sees the miss and a persistently-missing shot fails loud.
##
## Stubs grim (renders an all-black, or a content, frame via real convert); the trim + identify
## are the REAL code path. Display-free, runs anywhere.
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-lib.bash (override WL_HEADLESS_LIB).
## helper-scripts has.bsh (sourced by the lib) + ImageMagick are REQUIRED (exit 1, R-220).

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
if ! type -P convert >/dev/null 2>&1 || ! type -P identify >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: ImageMagick (convert + identify) not found (required for the trim path)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## grim stub: write the frame described by GRIM_STUB_FRAME to grim's output arg (the last one).
## 'black' = an all-black output (nothing mapped -> trims to ~1x1); 'content' = a window on black.
stub_bin="${work}/bin"
mkdir --parents -- "${stub_bin}"
cat > "${stub_bin}/grim" <<'STUB'
#!/bin/bash
out=''
for a in "$@"; do out="$a"; done   ## grim's last arg is the output path
if [ "${GRIM_STUB_FRAME:-black}" = 'content' ]; then
   convert -size 400x300 xc:black -fill white -draw 'rectangle 40,40 360,260' "${out}"
else
   convert -size 400x300 xc:black "${out}"
fi
STUB
chmod +x -- "${stub_bin}/grim"
export PATH="${stub_bin}:${PATH}"

# shellcheck source=../dist-ai-tests-common/wl-headless-lib.bash
source "${lib}"

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

## ARM 1 (canary): an all-black grab (nothing mapped) -> trim collapses to ~1x1 -> return 2 AND
## NO outfile left behind. Pre-fix: return 2 but the 1x1 outfile persists (the published-1x1 bug).
out1="${work}/degenerate.png"
export GRIM_STUB_FRAME='black'
rc=0; wl_headless_capture_window "${out1}" >/dev/null 2>&1 || rc=$?
check 'a degenerate (nothing-mapped) capture returns non-zero' "$([ "${rc}" -ne 0 ] && printf y)"
check 'a degenerate capture leaves NO outfile behind (no 1x1 to publish)' "$([ ! -e "${out1}" ] && printf y)"

## ARM 2: a real window on the output -> a sane, non-degenerate shot IS written (fix didn't break
## the happy path).
out2="${work}/good.png"
export GRIM_STUB_FRAME='content'
rc=0; wl_headless_capture_window "${out2}" >/dev/null 2>&1 || rc=$?
check 'a mapped window captures successfully (rc 0)' "$([ "${rc}" -eq 0 ] && printf y)"
if [ -f "${out2}" ]; then
   read -r gw gh < <(identify -format '%w %h' "${out2}" 2>/dev/null || printf '0 0')
   check "the captured shot has sane dimensions (${gw}x${gh}, both >= 20)" \
      "$([ "${gw:-0}" -ge 20 ] && [ "${gh:-0}" -ge 20 ] && printf y)"
else
   check 'the captured shot has sane dimensions' ''
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: wl_headless_capture_window never leaves a degenerate outfile behind'
