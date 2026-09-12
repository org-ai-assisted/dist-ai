#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: wl-headless-lib.bash must contain NO bare `exec {fd}<redir> 2>/dev/null`.
## `exec` with redirections and NO command applies them to the shell PERMANENTLY, so a trailing
## 2>/dev/null there does not just hush the fd-open -- it silently discards EVERY later stderr
## write for the rest of the run. That swallowed each test suite's `FAIL:` line (the widget
## suites write failures to stderr): a failing suite showed only "exit 1" with no reason, making
## the flaky coverage gate undiagnosable. The safe form group-scopes the suppression:
## `{ exec {fd}<redir>; } 2>/dev/null` opens the fd (persists) while the 2>/dev/null lasts only
## for the group. This guard fails if any bare persist-trap re-appears anywhere in the lib.
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-lib.bash (override WL_HEADLESS_LIB).
## Display-free (a static invariant over the lib text) -- runs anywhere, no compositor.

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

## The detector: a persist-trap is an `exec {name}<redir>...2>/dev/null` where 2>/dev/null is
## reached WITHOUT a preceding `;` -- i.e. it is NOT inside a `{ exec ...; } 2>/dev/null` group
## (the safe form places a `;` before the group-close, so 2>/dev/null falls outside [^;]*).
## Comment lines are stripped first so the explanatory comment above the fix is not flagged.
persist_traps() {  ## $1 = file; prints each offending line, empty when clean
   grep -vE '^[[:space:]]*#' -- "$1" \
      | grep -nE 'exec[[:space:]]+\{[A-Za-z_]+\}[^;]*2>/dev/null' \
      || true
}

pass=0
fail=0
_pass() { printf 'PASS: %s\n' "$1"; pass=$(( pass + 1 )); }
_fail() { printf 'FAIL: %s\n' "$1"; fail=$(( fail + 1 )); }

## CHECK 1: the real lib is free of the persist-trap.
lbl1='wl-headless-lib.bash has no bare exec-with-2>/dev/null persist-trap'
found="$(persist_traps "${lib}")"
if [ -z "${found}" ]; then
   _pass "${lbl1}"
else
   printf '%s\n' 'persist-trap line(s) in the lib:' "${found}" >&2
   _fail "${lbl1}"
fi

## CHECK 2 (teeth): the detector MUST flag a known-bad sample -- else CHECK 1 is vacuous
## (a broken detector that matches nothing would pass CHECK 1 on ANY file). A synthetic file
## carrying the exact pre-fix bare form is expected to be flagged; the group-wrapped safe form
## in the same file is expected NOT to be flagged.
work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT
bad="${work}/sample.bash"
## Distinct fd names (barefd_* vs safefd_*) so a teeth-check grep cannot match by accident.
cat > "${bad}" <<'SAMPLE'
if exec {barefd_a}<>"${lk}" 2>/dev/null; then :; fi
{ exec {safefd_x}<>"${lk}"; } 2>/dev/null
[ -n "${lk}" ] && { { exec {safefd_y}>&-; } 2>/dev/null || true; }
[ -n "${lk}" ] && { exec {barefd_b}>&- 2>/dev/null || true; }
SAMPLE
sample_hits="$(persist_traps "${bad}")"
## the two bare forms (barefd_a<> and barefd_b>&-) must be caught (here-strings, not pipes)
lbl2='detector flags the bare exec<> persist-trap (teeth)'
if grep --quiet 'barefd_a' <<< "${sample_hits}"; then _pass "${lbl2}"; else _fail "${lbl2}"; fi
lbl3='detector flags the bare exec>&- persist-trap (teeth)'
if grep --quiet 'barefd_b' <<< "${sample_hits}"; then _pass "${lbl3}"; else _fail "${lbl3}"; fi
## the group-wrapped safe forms must NOT be flagged
lbl4='detector does NOT flag the group-wrapped safe forms'
if grep --quiet 'safefd' <<< "${sample_hits}"; then _fail "${lbl4}"; else _pass "${lbl4}"; fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: no exec-with-2>/dev/null stderr persist-trap in wl-headless-lib.bash'
