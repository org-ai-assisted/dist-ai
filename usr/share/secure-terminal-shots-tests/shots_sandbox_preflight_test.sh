#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: secure-terminal-shots-sandbox (the forget-proof host driver) must REFUSE, loudly
## and non-zero, when a source tree is missing -- never fall through to a stale/absent capture.
## The tree checks run BEFORE the `sandbox` transport check on purpose, so this preflight is
## verifiable with no sandbox present (CI container). Drives the REAL driver (no synthetic copy).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

driver="${script_dir}/../../bin/secure-terminal-shots-sandbox"
if [ ! -x "${driver}" ]; then
   printf '%s\n' "SKIP: secure-terminal-shots-sandbox not found at ${driver}" >&2
   exit 77
fi

pass=0
fail=0

## Assert the driver exits non-zero and its stderr matches ${2} when run with env ${@:3}.
refuses() {  ## $1=label $2=expected-substring VAR=val ...
   local label want out rc
   label="$1"
   want="$2"
   shift 2
   rc=0
   out="$(env "$@" "${driver}" comparison 2>&1)" || rc=$?
   if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -qF -- "${want}"; then
      printf '%s\n' "PASS: ${label} (rc=${rc}, matched '${want}')"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} (rc=${rc}); wanted non-zero + '${want}', got:"
      printf '%s\n' "${out}" | sed 's/^/    /' >&2
      fail=$(( fail + 1 ))
   fi
}

## A missing secure-terminal source must refuse BEFORE any sandbox call (so no sandbox needed).
refuses 'missing secure-terminal source refuses' 'secure-terminal source not found' \
   SECURE_TERMINAL_REPO=/nonexistent-st CORPUS_REPO=/nonexistent-corpus SECURE_TERMINAL_SITE=/nonexistent-site
## A missing corpus refuses (point secure-terminal at this repo's own tree so the first check passes;
## any dir with usr/lib/.../secure_terminal would do, but a bogus corpus is the target here).
st_repo="${SECURE_TERMINAL_REPO:-${HOME}/private-sources/secure-terminal}"
if [ -d "${st_repo}/usr/lib/python3/dist-packages/secure_terminal" ]; then
   refuses 'missing corpus refuses' 'terminal-poc-corpus not found' \
      SECURE_TERMINAL_REPO="${st_repo}" CORPUS_REPO=/nonexistent-corpus SECURE_TERMINAL_SITE=/nonexistent-site
else
   ## The corpus-refusal case needs a real secure-terminal checkout to get past the first
   ## tree check; without it the test cannot fully verify, so SKIP the whole thing (77) rather
   ## than report a partial run as green (an unauthorized skip is a failure, not a pass).
   printf '%s\n' 'SKIP: secure-terminal checkout absent; cannot verify the corpus-refusal case' >&2
   exit 77
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' 'OK: secure-terminal-shots-sandbox refuses to run on a missing source tree'
