#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## safe-pkill / safe-pgrep generic-name denylist.
##
## A bare generic process name (sleep, cat, python3, ...) matches UNRELATED processes in other
## sessions and the system tree; signalling one by name is the cross-session kill trap -- a
## `pkill sleep` once killed the qubes-session `sleep inf` keepalive and wedged the VM GUI, and
## ancestry exclusion does NOT help (the victim is not the caller's ancestor). safe-pkill and
## safe-pgrep therefore REFUSE a generic-name target (exit 2) unless SAFE_PROC_ALLOW_GENERIC=1.
##
## Drives the shipped scripts from the dist-ai tree (subject + shared denylist lib), so it needs
## no root, no network, and signals NOTHING (every refusal exits before pgrep runs; the override
## case is --dry-run only).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
## usr/share/dist-ai-registry-tests -> repo root is three levels up (installed: '/').
repo="${DIST_AI_REPO:-${test_dir}/../../..}"
safe_pkill="${repo}/usr/bin/safe-pkill"
safe_pgrep="${repo}/usr/bin/safe-pgrep"
lib="${repo}/usr/libexec/dist-ai/generic-proc-names.bsh"
for f in "${safe_pkill}" "${safe_pgrep}" "${lib}"; do
   [ -f "${f}" ] || { printf '%s\n' "FATAL: required dist-ai file not found: ${f}" >&2; exit 1; }
done
## The subjects source the shared denylist from here.
export DIST_AI_LIBEXEC_DIR="${repo}/usr/libexec/dist-ai"

failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; failures=$(( failures + 1 )); }

## Run a subject, capture rc + stderr; never let a non-zero abort the test.
r_rc=0
r_err=''
run() { r_err="$("$@" 2>&1 >/dev/null)" && r_rc=0 || r_rc=$?; }

# --- refusals (exit 2, message names the generic target) ----------------------
for name in sleep cat python3 bash; do
   run "${safe_pkill}" "${name}"
   if [ "${r_rc}" -eq 2 ] && case "${r_err}" in *"generic process name"*) true;; *) false;; esac; then
      pass "safe-pkill refuses generic name '${name}' (exit 2)"
   else
      fail "safe-pkill did NOT refuse '${name}' (rc=${r_rc}; err: ${r_err})"
   fi
done

run "${safe_pkill}" --name python3
if [ "${r_rc}" -eq 2 ]; then
   pass "safe-pkill --name refuses generic name (exit 2)"
else
   fail "safe-pkill --name did not refuse python3 (rc=${r_rc}; err: ${r_err})"
fi

run "${safe_pgrep}" sleep
if [ "${r_rc}" -eq 2 ] && case "${r_err}" in *"generic process name"*) true;; *) false;; esac; then
   pass "safe-pgrep refuses generic name 'sleep' (exit 2)"
else
   fail "safe-pgrep did NOT refuse 'sleep' (rc=${r_rc}; err: ${r_err})"
fi

# --- whitespace variant is still refused (accidental "$VAR" interpolation) ----
## 'sleep ' (trailing space) still matches the generic process at the pgrep layer, so the trim
## in safe_proc_is_generic must still refuse it. Canary: pre-trim (exact-only) this exits 1/0.
for variant in 'sleep ' ' sleep'; do
   run "${safe_pkill}" "${variant}"
   if [ "${r_rc}" -eq 2 ]; then
      pass "safe-pkill refuses whitespace variant '${variant}' (trimmed to generic)"
   else
      fail "safe-pkill did NOT refuse whitespace variant '${variant}' (rc=${r_rc}; err: ${r_err})"
   fi
done

# --- a specific (non-generic) pattern is NOT refused --------------------------
## A pattern that matches nothing exits 1 (no match), never the generic-refusal 2. Proves the
## denylist does not over-block ordinary targets.
uniq="zzz-nonexistent-$$-${RANDOM}"
run "${safe_pkill}" "${uniq}"
if [ "${r_rc}" -ne 2 ] && case "${r_err}" in *"generic process name"*) false;; *) true;; esac; then
   pass "safe-pkill allows a specific pattern (not refused as generic)"
else
   fail "safe-pkill wrongly refused a specific pattern '${uniq}' (rc=${r_rc}; err: ${r_err})"
fi

# --- override lets a generic name through ------------------------------------
## --dry-run so nothing is signalled; assert only that the generic REFUSAL did not fire.
run env SAFE_PROC_ALLOW_GENERIC=1 "${safe_pkill}" --dry-run sleep
if case "${r_err}" in *"refusing the generic"*) false;; *) true;; esac; then
   pass "SAFE_PROC_ALLOW_GENERIC=1 overrides the refusal"
else
   fail "override did not bypass the generic refusal (rc=${r_rc}; err: ${r_err})"
fi

# --- shared lib membership function ------------------------------------------
# shellcheck source=../../libexec/dist-ai/generic-proc-names.bsh
source "${lib}"
if safe_proc_is_generic sleep && safe_proc_is_generic python3 && ! safe_proc_is_generic "${uniq}"; then
   pass "safe_proc_is_generic classifies generic vs specific names"
else
   fail "safe_proc_is_generic misclassified (sleep/python3 must be generic, '${uniq}' must not)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' '' "FAILED: ${failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' '' 'OK: safe-pkill/safe-pgrep refuse generic-name targets; specific patterns and the override pass.'
