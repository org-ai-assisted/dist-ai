#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## safe-pgrep / safe-pkill must resolve their shared generic-proc-names.bsh denylist RELATIVE to
## themselves (../libexec/dist-ai), so a copy invoked from a CHECKOUT that is on PATH but NOT
## installed finds the checkout helper -- not the hardcoded installed /usr/libexec/dist-ai.
##
## Why this matters: the consumer CI puts the dist-ai checkout's usr/bin on PATH but never wires
## its usr/libexec, so the OLD hardcoded-path code sourced the (empty) installed path, aborted
## under errexit, and every `safe-pgrep --full` silently reported "no match" -- which broke
## reap_run_test's marker-scoped reaping ONLY in CI (it passed in every installed/sandbox env).
##
## CANARY: builds a throwaway checkout-shaped tree with a MARKED sibling helper and asserts the
## subject sourced THAT sibling, not the installed one. FAILS on the pre-fix scripts. No root, no
## network, signals nothing (only `--help`, which sources the helper then prints usage).

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
lib="${repo}/usr/libexec/dist-ai/generic-proc-names.bsh"
for f in "${repo}/usr/bin/safe-pgrep" "${repo}/usr/bin/safe-pkill" "${lib}"; do
   [ -f "${f}" ] || { printf '%s\n' "FATAL: required dist-ai file not found: ${f}" >&2; exit 1; }
done

failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; failures=$(( failures + 1 )); }

## Throwaway checkout-shaped tree: usr/bin/<tool> beside a MARKED usr/libexec/dist-ai helper. The
## marker line echoes to stderr when the helper is sourced, so we can tell WHICH copy was used.
work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT
mkdir --parents -- "${work}/usr/bin" "${work}/usr/libexec/dist-ai"
marker="SIBLING-HELPER-$$-${RANDOM}${RANDOM}"
cp -- "${lib}" "${work}/usr/libexec/dist-ai/generic-proc-names.bsh"
printf "printf '%%s\\\\n' '%s' >&2\n" "${marker}" \
   >> "${work}/usr/libexec/dist-ai/generic-proc-names.bsh"

## Run <tool> --help (sources the helper, then prints usage) from the throwaway bin with
## DIST_AI_LIBEXEC_DIR UNSET, so ONLY self-location can reach the marked sibling. The pre-fix
## code sources the installed helper (no marker) or aborts when it is absent.
check_self_locate() {  ## $1=tool name
   local tool="$1" err=''
   cp -- "${repo}/usr/bin/${tool}" "${work}/usr/bin/${tool}"
   err="$(env --unset=DIST_AI_LIBEXEC_DIR "${work}/usr/bin/${tool}" --help 2>&1 >/dev/null || true)"
   if case "${err}" in *"${marker}"*) true ;; *) false ;; esac; then
      pass "${tool} resolves generic-proc-names.bsh relative to itself (checkout-safe)"
   else
      fail "${tool} did NOT source its sibling helper -- self-location broken (stderr: ${err})"
   fi
}
check_self_locate safe-pgrep
check_self_locate safe-pkill

printf '%s\n' '' "$(( 2 - failures )) pass, ${failures} fail, 0 skip"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: safe-pgrep/safe-pkill self-locate their shared denylist from a checkout'
