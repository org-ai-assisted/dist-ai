#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: the public hypervisor selector is --target {auto,kvm,virtualbox} (kvm == internal
## qemu, virtualbox == internal vbox); the OLD --backend / --resolve-backend flags are GONE with
## no lingering alias. Asserts BOTH directions so it cannot pass vacuously -- the new flag is
## accepted and resolves to the public token, the old flag is rejected by argparse. Drives the
## REAL dm-smbios-reader-image-test (dist-ai convention: no synthetic copy).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## style-ok: no-has -- no helper-scripts sourced here; only the shipped harness is driven.

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## The harness is a sibling in this same share dir; an explicit override wins (test seam).
TOOL="${DM_SMBIOS_READER_IMAGE_TEST_BIN:-${test_dir}/dm-smbios-reader-image-test}"

## The harness file must be present and executable; it is a hard dep of this suite, so a genuine
## absence is the ONLY skip, loudly waived.
if [ ! -x "${TOOL}" ]; then
  printf '%s\n' "target_switch_test.sh: harness absent or not executable at ${TOOL}. SKIP." >&2
  ## style-ok: allow-skip: dm-smbios-reader-image-test harness genuinely absent
  exit 77
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

## Drive the REAL executable harness directly (R-193): its shebang picks the interpreter, so the
## flags that shebang carries are not dropped the way `python3 <file>` would drop them.
img() { "${TOOL}" "$@"; }

## --- NEW surface: --target kvm resolves to the public token 'kvm'. Force kvm so /dev/kvm presence
## is irrelevant and the result is host-independent. ---
out="$(img --disk /dev/null --target kvm --resolve-target --arch amd64 2>/dev/null || true)"
if [ "${out}" = 'kvm' ]; then
  pass "--target kvm --resolve-target prints the public token 'kvm'"
else
  fail "--target kvm --resolve-target should print 'kvm', got '${out}'"
fi

## --target virtualbox is ACCEPTED as a choice (argparse does not reject it); whether it then
## resolves (VBoxManage present) or die_setups (absent) is host-dependent, so gate ONLY on argparse
## acceptance -- no 'unrecognized'/'invalid choice'.
err="$(img --disk /dev/null --target virtualbox --resolve-target --arch amd64 2>&1 || true)"
case "${err}" in
  *'unrecognized arguments'*|*'invalid choice'*)
    fail "--target virtualbox must be an accepted choice; argparse rejected it: ${err}"
    ;;
  *)
    pass "--target virtualbox is an accepted --target choice"
    ;;
esac

## --- CANARY, old flag GONE: --backend is rejected by argparse (exit 2, unrecognized). A lingering
## alias would make the rename pass vacuously. ---
rc=0; err="$(img --disk /dev/null --backend qemu --resolve-target 2>&1)" || rc=$?
case "${err}" in *'unrecognized arguments: --backend'*) hit=0 ;; *) hit=1 ;; esac
if [ "${rc}" -eq 2 ] && [ "${hit}" -eq 0 ]; then
  pass "old --backend is rejected by argparse (exit 2, unrecognized)"
else
  fail "old --backend must be rejected (exit 2, unrecognized); rc=${rc} err=${err}"
fi

## The old query flag is GONE too.
rc=0; err="$(img --disk /dev/null --resolve-backend 2>&1)" || rc=$?
case "${err}" in *'unrecognized arguments: --resolve-backend'*) hit=0 ;; *) hit=1 ;; esac
if [ "${rc}" -eq 2 ] && [ "${hit}" -eq 0 ]; then
  pass "old --resolve-backend is rejected by argparse (exit 2, unrecognized)"
else
  fail "old --resolve-backend must be rejected (exit 2, unrecognized); rc=${rc} err=${err}"
fi

## --- Hardening (allow_abbrev=False): an abbreviated flag is a HARD unrecognized-argument error,
## not a silent expansion the shell front-ends (which match only the exact --target spelling) would
## gate inconsistently. ---
rc=0; err="$(img --disk /dev/null --targ kvm --resolve-target --arch amd64 2>&1)" || rc=$?
case "${err}" in *'unrecognized arguments: --targ'*) hit=0 ;; *) hit=1 ;; esac
if [ "${rc}" -eq 2 ] && [ "${hit}" -eq 0 ]; then
  pass "abbreviated --targ is rejected (allow_abbrev=False, exit 2)"
else
  fail "abbreviated --targ must be rejected (exit 2, unrecognized); rc=${rc} err=${err}"
fi

## --- The old INTERNAL tokens are invalid PUBLIC values: --target vbox / qemu must be an argparse
## invalid-choice error (exit 2), never silently accepted (guards the muscle-memory old-value case). ---
rc=0; err="$(img --disk /dev/null --target vbox --resolve-target --arch amd64 2>&1)" || rc=$?
case "${err}" in *"invalid choice: 'vbox'"*) hit=0 ;; *) hit=1 ;; esac
if [ "${rc}" -eq 2 ] && [ "${hit}" -eq 0 ]; then
  pass "old value --target vbox is rejected (invalid choice, exit 2)"
else
  fail "old value --target vbox must be rejected (exit 2, invalid choice); rc=${rc} err=${err}"
fi

printf '%s\n' "" "$(basename -- "$0"): ${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ] || exit 1
exit 0
