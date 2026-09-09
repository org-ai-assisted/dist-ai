#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for /etc/uwt.d/40_qubes.conf under 'set -o nounset'.
##
## THE BUG: the uwt wrapper sources this conf under 'set -o nounset'. It tested
## '[ "$torified_check" = "skip" ]' before torified_check was ever set, so
## sourcing with torified_check unset aborted with 'torified_check: unbound
## variable' (line 15, seen 3x). The fix defaults it up front:
## 'torified_check="${torified_check:-}"'.
##
## Drives the REAL shipped conf: sources it under nounset with torified_check
## unset (the exact trigger) and a non-apt uwtwrapper_parent so it takes the
## benign early-return path. It must source through without an unbound-variable
## abort.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v QUBES_WHONIX_REPO ] || QUBES_WHONIX_REPO=""
if [ -n "${QUBES_WHONIX_REPO}" ]; then
   subject="${QUBES_WHONIX_REPO}/etc/uwt.d/40_qubes.conf"
else
   subject='/etc/uwt.d/40_qubes.conf'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: 40_qubes.conf not found at '${subject}'; set QUBES_WHONIX_REPO or install qubes-whonix." >&2
   exit 1
fi

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
probe_script="${test_dir}/qubes_conf_nounset_probe.sh"
if [ ! -r "${probe_script}" ]; then
   printf '%s\n' "FATAL: probe script not found at '${probe_script}'." >&2
   exit 1
fi

test_failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; test_failures=$((test_failures + 1)); }

## Source the conf under nounset with torified_check UNSET (the probe sets a
## non-apt uwtwrapper_parent so it hits the benign 'not torified -> return'
## path). A pre-fix conf aborts here with an unbound-variable error.
run_rc=0
run_output="$(env -u torified_check bash "${probe_script}" "${subject}" 2>&1)" || run_rc=$?

case "${run_output}" in
   *"unbound variable"*)
      fail "40_qubes.conf tripped nounset on unset torified_check: ${run_output}"
      ;;
   *)
      pass "40_qubes.conf sources under nounset with torified_check unset (no unbound variable)"
      ;;
esac

case "${run_output}" in
   *"SOURCED_OK"*)
      pass "40_qubes.conf sourced through to the benign return path (rc=${run_rc})"
      ;;
   *)
      fail "40_qubes.conf did not source through -- rc=${run_rc}, output: ${run_output}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: 40_qubes.conf is nounset-safe with torified_check unset."
