#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard for use_leaprun_test.sh's probe captures.
##
## use_leaprun_test.sh runs the probe inside two command substitutions under
## set -o errexit + shopt -s inherit_errexit. If a capture lacks a '|| sentinel'
## fallback, a non-zero probe exit aborts the WHOLE test mid-script -- before any
## NOT OK line or the summary -- so a probe crash is masked as a silent abort
## instead of a reported test failure.
##
## This drives the REAL use_leaprun_test.sh with the probe forced to exit
## non-zero, and asserts it (a) fails, (b) still emits a NOT OK diagnostic, and
## (c) runs to completion (prints its summary). Without the fallback, (b) and (c)
## do not hold -- so this test is RED on the pre-fix code. No root, no network,
## no installed helper-scripts (the stub below stands in for use_leaprun.sh).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject="${script_dir}/use_leaprun_test.sh"
[ -r "${subject}" ] || { printf '%s\n' "FATAL: subject missing: ${subject}" >&2; exit 1; }

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Deliberately broken use_leaprun.sh stub so the REAL probe's `source` of it
## exits non-zero -- forcing the "probe exits non-zero" branch the subject must
## report. This is a test-isolation stub, NOT a copy of the real script (nothing
## to drift from): its only job is to fail when sourced. HELPER_SCRIPTS_REPO is
## how use_leaprun_test.sh resolves which use_leaprun.sh the probe sources, so
## the subject itself picks this stub up unchanged.
stub_dir="${work_dir}/usr/libexec/helper-scripts"
mkdir --parents -- "${stub_dir}"
cat > "${stub_dir}/use_leaprun.sh" <<'STUB'
#!/bin/bash
## Broken-on-purpose: sourcing must return non-zero (see the test that writes me).
exit 1
STUB

## Capture combined streams + exit status. The subject is EXPECTED to exit
## non-zero here, so guard the run so this test's own errexit does not abort.
out=''
rc=0
out="$(HELPER_SCRIPTS_REPO="${work_dir}" "${subject}" 2>&1)" || rc="$?"

if [ "${rc}" != '0' ]; then
   ok "broken probe fails the subject (rc=${rc})"
else
   notok "broken probe did not fail the subject (rc=0)"
fi

if [[ "${out}" == *'NOT OK'* ]]; then
   ok "subject emits a NOT OK diagnostic instead of aborting silently"
else
   notok "no NOT OK diagnostic -- subject aborted silently under errexit: '${out}'"
fi

if [[ "${out}" == *'passed,'*'failed'* ]]; then
   ok "subject runs to completion (prints the summary line)"
else
   notok "summary line missing -- subject did not run to completion: '${out}'"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
