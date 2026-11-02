#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's R-170 per-LINE waiver: a TRAILING inline
## '## style-ok: R-170' (or 'no-tmp-hardcode') on a flagged line waives THAT
## line only -- the narrow escape for the one legitimate hardcoded /tmp (e.g. a
## literal /tmp HOME in a test) without freezing the whole file against NEW /tmp
## debt. The FILE-WIDE line-leading waiver (a standalone '## style-ok: R-170' on
## its own line) is unchanged and still suppresses the entire file.
##
## Drives the REAL in-tree gate end to end over throwaway repos, never a copy of
## the rule. The '/tmp' literal and the R-170 tag are assembled at RUN TIME so
## neither appears verbatim in THIS tracked file (which the gate greps and would,
## correctly, flag / waive).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
   printf '%s\n' "FATAL: helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)" >&2
   exit 1
fi
# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has git ; then
   printf '%s\n' "FATAL: git not on PATH" >&2
   exit 1
fi
if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the gate RELATIVE to this test file; PRE_PUSH_STATIC_BIN overrides for
## a canary run against an alternate (pre-fix) gate copy.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## An EXPLICIT override is honored exactly -- never silently fall back to the installed gate (a
## canary pointed at a missing/non-exec binary would otherwise pass without testing what it named).
## Only an UNSET override falls back from the in-tree copy to the installed one.
if [ -n "${PRE_PUSH_STATIC_BIN:-}" ]; then
   GATE="${PRE_PUSH_STATIC_BIN}"
else
   GATE="${gate_test_dir}/../../bin/dist-ai-style"
   [ -x "${GATE}" ] || GATE='/usr/bin/dist-ai-style'
fi
[ -x "${GATE}" ] \
   || { printf '%s\n' "FATAL: gate not executable at '${GATE}'." >&2; exit 1; }

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

pass_count=0
fail_count=0

## The hardcoded temp path R-170 forbids, and the R-170 tag, assembled so the
## literals never live in THIS tracked file.
tmpp="/$(printf '%s' 'tmp')"
r170='R-170'
no_tmp='no-tmp-hardcode'

## Build a one-file repo whose sample.sh is the given body lines, run the gate,
## and return its combined output in gate_output and exit code in gate_rc.
## run_gate <line>...
run_gate() {
   local repo base
   repo="$(mktemp --directory --tmpdir="${test_dir}" repo.XXXXXX)"
   git -C "${repo}" -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet
   git -C "${repo}" -c core.hooksPath=/dev/null config user.email 'ci-test@example.com'
   git -C "${repo}" -c core.hooksPath=/dev/null config user.name 'ci-test'
   git -C "${repo}" -c core.hooksPath=/dev/null commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   printf '%s\n' "$@" > "${repo}/sample.sh"
   chmod 0755 -- "${repo}/sample.sh"
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null commit --quiet --no-verify --message fixture
   ## '|| true': the gate exits non-zero whenever a fixture carries a finding,
   ## which is the normal case here -- the assertions read gate_output, not rc.
   gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base}" 2>&1 )" || true
}

have_verdict() {
   grep --quiet --extended-regexp \
      'all static checks passed|[0-9]+ check\(s\) failed' <<< "${gate_output}"
}

## assert_r170_line <label> <lineno> <present|absent>
## Assert an R-170 finding for sample.sh:<lineno> is / is not in gate_output.
assert_r170_line() {
   local label lineno want got
   label="$1"
   lineno="$2"
   want="$3"
   if ! have_verdict; then
      printf '%s\n' "FAIL: ${label} -- gate produced no terminal verdict" >&2
      printf '%s\n' "${gate_output}" | tail -5 >&2
      fail_count=$((fail_count + 1))
      return 0
   fi
   local r170_lines
   r170_lines="$(printf '%s\n' "${gate_output}" | grep --fixed-strings -- "${r170}" || true)"
   ## grep --quiet reads a here-string, not a pipe, so it cannot SIGPIPE a
   ## producer (R-161).
   if grep --quiet --fixed-strings -- "sample.sh:${lineno}'" <<< "${r170_lines}"; then
      got='present'
   else
      got='absent'
   fi
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label} (R-170 ${want} at line ${lineno})"
      pass_count=$((pass_count + 1))
   else
      printf '%s\n' "FAIL: ${label} -- R-170 at line ${lineno} expected ${want}, was ${got}" >&2
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- "${r170}" | head -4 >&2
      fail_count=$((fail_count + 1))
   fi
}

## Core fix: a TRAILING '## style-ok: R-170' on line 2 (A) waives ONLY line 2;
## the unwaived hardcode on line 3 (B) is still flagged. FAILS on the pre-fix
## gate, which honors no trailing waiver and flags line 2 too.
run_gate \
   '#!/bin/bash' \
   "a=\"${tmpp}/aaa\"  ## style-ok: ${r170}" \
   "b=\"${tmpp}/bbb\""
assert_r170_line 'trailing R-170 waiver spares its own line' 2 'absent'
assert_r170_line 'trailing R-170 waiver does NOT spare the next line' 3 'present'

## The 'no-tmp-hardcode' spelling of the trailing waiver behaves identically.
run_gate \
   '#!/bin/bash' \
   "a=\"${tmpp}/aaa\"  ## style-ok: ${no_tmp}" \
   "b=\"${tmpp}/bbb\""
assert_r170_line 'trailing no-tmp-hardcode waiver spares its own line' 2 'absent'
assert_r170_line 'trailing no-tmp-hardcode waiver does NOT spare the next line' 3 'present'

## No waiver anywhere: both hardcodes are flagged (the rule actually fires, so
## the 'absent' assertions above are not vacuous).
run_gate \
   '#!/bin/bash' \
   "a=\"${tmpp}/aaa\"" \
   "b=\"${tmpp}/bbb\""
assert_r170_line 'unwaived hardcode on line 2 is flagged' 2 'present'
assert_r170_line 'unwaived hardcode on line 3 is flagged' 3 'present'

## The FILE-WIDE line-leading waiver is UNCHANGED: a standalone '## style-ok:
## R-170' on its own line suppresses the rule for the WHOLE file.
run_gate \
   '#!/bin/bash' \
   "## style-ok: ${r170}" \
   "a=\"${tmpp}/aaa\"" \
   "b=\"${tmpp}/bbb\""
assert_r170_line 'file-wide waiver spares line 3' 3 'absent'
assert_r170_line 'file-wide waiver spares line 4' 4 'absent'

## A SINGLE '#' is NOT a valid waiver (the shell grammar requires '##'), so a trailing
## '# style-ok: R-170' must NOT clear its line -- both lines stay flagged.
run_gate \
   "c=\"${tmpp}/ccc\"  # style-ok: ${r170}" \
   "d=\"${tmpp}/ddd\""
assert_r170_line 'single-# trailing waiver does NOT spare its line' 1 'present'
assert_r170_line 'the following unwaived temp-path line is still flagged' 2 'present'

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
