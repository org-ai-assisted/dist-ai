#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-tests-all's no-root WARNING: run with NEITHER
## --repo-root NOR --component-root, every suite resolves its subject from the
## INSTALLED /usr copy, not a checkout -- a stale install then reports FALSE
## version-skew failures for a local AI run that believed it was testing its
## working tree. The runner now warns loudly (stderr, non-fatal) in that case.
##
## Drives the REAL shipped orchestrator as a subprocess. '--list' is the no-op
## that parses args, passes THROUGH the warning block, prints the selected suite
## lines, and exits BEFORE any suite (or the sandbox gate) runs -- '--list-
## components' exits EARLIER, before the warning block, so it is not the probe.
## DIST_AI_TESTS_ALL_BIN overrides the binary for a canary run against a pre-fix
## copy.

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

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the orchestrator RELATIVE to this test file (usr/share/<suite>/ ->
## usr/bin/), so editing the in-tree runner tests THAT copy, not the packaged
## one. DIST_AI_TESTS_ALL_BIN overrides for a canary run against a pre-fix copy.
test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
subject_resolve="${test_dir}/../dist-ai-tests-common/subject-resolve.bash"
if [ ! -r "${subject_resolve}" ]; then
   subject_resolve='/usr/share/dist-ai-tests-common/subject-resolve.bash'
fi
if [ ! -r "${subject_resolve}" ]; then
   printf '%s\n' "FATAL: subject-resolve.bash not found (checkout or installed)" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/subject-resolve.bash
source "${subject_resolve}"
## SET (even empty) override honored exactly; only UNSET falls back in-tree then
## installed; result is absolute so a slash-free value is not PATH-searched at
## invocation (which would silently run the installed orchestrator).
ORCH="$(resolve_test_subject DIST_AI_TESTS_ALL_BIN dist-ai-tests-all "${test_dir}")" || exit 1

scratch="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${scratch}"
}
trap cleanup_handler EXIT

pass_count=0
fail_count=0

warn_tag='no --repo-root/--component-root'

## A valid, existing directory to pass as --repo-root; its contents do not
## matter -- '--list' exits before any suite resolves a subject under it.
some_dir="$(mktemp --directory --tmpdir="${scratch}" root.XXXXXX)"

## run_orch <stdout-file> <stderr-file> <arg>...
## Run the orchestrator, capturing streams separately; returns rc in orch_rc.
run_orch() {
   local out err
   out="$1"
   err="$2"
   shift 2
   orch_rc=0
   "${ORCH}" "$@" > "${out}" 2> "${err}" || orch_rc=$?
}

## printf-only (R-034): a word describing whether FILE has content, for the
## diagnostic lines below.
stdout_state() {
   if [ -s "$1" ]; then
      printf '%s' 'non-empty'
   else
      printf '%s' 'EMPTY'
   fi
}

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'ok' ]; then
      printf '%s\n' "PASS: ${label}"
      pass_count=$((pass_count + 1))
   else
      printf '%s\n' "FAIL: ${label}" >&2
      fail_count=$((fail_count + 1))
   fi
}

## With NO roots: the warning MUST be on stderr. FAILS on the pre-fix runner,
## which emits no such warning.
run_orch "${scratch}/a.out" "${scratch}/a.err" --list
if grep --quiet --fixed-strings -- "${warn_tag}" "${scratch}/a.err"; then
   check 'no-root run warns about the INSTALLED /usr copy' 'ok'
else
   check 'no-root run warns about the INSTALLED /usr copy' 'bad'
fi
## The no-root '--list' must have RUN to completion (printed suite lines, exit 0),
## or the stderr grep above could pass/fail on a crash rather than on the warning.
if [ "${orch_rc}" -eq 0 ] && [ -s "${scratch}/a.out" ]; then
   check 'no-root --list ran to completion (exit 0, suite list emitted)' 'ok'
else
   printf '%s\n' "  orch_rc=${orch_rc}; stdout $(stdout_state "${scratch}/a.out")" >&2
   check 'no-root --list ran to completion (exit 0, suite list emitted)' 'bad'
fi

## WITH --repo-root: the warning MUST be ABSENT. The completion guard (stdout
## non-empty, exit 0) keeps this absence from passing vacuously on a crash.
run_orch "${scratch}/b.out" "${scratch}/b.err" --repo-root "${some_dir}" --list
if [ "${orch_rc}" -eq 0 ] && [ -s "${scratch}/b.out" ]; then
   if grep --quiet --fixed-strings -- "${warn_tag}" "${scratch}/b.err"; then
      check 'a --repo-root run does NOT warn' 'bad'
   else
      check 'a --repo-root run does NOT warn' 'ok'
   fi
else
   printf '%s\n' "  orch_rc=${orch_rc}; stdout $(stdout_state "${scratch}/b.out")" >&2
   check 'a --repo-root run ran to completion (exit 0, suite list emitted)' 'bad'
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
