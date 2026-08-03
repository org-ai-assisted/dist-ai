#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-build-step-fn must extract the RIGHT function, whole, or fail loudly.
##
## WHY THIS IS WORTH TESTING: the tool exists so a build-step function can be
## exercised without a ~50min build, which means its answer is TRUSTED. A silent
## mis-extraction does not look like a failure -- it looks like the function
## passing. The three ways it can lie (wrong function via a regex metacharacter,
## two definitions concatenated, a body truncated at a flush-left '}') each get
## a case here, and each case is written so it FAILS against the unhardened
## tool.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DIST_AI_DIR:-}" ]; then
   dist_ai_dir="${DIST_AI_DIR}"
else
   dist_ai_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../../.." && pwd )"
fi
tool="${dist_ai_dir}/usr/bin/dm-build-step-fn"
if [ ! -x "${tool}" ]; then
   tool="$( type -P dm-build-step-fn || true )"
fi
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "FAIL: dm-build-step-fn not found or not executable" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## A fixture shaped like a real build step: flush-left definitions, a trailing
## 'main "$@"' that must NOT run, and the three hazards.
fixture="${work_dir}/9999_fixture"
cat > "${fixture}" <<'FIXTURE'
#!/bin/bash
set -o errexit

source /nonexistent/pre-that-would-explode-if-sourced

check-stale-nbd() {
   printf '%s\n' "REAL-STALE-NBD"
}

check.stale.nbd() {
   printf '%s\n' "METACHAR-DECOY"
}

writes-brace-heredoc() {
   cat > /dev/null <<'INNER'
}
INNER
   printf '%s\n' "AFTER-THE-HEREDOC"
}

defined-twice() {
   printf '%s\n' "FIRST"
}

defined-twice() {
   printf '%s\n' "SECOND"
}

main "$@"
FIXTURE

## --- 1. the happy path: the named function, and ONLY it, actually runs -------
output="$( "${tool}" --file "${fixture}" --fn check-stale-nbd --run 2>&1 || true )"
if [ "${output}" = "REAL-STALE-NBD" ]; then
   pass 'extracts and runs the named function, without running the step'
else
   fail "expected 'REAL-STALE-NBD', got: ${output}"
fi

## The step's own 'source' and 'main "$@"' must never execute. If they did, the
## nonexistent source would abort and the output above could not have matched --
## so assert the negative explicitly rather than inferring it.
if [[ "${output}" != *"nonexistent"* ]] && [[ "${output}" != *"main"* ]]; then
   pass 'the step body (source, main) is not executed'
else
   fail "the step body leaked into the run: ${output}"
fi

## --- 2. a regex metacharacter must not select a different function ----------
## Unhardened, 'check.stale.nbd' is a sed address whose dots match the hyphens
## in 'check-stale-nbd', so this printed REAL-STALE-NBD -- the wrong function,
## reported as a success.
status=0
output="$( "${tool}" --file "${fixture}" --fn 'check.stale.nbd' --run 2>&1 )" || status="$?"
if [ "${status}" -ne 0 ] && [[ "${output}" != *"REAL-STALE-NBD"* ]]; then
   pass 'a regex metacharacter in --fn is refused, not silently mis-resolved'
else
   fail "metacharacter name gave status=${status} output=${output}"
fi

## --- 3. a doubly-defined function must be refused, not silently last-wins ---
status=0
output="$( "${tool}" --file "${fixture}" --fn defined-twice --run 2>&1 )" || status="$?"
if [ "${status}" -ne 0 ] && [[ "${output}" == *"defined 2 times"* ]]; then
   pass 'a doubly-defined function is refused with a count'
else
   fail "doubly-defined gave status=${status} output=${output}"
fi

## --- 4. truncation at a flush-left '}' must fail loudly ---------------------
## The heredoc body carries a '}' at column zero, so the sed range ends inside
## the heredoc. The truncated text is not parseable bash, which is exactly what
## the bash -n check is for.
status=0
output="$( "${tool}" --file "${fixture}" --fn writes-brace-heredoc --run 2>&1 )" || status="$?"
if [ "${status}" -ne 0 ] && [[ "${output}" == *"truncated"* ]]; then
   pass 'truncation at a flush-left brace is detected and reported'
else
   fail "truncated extraction gave status=${status} output=${output}"
fi

## It must specifically NOT have run the half-function as if it were whole.
if [[ "${output}" != *"AFTER-THE-HEREDOC"* ]]; then
   pass 'the truncated body is not executed'
else
   fail 'the truncated body ran anyway'
fi

## --- 5. an absent function reports, and lists what IS there -----------------
status=0
output="$( "${tool}" --file "${fixture}" --fn no-such-function --run 2>&1 )" || status="$?"
if [ "${status}" -ne 0 ] && [[ "${output}" == *"not found"* ]] \
   && [[ "${output}" == *"check-stale-nbd"* ]]; then
   pass 'an absent function is reported, with the available names'
else
   fail "absent function gave status=${status} output=${output}"
fi

## --- 6. --run must propagate the function's own exit code ------------------
## The whole point is judging a build-step function by its result, so an exit
## code that got flattened to 0 would turn a failing check into a green one.
## A distinctive 7 catches a hardcoded 0 AND a collapsed-to-1.
cat > "${work_dir}/exit_fixture" <<'EXITFIX'
#!/bin/bash
returns-seven() {
   return 7
}
EXITFIX
status=0
"${tool}" --file "${work_dir}/exit_fixture" --fn returns-seven --run >/dev/null 2>&1 || status="$?"
if [ "${status}" -eq 7 ]; then
   pass '--run propagates the function exit code verbatim'
else
   fail "expected exit 7 from the extracted function, got ${status}"
fi

## --- 7. CANARY: the fixture must really contain what the cases assume -------
## Without this, a fixture that silently stopped carrying the hazards would let
## every case above pass by testing nothing.
if grep -qE '^check-stale-nbd\(\) \{$' -- "${fixture}" \
   && [ "$( grep -cE '^defined-twice\(\) \{$' -- "${fixture}" )" -eq 2 ]; then
   pass 'canary: the fixture carries the shapes these cases depend on'
else
   fail 'canary broken: the fixture no longer carries the tested shapes'
fi

## --- 8. CANARY: the tool must be capable of failing at all ------------------
status=0
"${tool}" --file /nonexistent/step --fn whatever >/dev/null 2>&1 || status="$?"
if [ "${status}" -ne 0 ]; then
   pass 'canary: the tool exits non-zero on an unreadable step'
else
   fail 'canary broken: the tool exits 0 even on an unreadable step'
fi

summary_line="===== dm-build-step-fn: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
