#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression tests for dist-ai-config's 'ci-status'.
##
## Hermetic: a stub 'git-api' earlier on PATH serves generated fixture files,
## so there is no network call, no GitHub token, and no real repository.
##
## Every assertion here corresponds to a bug that shipped. The tool answers a
## single question -- "did CI actually pass?" -- so each of these is a case
## where it answered YES incorrectly, or turned an unreadable answer into a
## confident one:
##
##   - a failing check on the SECOND page of results was invisible, because
##     only the first page was fetched. A wide matrix therefore reported
##     green with a red job in it.
##   - a check-run NAME reached a shell 'eval'. Names come from workflow
##     files, so a fork PR could name a job such that ci-status executed
##     arbitrary commands on the machine that ran it.
##   - an API error object ("Bad credentials") and a non-JSON response (a
##     proxy error page) were both read as "this ref has no checks", which is
##     a claim about the repository rather than about the failure to read it.
##   - '--timeout' was ignored until the next fixed poll interval elapsed.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir=""
gate=""
pass_count=0
fail_count=0

cleanup() {
   [ -z "${test_dir}" ] || safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup EXIT

## Prefer an in-tree checkout over the installed copy: testing the packaged
## binary while editing the source silently tests the wrong file.
resolve_ci_status() {
   local script_dir candidate
   script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
   for candidate in \
      "${script_dir}/../../../dist-ai-config/usr/bin/ci-status" \
      "${HOME}/private-sources/dist-ai-config/usr/bin/ci-status" \
      /usr/bin/ci-status
   do
      if [ -r "${candidate}" ]; then
         printf '%s\n' "$(readlink --canonicalize -- "${candidate}")"
         return 0
      fi
   done
   printf '%s\n' "error: ci-status not found (in-tree or installed)" >&2
   return 1
}

make_fixtures() {
   python3 - "${test_dir}/fx" <<'PYTHON'
import json
import os
import sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def write(name, obj):
    with open(os.path.join(out, name), "w", encoding="utf-8") as handle:
        handle.write(obj if isinstance(obj, str) else json.dumps(obj))


def run(index, status="completed", conclusion="success", name=None):
    return {
        "id": index,
        "name": name or ("job-%d" % index),
        "status": status,
        "conclusion": conclusion,
    }


## 250 checks over three pages, the ONLY failure on the last one.
write("many.p1", {"total_count": 250, "check_runs": [run(i) for i in range(100)]})
write("many.p2", {"total_count": 250, "check_runs": [run(i) for i in range(100, 200)]})
write(
    "many.p3",
    {
        "total_count": 250,
        "check_runs": [run(i) for i in range(200, 249)]
        + [run(999, conclusion="failure", name="late-matrix-job")],
    },
)
## A check-run name carrying a newline plus a shell payload.
write(
    "inject.p1",
    {
        "total_count": 1,
        "check_runs": [
            run(
                1,
                conclusion="failure",
                name="benign\nTOTAL=1; touch PWNED",
            )
        ],
    },
)
## Valid JSON, but an API error object rather than a check-runs payload.
write("apierr.p1", {"message": "Bad credentials", "documentation_url": "https://example.com"})
## Not JSON at all.
write("notjson.p1", "<html><body>502 Bad Gateway</body></html>")
write("empty.p1", {"total_count": 0, "check_runs": []})
write(
    "green.p1",
    {"total_count": 2, "check_runs": [run(1), run(2, conclusion="skipped")]},
)
## Round 1 spans two pages and is still pending; round 2 is a single short
## page. The tool must answer from round 2 ALONE -- if the previous round's
## page files survive in the working directory they are counted again, so a
## finished-and-green ref reports 152 checks and a stale pending one.
write(
    "shrink.r1.p1",
    {"total_count": 150, "check_runs": [run(i) for i in range(99)]
     + [run(500, status="in_progress", conclusion=None)]},
)
write(
    "shrink.r1.p2",
    {"total_count": 150, "check_runs": [run(i) for i in range(100, 150)]},
)
write("shrink.r2.p1", {"total_count": 2, "check_runs": [run(1), run(2)]})
write(
    "pendingonly.p1",
    {
        "total_count": 1,
        "check_runs": [run(1, status="in_progress", conclusion=None)],
    },
)
PYTHON
}

make_stub() {
   mkdir --parents -- "${test_dir}/bin"
   cat > "${test_dir}/bin/git-api" <<'STUB'
#!/bin/bash
## Serves a fixture page for the requested URL. No auth, no network.
set -o errexit
set -o nounset
set -o pipefail
here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
path="$2"
page="1"
## Anchored on '?page='/'&page=' -- a bare 'page=' also matches inside
## 'per_page=', which would silently serve page 100 and thus an empty result
## for every request, making every assertion pass vacuously.
case "${path}" in
   *[?\&]page=*)
      page="${path##*[?\&]page=}"
      page="${page%%&*}"
      ;;
esac
## Some scenarios must answer differently on the second poll. A request for
## page 1 starts a new round; a fixture may provide per-round files.
round_file="${here}/../fx/.round"
[ -r "${round_file}" ] || printf '%s' 0 > "${round_file}"
round="$(cat -- "${round_file}")"
if [ "${page}" = "1" ]; then
   round=$(( round + 1 ))
   printf '%s' "${round}" > "${round_file}"
fi

fixture="${here}/../fx/${CI_FIXTURE}.r${round}.p${page}"
[ -r "${fixture}" ] || fixture="${here}/../fx/${CI_FIXTURE}.p${page}"
if [ -r "${fixture}" ]; then
   cat -- "${fixture}"
else
   ## An absent page is an empty page, so the pagination loop terminates.
   printf '%s' '{"total_count":0,"check_runs":[]}'
fi
STUB
   chmod +x -- "${test_dir}/bin/git-api"
}

report() {
   local outcome="$1" label="$2" detail="$3"
   if [ "${outcome}" = "pass" ]; then
      printf 'PASS  %-52s %s\n' "${label}" "${detail}"
      pass_count=$(( pass_count + 1 ))
   else
      printf 'FAIL  %-52s %s\n' "${label}" "${detail}"
      fail_count=$(( fail_count + 1 ))
   fi
}

## Runs ci-status against a fixture and compares the EXIT CODE, which is the
## tool's actual contract; its stdout is for humans.
expect_exit() {
   local label="$1" expected="$2" fixture="$3"
   shift 3
   local rc=0 output=""
   ## Each scenario starts at round 1; the counter is shared state otherwise.
   printf '%s' 0 > "${test_dir}/fx/.round"
   output="$(CI_FIXTURE="${fixture}" PATH="${test_dir}/bin:${PATH}" \
      "${gate}" --repo owner/name --ref deadbeef "$@" 2>&1)" || rc=$?
   printf '%s\n' "${output}" > "${test_dir}/out.${fixture}"
   if [ "${rc}" -eq "${expected}" ]; then
      report pass "${label}" "exit ${rc}"
   else
      report fail "${label}" "exit ${rc}, wanted ${expected}"
      printf '%s\n' "${output}" | sed 's/^/        /'
   fi
}

test_dir="$(mktemp --directory -- "${TMP:-/tmp}/ci-status-tests.XXXXXX")"
gate="$(resolve_ci_status)"
printf '%s\n\n' "testing: ${gate}"
make_fixtures
make_stub

expect_exit "green: every check succeeded"              0 green   --no-wait
expect_exit "no checks at all is a finding, not a pass" 2 empty   --no-wait
expect_exit "non-JSON response is an error"             1 notjson --no-wait
expect_exit "API error object is not 'no checks'"       1 apierr  --no-wait
expect_exit "failure on page 3 of 3 is caught"          1 many    --no-wait
expect_exit "failing check-run name does not pass"      1 inject  --no-wait

## The pagination assertion above only proves the exit code. Confirm the tool
## genuinely read page three rather than failing for some unrelated reason.
if grep --quiet --fixed-strings 'late-matrix-job' "${test_dir}/out.many"; then
   report pass "pagination reaches the final page" "page-3 job listed"
else
   report fail "pagination reaches the final page" "page-3 job absent"
fi

## The load-bearing security assertion: the payload must not have run.
if [ -e "${test_dir}/PWNED" ] || [ -e "PWNED" ]; then
   report fail "check-run name cannot execute commands" "payload EXECUTED"
else
   report pass "check-run name cannot execute commands" "payload inert"
fi

## Polling must not accumulate the previous round's pages. Two polls: the
## first is a pending 150-check spread, the second a green 2-check answer.
expect_exit "stale pages are cleared between polls"     0 shrink  --timeout 2
if grep --quiet --extended-regexp 'all 2 check' "${test_dir}/out.shrink"; then
   report pass "poll answers from the latest round only" "2 checks"
else
   report fail "poll answers from the latest round only" \
      "$(grep --extended-regexp 'check\(s\)' "${test_dir}/out.shrink" | tail -1)"
fi

## An argument the tool ACCEPTS must not abort it later. '08' passes the
## all-digits check, then arithmetic expansion reads it as octal.
zero_padded_output="$(CI_FIXTURE=pendingonly PATH="${test_dir}/bin:${PATH}" \
   "${gate}" --repo owner/name --ref deadbeef --timeout 08 2>&1 || true)"
if printf '%s' "${zero_padded_output}" | grep --quiet --fixed-strings 'value too great for base'; then
   report fail "zero-padded --timeout is read as decimal" "aborted on octal"
else
   report pass "zero-padded --timeout is read as decimal" "no octal abort"
fi

## A short timeout must not block for a whole poll interval first.
start_seconds="${SECONDS}"
CI_FIXTURE=pendingonly PATH="${test_dir}/bin:${PATH}" \
   "${gate}" --repo owner/name --ref deadbeef --timeout 2 >/dev/null 2>&1 || true
elapsed=$(( SECONDS - start_seconds ))
if [ "${elapsed}" -le 6 ]; then
   report pass "--timeout is honoured before the poll interval" "${elapsed}s"
else
   report fail "--timeout is honoured before the poll interval" "${elapsed}s"
fi

printf '\n%s passed, %s failed\n' "${pass_count}" "${fail_count}"
[ "${fail_count}" -eq 0 ]
