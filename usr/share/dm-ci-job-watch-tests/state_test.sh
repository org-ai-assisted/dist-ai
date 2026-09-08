#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-ci-job-watch-state.py reduces a commit's GitHub check-runs JSON to one
## build-lane verdict. A single head-sha can carry check-runs from MORE THAN ONE
## workflow run (a rerun-failed-jobs, or a fresh dispatch on the same sha). The
## helper once aggregated ALL matching check-runs, so a STALE prior run's
## completed:failure outvoted the current run still in progress -- the watcher
## then reported the fresh build as already failed and exited. Each workflow run
## is exactly one check-suite, so the fix keeps only the newest suite's jobs.
## This drives the REAL helper and asserts the newest suite decides the verdict.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

locate_helper() {
   local candidate repo_from_self
   repo_from_self="$(dirname -- "$(dirname -- "$(dirname -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")")")")"
   for candidate in \
      "${DM_CI_JOB_WATCH_STATE:-}" \
      "${repo_from_self}/usr/libexec/dist-ai/dm-ci-job-watch-state.py" \
      "/usr/libexec/dist-ai/dm-ci-job-watch-state.py"
   do
      [ -n "${candidate}" ] || continue
      if test -r "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

helper="$(locate_helper)" || {
   printf '%s\n' "FATAL: dm-ci-job-watch-state.py not found (set DM_CI_JOB_WATCH_STATE)" >&2
   exit 1
}
printf '%s\n' "INFO: helper under test: ${helper}"

pass=0
fail=0

## $1 label, $2 expected stdout, $3 job_filter, stdin = check-runs JSON.
check() {
   local label="$1" want="$2" flt="$3" got
   ## Exec the helper via its own '#!/usr/bin/python3 -Bsu' shebang (it is +x);
   ## invoking python3 explicitly would drop the shebang's flags.
   got="$(job_filter="${flt}" "${helper}")"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS  %s\n' "${label}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL  %s: want [%s] got [%s]\n' "${label}" "${want}" "${got}"
      fail=$(( fail + 1 ))
   fi
}

## Suite 100 (older): both build jobs concluded failure. Suite 200 (newer): jobs
## still queued/running. The reducer must read suite 200.
check "stale failed run does not outvote fresh in-progress run" "in_progress:None" "uild" <<'JSON'
{"check_runs":[
  {"name":"build (a)","status":"completed","conclusion":"failure","check_suite":{"id":100}},
  {"name":"build (b)","status":"completed","conclusion":"failure","check_suite":{"id":100}},
  {"name":"build (a)","status":"in_progress","conclusion":null,"check_suite":{"id":200}},
  {"name":"build (b)","status":"queued","conclusion":null,"check_suite":{"id":200}}
]}
JSON

## Newest suite fully green while an old suite failed -> PASSED (green rerun over red).
check "fresh green run overrides an old failed run" "completed:success" "uild" <<'JSON'
{"check_runs":[
  {"name":"build (a)","status":"completed","conclusion":"failure","check_suite":{"id":100}},
  {"name":"build (a)","status":"completed","conclusion":"success","check_suite":{"id":200}},
  {"name":"build (b)","status":"completed","conclusion":"success","check_suite":{"id":200}}
]}
JSON

## Newest suite has a real failure -> FAILED (not masked by an old green run).
check "fresh failure reported even when an old run was green" "completed:failure" "uild" <<'JSON'
{"check_runs":[
  {"name":"build (a)","status":"completed","conclusion":"success","check_suite":{"id":100}},
  {"name":"build (a)","status":"completed","conclusion":"failure","check_suite":{"id":200}},
  {"name":"build (b)","status":"completed","conclusion":"success","check_suite":{"id":200}}
]}
JSON

## Single suite, one job still running -> in_progress (all-jobs, not last-one-wins).
check "single suite still building" "in_progress:None" "uild" <<'JSON'
{"check_runs":[
  {"name":"build (a)","status":"completed","conclusion":"success","check_suite":{"id":300}},
  {"name":"build (b)","status":"in_progress","conclusion":null,"check_suite":{"id":300}}
]}
JSON

## Missing check_suite on every job -> falls back to the pre-existing all-jobs
## aggregation (both treated as suite 0), so a single-run payload still works.
check "absent check_suite falls back to plain aggregation" "completed:failure" "uild" <<'JSON'
{"check_runs":[
  {"name":"build (a)","status":"completed","conclusion":"failure"},
  {"name":"build (b)","status":"completed","conclusion":"success"}
]}
JSON

## The newest suite (id 300) is still in its BUILD phase and has not created the
## filtered job type (boot-test legs) yet; an older suite (id 200) on the same
## head-sha has completed, green boot-test legs. Watching boot-test must NOT read
## the old suite's success -- it must keep waiting (empty output).
check "newest suite lacking the filtered job type does not read a prior run" "" "boot-test" <<'JSON'
{"check_runs":[
  {"name":"build (a)","status":"in_progress","conclusion":null,"check_suite":{"id":300}},
  {"name":"build (b)","status":"in_progress","conclusion":null,"check_suite":{"id":300}},
  {"name":"boot-test (iso, bios, user)","status":"completed","conclusion":"success","check_suite":{"id":200}},
  {"name":"boot-test (iso, efi, user)","status":"completed","conclusion":"success","check_suite":{"id":200}}
]}
JSON

## Malformed / unexpected-shape input must yield NO verdict and exit 0 (the
## documented contract), never a stack-trace crash: the JSON is a network payload
## whose shape is not guaranteed (an error body, a truncated read, a list instead
## of an object). rc is captured so a crash reads as a FAIL, not an errexit abort.
for bad_input in '[]' '{}' 'not json' '{"check_runs":"x"}' '{"check_runs":[null,3]}'; do
   bad_rc=0
   bad_out="$(printf '%s' "${bad_input}" | job_filter=uild "${helper}" 2>&1)" || bad_rc=$?
   if [ "${bad_rc}" -eq 0 ] && [ -z "${bad_out}" ]; then
      printf 'PASS  malformed input yields no verdict, no crash: %s\n' "${bad_input}"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL  malformed input crashed or emitted (rc=%s out=[%s]): %s\n' "${bad_rc}" "${bad_out}" "${bad_input}"
      fail=$(( fail + 1 ))
   fi
done

printf '%s\n' "state_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
