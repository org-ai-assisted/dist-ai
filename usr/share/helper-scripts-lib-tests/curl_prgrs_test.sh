#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## curl-prgrs: source-ability, the pure decision helpers, and the full download
## orchestration driven end-to-end against a deterministic 'curl' stub
## (curl_prgrs_fake_curl.sh) -- no network, no real downloads.
##
## Drives the REAL script from the checkout. Two entry styles, both exercising
## the same file:
##  - SOURCE via curl_prgrs_probe.sh: source curl-prgrs in a child shell and call
##    one reusable function, for the branches a real download cannot reach on
##    demand (a broken 'stat' reading -> 113, the shutdown trap's status arms,
##    the initialize_terminal TTY seam, the post-loop final-size ceiling).
##  - EXEC: run the real script under the fake curl, for the orchestration, the
##    poll loop, the endless-data ceilings, progress redraw, truncation and a
##    real SIGTERM.
##  - A property fuzz (curl_prgrs_fuzz.sh) over the pure functions.
##
## A missing dependency is a HARD FAIL, never a skip. Only an absent SUBJECT
## (no checkout / helper-scripts not installed) is a SKIP (exit 77).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
fake_curl="${tool_dir}/curl_prgrs_fake_curl.sh"
probe_script="${tool_dir}/curl_prgrs_probe.sh"
fuzz_script="${tool_dir}/curl_prgrs_fuzz.sh"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   repo="${HELPER_SCRIPTS_REPO}"
else
   repo="/"
fi
subject="${repo%/}/usr/libexec/helper-scripts/curl-prgrs"
libdir="${repo%/}/usr/libexec/helper-scripts"

## Absent subject -> SKIP (a source-tree / partial run without helper-scripts).
if [ ! -x "${subject}" ]; then
   printf '%s\n' "SKIP: subject not executable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 77
fi
for lib in check_runtime.bsh progress-bar strings.bsh has.sh; do
   if [ ! -r "${libdir}/${lib}" ]; then
      printf '%s\n' "SKIP: helper-scripts lib '${lib}' not readable under '${libdir}'" >&2
      exit 77
   fi
done
for support in "${fake_curl}" "${probe_script}" "${fuzz_script}"; do
   if [ ! -x "${support}" ]; then
      printf '%s\n' "FATAL: test support script missing: '${support}'" >&2
      exit 1
   fi
done

# shellcheck disable=SC1090
source "${libdir}/has.sh"

## Real dependencies the subject and this test need. A missing one is a FAIL.
for dep in curl safe-rm tput mktemp truncate stat; do
   if ! has "${dep}" ; then
      printf '%s\n' "FATAL: dependency '${dep}' not on PATH" >&2
      exit 1
   fi
done

## The subject resolves its own libs via HELPER_SCRIPTS_PATH; SUBJECT lets the
## probe source it without re-quoting the path.
export HELPER_SCRIPTS_PATH="${repo%/}"
export SUBJECT="${subject}"
## Every EXEC scenario uses the deterministic stub and a fast poll.
export CURL="${fake_curl}"
export curl_prgrs_poll_interval="0.05"

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Run the source-probe, capturing only its exit code.
probe_rc() {
   local rc=0
   "${probe_script}" "$@" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## Run the source-probe, capturing "exitcode|stdout" (for ops that may abort via
## curl_exit under errexit, where the exit code AND any printed value matter).
probe_out_rc() {
   local out rc=0
   out="$("${probe_script}" "$@" 2>/dev/null)" || rc=$?
   printf '%s' "${rc}|${out}"
}

## Run the real subject with the caller's env prefix; echo only its exit code.
run_rc() {
   local rc=0
   "${subject}" "$@" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## ============================================================
## (A) Source-ability: no auto-run, no strict-mode leak, functions defined.
## ============================================================
check "source: no auto-run and no errexit leak" "$(probe_out_rc noauto)" "0|NO_LEAK"

check "source: every function defined" \
   "$("${probe_script}" defined \
      stderr_is_tty initialize_terminal initialize_variables check_variables \
      shutdown traps_enable compute_percent print_progress curl_exit \
      classify_download_size enforce_final_size curl_download \
      remove_argument_for_header_request run_body_download run_download main \
      was_executed)" \
   "function,function,function,function,function,function,function,function,function,function,function,function,function,function,function,function,function,"

## ============================================================
## (B) compute_percent -- pure, including the div-by-zero (length 0) guard.
## ============================================================
check "compute_percent: 0/0 -> 100 (no division by zero)" "$("${probe_script}" call compute_percent 0 0)" "100"
check "compute_percent: 25/100 -> 25" "$("${probe_script}" call compute_percent 25 100)" "25"
check "compute_percent: 3/7 -> 42 (integer floor)" "$("${probe_script}" call compute_percent 3 7)" "42"
check "compute_percent: 200/100 -> clamped to 100" "$("${probe_script}" call compute_percent 200 100)" "100"

## ============================================================
## (C) classify_download_size -- the endless-data ceilings, including the 113
## 'stat gave a non-number' guard a real stat cannot produce.
## ============================================================
check "classify: within bounds -> 0"          "$("${probe_script}" call classify_download_size 50 100 100)"   "0"
check "classify: non-numeric size -> 113"     "$("${probe_script}" call classify_download_size xx 100 100)"   "113"
check "classify: over max cap -> 81"          "$("${probe_script}" call classify_download_size 200 100 1000)" "81"
check "classify: over content-length -> 114"  "$("${probe_script}" call classify_download_size 200 1000 100)" "114"

## ============================================================
## (D) remove_argument_for_header_request -- strips the output/resume pairs.
## ============================================================
strip_args() {
   "${probe_script}" strip "$@" | tr '\n' ','
}
check "strip: -o pair removed"            "$(strip_args -o /out https://example.com/f)" "https://example.com/f,"
check "strip: --output pair removed"      "$(strip_args --output /out url)"             "url,"
check "strip: -C pair removed"            "$(strip_args -C - url)"                      "url,"
check "strip: --continue-at pair removed" "$(strip_args --continue-at 0 url)"           "url,"
check "strip: plain args preserved"       "$(strip_args -sSL url)"                      "-sSL,url,"

## ============================================================
## (E) initialize_terminal -- both fd-4 arms via the stderr_is_tty seam.
## ============================================================
check "initialize_terminal: TTY branch (exec 4>&2)"           "$(probe_rc term 0)" "0"
check "initialize_terminal: non-TTY branch (exec 4>/dev/null)" "$(probe_rc term 1)" "0"

## ============================================================
## (F) curl_exit -- statusfile write, the return-0 fast path, and the kill arm.
## ============================================================
check "curl_exit 0: returns 0, records 0"             "$("${probe_script}" curl_exit 0 no)"   "0:0"
check "curl_exit 81 (no pid): returns 81, records 81" "$("${probe_script}" curl_exit 81 no)"   "81:81"
check "curl_exit 81 (live pid): kills pid, returns 81" "$("${probe_script}" curl_exit 81 live)" "81:81"

## ============================================================
## (G) shutdown -- status resolution across signal, statusfile and code arms.
## Driven directly so every branch is deterministic (no signal-timing races).
## ============================================================
check "shutdown err + no statusfile -> 112"       "$(probe_rc shutdown err NOFILE 0 true no)"   "112"
check "shutdown err + specific status 81 -> 81 (code survives)" \
   "$(probe_rc shutdown err 81 0 true no)" "81"
check "shutdown err + status 0 -> 110 (generic, not false success)" \
   "$(probe_rc shutdown err 0 0 true no)" "110"
check "shutdown exit + status 0 -> 0"             "$(probe_rc shutdown exit 0 0 true no)"        "0"
check "shutdown sigterm + status 7 -> 7"          "$(probe_rc shutdown sigterm 7 0 true no)"     "7"
check "shutdown exit + non-numeric status -> 111" "$(probe_rc shutdown exit garbage 0 true no)"  "111"
check "shutdown sigint + status 0 + live pid + no auto temp -> 0" \
   "$(probe_rc shutdown sigint 0 0 false live)" "0"

## ============================================================
## (H) shutdown_* trap wrappers -- each forwards to shutdown.
## ============================================================
check "wrapper shutdown_sigint"  "$(probe_rc wrapper shutdown_sigint)"  "0"
check "wrapper shutdown_sigterm" "$(probe_rc wrapper shutdown_sigterm)" "0"
check "wrapper shutdown_sighup"  "$(probe_rc wrapper shutdown_sighup)"  "0"
check "wrapper shutdown_exit"    "$(probe_rc wrapper shutdown_exit)"    "0"
## shutdown_err takes the ERR arm: the generic 110 wins over the status 0.
check "wrapper shutdown_err -> 110" "$(probe_rc wrapper shutdown_err)"  "110"

## ============================================================
## (I) check_variables -- the two mandatory-variable guards and the happy path.
## ============================================================
check "check_variables: empty CURL_OUT_FILE -> 57"        "$(probe_rc checkvars '' 100)" "57"
check "check_variables: empty MAX_FILE_SIZE -> 57"        "$(probe_rc checkvars /x '')"  "57"
check "check_variables: both set and valid -> 0"          "$(probe_rc checkvars /x 100)" "0"

## ============================================================
## (J) print_progress -- input guards, the redraw path, dedup and CURL_PRGRS_EXEC.
## "rc|percent_last": a 113 abort yields "113|"; a redraw yields "0|50".
## ============================================================
check "print_progress: non-numeric bytes -> 113"    "$(probe_out_rc print_progress x 100 '' '')"    "113|"
check "print_progress: non-numeric length -> 113"   "$(probe_out_rc print_progress 50 y '' '')"     "113|"
check "print_progress: redraw, EXEC empty"          "$(probe_out_rc print_progress 50 100 '' '')"   "0|50"
check "print_progress: percent unchanged (dedup)"   "$(probe_out_rc print_progress 50 100 50 '')"   "0|50"
check "print_progress: redraw runs CURL_PRGRS_EXEC"  "$(probe_out_rc print_progress 50 100 '' true)" "0|50"

## ============================================================
## (K) curl_download entry guard -- the defensive 116 re-check on a bad length.
## ============================================================
check "curl_download: non-numeric content length -> 116" "$(probe_rc curl_download_bad_length)" "116"

## ============================================================
## (L) enforce_final_size -- the post-loop final-size re-check, driven directly
## so the over-cap arm is deterministic (a live download races loop vs post-loop).
## ============================================================
check "enforce_final_size: within bounds -> re-reads size, no exit" \
   "$(probe_out_rc enforce 50 100 100000)" "0|50"
check "enforce_final_size: over the max cap -> 81" \
   "$(probe_out_rc enforce 500 100 100000)" "81|"
check "enforce_final_size: absent file -> 0" "$(probe_rc enforce_nofile)" "0"

## ============================================================
## (M) Full EXEC runs against the fake curl. Each scenario uses its OWN output
## path: the poll loop stats CURL_OUT_FILE concurrently with the fake curl, so a
## reused path could momentarily expose a prior scenario's bytes.
## ============================================================

## M1 normal multi-step download succeeds.
out_file="${test_dir}/M1.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=100 FAKE_CURL_BODY_BYTES=100 FAKE_CURL_BODY_STEPS=4 \
   FAKE_CURL_BODY_STEP_SLEEP=0.05 \
   run_rc -o "${out_file}" https://example.com/file)"
check "exec: normal download -> 0" "${rc}" "0"

## M2 REGRESSION (ISSUE-1): Content-Length 0 / empty file no longer divides by
## zero. Old code crashed here via the ERR trap (exit 110).
out_file="${test_dir}/M2.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=0 FAKE_CURL_BODY_BYTES=0 \
   run_rc -o "${out_file}" https://example.com/empty)"
check "exec: empty file (Content-Length 0) -> 0 (div-by-zero fixed)" "${rc}" "0"

## M3 endless-data: over the hard max-file-size cap.
out_file="${test_dir}/M3.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100 \
   FAKE_CURL_HEADER_CL=5000 FAKE_CURL_BODY_BYTES=500 FAKE_CURL_BODY_STEPS=5 \
   FAKE_CURL_BODY_STEP_SLEEP=0.05 \
   run_rc -o "${out_file}" https://example.com/big)"
check "exec: exceeds max-file-size cap -> 81" "${rc}" "81"

## M4 endless-data: past the advertised content length.
out_file="${test_dir}/M4.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=100 FAKE_CURL_BODY_BYTES=500 FAKE_CURL_BODY_STEPS=5 \
   FAKE_CURL_BODY_STEP_SLEEP=0.05 \
   run_rc -o "${out_file}" https://example.com/toolong)"
check "exec: exceeds content length -> 114" "${rc}" "114"

## M5 truncated download (fewer bytes than advertised, curl exits 0).
out_file="${test_dir}/M5.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=1000 FAKE_CURL_BODY_BYTES=500 \
   run_rc -o "${out_file}" https://example.com/short)"
check "exec: truncated download -> 115" "${rc}" "115"

## M6 header Content-Length is not a number.
out_file="${test_dir}/M6.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=not-a-number FAKE_CURL_BODY_BYTES=10 \
   run_rc -o "${out_file}" https://example.com/badheader)"
check "exec: non-numeric header content-length -> 116" "${rc}" "116"

## M7 curl itself fails on the body request.
out_file="${test_dir}/M7.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=100 FAKE_CURL_BODY_BYTES=100 FAKE_CURL_BODY_EXIT=22 \
   run_rc -o "${out_file}" https://example.com/fail)"
check "exec: curl body failure propagates -> 22" "${rc}" "22"

## M8 file never appears on disk (exercises the 'no file yet' loop arm and the
## post-loop 'size never set' skip).
out_file="${test_dir}/M8.absent"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100000 \
   FAKE_CURL_HEADER_CL=100 FAKE_CURL_BODY_NO_FILE=1 \
   run_rc -o "${out_file}" https://example.com/nofile)"
check "exec: body never writes a file -> 0" "${rc}" "0"

## M9 the whole body lands in a single final write the poll loop never sees, and
## it is over the max-file-size cap: the post-loop final-size check must catch it.
out_file="${test_dir}/M9.bin"
rc="$(CURL_OUT_FILE="${out_file}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=100 \
   FAKE_CURL_HEADER_CL=100000 FAKE_CURL_BODY_CREATE_AT_END=500 \
   run_rc -o "${out_file}" https://example.com/finalburst)"
check "exec: over-cap final write caught post-loop -> 81" "${rc}" "81"

## ============================================================
## (N) Real SIGTERM during an in-flight download: the subject handles the signal
## and terminates promptly (exercises shutdown_sigterm via a real trap). The
## body child idles (FAKE_CURL_BODY_PRESLEEP) so SIGTERM lands mid-download.
## ============================================================
sig_out="${test_dir}/sig.bin"
CURL_OUT_FILE="${sig_out}" CURL_PRGRS_MAX_FILE_SIZE_BYTES=10000000 \
   FAKE_CURL_HEADER_CL=1000000 FAKE_CURL_BODY_BYTES=1000000 \
   FAKE_CURL_BODY_PRESLEEP=3 \
   "${subject}" -o "${sig_out}" https://example.com/slow >/dev/null 2>&1 &
subject_pid=$!
## The header phase (a fast fake-curl call) is well over within 1s, so the body
## poll loop is running when SIGTERM arrives.
sleep 1
kill -s SIGTERM "${subject_pid}" 2>/dev/null || true
gone=no
for _ in $(seq 1 30); do
   if ! kill -0 "${subject_pid}" 2>/dev/null; then
      gone=yes
      break
   fi
   sleep 0.1
done
wait "${subject_pid}" 2>/dev/null || true
check "signal: SIGTERM terminates the subject promptly (no hang)" "${gone}" "yes"

## ============================================================
## (O) Property fuzz: drive the REAL pure bash functions over many random inputs
## and assert their invariants. Deterministic by default so CI is reproducible
## (override the seed/iteration count via env); the seed is printed for repro.
## ============================================================
fuzz_seed="${CURL_PRGRS_FUZZ_SEED:-1}"
fuzz_iters="${CURL_PRGRS_FUZZ_ITERS:-500}"
fuzz_report="$("${fuzz_script}" "${fuzz_seed}" "${fuzz_iters}" 2>&1)"
fuzz_fails="$(printf '%s\n' "${fuzz_report}" | sed -n 's/^FUZZFAILS=//p')"
if [ "${fuzz_fails:-1}" != "0" ]; then
   printf '%s\n' "${fuzz_report}"
   printf '%s\n' "property fuzz FAILED -- reproduce with CURL_PRGRS_FUZZ_SEED=${fuzz_seed} CURL_PRGRS_FUZZ_ITERS=${fuzz_iters}" >&2
fi
check "property fuzz: ${fuzz_iters} iterations, 0 invariant violations (seed ${fuzz_seed})" \
   "${fuzz_fails:-missing}" "0"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
