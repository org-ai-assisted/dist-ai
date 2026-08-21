#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NOT strict at top level: this probe
## sources SUBJECT (the real curl-prgrs) and must observe source-ability and the
## per-operation abort behaviour itself, enabling errexit ONLY for the operations
## whose assertion depends on it. Driven by curl_prgrs_test.sh, which asserts on
## this probe's stdout and exit code.
##
## Usage: curl_prgrs_probe.sh OPERATION [ARGS...]
## SUBJECT (the curl-prgrs path) and HELPER_SCRIPTS_PATH come from the env.

# shellcheck disable=SC1090
source "${SUBJECT}"

operation="${1:-}"
shift || true

## Scaffolding the reusable functions expect. fd 4 is curl-prgrs' progress sink.
exec 4>/dev/null
probe_tmp="$(mktemp --directory)"
## Clean up on exit -- the suite invokes this probe dozens of times. The shutdown
## and wrapper operations run curl-prgrs' own 'trap - EXIT' and remove the dir
## themselves; for every other operation this trap is what reaps it.
# shellcheck disable=SC2317
probe_cleanup() {
   safe-rm -r -f -- "${probe_tmp}" 2>/dev/null || true
}
trap probe_cleanup EXIT
statusfile="${probe_tmp}/status"
curl_pid_file="${probe_tmp}/curl.pid"
curl_pid=""

case "${operation}" in
   ## Source-ability: a leaked 'set -o errexit' from sourcing aborts before
   ## NO_LEAK prints (this probe sets no strict mode of its own).
   noauto)
      false
      printf '%s' NO_LEAK
      ;;

   ## Report the type of each named function, comma-joined.
   defined)
      type -t "$@" | tr '\n' ','
      ;;

   ## Source and call a pure function with its arguments (compute_percent,
   ## classify_download_size); its stdout is the result.
   call)
      "$@"
      ;;

   ## remove_argument_for_header_request, then print the resulting array.
   strip)
      remove_argument_for_header_request "$@"
      printf '%s\n' "${header_arguments[@]}"
      ;;

   ## initialize_terminal with the stderr_is_tty result forced to $1 (0 or 1).
   term)
      want="${1}"
      stderr_is_tty() { return "${want}"; }
      initialize_terminal
      ;;

   ## curl_exit CODE [live]: records the code; 'live' attaches a real curl_pid so
   ## the kill arm runs. Prints "returncode:statusfile-content".
   curl_exit)
      if [ "${2:-}" = "live" ]; then
         sleep 5 &
         curl_pid="$!"
      fi
      exit_rc=0
      curl_exit "${1}" || exit_rc="$?"
      printf '%s' "${exit_rc}:$(cat "${statusfile}")"
      if [ -n "${curl_pid}" ]; then
         kill "${curl_pid}" 2>/dev/null || true
      fi
      ;;

   ## shutdown SIGNAL STATUSCONTENT EXITCODE TEMPAUTO [live]: drives the trap
   ## handler with a controlled status file, simulated exit code and curl_pid.
   ## The process exits with shutdown's chosen code.
   shutdown)
      temporary_directory="${probe_tmp}"
      temp_dir_auto_generated="${4}"
      if [ "${2}" != "NOFILE" ]; then
         printf '%s' "${2}" > "${statusfile}"
      fi
      if [ "${5:-}" = "live" ]; then
         sleep 5 &
         curl_pid="$!"
      fi
      ( exit "${3}" )
      shutdown "${1}"
      ;;

   ## Run a shutdown_* trap wrapper with a clean status file of 0.
   wrapper)
      temporary_directory="${probe_tmp}"
      temp_dir_auto_generated=true
      printf '%s' 0 > "${statusfile}"
      "${1}"
      ;;

   ## check_variables with a given CURL_OUT_FILE ($1) and max-file-size ($2). The
   ## process exits with check_variables' code (0, or 57).
   checkvars)
      expected_header_size=8000
      maximum_http_header_size=32000
      CURL_OUT_FILE="${1}"
      CURL_PRGRS_MAX_FILE_SIZE_BYTES="${2}"
      check_variables
      ;;

   ## print_progress BYTES LENGTH PERCENTLAST EXEC under errexit: the 113 input
   ## guards abort via curl_exit; otherwise prints the resulting percent_last.
   print_progress)
      percent_last="${3}"
      CURL_PRGRS_EXEC="${4}"
      set -o errexit
      print_progress "${1}" "${2}"
      printf '%s' "${percent_last}"
      ;;

   ## curl_download with a non-numeric content length under errexit: hits the
   ## defensive 116 re-check and aborts.
   curl_download_bad_length)
      CURL=/bin/true
      CURL_OUT_FILE="${probe_tmp}/out"
      CURL_PRGRS_MAX_FILE_SIZE_BYTES=1000
      curl_prgrs_content_length="not-a-number"
      set -o errexit
      curl_download https://example.com/file
      ;;

   ## enforce_final_size against a file of SIZE ($1) with max ($2) and content
   ## length ($3) under errexit: the over-cap arm aborts via curl_exit; otherwise
   ## prints the re-read size.
   enforce)
      CURL_OUT_FILE="${probe_tmp}/out"
      truncate --size="${1}" -- "${CURL_OUT_FILE}"
      CURL_PRGRS_MAX_FILE_SIZE_BYTES="${2}"
      curl_prgrs_content_length="${3}"
      set -o errexit
      enforce_final_size
      printf '%s' "${size_file_downloaded_bytes}"
      ;;

   ## curl_exit must drop the published curl PID so a later shutdown cannot
   ## SIGKILL a reaped/reused PID. Publish a sentinel, run curl_exit, report
   ## whether the pid file was cleared.
   pidfile_clear)
      printf '%s\n' 999999 > "${curl_pid_file}"
      curl_exit 0 >/dev/null 2>&1 || true
      if [ -s "${curl_pid_file}" ]; then
         printf '%s' not-cleared
      else
         printf '%s' cleared
      fi
      ;;

   ## enforce_final_size when the output file is absent: nothing to do, returns 0.
   enforce_nofile)
      CURL_OUT_FILE="${probe_tmp}/does-not-exist"
      CURL_PRGRS_MAX_FILE_SIZE_BYTES=100
      curl_prgrs_content_length=100
      enforce_final_size
      ;;

   *)
      printf '%s\n' "curl_prgrs_probe: unknown operation '${operation}'" >&2
      exit 64
      ;;
esac
