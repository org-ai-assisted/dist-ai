#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the secure-terminal (ST) capture paths must confirm the injected command actually
## RAN before publishing a shot. capture_settled only rejects a fully BLANK frame, and
## shots_transcript_has_content passes on ANY non-prompt content -- so a dropped keystroke that
## turned `cat X.payload` into `at X.payload` -> `at: command not found` produced a NON-blank
## shell-error shot that published silently, and a swallowed `send-text ... || true` published a
## shot whose command was never submitted. The compat path (lineedit_capture_row) now gates on
## shots_cmd_ran_ok reading the SHOTS_CMDLOG the ST shell writes, and treats a nonzero send-text as
## failure. Display-free: SOURCE the real comparison-capture.sh (source-safe via its was_executed
## guard) so lineedit_capture_row is the CURRENT body, stub its collaborators, and drive it -- the
## fake `secure-terminal` client simulates the shell's cmdlog write on send-text.
##
## FAILS on the old harness: the old lineedit_capture_row published on capture_settled +
## transcript-content alone, so the dropped-keystroke and swallowed-submit cases below read GREEN.
##
## Subject: comparison-capture.sh + lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR / a
## checkout default / the installed path. Absent -> exit 1 (FATAL, R-220). Runs no real capture,
## spawns no process group -- pure logic, safe anywhere.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/comparison-capture.sh" \
   "${script_dir}/../secure-terminal-shots/comparison-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/comparison-capture.sh" \
   '/usr/share/secure-terminal-shots/comparison-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      subject="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' 'FATAL: comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3 (got '$1', want '$2')"
      fail=$(( fail + 1 ))
   fi
}

work="$(mktemp --directory)"
## Uniquely named: the sourced comparison-capture.sh defines its OWN cleanup(); a shared name would
## clobber this trap's target (see zoom_live_wiring_test.sh).
cv_cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cv_cleanup EXIT

# shellcheck source=../secure-terminal-shots/comparison-capture.sh
source "${subject}"
for fn in lineedit_capture_row shots_cmd_ran_ok; do
   if ! declare -F "${fn}" >/dev/null 2>&1; then
      printf '%s\n' "FAIL: ${fn} not defined after sourcing comparison-capture.sh -- old harness" >&2
      printf '%s\n' '' '0 pass, 1 fail, 0 skip'
      exit 1
   fi
done

## A fake `secure-terminal` CLI (this IS st_bin). It answers `ctl ls` with one tab (id 0) and, on
## `ctl send-text ... --submit <cmd>`, SIMULATES the ST shell's PROMPT_COMMAND / command_not_found
## write to SHOTS_CMDLOG so the real shots_cmd_ran_ok gate sees exactly what a live shell would log.
## CV_STUB_MODE drives the scenarios: ok | notfound | ran-fail | send-fail.
st_bin="${work}/fake-st"
cat > "${st_bin}" <<'PY'
#!/bin/bash
## args: ctl --instance-group <group> <ls | send-text --tab id:0 --submit <cmd>>
: "${SHOTS_CMDLOG:=${HOME}/.shots-cmdlog}"
mode="${CV_STUB_MODE:-ok}"
subcmd=''
cmd=''
prev=''
for a in "$@"; do
   case "${a}" in
      ls|send-text) [ -z "${subcmd}" ] && subcmd="${a}" ;;
   esac
   [ "${prev}" = '--submit' ] && cmd="${a}"
   prev="${a}"
done
if [ "${subcmd}" = ls ]; then
   printf '0\tmain\n'
   exit 0
fi
if [ "${subcmd}" = send-text ]; then
   case "${mode}" in
      send-fail)
         ## The submit itself failed: nothing typed, nonzero exit.
         exit 1
         ;;
      notfound)
         ## Dropped keystroke in the COMMAND: the mangled first word is not found.
         printf 'NOTFOUND\t%s\n' "${cmd%% *}" >> "${SHOTS_CMDLOG}"
         printf 'RAN\t127\t%s\n' "${cmd}" >> "${SHOTS_CMDLOG}"
         ;;
      wrong-cmd)
         ## Dropped keystroke in the ARGUMENT: a DIFFERENT command completed (last char dropped).
         printf 'RAN\t0\t%s\n' "${cmd%?}" >> "${SHOTS_CMDLOG}"
         ;;
      exit-nonzero)
         ## The EXACT command ran but exited nonzero -- legitimate for a compat row (diff exits 1).
         printf 'RAN\t1\t%s\n' "${cmd}" >> "${SHOTS_CMDLOG}"
         ;;
      *)
         ## Happy path: the exact injected command ran and exited 0.
         printf 'RAN\t0\t%s\n' "${cmd}" >> "${SHOTS_CMDLOG}"
         ;;
   esac
   exit 0
fi
exit 0
PY
chmod +x "${st_bin}"

## Stub the GUI/capture collaborators so no display / process / real sleep is needed. capture_settled
## CREATES the shot file (as grim would) and succeeds; shots_transcript_has_content passes so the
## cmdlog gate is the deciding factor under test (content_verify_test covers the transcript gate).
shots_spawn_session() { : ; }
shots_watchdog_start() { printf '%s' '0'; }
shots_watchdog_cancel() { : ; }
shots_reap_group() { : ; }
set_window_rule() { : ; }
find_window() { printf '%s' '12345'; }
wait_window_ready() { : ; }
st_wait_render_settled() { : ; }
sleep() { : ; }                                  ## skip the real 3s+1s settle waits
capture_settled() { printf '' > "$1"; }          ## write the "PNG", succeed
shots_transcript_has_content() { return 0; }     ## isolate the cmdlog gate

## Globals lineedit_capture_row reads (normally set by the main flow above the source boundary).
runtime_dir="${work}/rt"; mkdir --parents -- "${runtime_dir}"
export HOME="${work}/home"; mkdir --parents -- "${HOME}"
out="${work}/shots"; mkdir --parents -- "${out}"
st_pkg="${work}/pkg"
SHOT_DEADLINE=90
SHOT_PROMPT='user@host:~$ '
export SHOTS_CMDLOG="${HOME}/.shots-cmdlog"
run_marker="${runtime_dir}/run-marker"

CMD='cat escape.payload'

## Drive lineedit_capture_row in each scenario; assert the return code AND that the shot file is
## KEPT on publish / REMOVED on discard.
run_case() {  ## $1=stub-mode $2=shot-name -> echoes "rc:<0|1> png:<yes|no>"
   local mode name rc
   mode="$1"; name="$2"
   true > "${SHOTS_CMDLOG}"
   rc=0
   CV_STUB_MODE="${mode}" lineedit_capture_row compat "${name}" full "${CMD}" >/dev/null 2>&1 || rc="$?"
   if [ -f "${out}/${name}.png" ]; then printf 'rc:%s png:yes' "${rc}"; else printf 'rc:%s png:no' "${rc}"; fi
}

## 1. Happy path: the injected command ran cleanly -> publish (rc 0, PNG kept).
check "$(run_case ok ok-shot)" 'rc:0 png:yes' 'a cleanly-run command publishes the shot'

## 2. Dropped keystroke -> command_not_found -> DISCARD (rc nonzero, PNG removed). The core bug.
got="$(run_case notfound nf-shot)"
check "${got}" 'rc:1 png:no' 'a dropped-keystroke (command not found) shot is DISCARDED, not published'

## 3. A dropped keystroke in the ARGUMENT completes a DIFFERENT command -> DISCARD.
got="$(run_case wrong-cmd wc-shot)"
check "${got}" 'rc:1 png:no' 'a mangled-argument (different completed command) shot is DISCARDED'

## 4. The EXACT command ran but exited NONZERO -> PUBLISH (a compat row like `diff` exits 1 as its
## demo; the gate requires the command to have run, not rc 0).
got="$(run_case exit-nonzero en-shot)"
check "${got}" 'rc:0 png:yes' 'a nonzero exit of the exact command (diff-style) still publishes'

## 5. send-text itself FAILED (was swallowed by `|| true` before) -> DISCARD.
got="$(run_case send-fail sf-shot)"
check "${got}" 'rc:1 png:no' 'a failed send-text (submit error) is DISCARDED, not published'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' 'OK: the compat capture path gates the shot on the injected command actually running'
