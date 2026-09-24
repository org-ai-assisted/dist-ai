#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the COMPETITOR (emulator) comparison shots gained a fail-closed content verifier.
## capture_settled only rejects a fully BLANK frame, so a dropped keystroke that turned the injected
## `cat X.payload` into `at X.payload` -> `at: command not found` produced a NON-blank shell-error
## shot that published silently (this shipped broken st/alacritty/gnome/mate shots). The emulator
## shell (bash --rcfile .strc) now records, per completed command, a `command_not_found_handle`
## sentinel and the exit status; shots_cmd_ran_ok reads that log and the capture DISCARDS a shot
## whose injected command did not run cleanly.
##
## Two layers, both without a display or a real capture (milliseconds):
##   Part A -- shots_cmd_ran_ok verdicts on synthetic command-logs (the fail-closed classifier).
##   Part B -- the REAL .strc hooks extracted from comparison-capture.sh, driven through a live
##             `bash --rcfile`, so a drift between the hook log FORMAT and the classifier trips.
##
## FAILS on the old harness (shots_cmd_ran_ok did not exist; the hooks were absent), a real tripwire.
##
## Subjects: lib-capture.sh + comparison-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a
## checkout default, or the installed path. Absent -> exit 1 (FATAL): a required subject is an
## environment bug (R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

resolve() {  ## $1=basename -> absolute path under the shots dir, or empty
   local base cand
   base="$1"
   for cand in \
      "${SECURE_TERMINAL_SHOTS_DIR:-}/${base}" \
      "${script_dir}/../secure-terminal-shots/${base}" \
      "${script_dir}/../../share/secure-terminal-shots/${base}" \
      "/usr/share/secure-terminal-shots/${base}"; do
      if [ -n "${cand}" ] && [ -f "${cand}" ]; then
         readlink --canonicalize -- "${cand}"
         return 0
      fi
   done
   return 1
}

lib="$(resolve lib-capture.sh || true)"
cap="$(resolve comparison-capture.sh || true)"
if [ -z "${lib}" ] || [ -z "${cap}" ]; then
   printf '%s\n' 'FATAL: lib-capture.sh / comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

# shellcheck source=../secure-terminal-shots/lib-capture.sh
source "${lib}"

pass=0
fail=0
skip=0
eq() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3"
      printf '%s\n' "  got : $1"
      printf '%s\n' "  want: $2"
      fail=$(( fail + 1 ))
   fi
}

## shots_cmd_ran_ok MUST exist -- absent means the old harness (no competitor content verifier).
if ! declare -F shots_cmd_ran_ok >/dev/null 2>&1; then
   printf '%s\n' 'FAIL: shots_cmd_ran_ok not defined -- old harness'
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi

tmp="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${tmp}" 2>/dev/null || true; }
trap cleanup EXIT

EXP='cat escape.payload'   ## the expected injected command for the synthetic-log cases
verdict() {  ## $1=cmdlog-contents (printf %b)  [$2=expected-cmd, default EXP] -> 'ok' | 'fail'
   printf '%b' "$1" > "${tmp}/log"
   if shots_cmd_ran_ok "${tmp}/log" "${2-${EXP}}"; then printf 'ok'; else printf 'fail'; fi
}

## --- Part A: fail-closed classifier verdicts (log format RAN<TAB>rc<TAB>cmd) ---------

## The injected command ran and exited 0 -> publish.
eq "$(verdict 'RAN\t0\tcat escape.payload\n')" ok 'the exact injected command, rc 0, passes'

## A startup/empty-line entry before the real command does not block acceptance.
eq "$(verdict 'RAN\t0\t\nRAN\t0\tcat escape.payload\n')" ok 'a leading empty-command entry is ignored'

## Dropped keystroke -> command_not_found_handle fired -> DISCARD.
eq "$(verdict 'NOTFOUND\tat\nRAN\t127\tat escape.payload\n')" fail 'a not-found (dropped-keystroke) command is rejected'

## A not-found sentinel wins even if a later command exits 0 (fail-closed on any NOTFOUND).
eq "$(verdict 'NOTFOUND\tat\nRAN\t0\tcat escape.payload\n')" fail 'any NOTFOUND rejects the shot regardless of later rc'

## The injected command ran but FAILED (e.g. cat of a missing payload) -> DISCARD.
eq "$(verdict 'RAN\t1\tcat escape.payload\n')" fail 'a non-zero completion of the injected command is rejected'

## Dropped RETURN: the command was typed but never executed, so only a startup empty-command entry
## exists -- an rc-only check would wrongly accept this; requiring the command text rejects it.
eq "$(verdict 'RAN\t0\t\n')" fail 'a dropped-Return (empty-command-only) log is rejected'

## Empty injection (only Enter): two empty-command entries, no real command -> rejected.
eq "$(verdict 'RAN\t0\t\nRAN\t0\t\n')" fail 'an empty injection (no command) is rejected'

## A DIFFERENT command that happened to run cleanly is NOT the injected one -> rejected.
eq "$(verdict 'RAN\t0\tls\n')" fail 'a clean run of a different command is rejected'

## An unrecognized case yields an empty expected command; that must never be satisfiable.
eq "$(verdict 'RAN\t0\t\n' '')" fail 'an empty expected command is rejected (unrecognized case)'

## An empty log (nothing recorded) is a MISS, never a pass.
eq "$(verdict '')" fail 'an empty command-log is rejected (fail-closed)'

## A missing log file is a MISS.
if shots_cmd_ran_ok "${tmp}/does-not-exist" "${EXP}"; then
   eq ok fail 'a missing command-log file is a miss, not a pass'
else
   eq fail fail 'a missing command-log file is a miss, not a pass'
fi

## --- Part B: the REAL .strc hooks agree with the classifier (driven through a PTY) ----

## Extract the QUOTED-heredoc hook block written into .strc by comparison-capture.sh (reads the
## CURRENT script text -> no drift / no synthetic copy). The unquoted PS1 heredoc (`<<RC`) is NOT
## matched: the quote before RC (`<<'RC'`) is required.
strc="${tmp}/strc"
awk "/<<[[:punct:]]RC[[:punct:]]\$/{f=1;next} f&&/^RC\$/{f=0} f{print}" "${cap}" > "${strc}"
if ! grep --quiet 'command_not_found_handle' "${strc}" || ! grep --quiet "PROMPT_COMMAND='__shots_log'" "${strc}"; then
   printf '%s\n' 'FAIL: could not extract the .strc command-log hooks from comparison-capture.sh'
   fail=$(( fail + 1 ))
elif ! type -P script >/dev/null 2>&1; then
   # shellcheck disable=SC2016  # literal SKIP message; the backticked `script` is prose, not a substitution
   printf '%s\n' 'SKIP: util-linux `script` not available; live-hook PTY checks not exercised' >&2
   ## style-ok: allow-skip: Part B needs a PTY (util-linux `script`) to drive interactive bash faithfully; Part A fully covers the classifier
   skip=$(( skip + 1 ))
else
   home="${tmp}/home"
   mkdir --parents -- "${home}"
   printf '%s\n' 'hi' > "${home}/escape.payload"
   ## Drive the REAL hooks through a live interactive bash over a PTY (as the emulator does; fc /
   ## history behave as in production, unlike piped stdin), submitting one command line, then
   ## return the produced cmdlog path.
   run_shell() {  ## $1=command-line to submit -> the produced cmdlog contents
      local log
      log="${home}/.shots-cmdlog"
      printf '' > "${log}"
      printf '%b' "$1\nexit\n" | script --quiet --return --command \
         "cd '${home}'; SHOTS_CMDLOG='${log}' HOME='${home}' bash --rcfile '${strc}' -i" \
         /dev/null >/dev/null 2>&1 || true
      printf '%s' "${log}"
   }

   ## GOOD: the real `cat escape.payload` runs -> accepted for that exact command.
   if shots_cmd_ran_ok "$(run_shell 'cat escape.payload')" 'cat escape.payload'; then
      eq ok ok 'live hooks: a real cat is accepted'
   else
      eq fail ok 'live hooks: a real cat is accepted'
   fi

   ## BAD (the actual bug): the dropped-`c` `at escape.payload` is rejected for the expected cmd.
   if shots_cmd_ran_ok "$(run_shell 'at escape.payload')" 'cat escape.payload'; then
      eq ok fail 'live hooks: a dropped-keystroke command is rejected'
   else
      eq fail fail 'live hooks: a dropped-keystroke command is rejected'
   fi

   ## The command_not_found_handle WIRING itself: inject a GUARANTEED-missing command (independent
   ## of whether a real `at` binary is on PATH -- claude F2) and assert the NOTFOUND sentinel was
   ## actually written, not just that the aggregate verdict was reject.
   nf_log="$(run_shell 'st-nonexistent-cmd-zzq escape.payload')"
   if grep --quiet "^NOTFOUND$(printf '\t')" -- "${nf_log}"; then
      eq ok ok 'live hooks: command_not_found_handle writes the NOTFOUND sentinel'
   else
      eq fail ok 'live hooks: command_not_found_handle writes the NOTFOUND sentinel'
   fi
fi

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, ${skip} skip"
[ "${fail}" -eq 0 ]
