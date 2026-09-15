#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY: the shots harness must reap a run's leaked process groups by that run's
## UNIQUE marker and NOTHING ELSE. Spawns one dummy process group carrying the marker and one
## WITHOUT it (each in its own session), runs the REAL shots_reap_run, and asserts ONLY the
## marked group died -- a too-broad kill would take the unmarked one too. Also asserts the
## safe-pgrep/safe-pkill HARD-FAIL: with the wrappers off PATH, shots_require_safe_ps refuses
## rather than falling back to a bare (self-matching / cross-session) pgrep/pkill.
##
## This FAILS on the old harness (no shots_reap_run / shots_require_safe_ps at all), so it is a
## genuine regression test, not a tautology.
##
## Subject: lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a checkout default, or the
## installed path. Absent -> exit 1 (FATAL): a required subject is an environment bug (R-220). Spawns + kills processes, so run it in
## the sandbox (it only ever touches its OWN uniquely-marked dummies).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: lib-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

# shellcheck source=../secure-terminal-shots/lib-capture.sh
source "${lib}"

## The real safe wrappers are a REQUIRED dependency of the reaper; absent -> exit 1 (FATAL, R-220).
if ! type -P safe-pgrep >/dev/null 2>&1 || ! type -P safe-pkill >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: safe-pgrep/safe-pkill not on PATH (provision private-ai-config)' >&2
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

## unique per-run marker; nothing else on the system carries it.
marker="SHOTS-CANARY-$$-${RANDOM}${RANDOM}${RANDOM}"
marked_pid=''
unmarked_pid=''

cleanup() {
   ## belt-and-suspenders: reap the marked group + kill the unmarked dummy, whatever happened.
   [ -n "${marked_pid}" ] && kill -s KILL "-${marked_pid}" 2>/dev/null || true
   [ -n "${unmarked_pid}" ] && kill -s KILL "-${unmarked_pid}" 2>/dev/null || true
}
trap cleanup EXIT

## The harness API MUST exist -- absent means the old, leaky harness (regression tripwire).
if ! declare -F shots_reap_run >/dev/null 2>&1 || ! declare -F shots_require_safe_ps >/dev/null 2>&1; then
   printf '%s\n' 'FAIL: shots_reap_run / shots_require_safe_ps not defined -- old harness has no marker-scoped reaper'
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi

## MARKED dummy: a bash whose argv carries the marker (the `; true` keeps bash from exec-
## optimizing sleep away, so the marker stays in argv), in its OWN session. Its child sleep
## shares the group, so reaping the group must take BOTH down.
setsid bash -c 'sleep 300; true' "${marker}" &
marked_pid="$!"
## UNMARKED control: a plain sleep in its OWN session, no marker in argv.
setsid sleep 300 &
unmarked_pid="$!"
sleep 0.7   ## let argv/cmdline settle

## sanity: safe-pgrep finds the marked one and NOT the unmarked one.
if safe-pgrep --full -- "${marker}" >/dev/null 2>&1; then
   check found found 'safe-pgrep finds the marked group by its unique marker'
else
   check notfound found 'safe-pgrep finds the marked group by its unique marker'
   ## CI-env diagnostic: this test passes in every reproducible env (sandbox user/root,
   ## ubuntu container, runuser as a fresh build user), so a miss is a runner-specific
   ## process-model quirk. Dump the facts needed to pin it: whether RAW pgrep sees it (vs
   ## the safe-pgrep wrapper's is_own_descendant filter), the process state/ppid/tracer/uid/
   ## cmdline, and the marked pid's ancestry (what is_own_descendant walks).
   {
      printf -- '--- reap_run_test CI diag (safe-pgrep MISS) ---\n'
      printf 'whoami=%s uid=%s test_pid=%s procps=[%s]\n' \
         "$(whoami 2>/dev/null || true)" "$(id -u)" "$$" "$(pgrep --version 2>&1 | head -1)"
      printf 'marker=%s marked_pid=%s unmarked_pid=%s\n' "${marker}" "${marked_pid}" "${unmarked_pid}"
      printf 'raw pgrep --full: [%s]\n' "$(pgrep --full -- "${marker}" 2>&1 | tr '\n' ' ' || true)"
      printf 'raw pgrep -f: [%s]\n' "$(pgrep -f "${marker}" 2>&1 | tr '\n' ' ' || true)"
      for _p in "${marked_pid}" "${unmarked_pid}"; do
         if [ -r "/proc/${_p}/status" ]; then
            printf 'pid %s: state=[%s] ppid=%s tracer=%s uid=[%s] cmd=[%s]\n' "${_p}" \
               "$(sed -n 's/^State:[[:space:]]*//p' "/proc/${_p}/status" || true)" \
               "$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/${_p}/status" || true)" \
               "$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/${_p}/status" || true)" \
               "$(sed -n 's/^Uid:[[:space:]]*//p' "/proc/${_p}/status" || true)" \
               "$(tr '\0' ' ' < "/proc/${_p}/cmdline" 2>/dev/null || true)"
         else
            printf 'pid %s: /proc/%s/status unreadable\n' "${_p}" "${_p}"
         fi
      done
      printf 'marked_pid ancestry (child<-...<-root): '
      _a="${marked_pid}"
      while [ -n "${_a}" ] && [ "${_a}" != '0' ] && [ "${_a}" != '1' ]; do
         printf '%s<-' "${_a}"
         _a="$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/${_a}/status" 2>/dev/null || true)"
      done
      printf '%s\n' "${_a:-END}"
      ## The smoking gun: trace the wrapper so we see its protected set + why it drops the pid.
      ## 2>&1 >/dev/null routes the -x trace (stderr) to the pipe, the wrapper's stdout to null.
      printf 'wrapper -x trace (tail):\n'
      bash -x -- "$(type -P safe-pgrep)" --full -- "${marker}" 2>&1 >/dev/null \
         | sed 's/^/  x /' | tail -45 || true
      printf -- '--- end diag ---\n'
   } >&2
fi

## the reap under test.
shots_reap_run "${marker}"
sleep 1

## marked group gone?
if kill -0 "${marked_pid}" 2>/dev/null; then
   check alive dead 'reap_run killed the MARKED group'
else
   check dead dead 'reap_run killed the MARKED group'
fi
## unmarked survivor still there? (a too-broad kill would have taken it too)
if kill -0 "${unmarked_pid}" 2>/dev/null; then
   check alive alive 'reap_run left the UNMARKED process alive'
else
   check dead alive 'reap_run left the UNMARKED process alive'
fi

## HARD-FAIL path: with the safe wrappers off PATH, require_safe_ps refuses (no fallback).
## require_safe_ps uses only shell builtins (command -v / printf), so an empty PATH is safe.
rc=0
PATH=/var/empty shots_require_safe_ps >/dev/null 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
   check hardfail hardfail 'shots_require_safe_ps hard-fails when safe-pgrep/pkill are absent'
else
   check ok hardfail 'shots_require_safe_ps hard-fails when safe-pgrep/pkill are absent'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: reap_run marker-scoped reaping'
