#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (functional): wl-headless-run's teardown must ESCALATE TERM->KILL on a command
## whose whole process group IGNORES SIGTERM, within a BOUND well under the outer
## `timeout --kill-after=30s` -- else the suite group leaks forever after the watchdog fires.
## The sibling wl_headless_signal_teardown_test uses a TERM-DEFERRING command (bash in `wait`
## + a default-disposition sleep), which both die on the plain TERM -- so it never exercises
## cleanup's `kill -KILL -- -group`. This test makes BOTH group members IGNORE TERM (a SIG_IGN
## disposition survives exec, so an exec'd sleep is reapable only by SIGKILL), so a passing run
## PROVES the bounded wait escalates to the group SIGKILL.
##
## Drives the REAL wl-headless-run with start/stop STUBBED (WL_HEADLESS_LIB), so the signal
## path runs with no live compositor. After SIGTERM, both members must be dead (group SIGKILL)
## and the script must exit non-zero in bounded time.
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-run (cleanup TERM->grace->KILL).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

run=''
for cand in \
   "${WL_HEADLESS_RUN:-}" \
   "${script_dir}/../dist-ai-tests-common/wl-headless-run" \
   '/usr/share/dist-ai-tests-common/wl-headless-run'; do
   if [ -n "${cand}" ] && [ -x "${cand}" ]; then
      run="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${run}" ]; then
   printf '%s\n' 'FATAL: wl-headless-run not found (set WL_HEADLESS_RUN)' >&2
   exit 1
fi

## Shared, zombie-aware liveness helpers (proc_dead / proc_diag) live beside wl-headless-run --
## a bare `kill -0` reports a killed-but-unreaped process as alive, the flake this closes.
proc_lib="$(dirname -- "${run}")/proc-lib.bash"
if [ ! -r "${proc_lib}" ]; then
   printf '%s\n' "FATAL: proc-lib.bash not found beside wl-headless-run: ${proc_lib}" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/proc-lib.bash
. "${proc_lib}"

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"; pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"; fail=$(( fail + 1 ))
   fi
}

work="$(mktemp --directory)"
cleanup() {
   ## Reap anything left: the SUBJECT is what should have reaped the tree, but a pre-fix
   ## (unescalated) run leaks the TERM-ignoring group, so reap it here too. Never fail on
   ## cleanup. The CHILD is the setsid group leader, so a group-kill on ITS pid reaps the
   ## whole group (child + grandchild). The grandchild is NOT a group leader -- a group-kill
   ## on its pid would hit an unrelated group on PID reuse, so reap it DIRECTLY by pid.
   if [ -f "${work}/child.pid" ]; then
      cpid="$(cat -- "${work}/child.pid" 2>/dev/null || true)"
      if [ -n "${cpid}" ]; then
         kill -KILL -- -"${cpid}" 2>/dev/null || true
      fi
   fi
   for f in "${work}/child.pid" "${work}/grandchild.pid"; do
      if [ -f "${f}" ]; then
         pid="$(cat -- "${f}" 2>/dev/null || true)"
         if [ -n "${pid}" ]; then
            kill -KILL "${pid}" 2>/dev/null || true
         fi
      fi
   done
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

## Stub lib: start/stop are no-ops, so wl-headless-run reaches its setsid+wait+trap path
## with no real labwc. Only these two symbols are needed by wl-headless-run.
stub_lib="${work}/wl-headless-lib.bash"
{
   printf '%s\n' '# stub for wl_headless_group_sigkill_escalation_test'
   printf '%s\n' 'wl_headless_start() { : ; }'
   printf '%s\n' 'wl_headless_stop() { : ; }'
} > "${stub_lib}"

## The command, as a script to avoid nested-quoting hell. BOTH members IGNORE SIGTERM:
## `trap "" TERM` then `exec sleep` -- the SIG_IGN disposition survives exec, so the sleep
## cannot be killed by SIGTERM, only by SIGKILL. The child records its own pid, spawns a
## likewise-TERM-ignoring grandchild, signals readiness, then becomes an unkillable-by-TERM
## sleep itself. If cleanup escalates to the group SIGKILL, BOTH die; if it stops at TERM +
## an unescalated wait, BOTH leak.
##
## Overall readiness (the gate for the test's TERM) is signaled ONLY after the grandchild has
## installed its OWN trap (gc-ready handshake). Signaling it right after the fork would leave a
## window where the grandchild still has the DEFAULT TERM disposition, so a broken runner's plain
## group-TERM could kill it before escalation -- and the test would FALSE-PASS the escalation check.
ready="${work}/ready"
victim="${work}/victim.sh"
cat > "${victim}" <<EOF
#!/bin/bash
trap '' TERM
echo "\$\$" > "${work}/child.pid"
bash -c 'trap "" TERM; : > "${work}/gc-ready"; exec sleep 300' &
echo "\$!" > "${work}/grandchild.pid"
for _ in \$(seq 1 50); do [ -e "${work}/gc-ready" ] && break; sleep 0.1; done
: > "${ready}"
exec sleep 300
EOF
chmod 0755 -- "${victim}"

WL_HEADLESS_LIB="${stub_lib}" "${run}" --no-autoconfirm -- bash "${victim}" &
runner="$!"

for _ in $(seq 1 50); do
   [ -e "${ready}" ] && break
   sleep 0.1
done
if [ ! -e "${ready}" ]; then
   printf '%s\n' 'FATAL: command never signalled readiness' >&2
   kill -KILL "${runner}" 2>/dev/null || true
   exit 1
fi
child="$(cat -- "${work}/child.pid")"
grandchild="$(cat -- "${work}/grandchild.pid")"

## Bound the test: if the fix regresses and the group is never SIGKILLed, this watchdog
## SIGKILLs the whole group (not just the runner script) so the test itself cannot hang,
## and reports the leak via the elapsed/liveness assertions below.
( sleep 20; kill -KILL -- -"${child}" 2>/dev/null || true ) &
watchdog="$!"

start="${SECONDS}"
kill -TERM "${runner}" 2>/dev/null || true
wait "${runner}" 2>/dev/null && rc=0 || rc="$?"
elapsed="$(( SECONDS - start ))"

kill "${watchdog}" 2>/dev/null || true
wait "${watchdog}" 2>/dev/null || true

## Poll for the whole TERM-ignoring group to die (bounded): cleanup sends group TERM (ignored),
## waits a brief grace, then escalates to group SIGKILL. proc_dead (from proc-lib.bash) counts a
## killed-but-unreaped zombie as dead; a genuine survivor (state R/S/D) still fails the poll.
child_dead=''
gc_dead=''
for _ in $(seq 1 45); do
   proc_dead "${child}" && child_dead='1'
   proc_dead "${grandchild}" && gc_dead='1'
   [ -n "${child_dead}" ] && [ -n "${gc_dead}" ] && break
   sleep 0.2
done

[ -z "${child_dead}" ] && proc_diag 'child' "${child}"
[ -z "${gc_dead}" ] && proc_diag 'grandchild' "${grandchild}"

check "SIGKILL-escalation reaps the TERM-ignoring command child (pid ${child})" "${child_dead}"
check "SIGKILL-escalation reaps the TERM-ignoring GRANDCHILD too (whole group, pid ${grandchild})" "${gc_dead}"
check "wl-headless-run exits non-zero on SIGTERM (rc=${rc})" \
   "$( [ "${rc}" -ne 0 ] && printf '1' )"
## The escalation bound (~2s) must be well under the callers' outer --kill-after=30s.
check "teardown escalates in bounded time, not hung (elapsed=${elapsed}s < 15)" \
   "$( [ "${elapsed}" -lt 15 ] && printf '1' )"

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
