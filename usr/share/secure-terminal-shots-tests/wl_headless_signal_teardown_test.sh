#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (functional): wl-headless-run must TEAR DOWN its command's whole process
## group on SIGTERM, so the per-suite wedge watchdog (`timeout` in secure-terminal-tests)
## kills a hung suite AND every child shell/pty it spawned -- not just the script, leaving
## orphans that thrash the shared box. Pre-fix, wl-headless-run ran the command in the
## FOREGROUND with only an EXIT-trap teardown of labwc, so a SIGTERM to the script left the
## command tree running (the exact 30-min wedge + zsh-orphan leak this closes).
##
## Drives the REAL wl-headless-run with start/stop STUBBED (WL_HEADLESS_LIB), so the signal
## path is exercised with no live compositor. The command is a shell that spawns a
## GRANDCHILD, records both pids, then blocks; after SIGTERM both must be dead (group-kill)
## and the script must exit non-zero in bounded time.
##
## Subject: usr/share/dist-ai-tests-common/wl-headless-run (setsid child + TERM/INT trap).

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
   ## Reap anything the test itself left (belt-and-braces; the SUBJECT is what should
   ## have reaped the tree). Never fail the test on cleanup.
   for f in "${work}/child.pid" "${work}/grandchild.pid"; do
      if [ -f "${f}" ]; then
         kill -KILL "$(cat -- "${f}" 2>/dev/null)" 2>/dev/null || true
      fi
   done
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

## Stub lib: start/stop are no-ops, so wl-headless-run reaches its setsid+wait+trap path
## with no real labwc. Only these two symbols are needed by wl-headless-run.
stub_lib="${work}/wl-headless-lib.bash"
{
   printf '%s\n' '# stub for wl_headless_signal_teardown_test'
   printf '%s\n' 'wl_headless_start() { : ; }'
   printf '%s\n' 'wl_headless_stop() { : ; }'
} > "${stub_lib}"

ready="${work}/ready"
## The command: record own pid (the child wl-headless-run runs), spawn a grandchild sleep
## and record ITS pid, signal readiness, then block. If wl-headless-run group-kills on
## SIGTERM, BOTH die; pre-fix, both survive the SIGTERM sent to the script.
WL_HEADLESS_LIB="${stub_lib}" "${run}" --no-autoconfirm -- \
   bash -c 'echo "$$" > "'"${work}"'/child.pid"; sleep 300 & echo "$!" > "'"${work}"'/grandchild.pid"; : > "'"${ready}"'"; wait' &
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

## Bound the test: if the fix regresses and the runner never exits on SIGTERM, this watchdog
## SIGKILLs it so the test cannot itself hang.
( sleep 20; kill -KILL "${runner}" 2>/dev/null || true ) &
watchdog="$!"

start="${SECONDS}"
kill -TERM "${runner}" 2>/dev/null || true
wait "${runner}" 2>/dev/null && rc=0 || rc="$?"
elapsed="$(( SECONDS - start ))"

kill "${watchdog}" 2>/dev/null || true
wait "${watchdog}" 2>/dev/null || true

## Poll for the whole tree to die (bounded): the teardown sends SIGTERM, then after a brief
## grace escalates to SIGKILL, so a TERM-deferring child (bash in `wait`) dies a beat later.
## A single fixed sleep raced this on a slow CI runner; poll up to ~9s instead. A genuine
## orphan (never reaped) still fails -- the poll times out with the pid alive.
child_dead=''
gc_dead=''
for _ in $(seq 1 45); do
   kill -0 "${child}" 2>/dev/null || child_dead='1'
   kill -0 "${grandchild}" 2>/dev/null || gc_dead='1'
   [ -n "${child_dead}" ] && [ -n "${gc_dead}" ] && break
   sleep 0.2
done

check "SIGTERM reaps the command child (pid ${child})" "${child_dead}"
check "SIGTERM reaps the GRANDCHILD too (whole process group, pid ${grandchild})" "${gc_dead}"
check "wl-headless-run exits non-zero on SIGTERM (rc=${rc})" \
   "$( [ "${rc}" -ne 0 ] && printf '1' )"
check "teardown is bounded, not hung (elapsed=${elapsed}s < 15)" \
   "$( [ "${elapsed}" -lt 15 ] && printf '1' )"

printf '%s\n' ''
printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
