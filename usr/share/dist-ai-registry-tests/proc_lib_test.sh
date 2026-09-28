#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: proc_dead (dist-ai-tests-common/proc-lib.bash) must count a ZOMBIE as DEAD, which is
## the whole reason the helper exists. A bare `kill -0` reports a killed-but-unreaped process as
## ALIVE; a test that polls with `kill -0` alone then flakes when an orphan lingers as a zombie
## under a slow-reaping CI PID 1. The CANARY below builds a real zombie and pins that proc_dead
## says dead WHERE `kill -0` says alive -- if that ever regresses, the flake is back.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
## usr/share/dist-ai-registry-tests -> repo root is three levels up (installed: '/').
repo="${DIST_AI_REPO:-${test_dir}/../../..}"
lib="${repo}/usr/share/dist-ai-tests-common/proc-lib.bash"
[ -r "${lib}" ] || { printf '%s\n' "FATAL: proc-lib.bash not found: ${lib}" >&2; exit 1; }
# shellcheck source=../dist-ai-tests-common/proc-lib.bash
. "${lib}"

failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; failures=$(( failures + 1 )); }

## 1. A live process is NOT dead.
sleep 30 &
live="$!"
if proc_dead "${live}"; then
   fail "proc_dead called a live process (pid ${live}) dead"
else
   pass 'proc_dead: a running process is alive'
fi
kill -KILL "${live}" 2>/dev/null || true
wait "${live}" 2>/dev/null || true

## 2. A gone pid IS dead.
sleep 0 &
gone="$!"
wait "${gone}" 2>/dev/null || true
if proc_dead "${gone}"; then
   pass 'proc_dead: a reaped/absent pid is dead'
else
   fail "proc_dead did not call an absent pid (${gone}) dead"
fi

## 3. CANARY: a real ZOMBIE (killed child its parent has not reaped) -- proc_dead MUST say dead
## exactly where `kill -0` still says alive. This is the flake the helper closes.
work="$(mktemp --directory)"
zcleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap zcleanup EXIT
zpid_file="${work}/zpid"
## Parent spawns a child, KILLS it, then sleeps WITHOUT reaping -> child is a zombie for ~4s.
## Quoted heredoc so the body expands when THIS parent runs (with $1 = the pid file), not now.
zparent_sh="${work}/zparent.sh"
cat > "${zparent_sh}" <<'ZEOF'
#!/bin/bash
sleep 300 &
echo "$!" > "$1"
kill -KILL "$(cat -- "$1")"
## exec (not a plain `sleep`): bash would reap its own background zombie during a builtin wait,
## so REPLACE bash with sleep -- /bin/sleep never wait()s, holding the zombie for the full 4s.
exec sleep 4
ZEOF
setsid bash "${zparent_sh}" "${zpid_file}" &
zparent="$!"
## Wait for the zombie to exist.
zombie=''
for _ in $(seq 1 50); do
   if [ -s "${zpid_file}" ]; then
      zombie="$(cat -- "${zpid_file}")"
      break
   fi
   sleep 0.1
done
if [ -z "${zombie}" ]; then
   fail 'canary setup: the zombie child never registered its pid'
else
   ## Give the parent a beat to KILL the child so it is a zombie, not still running.
   for _ in $(seq 1 30); do
      raw="$(cat -- "/proc/${zombie}/stat" 2>/dev/null || printf '')"
      state="${raw##*') '}"
      state="${state%% *}"
      [ "${state}" = 'Z' ] && break
      sleep 0.1
   done
   if [ "${state}" = 'Z' ]; then
      if kill -0 "${zombie}" 2>/dev/null && proc_dead "${zombie}"; then
         pass 'canary: proc_dead calls a zombie DEAD where kill -0 calls it alive'
      else
         k0='gone'
         if kill -0 "${zombie}" 2>/dev/null; then
            k0='alive'
         fi
         pd='alive'
         if proc_dead "${zombie}"; then
            pd='dead'
         fi
         fail "canary: on a zombie (pid ${zombie}) kill-0=${k0}, proc_dead=${pd}"
      fi
   else
      ## The kernel reaped it faster than we could observe Z (a fast PID 1) -- still a valid
      ## outcome: proc_dead must call it dead (it is gone).
      if proc_dead "${zombie}"; then
         pass 'canary: zombie already reaped; proc_dead calls it dead'
      else
         fail "canary: proc_dead did not call the (reaped) zombie ${zombie} dead"
      fi
   fi
fi
kill -KILL "${zparent}" 2>/dev/null || true
wait "${zparent}" 2>/dev/null || true

## 4. proc_diag prints a survivor's state to stderr and nothing for an absent pid.
sleep 30 &
surv="$!"
diag="$(proc_diag 'unit' "${surv}" 2>&1 || true)"
case "${diag}" in
   *"pid ${surv} SURVIVED"*)
      pass 'proc_diag: reports a survivor with its state'
      ;;
   *)
      fail "proc_diag did not report a live survivor: '${diag}'"
      ;;
esac
kill -KILL "${surv}" 2>/dev/null || true
wait "${surv}" 2>/dev/null || true
empty="$(proc_diag 'unit' "${surv}" 2>&1 || true)"
if [ -z "${empty}" ]; then
   pass 'proc_diag: silent for an absent pid'
else
   fail "proc_diag printed for an absent pid: '${empty}'"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: proc-lib.bash has ${failures} defect(s)" >&2
   exit 1
fi
printf '%s\n' 'OK: proc_dead treats a zombie as dead; proc_diag reports survivors'
