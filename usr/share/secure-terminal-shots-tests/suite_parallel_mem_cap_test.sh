#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (behavioral): suite-parallel's RAM-aware job cap must subtract a headroom band
## before dividing, so an IDLE Qubes qube whose memory balloon reports an optimistic MemAvailable
## (not physically backed the instant several lanes allocate) does not OVER-COMMIT and corrupt /
## OOM-kill a lane. Drives run_suites_parallel with a FAKE /proc/meminfo (DIST_AI_MEMINFO_PATH) so
## the verdict is independent of the real box:
##   - idle ~1200 MiB free, default 768 headroom -> (1200-768)/512 = 0 -> floor 1 job;
##   - same free with headroom 0 -> 1200/512 = 2 jobs (proves the band is the lever);
##   - a large box -> no RAM clamp at all (CPU cap binds).
## Canary: old code reads /proc/meminfo directly (ignores DIST_AI_MEMINFO_PATH) and has no
## headroom, so none of these assertions hold on it.
##
## Subject: usr/share/dist-ai-tests-common/suite-parallel.bash (override SUITE_PARALLEL_LIB).

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
   "${SUITE_PARALLEL_LIB:-}" \
   "${script_dir}/../dist-ai-tests-common/suite-parallel.bash" \
   '/usr/share/dist-ai-tests-common/suite-parallel.bash'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: suite-parallel.bash not found (set SUITE_PARALLEL_LIB)' >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/suite-parallel.bash
source "${lib}"

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

## Fake meminfo sources.
{
   printf '%s\n' 'MemTotal:        1310720 kB'
   printf '%s\n' 'MemAvailable:    1228800 kB'
} > "${work}/meminfo-idle"    ## ~1200 MiB free
{
   printf '%s\n' 'MemTotal:       16777216 kB'
   printf '%s\n' 'MemAvailable:   16777216 kB'
} > "${work}/meminfo-big"     ## 16384 MiB free

## Three trivial suites + a no-op runner; a high jobs override so the RAM cap always decides.
touch -- "${work}/s1.py" "${work}/s2.py" "${work}/s3.py"
noop_runner() { return 0; }

## Echo only the RAM-aware cap line from stderr (empty if none printed).
cap_line() {
   run_suites_parallel "${work}" '' 8 noop_runner \
      "${work}/s1.py" "${work}/s2.py" "${work}/s3.py" 2>&1 1>/dev/null | grep 'RAM-aware cap' || true
}

pass=0
fail=0
check() {  ## $1=label $2=ok?(non-empty=pass)
   if [ -n "$2" ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"
      fail=$(( fail + 1 ))
   fi
}

## 1. idle + default headroom -> 1 job.
line="$( DIST_AI_MEMINFO_PATH="${work}/meminfo-idle" cap_line )"
case "${line}" in *'-> 1 parallel jobs'*) ok=1 ;; *) ok='' ;; esac
check 'idle-ballooned free (~1200 MiB) with default 768 headroom caps to 1 parallel job' "${ok}"

## 2. idle + headroom 0 -> 2 jobs (the band is the lever).
line="$( DIST_AI_SUITE_MEM_HEADROOM_MIB=0 DIST_AI_MEMINFO_PATH="${work}/meminfo-idle" cap_line )"
case "${line}" in *'-> 2 parallel jobs'*) ok=1 ;; *) ok='' ;; esac
check 'same free with headroom 0 caps to 2 jobs (proves the headroom band is the lever)' "${ok}"

## 3. large box -> no RAM clamp.
line="$( DIST_AI_MEMINFO_PATH="${work}/meminfo-big" cap_line )"
if [ -z "${line}" ]; then ok=1; else ok=''; fi
check 'a large box (16 GiB free) is not RAM-clamped (CPU cap binds instead)' "${ok}"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: RAM-aware cap subtracts headroom (no idle-balloon over-commit)'
