#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (behavioral): suite-parallel's RAM-aware job cap must subtract a headroom band
## before dividing, so an IDLE Qubes qube whose memory balloon reports an optimistic MemAvailable
## (not physically backed the instant several lanes allocate) does not OVER-COMMIT and corrupt /
## OOM-kill a lane. Drives run_suites_parallel with a FAKE /proc/meminfo (DIST_AI_MEMINFO_PATH) so
## the verdict is independent of the real box:
##   - ~1200 MiB free, 768 headroom pinned -> (1200-768)/512 = 0 -> floor 1 job;
##   - same free with headroom 0 -> 1200/512 = 2 jobs (proves the band is the lever);
##   - a large box -> no RAM clamp at all (CPU cap binds);
##   - the built-in defaults ARE 768 MiB headroom / 512 MiB per suite (levers unset).
## Every case pins its levers INLINE (an inline assignment overrides any ambient value for that one
## call) -- or, for the defaults probe, clears them in its own subshell -- so the verdict never
## depends on an inherited DIST_AI_SUITE_MEM_HEADROOM_MIB / DIST_AI_SUITE_MEM_MIB, with nothing
## global to unset.
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

## 1. A nonzero headroom band clamps: 768 subtracted from ~1200 free -> (1200-768)/512 = 0 -> 1.
## Assert the arithmetic INPUTS in the cap line (headroom + per-suite), not just the job count.
line="$( DIST_AI_SUITE_MEM_HEADROOM_MIB=768 DIST_AI_SUITE_MEM_MIB=512 DIST_AI_MEMINFO_PATH="${work}/meminfo-idle" cap_line )"
case "${line}" in *'768 MiB headroom / 512 MiB per suite -> 1 parallel jobs'*) ok=1 ;; *) ok='' ;; esac
check '768 MiB headroom clamps ~1200 MiB idle free to 1 parallel job (band subtracted before dividing)' "${ok}"

## 2. Same free, headroom 0 -> no band -> 1200/512 = 2 jobs. The contrast with case 1 is the lever.
line="$( DIST_AI_SUITE_MEM_HEADROOM_MIB=0 DIST_AI_SUITE_MEM_MIB=512 DIST_AI_MEMINFO_PATH="${work}/meminfo-idle" cap_line )"
case "${line}" in *'-> 2 parallel jobs'*) ok=1 ;; *) ok='' ;; esac
check 'the same free with headroom 0 caps to 2 jobs (proves the headroom band is the lever)' "${ok}"

## 3. A large box is never RAM-clamped even WITH the band (the CPU cap binds instead).
line="$( DIST_AI_SUITE_MEM_HEADROOM_MIB=768 DIST_AI_SUITE_MEM_MIB=512 DIST_AI_MEMINFO_PATH="${work}/meminfo-big" cap_line )"
if [ -z "${line}" ]; then ok=1; else ok=''; fi
check 'a large box (16 GiB free) is not RAM-clamped (CPU cap binds instead)' "${ok}"

## 4. The BUILT-IN defaults are 768 MiB headroom / 512 MiB per suite: the one case that must run
## with the levers ABSENT to observe the default, scoped to its own subshell so it clears nothing
## globally (a leaked ambient value inside the subshell is unset before cap_line runs).
line="$( unset -v DIST_AI_SUITE_MEM_HEADROOM_MIB DIST_AI_SUITE_MEM_MIB; DIST_AI_MEMINFO_PATH="${work}/meminfo-idle" cap_line )"
case "${line}" in *'768 MiB headroom / 512 MiB per suite -> 1 parallel jobs'*) ok=1 ;; *) ok='' ;; esac
check 'the built-in defaults are 768 MiB headroom / 512 MiB per suite (levers unset)' "${ok}"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: RAM-aware cap subtracts headroom (no idle-balloon over-commit)'
