#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block would leak
## set -o errexit/nounset into the consumer (every caller already sets it).

## Single source for running a LIST of test-suite files IN PARALLEL, each under its OWN
## headless-Wayland compositor. SOURCE this file; it defines run_suites_parallel and sets
## nothing on load. Both the plain runner (secure-terminal-tests) and the coverage runner
## (secure-terminal-tests-coverage) dispatch through it, so the throttle + job-cap + the
## concurrent-.pyc-write defense live in one place, not copied per runner.
##
## Why parallel + per-suite compositor: the Qt suites run under a REAL labwc (software
## pixman render), which is far slower than the retired offscreen platform -- a sequential
## sweep of ~two dozen suites overruns any single per-suite CI timeout. A shared compositor
## cannot be reused across parallel suites (its wayland socket lives in its own runtime dir,
## which each suite would override -> "Failed to create wl_display", and the single-instance
## socket namespace would collide), so each suite mints its OWN compositor (own XDG_RUNTIME_DIR,
## own single-instance socket namespace). Wall-clock drops toward the slowest single suite.

## run_suites_parallel <work> <pkg|''> <jobs_override|''> <suite_runner_fn> <suite_path>...
##
##   work            caller's mktemp work dir (the caller owns its EXIT-trap cleanup). Per-suite
##                   stdout+stderr lands in <work>/out-<key> and the suite's exit status in
##                   <work>/rc-<key>, where <key> is the suite's basename without .py. The
##                   caller reads the rc-<key> files AFTER this returns and applies its own
##                   pass/skip/fail policy; a MISSING rc-<key> (a job killed before it recorded
##                   one) is the caller's to treat as failure (fail-closed).
##   pkg             package dir to pre-compile once, single-process, into a private bytecode
##                   cache so the parallel suites never race to write the same __pycache__/*.pyc
##                   (a half-written .pyc reads back as subtly wrong bytecode). '' skips it.
##   jobs_override   caller-resolved concurrency override (its own env knob), or '' for auto.
##                   Auto = nproc. Either way clamped to [1, 4*ncpu] and then to a RAM-aware
##                   ceiling (each parallel suite runs its own labwc + Python, ~400MB; capped
##                   by floor(MemAvailable / 512MiB) so a tight/ballooned box does not OOM-kill
##                   a suite mid-run, exit 137 -- a false red that is not a test verdict).
##   suite_runner_fn a shell FUNCTION NAME taking one suite path, running it under its OWN
##                   wl-headless-run, and returning the suite's exit status. It must not write
##                   the rc/out files itself -- this helper captures them. The helper isolates
##                   XDG_CONFIG_HOME/XDG_STATE_HOME per suite (clean defaults, no cross-suite
##                   collision) but leaves XDG_RUNTIME_DIR unset: the runner fn's wl-headless-run
##                   mints (and tears down) a private runtime dir per suite.
##   suite_path...   suite .py paths, in the canonical order their output is replayed.
##
## Output is buffered per suite and replayed in the given order after the barrier, so the log
## stays deterministic regardless of finish order. Suites whose file is absent are skipped
## (no rc-<key> written) -- the caller's `[ -f ... ] || continue` mirrors that.
run_suites_parallel() {
   local work="$1" pkg="$2" jobs_override="$3" suite_runner_fn="$4"
   shift 4
   local suites=("$@")

   ## Concurrency: auto-detect cores (nproc), overridable by the caller's resolved value.
   local ncpu jobs suite_cap
   ncpu="$(nproc 2>/dev/null || printf '%s\n' 2)"
   case "${ncpu}" in ''|*[!0-9]*) ncpu=2 ;; esac
   ncpu="$(( 10#${ncpu} ))"
   [ "${ncpu}" -ge 1 ] || ncpu=2
   jobs="${jobs_override}"
   case "${jobs}" in ''|*[!0-9]*) jobs="${ncpu}" ;; esac
   ## Base-10: a leading-zero all-digit value (e.g. 09) is a valid string but an invalid
   ## octal literal, which would abort the [ -ge ] test under errexit.
   jobs="$(( 10#${jobs} ))"
   [ "${jobs}" -ge 1 ] || jobs="${ncpu}"
   ## Upper clamp: a pathological override (e.g. a 20-digit value) survives >=1 and, since
   ## the throttle only fires at the job count, would launch every suite (and its labwc) at
   ## once and thrash the box. Cap at 4x cores (headroom for the I/O-bound Qt suites).
   suite_cap="$(( ncpu * 4 ))"
   [ "${jobs}" -le "${suite_cap}" ] || jobs="${suite_cap}"

   ## RAM-aware ceiling. N parallel suites need N * ~400MB (labwc + Python each); above free
   ## memory the OOM-killer SIGKILLs one mid-run (exit 137), a false red. Cap by
   ## floor(MemAvailable / 512MiB) -- MemAvailable (free right now) is conservative exactly when
   ## memory is scarce and accurate when it is not; 512MiB sits above the measured ~400MB.
   ## DIST_AI_SUITE_MEM_MIB overrides the per-suite footprint (tuning/tests). Floor of 1 so a
   ## very tight box still runs, serially.
   local mem_per_suite_mib mem_avail_kib mem_jobs
   mem_per_suite_mib="${DIST_AI_SUITE_MEM_MIB:-512}"
   case "${mem_per_suite_mib}" in ''|*[!0-9]*) mem_per_suite_mib=512 ;; esac
   mem_per_suite_mib="$(( 10#${mem_per_suite_mib} ))"
   [ "${mem_per_suite_mib}" -ge 1 ] || mem_per_suite_mib=512
   mem_avail_kib="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo 2>/dev/null || printf '%s\n' 0)"
   case "${mem_avail_kib}" in ''|*[!0-9]*) mem_avail_kib=0 ;; esac
   mem_avail_kib="$(( 10#${mem_avail_kib} ))"
   if [ "${mem_avail_kib}" -gt 0 ]; then
      mem_jobs="$(( mem_avail_kib / 1024 / mem_per_suite_mib ))"
      [ "${mem_jobs}" -ge 1 ] || mem_jobs=1
      if [ "${jobs}" -gt "${mem_jobs}" ]; then
         printf '%s\n' "run_suites_parallel: RAM-aware cap: $(( mem_avail_kib / 1024 )) MiB free / ${mem_per_suite_mib} MiB per suite -> ${mem_jobs} parallel jobs (from ${jobs})" >&2
         jobs="${mem_jobs}"
      fi
   fi

   ## Concurrent-.pyc-write defense (skipped when pkg is empty). Pre-compile the package once,
   ## single-process, into a private cache OUTSIDE the source tree, then forbid the suite
   ## processes from writing bytecode at all -- they only read, so no write can race even on an
   ## mtime edge. compileall MUST precede the DONTWRITEBYTECODE export or it would honour it and
   ## skip populating the cache. (Also keeps a sudo-run gate from leaving root-owned .pyc in the
   ## checkout that a later non-root sync cannot purge.)
   if [ -n "${pkg}" ]; then
      export PYTHONPYCACHEPREFIX="${work}/pycache"
      python3 -m compileall -q "${pkg}" >/dev/null 2>&1 || true
      export PYTHONDONTWRITEBYTECODE=1
   fi

   ## Run one suite: isolate its XDG config/state, capture combined output + rc to files, and
   ## always RETURN 0 so the backgrounded job never trips the caller's errexit via wait -- the
   ## rc is judged from the file after the barrier. Guard the mkdir inside an if (exempt from
   ## errexit): a mkdir failure records a FAILING rc rather than aborting the job before it
   ## writes rc-<key> (an abort would make the throttling `wait -n` inherit the failure and kill
   ## the whole run, and the caller's EXIT trap would wipe the shared work dir out from under the
   ## still-running suites).
   _run_suites_parallel_one() {  ## $1 = suite .py path
      local suite="$1" key rc=0 xdg
      key="$(basename -- "${suite}" .py)"
      xdg="${work}/xdg-${key}"
      if mkdir -p "${xdg}/config" "${xdg}/state"; then
         XDG_CONFIG_HOME="${xdg}/config" XDG_STATE_HOME="${xdg}/state" \
            "${suite_runner_fn}" "${suite}" > "${work}/out-${key}" 2>&1 || rc="$?"
      else
         rc=1
      fi
      printf '%s\n' "${rc}" > "${work}/rc-${key}"
   }

   local running=0 suite
   for suite in "${suites[@]}"; do
      [ -f "${suite}" ] || continue
      _run_suites_parallel_one "${suite}" &
      running=$(( running + 1 ))
      if [ "${running}" -ge "${jobs}" ]; then
         wait -n
         running=$(( running - 1 ))
      fi
   done
   wait

   ## Replay each suite's captured output in canonical order; leave rc-<key> for the caller.
   local key
   for suite in "${suites[@]}"; do
      [ -f "${suite}" ] || continue
      key="$(basename -- "${suite}" .py)"
      [ -f "${work}/out-${key}" ] && cat -- "${work}/out-${key}"
   done
}
