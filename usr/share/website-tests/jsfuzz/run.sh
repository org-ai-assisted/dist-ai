#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- runs INSIDE the confined sandbox workdir; does not source helper-scripts.

## Confined JS property/fuzz gate with TWO sub-gates over the modules in fuzzed.txt, invoked by
## webcheck-jsfuzz-sandbox (cwd = the synced workdir). fast-check + jsdom + c8 are global (provision
## jstest), so put the global node_modules on the require path.
##
##   1. COVERAGE sub-gate -- DETERMINISTIC: the *.fuzz.js run under c8 with a FIXED fast-check seed
##      and REQUIRE 100% statements/branches/functions/lines over exactly fuzzed.txt. Reproducible,
##      so it never flakes in the auto-merge repo. `c8 --all` is MANDATORY (an included-but-
##      unexercised module shows 0% and FAILs, not silently absent) -- same rationale as jscov.
##   2. INVARIANTS sub-gate -- the same *.fuzz.js re-run with JSFUZZ_MODE=invariants and NO coverage
##      threshold, to explore for a counterexample (no uncaught throw, no prototype pollution,
##      sanitizer holds). A red here is a genuine finding, never flake. TWO tiers of property, by
##      cost: the cheap VALUE-level properties written via fuzz-harness's fuzz() helper (e.g.
##      analyzer) honor the mode -- FRESH random seed + more runs -- and do the real exploration;
##      the DOM-per-run properties (a jsdom window per case) use a bounded FIXED seed in both modes,
##      because high run counts OOM jsdom -- they are deterministic adversarial corpora, not random
##      exploration. Both tiers assert real invariants; only the value-level tier rotates the seed.
##
## A fail-closed self-check (jsfuzz-selftest/) runs BOTH sub-gates first and REQUIRES each to FAIL
## as designed (coverage: an unexercised include at 0%; invariants: a deliberately-false property's
## counterexample) -- so neither sub-gate can silently regress to vacuous.
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

NODE_PATH="$(npm root -g)"
export NODE_PATH

## Build the c8 --include list from a fuzzed-set file (plain relative paths, each must exist --
## same validation + rationale as jscov's run_gate). Echoes the --include args, one per line.
build_includes(){
   local fuzzed_file="$1" line
   local -a includes=()
   while IFS= read -r line || [ -n "${line}" ]; do
      if [ -z "${line}" ] || [ "${line#\#}" != "${line}" ]; then
         continue
      fi
      case "${line}" in
         *[!A-Za-z0-9._/-]* | /* | ./* | */./* | *..* )
            printf '%s\n' "jsfuzz: FATAL: fuzzed entry is not a plain relative path: ${line} (in ${fuzzed_file})" >&2
            return 1
            ;;
      esac
      if [ ! -f "${line}" ]; then
         printf '%s\n' "jsfuzz: FATAL: fuzzed file not found: ${line} (in ${fuzzed_file}) -- a missing/mistyped entry would pass the coverage gate vacuously" >&2
         return 1
      fi
      includes+=( "--include" "${line}" )
   done < "${fuzzed_file}"
   if [ "${#includes[@]}" -eq 0 ]; then
      printf '%s\n' "jsfuzz: FATAL: ${fuzzed_file} lists no files -- the coverage gate would vacuously pass" >&2
      return 1
   fi
   printf '%s\n' "${includes[@]}"
}

## COVERAGE sub-gate: 100% over <fuzzed-file> executing <test-glob> with a FIXED seed. Returns c8's
## exit code. See jscov/run.sh for the --all / --config / node-22-glob rationale (shared config).
run_coverage(){
   local fuzzed_file="$1" test_glob="$2"
   local -a includes=()
   mapfile -t includes < <(build_includes "${fuzzed_file}")
   [ "${#includes[@]}" -gt 0 ] || return 1
   JSFUZZ_MODE=coverage c8 --config jsfuzz/c8-config.json --all --check-coverage \
      --statements 100 --branches 100 --functions 100 --lines 100 \
      "${includes[@]}" --reporter text-summary \
      node --test "${test_glob}"
}

## INVARIANTS sub-gate: the fuzz properties under a FRESH random seed + more runs, NO coverage.
run_invariants(){
   local test_glob="$1"
   JSFUZZ_MODE=invariants node --test "${test_glob}"
}

## --- fail-closed self-check: each sub-gate MUST catch its failure class ---
if [ ! -f jsfuzz-selftest/fuzzed.txt ] || [ ! -f jsfuzz-selftest/a.js ] || [ ! -f jsfuzz-selftest/b.js ]; then
   printf '%s\n' 'jsfuzz: FATAL: jsfuzz-selftest fixture incomplete (fuzzed.txt/a.js/b.js) -- cannot self-verify the gates are non-vacuous' >&2
   exit 1
fi

## (1) COVERAGE non-vacuity: the fixture lists a.js + b.js but cov.fuzz.js exercises only a.js;
## under --all, b.js at 0% MUST drop coverage below 100% and FAIL. A PASS means --all is
## missing/ineffective and the real coverage gate would be vacuous.
selfcov_rc=0
selfcov_out="$(run_coverage jsfuzz-selftest/fuzzed.txt 'jsfuzz-selftest/cov.fuzz.js' 2>&1)" || selfcov_rc="$?"
if [ "${selfcov_rc}" = '0' ]; then
   printf '%s\n' 'jsfuzz: FATAL: coverage self-check PASSED but MUST FAIL -- an unexercised fuzzed file was not caught (c8 --all missing/ineffective). Refusing a false green.' >&2
   exit 1
fi
if [ "${selfcov_out#*does not meet global threshold}" = "${selfcov_out}" ]; then
   printf '%s\n' 'jsfuzz: FATAL: coverage self-check failed for the WRONG reason (no c8 threshold failure) -- did not prove --all. Output:' >&2
   printf '%s\n' "${selfcov_out}" >&2
   exit 1
fi
if [ -n "${selfcov_out##*# pass [1-9]*}" ]; then
   printf '%s\n' 'jsfuzz: FATAL: coverage self-check hit the threshold with NO passing test -- the node --test glob matched zero files, a false signal. Output:' >&2
   printf '%s\n' "${selfcov_out}" >&2
   exit 1
fi

## (2) INVARIANTS non-vacuity: inv.fuzz.js asserts a deliberately-false property; the invariants
## sub-gate MUST find a counterexample and FAIL. A PASS means fast-check is not actually asserting
## (e.g. a swallowed property), so the real invariants gate would be vacuous.
selfinv_rc=0
selfinv_out="$(run_invariants 'jsfuzz-selftest/inv.fuzz.js' 2>&1)" || selfinv_rc="$?"
if [ "${selfinv_rc}" = '0' ]; then
   printf '%s\n' 'jsfuzz: FATAL: invariants self-check PASSED but MUST FAIL -- fast-check did not catch a deliberately-false property. Refusing a false green.' >&2
   exit 1
fi
if [ "${selfinv_out#*Property failed}" = "${selfinv_out}" ] && [ "${selfinv_out#*Counterexample}" = "${selfinv_out}" ]; then
   printf '%s\n' 'jsfuzz: FATAL: invariants self-check failed for the WRONG reason (no fast-check counterexample) -- did not prove the fuzz asserts. Output:' >&2
   printf '%s\n' "${selfinv_out}" >&2
   exit 1
fi

## --- real gates over the first-party modules ---
## Coverage sub-gate: deterministic 100% over fuzzed.txt.
run_coverage jsfuzz/fuzzed.txt 'jsfuzz/**/*.fuzz.js'
## Invariants sub-gate: rotating-seed exploration, fail loud on any counterexample.
run_invariants 'jsfuzz/**/*.fuzz.js'
