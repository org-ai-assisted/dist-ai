#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block
## would leak set -o errexit/nounset into the consumer build.sh (each already
## sets its own strict preamble).

## Shared ClusterFuzzLite build-time smoke-run guard. SOURCE this from a
## package's .clusterfuzzlite/build.sh; do not execute. The OSS-Fuzz
## base-builder container clones org-ai-assisted/dist-ai to $SRC/dist-ai, so the
## path is $SRC/dist-ai/usr/share/clusterfuzzlite-lib/smoke-run.bash.
##
## WHY one shared definition: a compiled Python fuzzer whose subject cannot be
## resolved inside the frozen PyInstaller bundle raises SystemExit(77) BEFORE
## atheris starts, so the CFLite fuzz job passes VACUOUSLY -- it never fuzzes.
## The guard was copy-pasted per package and missing from most; a single source
## makes the silent skip impossible to reintroduce, and the safe path the
## default (source + one call), never a step to remember.

## cflite_smoke_run_fuzzers NAME...
##   For each compiled fuzzer ${OUT}/NAME, run a bounded burst (-runs=100) with
##   PYTHONPATH and EVERY *_REPO override cleared from the CHILD env (env -u --
##   the run container has neither, so ONLY the frozen bundle can satisfy the
##   subject import). A non-zero exit (the SystemExit(77) silent-skip, a real
##   crash, or a timeout) returns 1 so the caller's errexit fails the build.
##   Output streams to the build log -- NOT captured via $(), which would block
##   forever on a fuzzer that forks a child holding the pipe; and NOT a temp
##   file (the container has no safe-rm, R-120). Exit-code check only, no
##   libFuzzer-output parsing.
##
## OUT is provided by the OSS-Fuzz base-builder container (the caller's env),
## not assigned here.
# shellcheck disable=SC2154
cflite_smoke_run_fuzzers() {
  local name smoke_rc var
  local -a clean_run
  ## No names is itself a silent skip -- the exact class this guard exists to
  ## catch, one level up. Fail loud rather than pass vacuously.
  if [ "$#" -eq 0 ]; then
    printf '%s\n' "FATAL: cflite_smoke_run_fuzzers called with no fuzzer names" >&2
    return 1
  fi
  for name in "$@"; do
    ## Clear the resolution env for the CHILD so ONLY the frozen bundle can
    ## satisfy the subject import: PYTHONPATH plus every *_REPO override
    ## (compgen -v lists them generically, no per-package list). env -u strips
    ## each from the child environment directly -- a readonly var, which `unset`
    ## cannot remove, still cannot leak in.
    clean_run=(env -u PYTHONPATH)
    while read -r var; do
      case "${var}" in
        *_REPO)
          clean_run+=(-u "${var}")
          ;;
      esac
    done < <(compgen -v)
    ## Run directly so output streams to the build log; timeout bounds a hung
    ## fuzzer (SIGKILL after the grace period). Do NOT capture via $(): a fuzzer
    ## that forks a child inheriting the pipe would block the substitution
    ## forever, even after timeout kills the fuzzer itself. The if-condition
    ## keeps the caller's errexit from aborting on the expected non-zero (the
    ## SystemExit(77) silent-skip, a real crash, or a timeout).
    if "${clean_run[@]}" timeout --kill-after=10 120 "${OUT}/${name}" -runs=100; then
      printf '%s\n' "smoke-run OK ${name}"
    else
      smoke_rc=$?
      printf '%s\n' \
        "FATAL: ${name} did not fuzz (exit ${smoke_rc}) -- subject unresolved in bundle" >&2
      return 1
    fi
  done
}
