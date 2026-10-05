#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block
## would leak set -o errexit/nounset into the consumer build.sh (each already
## sets its own strict preamble).

## Shared ClusterFuzzLite harness-glob helper. SOURCE this from a package's
## .clusterfuzzlite/build.sh; do not execute. The OSS-Fuzz base-builder container
## clones org-ai-assisted/dist-ai to $SRC/dist-ai, so the path is
## $SRC/dist-ai/usr/share/clusterfuzzlite-lib/harness-glob.bash.
##
## WHY one shared definition: expanding a harness glob by hand is a two-part trap
## under the build.sh errexit preamble --
##   - WITHOUT nullglob, a zero-match leaves the loop running once on the LITERAL
##     pattern (compile_python_fuzzer fuzz/fuzz_*.py), failing with a confusing
##     "file not found" far from the real cause.
##   - WITH nullglob but no count check, a zero-match runs the loop ZERO times:
##     the build passes having compiled NO fuzzers -- a SILENT GREEN, the worst
##     outcome.
## The safe form is nullglob PLUS an explicit zero-match FATAL, in one audited
## place, so the consumer calls one function and cannot reintroduce either half.

## cflite_list_harnesses OUTVAR GLOB
##   Expand GLOB into the caller's array named OUTVAR, and FATAL (return 1) if
##   nothing matches. Returned as a nameref array (not printed) so the zero-match
##   return 1 propagates to the caller's errexit as a simple command, rather than
##   through a process substitution that would swallow it.
##
##   The expansion runs under a controlled, then-restored shell state so the
##   zero-match guard cannot be faked:
##     - IFS empty  -- a GLOB containing a space is NOT word-split before
##                     globbing; a split, wildcard-less word would survive
##                     nullglob as a literal array entry and fake a match;
##     - noglob off -- a caller's `set -f` cannot leave GLOB unexpanded (the
##                     literal pattern would likewise fake a match);
##     - nullglob on -- a zero match yields an EMPTY array, caught below.
##   Internals are named `__clh_*` so a caller's OUTVAR is very unlikely to
##   collide with (and shadow) them.
##   Save/restore nullglob with `shopt -q` in a condition, NOT `$(shopt -p
##   nullglob)`: `shopt -p` returns non-zero when the option is UNSET, tripping
##   the caller's errexit on the assignment.
cflite_list_harnesses() {
  local -n __clh_out="$1"
  local __clh_nullglob='off'
  local __clh_noglob='off'
  if shopt -q nullglob; then
    __clh_nullglob='on'
  fi
  case "$-" in
    *f*)
      __clh_noglob='on'
      ;;
  esac
  local IFS=
  set +f
  shopt -s nullglob
  # shellcheck disable=SC2206  # intentional single-word pathname expansion
  __clh_out=( ${2} )
  if [ "${__clh_nullglob}" = 'off' ]; then
    shopt -u nullglob
  fi
  if [ "${__clh_noglob}" = 'on' ]; then
    set -f
  fi
  if [ "${#__clh_out[@]}" -eq 0 ]; then
    printf 'FATAL: no fuzz harnesses matched %s\n' "${2}" >&2
    return 1
  fi
}
