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
##   Expand GLOB under nullglob into the caller's array named OUTVAR, and FATAL
##   (return 1) if nothing matches. nullglob is saved and restored so the
##   caller's own globbing is left untouched. Returned as a nameref array (not
##   printed) so the zero-match return 1 propagates to the caller's errexit as a
##   simple command, rather than through a process substitution that would
##   swallow it.
cflite_list_harnesses() {
  local -n _cflite_out="$1"
  local _cflite_pattern="$2"
  ## Save/restore nullglob with `shopt -q` in a condition, NOT `_prev="$(shopt -p
  ## nullglob)"`: `shopt -p` returns non-zero when the option is UNSET, which
  ## trips the caller's errexit on the assignment (a bare call then aborts the
  ## build on the normal match path).
  local _cflite_had_nullglob='no'
  if shopt -q nullglob; then
    _cflite_had_nullglob='yes'
  fi
  shopt -s nullglob
  # shellcheck disable=SC2206  # intentional pathname expansion of the glob
  _cflite_out=( ${_cflite_pattern} )
  if [ "${_cflite_had_nullglob}" = 'no' ]; then
    shopt -u nullglob
  fi
  if [ "${#_cflite_out[@]}" -eq 0 ]; then
    printf 'FATAL: no fuzz harnesses matched %s\n' "${_cflite_pattern}" >&2
    return 1
  fi
}
