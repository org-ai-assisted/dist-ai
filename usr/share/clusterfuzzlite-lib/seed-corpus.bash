#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block
## would leak set -o errexit/nounset into the consumer build.sh (each already
## sets its own strict preamble).

## Shared ClusterFuzzLite seed-corpus helper. SOURCE this from a package's
## .clusterfuzzlite/build.sh; do not execute. The OSS-Fuzz base-builder container
## clones org-ai-assisted/dist-ai to $SRC/dist-ai, so the path is
## $SRC/dist-ai/usr/share/clusterfuzzlite-lib/seed-corpus.bash.
##
## WHY one shared definition: a seed corpus stored as NAME<space>HEX lines (hex
## keeps the file pure ASCII past the repo-wide non-ASCII gate) is exploded into
## individual input files by a read loop that has three easy-to-reintroduce
## traps, each silent or confusing under the consumer's errexit:
##   - a final line with no trailing newline is dropped by a bare `while read`,
##     silently SHRINKING the corpus;
##   - a NAME carrying `/` or `..` writes outside the output dir / crashes on a
##     missing subdir;
##   - zero decoded seeds later makes `zip ... .` exit 12 ("Nothing to do") and
##     crash the build with a confusing zip error rather than a clear message.
## Encapsulated once so a consumer calls one function and cannot reintroduce any
## of them.

## cflite_explode_hex_corpus SEEDS_FILE DECODER OUT_DIR
##   Read NAME<space>HEX lines from SEEDS_FILE, decode each HEX via DECODER (a
##   command reading hex on stdin and writing bytes on stdout), and write the
##   bytes to OUT_DIR/NAME. Blank and `##`-comment lines are skipped. On success
##   the count of decoded seeds is printed on stdout (nothing else) so the caller
##   can capture it. FATAL (return 1, under the caller's errexit) on a NAME
##   containing `/` or `..` (a malformed/escaping entry), or on zero seeds
##   decoded (an empty corpus the later zip step cannot handle).
cflite_explode_hex_corpus() {
  local seeds_file="$1"
  local decoder="$2"
  local out_dir="$3"
  local seed_name seed_hex
  local count=0
  ## `|| [ -n "${seed_name}" ]` keeps the final line when the file has no
  ## trailing newline (read returns non-zero but still sets the variables).
  while read -r seed_name seed_hex || [ -n "${seed_name}" ]; do
    case "${seed_name}" in
      ''|'##'*)
        continue
        ;;
      */*|*..*)
        printf 'FATAL: unsafe seed name %s in %s\n' "${seed_name}" "${seeds_file}" >&2
        return 1
        ;;
    esac
    [ -n "${seed_hex}" ] || continue
    printf '%s' "${seed_hex}" | "${decoder}" > "${out_dir}/${seed_name}"
    count=$(( count + 1 ))
  done < "${seeds_file}"
  if [ "${count}" -eq 0 ]; then
    printf 'FATAL: no seeds decoded from %s\n' "${seeds_file}" >&2
    return 1
  fi
  printf '%s\n' "${count}"
}
