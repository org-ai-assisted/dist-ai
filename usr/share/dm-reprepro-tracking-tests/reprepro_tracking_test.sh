#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Static test for derivative-maker's reprepro repository configuration
## (aptrepo_remote/<derivative>/conf/distributions).
##
## The reproducibility workflow republishes the build's own .deb, .buildinfo,
## .changes and source into the derivative apt repository so a third party can
## fetch exactly what was built and reproduce it. reprepro only RETAINS those
## extra files when the distribution stanza opts in via a 'Tracking:' line, so
## a stanza that silently loses that line would drop the .buildinfo / .changes /
## sources and quietly break reproducibility verification -- with no build-time
## error. This test pins that config.
##
## Asserts, for BOTH derivatives (kicksecure, whonix):
##
##   - every 'trixie*' codename stanza (trixie and its -proposed-updates,
##     -testers, -developers siblings) carries EXACTLY:
##         Tracking: minimal includebuildinfos includechanges keepsources
##     i.e. it keeps buildinfos (includebuildinfos), the .changes
##     (includechanges) and the source (keepsources) -- the three retention
##     knobs reproducibility verification depends on.
##   - at least one such stanza is actually checked per file (guards against a
##     parser bug passing vacuously).
##
## Legacy pre-trixie codenames (bullseye*, bookworm*) predate the reproducible
## lane and are intentionally NOT required to set Tracking; they are skipped.
##
## Subject selection (first that exists):
##   $DM_SOURCE_DIR/aptrepo_remote  ->  override
##   ->  ~/derivative-maker/aptrepo_remote (source checkout)
##
## Pure static text checks -- safe to run anywhere, no root, no side effects:
##   ./reprepro_tracking_test.sh

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Single source of truth for the required retention line and the codename
## prefix it is required on. Keep in sync with
## aptrepo_remote/*/conf/distributions.
readonly expected_tracking="Tracking: minimal includebuildinfos includechanges keepsources"
readonly tracked_codename_prefix="trixie"
readonly derivative_list=("kicksecure" "whonix")

test_failures=0

pass() {
   printf '%s\n' "PASS: $*"
}

fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## Locate the aptrepo_remote directory of the derivative-maker source tree.
## Prints the path on stdout; empty output means not found.
locate_aptrepo_remote() {
   local candidate

   if [ -n "${DM_SOURCE_DIR:-}" ]; then
      candidate="${DM_SOURCE_DIR}/aptrepo_remote"
      if [ -d "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   fi

   candidate="${HOME}/derivative-maker/aptrepo_remote"
   if [ -d "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return 0
   fi

   return 0
}

## Assert every 'trixie*' stanza in a single distributions file carries the
## required Tracking line. reprepro distributions files are RFC822-like: stanzas
## separated by blank lines, each field a 'Key: value' line.
check_distributions_file() {
   local file="$1"
   local repo="$2"

   local line codename stanza_tracking checked_count
   checked_count=0
   codename=""
   stanza_tracking=""

   ## Emit a trailing blank line so the final stanza is flushed by the same
   ## blank-line branch that handles the interior ones.
   while IFS="" read -r line; do
      case "${line}" in
         "")
            if [ -n "${codename}" ]; then
               case "${codename}" in
                  "${tracked_codename_prefix}"*)
                     checked_count=$((checked_count + 1))
                     if [ "${stanza_tracking}" = "${expected_tracking}" ]; then
                        pass "${repo}: ${codename}: Tracking line correct"
                     elif [ -z "${stanza_tracking}" ]; then
                        fail "${repo}: ${codename}: missing '${expected_tracking}'"
                     else
                        fail "${repo}: ${codename}: Tracking is '${stanza_tracking}', expected '${expected_tracking}'"
                     fi
                     ;;
               esac
            fi
            codename=""
            stanza_tracking=""
            ;;
         "Codename: "*)
            codename="${line#Codename: }"
            ;;
         "Tracking: "*)
            stanza_tracking="${line}"
            ;;
      esac
   done < <(cat -- "${file}"; printf '\n')

   if [ "${checked_count}" = "0" ]; then
      fail "${repo}: no '${tracked_codename_prefix}*' stanza found in ${file} (parser bug or config removed?)"
   fi
}

main() {
   local aptrepo_remote derivative file

   aptrepo_remote="$(locate_aptrepo_remote)"
   if [ -z "${aptrepo_remote}" ]; then
      printf '%s\n' "SKIP: aptrepo_remote not found (set DM_SOURCE_DIR)." >&2
      exit 77
   fi

   for derivative in "${derivative_list[@]}"; do
      file="${aptrepo_remote}/${derivative}/conf/distributions"
      if [ ! -r "${file}" ]; then
         fail "${derivative}: distributions file not readable: ${file}"
         continue
      fi
      check_distributions_file "${file}" "${derivative}"
   done

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all reprepro Tracking assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
