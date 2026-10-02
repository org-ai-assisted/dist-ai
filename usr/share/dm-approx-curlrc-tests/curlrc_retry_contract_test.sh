#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract: every curlrc that derivative-maker's approx instance reads MUST
## retry transient upstream failures.
##
## THE BUG: approx is a lazy cache that, on a miss, shells 'curl --fail' to
## snapshot.debian.org. snapshot.debian.org is load-balanced and rate-limited:
## a single file returns a transient 404 / 5xx / timeout even though the
## Packages index from the SAME snapshot guarantees it exists. With no retry,
## one blip makes approx hand apt a 404 and aborts the whole multi-package
## cowbuilder create after an hour of work. --retry-all-errors is mandatory
## because the transient status includes 404, which plain --retry ignores.
##
## Both curlrc variants fetch from snapshot.debian.org (clearnet and Tor), so
## both must carry the directives. Guards against a future edit silently
## dropping them.
##
## No root, no network. Reads the checkout only.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v DERIVATIVE_MAKER_DIR ] || DERIVATIVE_MAKER_DIR=""

if [ -z "${DERIVATIVE_MAKER_DIR}" ] || [ ! -d "${DERIVATIVE_MAKER_DIR}/approx" ]; then
   printf '%s\n' "FATAL: no derivative-maker checkout with approx/ to scan" >&2
   printf '%s\n' "set DERIVATIVE_MAKER_DIR to one" >&2
   exit 1
fi

## Every curlrc approx reads must carry these.
required=( '--retry' '--retry-all-errors' )
curlrc_files=( "${DERIVATIVE_MAKER_DIR}/approx/curlrc" "${DERIVATIVE_MAKER_DIR}/approx/curlrc-tor" )

fail=0
checked=0
for curlrc_file in "${curlrc_files[@]}"; do
   if [ ! -f "${curlrc_file}" ]; then
      printf '%s\n' "ERROR: ${curlrc_file}: missing." >&2
      fail=1
      continue
   fi
   checked=$(( checked + 1 ))
   for directive in "${required[@]}"; do
      ## Anchor to line start (a curl config directive), tolerate trailing args.
      if ! grep --quiet -E "^${directive}([[:space:]]|\$)" -- "${curlrc_file}"; then
         printf '%s\n' "ERROR: ${curlrc_file}: missing required directive '${directive}'." >&2
         fail=1
      fi
   done
done

if [ "${checked}" -eq 0 ]; then
   printf '%s\n' "ERROR: no approx curlrc file found to check." >&2
   exit 1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED: approx curlrc retry contract violated." >&2
   exit 1
fi

printf '%s\n' "OK: approx curlrc retry contract satisfied (${checked} file(s))."
