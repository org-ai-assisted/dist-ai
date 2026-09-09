#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build-steps.d/4350_reimage-raw-reproducible rebuilds the root filesystem with
## mke2fs -O <features>. That feature list MUST be prefixed with 'none,'.
##
## THE BUG: mke2fs initializes the feature set from the build host's
## /etc/mke2fs.conf ([defaults]/[fs_types] base_features) and only THEN edits it
## with -O. So a bare -O "${fs_features}" leaves the rebuilt filesystem carrying
## whatever extra features the REBUILD host's mke2fs.conf enables -- a
## host-dependent, non-reproducible feature set. The pseudo-feature 'none' clears
## the defaults first, so -O "none,${fs_features}" yields EXACTLY the original
## image's extracted features regardless of the rebuild host. (Verified: a bare
## list produced ~13 extra host-default features vs the 'none,' form.)
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

if [ -z "${DERIVATIVE_MAKER_DIR}" ] || [ ! -d "${DERIVATIVE_MAKER_DIR}/build-steps.d" ]; then
   printf '%s\n' "FATAL: no derivative-maker checkout to scan" >&2
   printf '%s\n' "set DERIVATIVE_MAKER_DIR to one" >&2
   exit 1
fi

reimage="${DERIVATIVE_MAKER_DIR}/build-steps.d/4350_reimage-raw-reproducible"
if [ ! -f "${reimage}" ]; then
   printf '%s\n' "FATAL: expected file missing: ${reimage}" >&2
   exit 1
fi

## The mke2fs feature-list argument, one per matching line (there should be one).
mapfile -t feature_args < <(grep -nE '\-O[[:space:]]+"[^"]*\$\{fs_features\}"' -- "${reimage}" || true)

if [ "${#feature_args[@]}" -eq 0 ]; then
   printf '%s\n' "FAIL: no mke2fs -O \"...\${fs_features}\" argument found in ${reimage##*/}"
   printf '%s\n' "      -- the check tested nothing (the invocation moved or changed shape)"
   exit 1
fi

fail=0
for line in "${feature_args[@]}"; do
   case "${line}" in
      *'-O "none,${fs_features}"'*)
         printf '%s\n' "PASS: mke2fs clears host defaults first (${line%%:*}: -O \"none,\${fs_features}\")"
         ;;
      *)
         printf '%s\n' "FAIL: mke2fs -O argument is NOT prefixed with 'none,' -- rebuilt filesystem"
         printf '%s\n' "      inherits the rebuild host's mke2fs.conf default features (non-reproducible):"
         printf '%s\n' "      ${line}"
         fail=1
         ;;
   esac
done

exit "${fail}"
