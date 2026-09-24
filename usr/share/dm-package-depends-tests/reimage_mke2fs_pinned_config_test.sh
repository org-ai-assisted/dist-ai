#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build-steps.d/4350_reimage-raw-reproducible rebuilds the root filesystem with
## mke2fs. That rebuild MUST be reproducible regardless of the rebuild host.
##
## THE BUG IT GUARDS: mke2fs initializes the feature set from mke2fs.conf. Left to
## the host's /etc/mke2fs.conf, the rebuilt filesystem carries whatever extra
## features the REBUILD host enables -- a host-dependent, non-reproducible feature
## set. The build step pins reproducibility by invoking mke2fs under
## MKE2FS_CONFIG=<in-repo build-data/mke2fs.conf>, so the host's /etc/mke2fs.conf
## cannot change the result; the pinned conf's [defaults]/[fs_types] fully
## determine the features. (An earlier form used '-O "none,${fs_features}"' to
## clear host defaults; the pinned-config form supersedes it.)
##
## STRUCTURAL check on the shipped invocation. A behavioral migration (drive the
## real mke2fs) is impractical: the call lives deep in reimage_raw(), behind
## dev-mapper setup, sudo and a real source image, so it needs a full image build.
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

fail=0

## 1. mke2fs must be invoked under a pinned MKE2FS_CONFIG (not the host default),
##    so the rebuild host's /etc/mke2fs.conf cannot leak features.
mapfile -t mke2fs_lines < <(grep -nE 'MKE2FS_CONFIG=[^[:space:]]+[[:space:]]+mke2fs' -- "${reimage}" || true)
if [ "${#mke2fs_lines[@]}" -eq 0 ]; then
   printf '%s\n' "FAIL: no 'MKE2FS_CONFIG=... mke2fs' invocation found in ${reimage##*/}"
   printf '%s\n' "      -- the reproducibility guard (pinned mke2fs.conf) moved or changed shape"
   fail=1
else
   for line in "${mke2fs_lines[@]}"; do
      printf '%s\n' "PASS: mke2fs runs under a pinned MKE2FS_CONFIG (${line%%:*})"
   done
fi

## 2. That MKE2FS_CONFIG must point at the in-repo build-data/mke2fs.conf, not /etc.
if grep --quiet --extended-regexp -- 'mke2fs_config=.*build-data/mke2fs\.conf' "${reimage}"; then
   pass_config='true'
else
   pass_config='false'
fi
if [ "${pass_config}" = 'true' ]; then
   printf '%s\n' "PASS: MKE2FS_CONFIG points at the in-repo build-data/mke2fs.conf"
else
   printf '%s\n' "FAIL: mke2fs_config does not resolve to the in-repo build-data/mke2fs.conf"
   printf '%s\n' "      -- reproducibility depends on the rebuild host's /etc/mke2fs.conf"
   fail=1
fi

## 3. The pinned conf must actually ship in the checkout (the guard is only real
##    if the file mke2fs reads exists).
if [ -f "${DERIVATIVE_MAKER_DIR}/build-data/mke2fs.conf" ]; then
   printf '%s\n' "PASS: pinned build-data/mke2fs.conf ships in the checkout"
else
   printf '%s\n' "FAIL: pinned build-data/mke2fs.conf is missing from the checkout"
   fail=1
fi

exit "${fail}"
