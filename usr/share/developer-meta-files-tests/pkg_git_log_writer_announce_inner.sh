#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Inner runner for test_pkg_git_packages_git_log_writer.sh: runs the extracted
## generate_announcement under its OWN active errexit, so the caller's `if`
## context cannot suppress the cat-abort this guards. A derivative whose
## giant_git_log.txt is absent -- a --no-batch run on a single package of the
## OTHER project, or a release with zero commits for that derivative -- must NOT
## abort generate_announcement: the fix creates the file empty first.
## ${1}=announcements-drafts dir (the caller seeds which changelog files exist).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC2034  # all consumed by the eval'd functions
{
   announcements_drafts_dir="${1}"
   derivative_name_list=( kicksecure whonix )
   derivative_version_old_main='18.2.1.0-developers-only'
   derivative_version_new_main='18.2.1.7-developers-only'
   derivative_release_type='point'
   batch_meta_dry_run='false'
}

# shellcheck disable=SC2154  # exported by the calling test
eval "${DRY_RUN_TEXT}"
# shellcheck disable=SC2154
eval "${ANNOUNCE_TEXT}"
generate_announcement >/dev/null 2>&1
