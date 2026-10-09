#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Inner runner for test_pkg_git_packages_git_log_writer.sh: runs the extracted
## pkg_git_packages_git_log_writer (passed as ${WRITER_TEXT}) under its OWN
## active strict mode, so the caller's `if` context cannot suppress the errexit
## abort the test relies on. ${1}=derivative-maker root, ${2}=package reponame.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

cd -- "${1}/packages/kicksecure/${2}"

# shellcheck disable=SC2034  # consumed by the eval'd function
derivative_maker_source_code_dir="${1}"
# shellcheck disable=SC2034
batch_current_package_reponame="${2}"
# shellcheck disable=SC2034
batch_func_init_done="true"
# shellcheck disable=SC2034
batch_meta_dry_run="true"
# shellcheck disable=SC2034
derivative_version_old_main="oldtag"
# shellcheck disable=SC2034
derivative_version_new_main="newtag"

# shellcheck disable=SC2154  # WRITER_TEXT is exported by the calling test
eval "${WRITER_TEXT}"
pkg_git_packages_git_log_writer >/dev/null 2>&1
