#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Emission-path inner runner for test_pkg_git_packages_git_log_writer.sh.
## Runs the extracted pkg_git_packages_git_log_writer (+ its real dry_run_or_run
## and commit_filter, passed via env) over the derivative-maker branch of a
## throwaway repo, so the single-pass commit loop (hash/author/body parse,
## AI-trailer strip, contributor credit, multi-line emit) is exercised.
## ${1}=repo (cwd + source root), ${2}=old tag, ${3}=new tag, ${4}=changelog out.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

cd -- "${1}"

# shellcheck disable=SC2034  # all consumed by the eval'd functions
{
   red=''
   bold=''
   reset=''
   cyan=''
   announcements_drafts_dir="$(dirname -- "${4}")"
   derivative_maker_source_code_dir="${1}"
   batch_current_package_reponame='derivative-maker'
   batch_current_package_changelog="${4}"
   batch_func_init_done='true'
   batch_meta_dry_run='false'
   derivative_version_old_main="${2}"
   derivative_version_new_main="${3}"
}

# shellcheck disable=SC2154  # exported by the calling test
eval "${DRY_RUN_TEXT}"
# shellcheck disable=SC2154
eval "${FILTER_TEXT}"
# shellcheck disable=SC2154
eval "${WRITER_TEXT}"
pkg_git_packages_git_log_writer >/dev/null 2>&1
