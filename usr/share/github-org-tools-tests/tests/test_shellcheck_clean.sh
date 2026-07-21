#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock-API test: every github-org-* / dm-github-*
## tool, the shared github-org-lib, and every ci/tests/*.sh script
## must pass shellcheck cleanly. The project-wide .shellcheckrc at
## the repo root applies; this test catches regressions before they
## reach a reviewer.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ "${CI:-}" != "true" ]; then
   printf '%s\n' \
      'error: this script must run with CI=true (GitHub Actions or equivalent).' >&2
   exit 1
fi

# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

has shellcheck \
   || { printf '%s\n' 'error: shellcheck not found on PATH; install via apt.' >&2; exit 1; }

## REPO_ROOT is the developer-meta-files checkout, provided by the
## github-org-tools-tests entrypoint via DEVELOPER_META_FILES_PATH (the tests
## live under dist-ai, not inside the developer-meta-files tree).
REPO_ROOT="${DEVELOPER_META_FILES_PATH:?run via the github-org-tools-tests entrypoint}"

## Files this test owns. Keep the list explicit rather than globbing
## the whole repo - the github-org-* tools and the dm-* wrappers are
## the surface this PR introduced; other parts of developer-meta-files
## have their own pre-existing shellcheck status that is out of scope.
files=(
   "${REPO_ROOT}/usr/bin/github-org-clone"
   "${REPO_ROOT}/usr/bin/github-org-fork"
   "${REPO_ROOT}/usr/bin/github-org-push"
   "${REPO_ROOT}/usr/bin/dm-github-org-policy"
   "${REPO_ROOT}/usr/bin/dm-github-personal-policy"
   "${REPO_ROOT}/usr/bin/dm-github-fork-sync"
   "${REPO_ROOT}/usr/libexec/developer-meta-files/github-org-lib.bsh"
   "${REPO_ROOT}/usr/libexec/developer-meta-files/github-policy-lib.bsh"
   "${REPO_ROOT}/.github/actions/install-deps/install-genmkfile.sh"
   "${REPO_ROOT}/.github/actions/install-deps/install-helper-scripts.sh"
   "${REPO_ROOT}/ci/live-probe-unauth.sh"
)
## The mock-test suite itself (this file, its siblings and the runner) moved to
## the dist-ai github-org-tools-tests payload and is linted by dist-ai's own
## shell gate; this test guards the developer-meta-files tools/libs surface.

fail=0
failed_scripts=()
for script_path in "${files[@]}"; do
   if [ ! -r "${script_path}" ]; then
      printf '%s\n' "FAIL: not readable: ${script_path}" >&2
      fail=1
      failed_scripts+=( "${script_path}" )
      continue
   fi
   ## --external-sources lets shellcheck follow the '# shellcheck
   ## source=...' directives, which is needed so SC2317 ("command
   ## appears to be unreachable") does not fire for show_help and
   ## similar callbacks invoked indirectly from the policy lib.
   if ! shellcheck --external-sources -- "${script_path}"; then
      fail=1
      failed_scripts+=( "${script_path}" )
   fi
done

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' '' "FAIL: shellcheck reported issues in:" >&2
   for failed in "${failed_scripts[@]}"; do
      printf '  - %s\n' "${failed}" >&2
   done
fi

exit "${fail}"
