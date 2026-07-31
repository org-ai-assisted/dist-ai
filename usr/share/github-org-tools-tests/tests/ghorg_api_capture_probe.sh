#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Probe helper for test_mock_body_capture_failure.sh.
##
## Makes ONE mocked ghorg_api call and prints its exit status on stdout,
## so the caller can assert the status of the call itself rather than of
## a whole `dm-github-org-policy --apply` run. --apply's status also
## reflects fixture coverage for every endpoint the current policy walks,
## which makes it useless as evidence about request-body capture.
##
## A separate file rather than a heredoc in the test: shell that needs
## strict mode, a source, and an exit-status contract is real code and
## belongs where shellcheck and the style gate can see it.
##
## Expected env:
##   DEVELOPER_META_FILES_PATH  developer-meta-files checkout
##   GHORG_MOCK, GHORG_MOCK_DIR, GHORG_MOCK_BODY_DIR  mock wiring
##
## Prints: the ghorg_api exit status, one line. Always exits 0 itself --
## the status under test is the payload, not this script's own verdict.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

# shellcheck source=/dev/null
source "${DEVELOPER_META_FILES_PATH}/usr/libexec/developer-meta-files/github-org-lib.bsh"

rc=0
ghorg_api PUT '/orgs/org-ai-assisted/actions/permissions' '{"probe":1}' \
   > /dev/null 2>&1 || rc="$?"

printf '%s\n' "${rc}"
