#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Test: the vendored step-summary-emit.sh has not drifted from the
## developer-meta-files original it is a copy of.
##
## Why a copy exists at all: developer-meta-files does not package its ci/
## directory (debian/developer-meta-files.install ships no ci/ entry), so a test
## run against the INSTALLED package has no upstream path to reach. Vendoring is
## therefore load-bearing, not laziness -- but a silent copy is a copy that goes
## stale, and then this suite would be testing a version of the helper that no
## workflow actually runs.
##
## Compares only when DEVELOPER_META_FILES_PATH points at a source checkout;
## in installed-package mode there is nothing to compare against and the test
## reports that plainly rather than pretending it verified something.

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

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
VENDORED="$(cd -- "${SCRIPT_DIR}/.." && pwd)/step-summary-emit.sh"

[ -r "${VENDORED}" ] || {
   printf '%s\n' "FAIL: vendored helper not found: '${VENDORED}'" >&2
   exit 1
}

[ -v DEVELOPER_META_FILES_PATH ] || DEVELOPER_META_FILES_PATH=''

if [ -z "${DEVELOPER_META_FILES_PATH}" ]; then
   printf '%s\n' \
      'NOTICE: DEVELOPER_META_FILES_PATH unset (installed-package mode); no source' \
      '        checkout to compare the vendored step-summary-emit.sh against.'
   exit 0
fi

ORIGINAL="${DEVELOPER_META_FILES_PATH}/ci/step-summary-emit.sh"

if [ ! -r "${ORIGINAL}" ]; then
   printf '%s\n' \
      "FAIL: DEVELOPER_META_FILES_PATH is set to '${DEVELOPER_META_FILES_PATH}' but" \
      "      '${ORIGINAL}' is missing. Either the path is not a developer-meta-files" \
      '      checkout, or ci/step-summary-emit.sh was moved or renamed there -- in' \
      '      which case the vendored copy here is now orphaned.' >&2
   exit 1
fi

if ! diff --unified -- "${ORIGINAL}" "${VENDORED}"; then
   printf '%s\n' \
      'FAIL: the vendored step-summary-emit.sh has drifted from developer-meta-files.' \
      "      Refresh it:  cp -- '${ORIGINAL}' '${VENDORED}'" >&2
   exit 1
fi

printf '%s\n' 'PASS: vendored step-summary-emit.sh matches developer-meta-files.'
