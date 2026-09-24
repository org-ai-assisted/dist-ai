#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## codeql-language-specific wrapper around dm-consumer-load.sh.
## When build-mode=manual (c-cpp consumers), 'build-command' is
## a required key in the dm-consumer.yml section; otherwise it
## is optional. 'prepare-command' is always optional.
##
## Expected env:
##   DM_SECTION  - section name in .github/dm-consumer.yml
##                 (e.g. 'codeql-python', 'codeql-cpp')
##   BUILD_MODE  - 'manual' (build-command required) or any
##                 other value (build-command optional)

set -o errexit
set -o errtrace
set -o nounset
set -o pipefail
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC2154  # BUILD_MODE: provided by the CI workflow env
case "${BUILD_MODE}" in
   manual)
      required='build-command'
      optional='prepare-command'
      ;;
   *)
      required=''
      optional='build-command,prepare-command'
      ;;
esac

# shellcheck disable=SC2154  # DM_SECTION: set by the CI workflow env
"$(dirname -- "$0")/dm-consumer-load.sh" \
   "${DM_SECTION}" "${required}" "${optional}"
