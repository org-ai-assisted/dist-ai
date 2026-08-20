#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock 'eglinfo' for detect_software_rendering_test.sh (symlinked onto PATH as
## 'eglinfo'). Prints the renderer line from EGLINFO_STUB_RENDERER (empty when
## unset) and, when EGLINFO_STUB_COUNT names a file, appends one byte per call so
## the test can assert the real probe runs at most once per boot. Arguments (the
## subject passes '-B') are ignored.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${EGLINFO_STUB_COUNT:-}" ]; then
   printf '%s' x >>"${EGLINFO_STUB_COUNT}"
fi

printf '%s\n' "${EGLINFO_STUB_RENDERER:-}"
