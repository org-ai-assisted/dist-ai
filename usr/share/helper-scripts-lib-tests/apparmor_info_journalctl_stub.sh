#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Mock 'journalctl' for apparmor_info_clean_boot_test.sh. apparmor-info always calls
## 'journalctl _TRANSPORT=audit --output cat "${@}"', so arguments are ignored.
##   APPARMOR_INFO_STUB_FIXTURE  file whose contents to emit as the audit output. When
##                               set it MUST be readable: an unreadable/missing fixture
##                               is a test-setup bug, so fail loudly rather than emit
##                               nothing (which would masquerade as an empty journal).
##                               Unset = emit nothing (an empty journal).
##   APPARMOR_INFO_STUB_RC       exit code (default 0). A non-zero value models a real
##                               journalctl read failure (permission denied, corrupted
##                               journal): empty stdout, non-zero exit -- so the test can
##                               assert that genuine read errors still propagate and are
##                               NOT swallowed by the fix's grep '|| true'.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

fixture="${APPARMOR_INFO_STUB_FIXTURE:-}"
rc="${APPARMOR_INFO_STUB_RC:-0}"

if [ -n "${fixture}" ]; then
   if [ ! -r "${fixture}" ]; then
      printf '%s\n' "apparmor_info_journalctl_stub: FATAL: fixture not readable: '${fixture}'" >&2
      exit 99
   fi
   cat -- "${fixture}"
fi

exit "${rc}"
