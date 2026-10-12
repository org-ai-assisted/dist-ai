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
##   APPARMOR_INFO_STUB_RC_SEQ   space-separated exit codes applied to SUCCESSIVE calls
##                               (call count tracked in APPARMOR_INFO_STUB_COUNT_FILE), so
##                               a test can fail ONLY the second (ALLOWED) pipeline's read
##                               -- apparmor-info calls journalctl once per pipeline. Falls
##                               back to APPARMOR_INFO_STUB_RC past the sequence.
##   APPARMOR_INFO_STUB_COUNT_FILE  file holding the running call count for the sequence.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

fixture="${APPARMOR_INFO_STUB_FIXTURE:-}"
rc="${APPARMOR_INFO_STUB_RC:-0}"
seq="${APPARMOR_INFO_STUB_RC_SEQ:-}"
count_file="${APPARMOR_INFO_STUB_COUNT_FILE:-}"

## Per-call exit code from the sequence, tracked across the two separate journalctl
## processes via the count file.
if [ -n "${seq}" ] && [ -n "${count_file}" ]; then
   n=0
   if [ -r "${count_file}" ]; then
      file_n="$(cat -- "${count_file}")"
      ## An empty or non-numeric count file must not poison the integer test below.
      case "${file_n}" in
         '' | *[!0-9]*)
            n=0
            ;;
         *)
            n="${file_n}"
            ;;
      esac
   fi
   codes=()
   read -r -a codes <<<"${seq}" || true
   if [ "${n}" -lt "${#codes[@]}" ]; then
      rc="${codes[${n}]}"
   fi
   printf '%s' "$(( n + 1 ))" >"${count_file}"
fi

if [ -n "${fixture}" ]; then
   if [ ! -r "${fixture}" ]; then
      printf '%s\n' "apparmor_info_journalctl_stub: FATAL: fixture not readable: '${fixture}'" >&2
      exit 99
   fi
   cat -- "${fixture}"
fi

exit "${rc}"
