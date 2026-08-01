#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'dns_probe_host_from_target' in developer-meta-files
## 'usr/bin/dm-upload-images'.
##
## THE BUG: the DNS warm-up looped over
## '$dist_server_with_upload_location_list' -- which holds rsync targets of the
## form '<user>@<host>:<path>' -- and handed each WHOLE string to the resolver.
## Every lookup therefore returned NXDOMAIN, and a blanket '|| true' hid it, so
## the warm-up never warmed anything. This asserts the bare host is derived.
##
## 'dm-upload-images' cannot be sourced without a build environment, so the
## function is EXTRACTED and exercised on its own -- the same technique
## 'pre_cleanup_dispatch_test.sh' uses.
##
## Needs no root and no network.
##
## Subject selection (first that exists):
##   $DM_UPLOAD_IMAGES  ->  ./dm-upload-images next to this test
##   ->  ~/derivative-maker/packages/kicksecure/developer-meta-files/usr/bin/dm-upload-images

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

## Resolve the subject into the global 'subject_path'. Returns through a
## global, not "$(locate_subject)": an 'exit 77' inside a command
## substitution ends only the SUBSHELL, so the SKIP would never reach the
## runner.
subject_path=""
locate_subject() {
   local candidate

   ## An EXPLICIT override that is unreadable is an error, never a silent
   ## fall-through to another candidate -- that would test a different file
   ## than the caller named.
   if [ -n "${DM_UPLOAD_IMAGES:-}" ]; then
      if [ ! -r "${DM_UPLOAD_IMAGES}" ]; then
         ## SKIP, not error: dist-ai-tests-all CONSTRUCTS this path
         ## unconditionally, so an unreadable value means the target is not
         ## checked out (the dist-ai-tests lane takes no submodules), which is
         ## exactly what 77 is for. A genuine typo still surfaces -- the runner
         ## reports SKIPPED, and an unauthorized skip is a failure under
         ## --component.
         printf '%s\n' "SKIP: DM_UPLOAD_IMAGES='${DM_UPLOAD_IMAGES}' is not readable (developer-meta-files not checked out?)." >&2
         exit 77
      fi
      subject_path="${DM_UPLOAD_IMAGES}"
      return 0
   fi

   for candidate in \
      "${test_dir}/dm-upload-images" \
      "${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-upload-images"; do
      if [ -n "${candidate}" ] && [ -r "${candidate}" ]; then
         subject_path="${candidate}"
         return 0
      fi
   done
   ## Absent target -> SKIP (77), the convention every dist-ai suite follows:
   ## the dist-ai-tests lane checks the component out WITHOUT submodules, so
   ## packages/kicksecure/developer-meta-files is simply not there. Hard-failing
   ## would report a missing checkout as a broken tool.
   printf '%s\n' "SKIP: dm-upload-images not readable (developer-meta-files not checked out; set DM_UPLOAD_IMAGES to override)." >&2
   exit 77
}

require_host() {
   local upload_target wanted_host actual_host

   upload_target="$1"
   wanted_host="$2"
   actual_host="$(dns_probe_host_from_target "${upload_target}")"

   if [ "${actual_host}" = "${wanted_host}" ]; then
      pass "'${upload_target}' -> '${actual_host}'"
   else
      fail "'${upload_target}': expected '${wanted_host}', got '${actual_host}'"
   fi
}

main() {
   local subject scratch_base extracted

   locate_subject
   subject="${subject_path}"
   printf '%s\n' "INFO: subject: ${subject}"

   scratch_base="$(mktemp --directory)"
   extracted="${scratch_base}/dns_probe_host_from_target.bsh"
   sed -n '/^dns_probe_host_from_target() {$/,/^}$/p' -- "${subject}" > "${extracted}"
   if [ ! -s "${extracted}" ]; then
      printf '%s\n' "ERROR: could not extract dns_probe_host_from_target from '${subject}' -- the function is expected in developer-meta-files usr/bin/dm-upload-images; a pin predating it will not have it." >&2
      safe-rm --recursive --force -- "${scratch_base}"
      return 1
   fi
   # shellcheck disable=SC1090
   source "${extracted}"

   ## The production shape: user, host and path. Passing this whole string to
   ## the resolver is the bug.
   require_host "root@example.com:/var/rsync/ova" "example.com"
   ## No user part.
   require_host "example.com:/srv/upload" "example.com"
   ## Path with colons after the first one.
   require_host "root@example.com:/srv/a:b" "example.com"
   ## Already a bare host.
   require_host "example.com" "example.com"
   ## Subdomain, longer path.
   require_host "user@mirror.example.org:/a/b/c" "mirror.example.org"

   safe-rm --recursive --force -- "${scratch_base}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all dm-upload-images DNS-probe assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
