#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the extracted 'filesystem_mounts_setup' guard (argv 1) against a stubbed
## environment, so the branch under test is chosen by the caller and not by
## whatever nbd state this machine happens to be in.
##
## $GUARD_MODPROBE_RC -- exit status of the stubbed 'sudo' (the modprobe attempt).
## $GUARD_CLAIM_RC    -- exit status of the stubbed 'nbd_device_claim'.
##
## nbd_device_claim is stubbed rather than the device path substituted: the guard
## now asks it whether ANY usable device exists, which is the whole point (a host
## whose nbd0 is busy but nbd1 free is usable). Stubbing '[' is not an option
## either -- '[' and 'test' are separate builtins, so a 'test' function does not
## intercept '[ -b ... ]'.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

body="$1"

## Referenced by the mkdir the guard falls through to.
# shellcheck disable=SC2034
mount_a=/nonexistent/a
# shellcheck disable=SC2034
mount_b=/nonexistent/b

sudo() {
   if [ "${GUARD_MODPROBE_RC}" -ne 0 ]; then
      printf '%s\n' "sudo: modprobe: command not found" >&2
   fi
   return "${GUARD_MODPROBE_RC}"
}

nbd_device_claim() {
   if [ "${GUARD_CLAIM_RC}" -eq 0 ]; then
      printf '%s\n' /dev/nbd7
   fi
   return "${GUARD_CLAIM_RC}"
}

## The trailing brace closes the function the extraction slice cut short: the
## sed range ends at the 'mkdir' line, mid-body, on purpose.
eval "${body}
}"
filesystem_mounts_setup /a /b
