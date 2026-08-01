#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the extracted 'filesystem_mounts_setup' guard (argv 1) with 'modprobe'
## guaranteed to fail: a 'sudo' stub that reports command-not-found, exactly as the
## kmod-less container does.
##
## The caller substitutes the DEVICE PATH into the body rather than stubbing the
## '[' builtin: '[' and 'test' are separate builtins, so overriding a 'test'
## function does not intercept '[ -b ... ]' at all. Substituting the path leaves
## the branch structure under test untouched.

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
   printf '%s\n' "sudo: modprobe: command not found" >&2
   return 1
}

## The trailing brace closes the function the extraction slice cut short: the
## sed range ends at the 'mkdir' line, mid-body, on purpose.
eval "${body}
}"
filesystem_mounts_setup /a /b
