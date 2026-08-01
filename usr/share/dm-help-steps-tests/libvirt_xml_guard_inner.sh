#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the extracted 'check-libvirt-xml' body (argv 1) with 'error' stubbed to
## report and exit non-zero, exactly as help-steps/pre's does.
##
## The inputs the guard reads come from the environment, so a case is expressed by
## what the caller exports: $dist_build_raw, $dist_build_qcow2,
## $libvirt_source_kvm_file, $dist_build_flavor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

body="$1"

error() {
   printf '%s\n' "$*" >&2
   exit 1
}

eval "${body}"
check-libvirt-xml
