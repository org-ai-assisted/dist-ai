#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Behavioral proof for the tb-updater dispvm home binds: with a no-canonicalize
## directive a root 'mount --bind' REFUSES a symlinked mountpoint; without it it
## FOLLOWS (the CWE-59 root symlink-follow LPE). Runs each case in a private
## mount namespace and prints 'MODE=<m> VERDICT=<v>' per case.
##
## Reuses dm-help-steps-tests' hardened-kernel-aware namespace selection
## (root -> --mount; unprivileged -> --user --map-root-user --mount) and its
## world-readable staging (needed under --map-root-user), from the SAME dist-ai
## package -- no duplication of that logic. (A shared dist-ai-tests-common harness
## is the standing follow-up; until it exists, source the one existing copy.)

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(dirname -- "$(readlink -f -- "$0")")"
# shellcheck source=../dm-help-steps-tests/help_steps_test_lib.bsh
source "${here}/../dm-help-steps-tests/help_steps_test_lib.bsh"

inner="${here}/dispvm_bind_probe_inner.sh"

if ! mount_namespace_available; then
   printf '%s\n' "VERDICT=NO_MOUNT_NAMESPACE"
   exit 3
fi

for mode in plain flag opt; do
   ## run_in_mount_namespace stages inner (+ a 'subject', unused here)
   ## world-readable and enters the namespace; inner reads the mode as its $2.
   out="$(run_in_mount_namespace "${inner}" "${inner}" "${mode}")"
   printf '%s\n' "MODE=${mode} ${out}"
done
