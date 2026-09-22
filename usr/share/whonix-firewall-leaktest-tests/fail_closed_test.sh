#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Leak test: Tor down must FAIL CLOSED, not leak to the clearnet.
##
## The killswitch invariant: if Tor is not running, workstation traffic must be
## DROPPED, never routed directly to the internet. Modeled by leaving the Tor
## TransPort dead (nolistener) and confirming a workstation connection produces
## no clearnet egress. The canary flushes the firewall so the same traffic
## forwards out -- proving the harness would catch a fail-OPEN.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

lib_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./leaktest_lib.sh
source "${lib_dir}/leaktest_lib.sh"

leaktest_preconditions
trap leaktest_teardown EXIT

rc=0
leaktest_fail_closed_case || rc=$?
exit "${rc}"
