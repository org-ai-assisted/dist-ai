#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Companion probe for qubes_conf_nounset_test.sh. Sources the 40_qubes.conf
## given as argv 1 under 'set -o nounset', with a non-apt uwtwrapper_parent so
## the conf takes its benign 'not torified -> return' path. Run by the test with
## torified_check UNSET -- the exact trigger for the unbound-variable abort. On
## the fixed conf this prints SOURCED_OK; a pre-fix conf aborts before it.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

uwtwrapper_parent="/usr/bin/nonapt-probe"
# shellcheck disable=SC1090
source "$1"
printf '%s\n' "SOURCED_OK"
