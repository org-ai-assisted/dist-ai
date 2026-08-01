#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Source the grub.d snippet named by argv 1 and print the variables it sets, one
## 'name=value' per line.
##
## Safe to source ONLY because the caller has already asserted the file performs
## no filesystem writes. The pre-fix version created and removed symlinks under an
## ABSOLUTE /boot/grub path, so sourcing THAT would have modified this machine's
## bootloader theme -- which is why the test asserts write-freedom first and
## treats sourcing as a follow-up, not as the primary check.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

# shellcheck disable=SC1090
source "$1"

printf 'GRUB_DISTRIBUTOR=%s\n' "${GRUB_DISTRIBUTOR:-}"
printf 'GRUB_THEME=%s\n' "${GRUB_THEME:-}"
printf 'GRUB_GFXMODE=%s\n' "${GRUB_GFXMODE:-}"
