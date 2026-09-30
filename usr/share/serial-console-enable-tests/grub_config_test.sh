#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL etc/default/grub.d/30_serial_console.cfg (sourced as
## grub-mkconfig does) and asserts the GRUB settings it must produce:
##  - GRUB_TERMINAL is forced to serial-only (set unconditionally, so a
##    pre-existing "console" is overridden -- a "console serial" dual terminal
##    is unreliable for serial INPUT and garbled under EFI).
##  - the console= kernel parameters are added, APPENDED to any pre-existing
##    GRUB_CMDLINE_LINUX rather than clobbering it.
##  - GRUB_SERIAL_COMMAND is set only when empty (a user override is respected).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

cfg="${SERIAL_CONSOLE_ENABLE_REPO:-}/etc/default/grub.d/30_serial_console.cfg"
if [ ! -r "${cfg}" ]; then
   printf '%s\n' "grub_config_test: 30_serial_console.cfg not readable at '${cfg}'; set SERIAL_CONSOLE_ENABLE_REPO to a checkout." >&2
   ## style-ok: allow-skip: config-only package -- nothing to source without the checkout
   exit 77
fi

pass_count=0
fail_count=0
pass() {
   printf '%s\n' "PASS: $1"
   pass_count=$(( pass_count + 1 ))
}
fail() {
   printf '%s\n' "FAIL: $1" >&2
   fail_count=$(( fail_count + 1 ))
}
check() {
   ## label expected actual
   if [ "$2" = "$3" ]; then
      pass "$1"
   else
      fail "$1: got '$3', want '$2'"
   fi
}

expected_cmdline_tail='console=tty0 console=ttyS0,115200n8'
expected_serial='serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1'

## Source the cfg with a controlled starting env in a subshell (so each case
## starts clean) and print the three GRUB variables it produces.
read_case() {
   (
      GRUB_CMDLINE_LINUX="$1"
      GRUB_TERMINAL="$2"
      GRUB_SERIAL_COMMAND="$3"
      # shellcheck disable=SC1090  # dynamic path: the component cfg under test
      . "${cfg}" >/dev/null 2>&1
      printf '%s\n' "${GRUB_TERMINAL}"
      printf '%s\n' "${GRUB_CMDLINE_LINUX}"
      printf '%s\n' "${GRUB_SERIAL_COMMAND}"
   )
}

## Case 1: a clean starting env -- the defaults the package installs.
mapfile -t out < <(read_case '' '' '')
check 'empty start: GRUB_TERMINAL forced to serial' 'serial' "${out[0]}"
check 'empty start: GRUB_CMDLINE_LINUX gets the console= parameters' \
   "${expected_cmdline_tail}" "${out[1]}"
check 'empty start: GRUB_SERIAL_COMMAND set' "${expected_serial}" "${out[2]}"

## Case 2: a pre-existing GRUB_CMDLINE_LINUX must be APPENDED to, not clobbered.
mapfile -t out < <(read_case 'quiet apparmor=1' '' '')
check 'pre-set cmdline: console= parameters appended, existing kept' \
   "quiet apparmor=1 ${expected_cmdline_tail}" "${out[1]}"

## Case 3: a user-set GRUB_SERIAL_COMMAND must be respected (set only when empty).
mapfile -t out < <(read_case '' '' 'serial --unit=1 --speed=57600')
check 'pre-set serial command: user override respected' \
   'serial --unit=1 --speed=57600' "${out[2]}"

## Case 4: a pre-existing GRUB_TERMINAL (e.g. 'console') must be OVERRIDDEN to
## serial-only -- it is set unconditionally, by design.
mapfile -t out < <(read_case '' 'console' '')
check 'pre-set terminal: console overridden to serial-only' 'serial' "${out[0]}"

total=$(( pass_count + fail_count ))
printf '%s\n' "grub_config_test: ${total} checks, ${pass_count} pass, ${fail_count} fail, 0 skip"
if [ "${fail_count}" -ne 0 ]; then
   exit 1
fi
exit 0
