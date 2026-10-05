#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## askpass-default is dsudo's SUDO_ASKPASS helper: it prints the password sudo should submit.
## Kicksecure accounts ship with an EMPTY password (not NOPASSWD), so the DEFAULT must be EMPTY
## (so `dsudo ...` works headlessly on a fresh image); an explicit `sudo_password=...` overrides.
## The old `${sudo_password:-changeme}` was doubly wrong: it defaulted to a stale "changeme" AND
## (via `:-`) could not emit an empty password even when asked. Drives the REAL script.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v DIST_BASE_FILES_REPO ] || DIST_BASE_FILES_REPO=""
rel='usr/libexec/derivative-base-files/askpass-default'
if [ -n "${DIST_BASE_FILES_REPO}" ] && [ -x "${DIST_BASE_FILES_REPO}/${rel}" ]; then
   askpass="${DIST_BASE_FILES_REPO}/${rel}"
else
   askpass="/${rel}"
fi
[ -x "${askpass}" ] || { printf 'FATAL: askpass-default not found/executable at %s\n' "${askpass}" >&2; exit 1; }

pass=0
fail=0
check() {
   local desc="$1" want="$2" got="$3"
   if [ "${got}" = "${want}" ]; then
      pass=$(( pass + 1 )); printf 'PASS: %s\n' "${desc}"
   else
      fail=$(( fail + 1 )); printf 'FAIL: %s -- got [%s], want [%s]\n' "${desc}" "${got}" "${want}"
   fi
}

## DEFAULT (no sudo_password): EMPTY -- so `dsudo` submits the empty password fresh images ship with.
check 'unset sudo_password -> empty (default)'      ''         "$(env -u sudo_password "${askpass}")"
## Explicit empty must stay empty (the `:-` -> `-` fix; old code wrongly emitted "changeme").
check 'sudo_password="" -> empty (honored)'         ''         "$(sudo_password='' "${askpass}")"
## A non-empty override is forwarded verbatim (legacy "changeme" image, or any set password).
check 'sudo_password=changeme -> changeme'          'changeme' "$(sudo_password='changeme' "${askpass}")"
check 'sudo_password=hunter2 -> hunter2'            'hunter2'  "$(sudo_password='hunter2' "${askpass}")"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
