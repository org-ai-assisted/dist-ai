#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh br_add_to_file must build its temp with a SHORT basename that is
## independent of the input basename. A template built from "${file_name}"
## (input basename + ".br.XXXXXX") overflows NAME_MAX for a long-but-valid input
## basename, so mktemp fails before any conversion and the "_br" file is never
## produced. Drives the REAL sourced strings.bsh -- no copy of the subject.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
  libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
  libdir='/usr/libexec/helper-scripts'
fi
strings_bsh_path="${libdir}/strings.bsh"
if [ ! -r "${strings_bsh_path}" ]; then
  printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh_path}'" >&2
  printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
  exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${strings_bsh_path}"
if [ "$(type -t br_add_to_file)" != 'function' ]; then
  printf '%s\n' "FATAL: sourcing '${strings_bsh_path}' defined no 'br_add_to_file'" >&2
  exit 1
fi

work="$(mktemp --directory --tmpdir br-add-name-max.XXXXXX)"
# shellcheck disable=SC2317  ## EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass_count=0
fail_count=0
check() {
  if [ "$2" = 'true' ]; then
    pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
  else
    fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1 ($3)"
  fi
}

## A 252-char basename: valid under NAME_MAX=255 and the 255-char "_br"
## destination, but a "${file_name}.br.XXXXXX" template needs 262 chars.
long_base="$(head --bytes=252 /dev/zero | tr '\0' 'a')"
long_src="${work}/${long_base}"
printf '%s\n' 'line1' 'line2' > "${long_src}"
rc=0
( br_add_to_file "${long_src}" ) || rc=$?
check "long input basename: br_add_to_file succeeds (short temp basename)" \
  "$( [ "${rc}" -eq 0 ] && [ -f "${long_src}_br" ] && printf '%s' true || printf '%s' false )" "rc=${rc}"
if [ -f "${long_src}_br" ]; then
  check "long input basename: output has <br /> appended per line" \
    "$( [ "$(head --lines 1 -- "${long_src}_br")" = 'line1<br />' ] && printf '%s' true || printf '%s' false )" \
    "first='$(head --lines 1 -- "${long_src}_br" 2>/dev/null)'"
fi

## Ordinary short basename still works and lands in the same directory.
printf '%s\n' 'x' 'y' > "${work}/short"
rc=0
( br_add_to_file "${work}/short" ) || rc=$?
check "short input basename still works" \
  "$( [ "${rc}" -eq 0 ] && [ "$(tr '\n' '|' < "${work}/short_br")" = 'x<br />|y<br />|' ] && printf '%s' true || printf '%s' false )" "rc=${rc}"

## A directory whose name ends in a newline: the temp MUST stay in that exact
## directory (byte-exact), the file is converted, and the newline-stripped
## sibling path is never created. $(dirname ...) would strip the newline and
## retarget the temp outside the directory (symlink-safety escape + wrong dir).
nl_dir="${work}/pre"$'\n'
mkdir -- "${nl_dir}"
printf '%s\n' 'hi' > "${nl_dir}/note"
rc=0
( br_add_to_file "${nl_dir}/note" ) || rc=$?
check "newline-named directory: converted in place, no stripped-sibling write" \
  "$( [ "${rc}" -eq 0 ] \
      && [ -f "${nl_dir}/note_br" ] \
      && [ "$(cat -- "${nl_dir}/note_br")" = 'hi<br />' ] \
      && [ ! -e "${work}/pre" ] \
      && printf '%s' true || printf '%s' false )" "rc=${rc}"

## A 253-byte basename: "${file_name}_br" exceeds NAME_MAX, so the rename fails.
## The function must fail AND leave no orphaned 0600 temp (the short template
## creates the temp before the doomed rename; it must be cleaned up).
leak_dir="${work}/leak"
mkdir -- "${leak_dir}"
b253="$(head --bytes=253 /dev/zero | tr '\0' 'b')"
printf '%s\n' 'M' > "${leak_dir}/${b253}"
rc=0
( br_add_to_file "${leak_dir}/${b253}" ) || rc=$?
orphans="$(find "${leak_dir}" -maxdepth 1 -name '.br.*' | wc --lines)"
check "253-byte basename: fails cleanly, no leaked temp" \
  "$( [ "${rc}" -ne 0 ] && [ ! -e "${leak_dir}/${b253}_br" ] && [ "${orphans}" -eq 0 ] && printf '%s' true || printf '%s' false )" \
  "rc=${rc} orphans=${orphans}"

printf '%s\n' ""
printf '%s\n' "===== br_add_to_file name-max: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
