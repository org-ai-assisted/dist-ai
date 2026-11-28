#!/bin/bash

## These globals cross the sourced-subject boundary.
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## persistence-setup read_passphrase must yield the SAME bytes cryptsetup enrolls
## as the LUKS keyslot. luksFormat consumes ONE line from its stdin pipe, so the
## keyslot is the passphrase's first line; the TPM transient --unlock-key-file
## must hold those same bytes. Reading the whole file instead would:
##   * mismatch the TPM unlock for a multi-line passphrase (enroll fails AFTER
##     the disk is repartitioned, so a no---force retry is then refused), and
##   * for a leading-newline file, enroll an EMPTY keyslot while the non-empty
##     check sees the later bytes -- a LUKS volume openable with no passphrase.
## Drives the REAL sourced read_passphrase (file AND stdin paths). No root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/persistence-setup"
else
   subject='/usr/bin/persistence-setup'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
export HELPER_SCRIPTS_PATH

# shellcheck disable=SC1090
source "${subject}"
if [ "$(type -t read_passphrase)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'read_passphrase'" >&2
   exit 1
fi

work="$(mktemp --directory --tmpdir persistence-setup-readpass.XXXXXX)"
# shellcheck disable=SC2317  ## EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass_count=0; fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1 ($3)"
   fi
}

## from a file: only the first line (the bytes cryptsetup's pipe keyslot uses).
multi="${work}/multi"; printf '%s\n' 'correct horse' 'battery staple' > "${multi}"
passphrase=''; passphrase_file="${multi}"; read_passphrase
check "multi-line file: passphrase is the FIRST line only" \
   "$( [ "${passphrase}" = 'correct horse' ] && printf '%s' true || printf '%s' false )" "got='${passphrase}'"

## a leading-newline file: the first line is empty, so the non-empty check can
## reject it instead of enrolling an empty keyslot.
lead="${work}/lead"; printf '%s\n' '' 'correct horse battery' > "${lead}"
passphrase='PRESET'; passphrase_file="${lead}"; read_passphrase
check "leading-newline file: passphrase is EMPTY (rejectable)" \
   "$( [ -z "${passphrase}" ] && printf '%s' true || printf '%s' false )" "got='${passphrase}'"

## an ordinary single-line file (with trailing newline): the line, no newline.
single="${work}/single"; printf '%s\n' 'swordfish' > "${single}"
passphrase=''; passphrase_file="${single}"; read_passphrase
check "single-line file: passphrase is the line without the trailing newline" \
   "$( [ "${passphrase}" = 'swordfish' ] && printf '%s' true || printf '%s' false )" "got='${passphrase}'"

## a file with NO trailing newline: still the content.
nonl="${work}/nonl"; printf '%s' 'nonewline' > "${nonl}"
passphrase=''; passphrase_file="${nonl}"; read_passphrase
check "no-trailing-newline file: passphrase is the content" \
   "$( [ "${passphrase}" = 'nonewline' ] && printf '%s' true || printf '%s' false )" "got='${passphrase}'"

## the stdin sentinel path reads the first line too (unchanged, pinned here).
passphrase=''; passphrase_file='-'; read_passphrase <<< $'from-stdin\nignored'
check "stdin sentinel: passphrase is the first stdin line" \
   "$( [ "${passphrase}" = 'from-stdin' ] && printf '%s' true || printf '%s' false )" "got='${passphrase}'"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup read_passphrase: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
