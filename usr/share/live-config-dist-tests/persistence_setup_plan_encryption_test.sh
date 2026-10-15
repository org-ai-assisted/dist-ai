#!/bin/bash

## These globals cross the sourced-subject boundary: the test SETS has_* that
## plan_encryption reads, and READS primary_key_kind/enroll_keyfile_extra/
## enroll_tpm that it sets. shellcheck cannot follow the dynamic
## HELPER_SCRIPTS_PATH source, so it mis-sees them as unused/unassigned.
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests persistence-setup's plan_encryption(): the key-type SET -> which
## PRIMARY slot cryptsetup luksFormat creates (password or keyfile; mandatory)
## and which extra slots are enrolled (keyfile via luksAddKey, tpm via
## systemd-cryptenroll). tpm WITHOUT a password/keyfile primary is refused (a
## portable overlay cannot be TPM-only). No root, no device.

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

pass_count=0
fail_count=0
eq() {
   if [ "$2" = "$3" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1 (want='$2' got='$3')"
   fi
}

## desc hp hk ht  want_primary want_kf_extra want_tpm
plan_ok() {
   has_password="$2"
   has_keyfile="$3"
   has_tpm="$4"
   primary_key_kind=''
   enroll_keyfile_extra=''
   enroll_tpm=''
   plan_encryption
   eq "$1: primary" "$5" "${primary_key_kind}"
   eq "$1: keyfile-extra" "$6" "${enroll_keyfile_extra}"
   eq "$1: tpm" "$7" "${enroll_tpm}"
}

plan_ok "password"             true  false false  password false false
plan_ok "keyfile"              false true  false  keyfile  false false
plan_ok "password+keyfile"     true  true  false  password true  false
plan_ok "password+tpm"         true  false true   password false true
plan_ok "keyfile+tpm"          false true  true   keyfile  false true
plan_ok "password+keyfile+tpm" true  true  true   password true  true

## tpm-only must be REFUSED (die) -- run in a subshell so the exit is contained.
has_password='false'
has_keyfile='false'
has_tpm='true'
rc=0
out="$( ( plan_encryption ) 2>&1 )" || rc=$?
if [ "${rc}" -ne 0 ] && [[ "${out}" == *"cannot be TPM-only"* ]]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: tpm-only is refused"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: tpm-only not refused (rc=${rc} out='${out}')"
fi

printf '%s\n' ""
printf '%s\n' "===== persistence-setup plan_encryption: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
