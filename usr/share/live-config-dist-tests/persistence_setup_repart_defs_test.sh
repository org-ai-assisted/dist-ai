#!/bin/bash

## These globals cross the sourced-subject boundary: the test SETS has_*/encrypt/
## filesystem that the subject's plan_encryption/assemble_repart_defs read, and
## READS encrypt_value/primary_key_kind/enroll_keyfile_extra/defdir they set.
## shellcheck cannot follow the dynamic HELPER_SCRIPTS_PATH source, so it mis-sees
## these as unused (SC2034) / unassigned (SC2154).
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests persistence-setup's ENGINE LOGIC without touching any device: the
## key-type -> Encrypt= mapping (plan_encryption) and the systemd-repart
## definition-file assembly (assemble_repart_defs). These build the dangerous
## partitioning commands, so getting Encrypt=/Type=/Label=/Format= and the extra
## unencrypted boot partition right is what this guards. The actual repart run on
## a block device is a separate e2e (its primitives were validated separately).
## Sources the REAL script (main behind a was_executed guard). No root, no device.

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
   local desc want got
   desc="$1"
   want="$2"
   got="$3"
   if [ "${want}" = "${got}" ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${desc}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${desc} (want='${want}' got='${got}')"
   fi
}

## --- plan_encryption: key-type set -> Encrypt= + primary key + extra slot ---
plan_case() {
   has_password="$1"
   has_keyfile="$2"
   has_tpm="$3"
   plan_encryption
}

plan_case true false false
eq "password-only: Encrypt=key-file" 'key-file' "${encrypt_value}"
eq "password-only: primary=password" 'password' "${primary_key_kind}"
eq "password-only: no keyfile extra" 'false' "${enroll_keyfile_extra}"

plan_case false false true
eq "tpm-only: Encrypt=tpm2" 'tpm2' "${encrypt_value}"
eq "tpm-only: primary=none" 'none' "${primary_key_kind}"

plan_case true false true
eq "password+tpm: Encrypt=key-file+tpm2" 'key-file+tpm2' "${encrypt_value}"
eq "password+tpm: primary=password" 'password' "${primary_key_kind}"

plan_case false true false
eq "keyfile-only: Encrypt=key-file" 'key-file' "${encrypt_value}"
eq "keyfile-only: primary=keyfile" 'keyfile' "${primary_key_kind}"

plan_case true true false
eq "password+keyfile: primary=password" 'password' "${primary_key_kind}"
eq "password+keyfile: keyfile enrolled as extra slot" 'true' "${enroll_keyfile_extra}"

plan_case true true true
eq "password+keyfile+tpm: Encrypt=key-file+tpm2" 'key-file+tpm2' "${encrypt_value}"
eq "password+keyfile+tpm: keyfile extra" 'true' "${enroll_keyfile_extra}"

## --- assemble_repart_defs: generated definition files -----------------------
has_file_line() {
   local file needle
   file="$1"
   needle="$2"
   [ -r "${file}" ] && grep --quiet --fixed-strings -- "${needle}" "${file}"
}

## plaintext: one persist def, ext4, no Encrypt=, no boot partition.
encrypt='false'
filesystem='ext4'
assemble_repart_defs
got=0; has_file_line "${defdir}/50-persist.conf" 'Type=root' || got=1
eq "plaintext: persist Type=root" 0 "${got}"
got=0; has_file_line "${defdir}/50-persist.conf" 'Label=persistence' || got=1
eq "plaintext: persist Label=persistence" 0 "${got}"
got=0; has_file_line "${defdir}/50-persist.conf" 'Format=ext4' || got=1
eq "plaintext: persist Format=ext4" 0 "${got}"
got=1; has_file_line "${defdir}/50-persist.conf" 'Encrypt=' || got=0
eq "plaintext: no Encrypt=" 0 "${got}"
got=1; [ -e "${defdir}/40-boot.conf" ] || got=0
eq "plaintext: no boot partition" 0 "${got}"
safe-rm --recursive --force -- "${defdir}"

## encrypted: persist carries Encrypt=<value>, plus the unencrypted boot area.
encrypt='true'
encrypt_value='key-file+tpm2'
filesystem='btrfs'
assemble_repart_defs
got=0; has_file_line "${defdir}/50-persist.conf" 'Encrypt=key-file+tpm2' || got=1
eq "encrypted: persist Encrypt=key-file+tpm2" 0 "${got}"
got=0; has_file_line "${defdir}/50-persist.conf" 'Format=btrfs' || got=1
eq "encrypted: persist Format=btrfs" 0 "${got}"
got=0; has_file_line "${defdir}/40-boot.conf" 'Label=persistbootx' || got=1
eq "encrypted: unencrypted boot partition present" 0 "${got}"
got=1; has_file_line "${defdir}/40-boot.conf" 'Encrypt=' || got=0
eq "encrypted: boot partition is NOT encrypted" 0 "${got}"
safe-rm --recursive --force -- "${defdir}"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup repart-defs logic: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
