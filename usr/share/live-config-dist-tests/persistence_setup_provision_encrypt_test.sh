#!/bin/bash

## These globals cross the sourced-subject boundary: the test SETS has_*/encrypt/
## filesystem/key material that provision_persistence_fs + plan_encryption read.
## shellcheck cannot follow the dynamic HELPER_SCRIPTS_PATH source, so it mis-sees
## them as unused/unassigned.
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests persistence-setup's provision_persistence_fs(): a key-type SELECTION
## must TRANSLATE into the correct cryptsetup / systemd-cryptenroll invocations. The
## sibling persistence_setup_plan_encryption_test.sh proves the DECISION
## (plan_encryption's globals); this proves the decision is carried into the right
## commands -- above all the NEGATIVE cases a globals test cannot catch: no
## luksAddKey without a keyfile extra, no TPM enroll on a non-tpm overlay, no crypto
## at all on a plaintext overlay.
##
## cryptsetup / systemd-cryptenroll / wipefs / mkfs.* are invoked by BARE NAME, so a
## PATH-prepended recording shim (a spy -- the subject-under-test is still the REAL
## function) captures each argv. seed_overlay_dirs mounts a real fs, so it is
## overridden to a no-op recorder. A FAKE partition path is used; no shim ever
## touches a real device, and the shim dir is isolated to this test's PATH and torn
## down on EXIT, so it can never leak into a real install path. No root, no device.

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

work="$(mktemp --directory --tmpdir persistence-setup-provision.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## One recording spy, symlinked under each intercepted command name: it appends
## "<command> <args>" to PS_RECORD and succeeds. These are exactly the external
## binaries provision_persistence_fs invokes by bare name.
shimdir="${work}/bin"
mkdir --parents -- "${shimdir}"
export PS_RECORD="${work}/record"
recorder="${shimdir}/recorder"
# shellcheck disable=SC2016  ## ${0##*/} / $* are literal in the emitted shim, expanded when it runs
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "${0##*/} $*" >> "${PS_RECORD}"'
   printf '%s\n' 'exit 0'
} > "${recorder}"
chmod 0770 -- "${recorder}"
for cmd in cryptsetup systemd-cryptenroll wipefs mkfs.ext4; do
   ln --symbolic -- recorder "${shimdir}/${cmd}"
done
export PATH="${shimdir}:${PATH}"

## seed_overlay_dirs mounts the freshly-made filesystem; override it to a recording
## no-op so the unit needs no real device.
# shellcheck disable=SC2317  ## called indirectly by provision_persistence_fs
seed_overlay_dirs() { printf '%s\n' "seed_overlay_dirs $*" >> "${PS_RECORD}"; }

fake_part='/dev/fake-persist'
## provision_persistence_fs opens the LUKS mapper as persistence_setup_${$}; it runs
## in THIS shell (sourced), so $$ matches. Pin the exact mapper token (not a prefix)
## so mkfs/luksOpen/luksClose are checked against the real opened device.
mapper="persistence_setup_$$"
mapper_dev="/dev/mapper/${mapper}"

pass_count=0
fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}

## Does SOME recorded line contain EVERY needle as a COMPLETE, space-delimited
## token? Both the line and each needle are space-padded and matched as " needle "
## so a token boundary is required: '--all' never matches '--allow-discards',
## 'persistence' never 'persistence-old', '/dev/fake-persist' never
## '/dev/fake-persist-extra'. Needles match anywhere on the line (argv-order
## independent). "$1" is the expected presence ('true'/'false'); prints 'true' iff
## presence matches. A NEGATIVE ("$1"=false) assertion is passed the COMMAND
## token(s) ONLY (never an operand), so a command run against the WRONG operand is
## still detected as having run (an operand needle would let it slip the negative).
line_has() {
   local want="$1" hay needle found='false' line_ok
   shift
   while IFS= read -r hay; do
      line_ok='true'
      for needle in "$@"; do
         if [[ " ${hay} " != *" ${needle} "* ]]; then
            line_ok='false'
            break
         fi
      done
      if [ "${line_ok}" = 'true' ]; then
         found='true'
         break
      fi
   done < "${PS_RECORD}"
   if [ "${found}" = "${want}" ]; then printf '%s' true; else printf '%s' false; fi
}

## desc hp hk ht expect_addkey expect_tpm
run_case() {
   local desc="$1"
   true > "${PS_RECORD}"
   has_password="$2"
   has_keyfile="$3"
   has_tpm="$4"
   primary_key_kind=''
   enroll_keyfile_extra=''
   enroll_tpm=''
   plan_encryption
   encrypt='true'
   luks_uuid="${default_luks_uuid}"
   filesystem='ext4'
   keyfile="${work}/keyfile"
   primary_key_file="${work}/primarykey"
   true > "${keyfile}"
   true > "${primary_key_file}"
   open_mapper=''
   provision_persistence_fs "${fake_part}"
   check "${desc}: wipefs targets the partition" "$(line_has true 'wipefs' '--all' "${fake_part}")"
   check "${desc}: luksFormat on the partition" "$(line_has true 'cryptsetup' 'luksFormat' "${fake_part}")"
   check "${desc}: luksOpen the partition onto the mapper" "$(line_has true 'cryptsetup' 'luksOpen' "${fake_part}" "${mapper}")"
   check "${desc}: luksClose closes the mapper" "$(line_has true 'cryptsetup' 'luksClose' "${mapper}")"
   check "${desc}: mkfs -L persistence on the opened mapper" "$(line_has true 'mkfs.ext4' '-L' 'persistence' "${mapper_dev}")"
   ## luksAddKey/TPM-enroll iff planned. A command run against the WRONG operand is
   ## still a run, so the NEGATIVE asserts the command absent (command token only).
   if [ "$5" = 'true' ]; then
      check "${desc}: luksAddKey on the partition" "$(line_has true 'cryptsetup' 'luksAddKey' "${fake_part}")"
   else
      check "${desc}: no luksAddKey" "$(line_has false 'cryptsetup' 'luksAddKey')"
   fi
   if [ "$6" = 'true' ]; then
      check "${desc}: tpm enroll on the partition" "$(line_has true 'systemd-cryptenroll' "${fake_part}")"
   else
      check "${desc}: no tpm enroll" "$(line_has false 'systemd-cryptenroll')"
   fi
}

## --- key-type -> command mapping (encrypt=true) ----------------------------
## primary always luksFormat; luksAddKey iff password AND keyfile; TPM enroll iff tpm.
run_case 'password'              true  false false  false false
run_case 'keyfile'              false  true  false  false false
run_case 'password+keyfile'      true  true  false  true  false
run_case 'password+tpm'          true  false true   false true
run_case 'keyfile+tpm'          false  true  true   false true
run_case 'password+keyfile+tpm'  true  true  true   true  true

## --- plaintext overlay: no crypto at all -----------------------------------
true > "${PS_RECORD}"
encrypt='false'
filesystem='ext4'
open_mapper=''
provision_persistence_fs "${fake_part}"
check 'plaintext: wipefs targets the partition' "$(line_has true 'wipefs' '--all' "${fake_part}")"
check 'plaintext: NO cryptsetup' "$(line_has false 'cryptsetup')"
check 'plaintext: NO tpm enroll' "$(line_has false 'systemd-cryptenroll')"
check 'plaintext: mkfs -L persistence on the bare partition' "$(line_has true 'mkfs.ext4' '-L' 'persistence' "${fake_part}")"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup provision encrypt: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
